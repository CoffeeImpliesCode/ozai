//! The relay handshake, client half, and the ping tracker that sits beside it.
//!
//! Upstream `iroh-relay` authenticates a client two ways, and they are one
//! protocol rather than two. A `KeyMaterialClientAuth` rides along on the
//! WebSocket upgrade request and is verified against keying material exported
//! from the same TLS session (RFC 5705): no extra round trip, and impossible
//! in a browser, which has no exporter. Failing that, the relay sends a
//! `ServerChallenge` and the client answers with a signature of it: one extra
//! round trip, and the only thing that works over plain HTTP.
//!
//! Captured 2026-09-30 from n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8: `handshake::clientside`,
//! `ServerChallenge`, `ClientAuth` and `KeyMaterialClientAuth` from
//! `iroh-relay/src/protos/handshake.rs`; `PingTracker` and its two constants
//! from `iroh-relay/src/ping_tracker.rs`; the call sites that decide which
//! path a client takes from `iroh-relay/src/client.rs` and
//! `iroh-relay/src/client/conn.rs`. Each is named where it is reproduced.
//!
//! The frames themselves belong to `relay/frame.zig` and are used from there
//! rather than restated. What is here is the part the codec cannot decide:
//! which message means what, and what to send next.
//!
//! Nothing here reads a clock, opens a socket, or reaches for a global. Time
//! arrives as an argument and I/O arrives as an event, and the whole output
//! is a value — which is what lets a test drive a handshake that upstream can
//! only run over a TLS session with a `duplex` pair in the middle of it.

const std = @import("std");
const key = @import("../base/key.zig");
const frame = @import("frame.zig");
const net_report = @import("../net/report.zig");

const NodeId = key.NodeId;
const SecretKey = key.SecretKey;
const Signature = key.Signature;

/// Nanoseconds on a monotonic timeline the caller owns.
///
/// The relay and the net report both measure time and neither may read a
/// clock, so the vocabulary is defined once, where the report fold that first
/// needed it put it.
pub const Nanos = net_report.Nanos;

/// The number of bytes of an export that are signed; the rest is passed
/// through. Upstream splits an export at 16 (`handshake.rs:263`) and explains
/// why at `handshake.rs:299-306`.
const signed_prefix = 16;

/// The bytes that are only echoed back. Upstream `key_material_suffix`.
pub const key_material_suffix_length = 16;

/// A TLS key-material export for one session, as the exporter produced it.
///
/// Upstream asks for 32 bytes with `[0u8; 32]` as the length
/// (`handshake.rs:256-260`). The export itself belongs to the TLS seam; this
/// is the value that seam hands over, and it is an argument because a
/// process-global exporter is what `base` forbids.
pub const KeyMaterial = [32]u8;

/// The label the export must be taken under. Upstream
/// `DOMAIN_SEP_TLS_EXPORT_LABEL` (`handshake.rs:56`).
///
/// It is here rather than at the call site because it is part of the
/// protocol: two ends that export under different labels produce different
/// key material, verify nothing, and fall back to a challenge for no visible
/// reason.
pub const key_material_label = "iroh-relay handshake v1";

/// Domain separation for the challenge signature. Upstream
/// `DOMAIN_SEP_CHALLENGE` (`handshake.rs:52`).
///
/// Signing a key derived from the challenge rather than the challenge itself
/// is what stops a malicious relay collecting arbitrary 16-byte signatures:
/// it picks the challenge, so without this step it could ask for a signature
/// over bytes of its own choosing. Upstream says so at `handshake.rs:211-219`.
const challenge_domain = "iroh-relay handshake v1 challenge signature";

/// Why a credential did not verify.
///
/// Every one of these is normal operation. Upstream `serverside` falls back to
/// a challenge on all of them (`handshake.rs:441-450`) and the comment there
/// says the point: a TLS exporter is not required to match across a proxy, and
/// a failed verify is the protocol working, not failing.
pub const VerifyError = error{
    /// This end has no exporter, so it cannot reproduce the client's export.
    NoKeyingMaterial,
    /// The passed-through half differs, so the two ends did not export the
    /// same material. A proxy that does not middle-man the exporter is the
    /// usual cause.
    MismatchedSuffix,
    /// The signed half does not verify under the claimed node id.
    SignatureInvalid,
};

/// The message a client signs for a challenge: `blake3::derive_key` of the
/// challenge under the domain separation string.
///
/// Upstream `ServerChallenge::message_to_sign` (`handshake.rs:210-220`). The
/// KDF context is the domain string and the key material is the challenge,
/// which is the argument order `Blake3.initKdf` takes.
pub fn messageToSign(challenge: frame.ServerChallenge) [32]u8 {
    var hasher = std.crypto.hash.Blake3.initKdf(challenge_domain, .{});
    hasher.update(&challenge.challenge);
    var message: [32]u8 = undefined;
    hasher.final(&message);
    return message;
}

/// Upstream `ClientAuth::new` (`handshake.rs:225-230`): the answer to a
/// challenge, which is a signature of the derived message under the node id
/// the client claims.
pub fn signChallenge(
    secret: *const SecretKey,
    challenge: frame.ServerChallenge,
) frame.ClientAuth {
    return .{
        .node_id = secret.nodeId(),
        .signature = secret.*.sign(&messageToSign(challenge)),
    };
}

/// Why a signed challenge did not verify.
///
/// Its own set with one arm rather than `VerifyError`: a challenge always has
/// bytes and no exporter is involved, so the other two arms describe a
/// failure this path cannot have, and an error set that names one is one a
/// caller can handle without an `else` that decides nothing.
pub const ChallengeError = error{
    /// The signature does not verify under the claimed node id.
    SignatureInvalid,
};

/// Upstream `ClientAuth::verify` (`handshake.rs:234-247`).
pub fn verifyClientAuth(
    auth: frame.ClientAuth,
    challenge: frame.ServerChallenge,
) ChallengeError!void {
    auth.signature.verify(&messageToSign(challenge), auth.node_id) catch
        return error.SignatureInvalid;
}

/// The credential a client puts in the `iroh-relay-key-material-auth` header
/// on its upgrade request. Upstream `KeyMaterialClientAuth`.
///
/// It is not a frame — upstream postcard-encodes it into a base64url header
/// value and puts it on the HTTP upgrade request, not in the WebSocket
/// stream — so the frame codec does not carry it and it lives here. What is
/// missing on purpose is the header encoding itself: it is the HTTP seam's
/// business, and upstream publishes no captured bytes of one to pin it to, so
/// an encoder here would be an interop claim with nothing behind it.
pub const KeyMaterialAuth = struct {
    /// The node id being claimed. Upstream `public_key`, which is a
    /// `NodeId` here for the reason `docs/ARCHITECTURE.md` gives.
    node_id: NodeId,
    /// A signature of the first 16 bytes of the export. Upstream `signature`,
    /// which is 64 raw bytes rather than 65 for that reason.
    signature: Signature,
    /// The last 16 bytes of the export, echoed back so the relay can tell a
    /// proxy that broke the exporter from a client that signed wrongly.
    key_material_suffix: [key_material_suffix_length]u8,

    /// Upstream `KeyMaterialClientAuth::new` (`handshake.rs:254-269`).
    ///
    /// A null result is not a failure, it is the ordinary state of a browser
    /// and of any client whose TLS stack has no exporter. Upstream returns
    /// `Option` for the same reason and the caller simply omits the header
    /// (`client.rs:328`).
    pub fn create(secret: *const SecretKey, material: ?KeyMaterial) ?KeyMaterialAuth {
        const exported = material orelse return null;
        return .{
            .node_id = secret.nodeId(),
            .signature = secret.*.sign(exported[0..signed_prefix]),
            .key_material_suffix = exported[signed_prefix..][0..key_material_suffix_length].*,
        };
    }

    /// Upstream `KeyMaterialClientAuth::verify` (`handshake.rs:288-330`).
    ///
    /// The suffix is compared before the signature is checked, and the order
    /// is the diagnostic: a matching suffix with a failing signature is a
    /// client with a broken key, and a mismatched suffix is a broken
    /// transport, which is a very different thing to go looking for.
    pub fn verify(self: KeyMaterialAuth, material: ?KeyMaterial) VerifyError!void {
        const exported = material orelse return error.NoKeyingMaterial;
        if (!std.mem.eql(u8, &self.key_material_suffix, exported[signed_prefix..])) {
            return error.MismatchedSuffix;
        }
        // No BLAKE3 here, unlike `messageToSign`: the exporter already
        // domain-separated and keyed its output, and hashing it again would
        // only add a step for the two ends to disagree about.
        self.signature.verify(exported[0..signed_prefix], self.node_id) catch
            return error.SignatureInvalid;
    }
};

/// Which path a client put itself on.
///
/// It is recorded before the first relay frame rather than decided by it,
/// because whether a credential was attached to the upgrade request is a fact
/// about what we sent, and only we know it.
pub const Path = enum {
    /// A `KeyMaterialAuth` went out on the upgrade request, so the relay can
    /// admit the client with no further frame at all.
    key_material,
    /// Nothing was attached, so a challenge is the only way in. Upstream's
    /// browser path.
    signed_challenge,
};

/// How the relay let the client in, as far as the client can tell.
pub const Admitted = enum {
    /// The relay confirmed the key material from the upgrade request. Zero
    /// extra round trips.
    key_material,
    /// The relay challenged us and we signed. One extra round trip.
    signed_challenge,
    /// The relay confirmed a client that offered no credential at all.
    ///
    /// Upstream accepts this — the first read accepts a confirmation whether
    /// or not a challenge was sent (`handshake.rs:344-363`) — and so does
    /// this machine, because tightening the check here would fork the
    /// protocol. It is named rather than folded into either real path
    /// because what authenticated nobody is worth being able to say out loud
    /// in a log.
    unauthenticated,
};

/// Why a handshake cannot finish.
pub const Failure = union(enum) {
    /// A frame arrived that this state does not accept. Upstream
    /// `Error::UnexpectedFrameType`, which carries the whole `FrameType`.
    unexpected_frame: frame.FrameType,
    /// The stream ended mid-handshake. Upstream `Error::UnexpectedEnd`.
    stream_ended,
};

/// What happened between two steps.
pub const Event = union(enum) {
    /// A frame arrived, decoded. Upstream `read_frame`.
    frame: frame.Message,
    /// The stream ended. Upstream `read_frame` on a closed stream.
    stream_ended,
};

/// The client half of the handshake.
pub const State = union(enum) {
    /// The upgrade request is out and the relay has not answered.
    ///
    /// `path` is the path that was offered, and it deliberately survives a
    /// challenge arriving here: a relay that challenges a client which
    /// offered key material has done nothing wrong, and treating it as a
    /// fault is the mistake this machine exists to prevent.
    awaiting_relay: Path,
    /// A `ClientAuth` is on the wire. Only a verdict can come next.
    awaiting_verdict,
    /// The relay admitted us. Terminal.
    established: Admitted,
    /// The relay refused us. Terminal.
    denied: frame.ServerDeniesAuth,
    /// The handshake cannot finish. Terminal.
    failed: Failure,
};

/// What the caller must do after a step.
///
/// At most one, and always a write or a close. Every outcome is visible in
/// the state, and nothing is said twice: a caller that wants to know how the
/// handshake went reads the state, and a caller that wants to know what to
/// write reads this.
pub const Action = union(enum) {
    /// Write this `ClientAuth`. Upstream `write_frame(io, client_info)`.
    send_client_auth: frame.ClientAuth,
    /// Drop the connection, writing nothing.
    ///
    /// Used for a denial as well as for a protocol error: upstream returns
    /// `Error::ServerDeniedAuth` and the caller closes the stream, and after
    /// a `ServerDeniesAuth` the client has nothing left to say either way.
    close,
};

/// One step: the next state, and the one thing to do about it.
pub const Step = struct {
    state: State,
    action: ?Action,
};

/// The machine a client starts in.
pub fn start(path: Path) State {
    return .{ .awaiting_relay = path };
}

/// One step of the client handshake.
///
/// `secret` is the signing key, taken as an argument rather than held: the
/// machine's state is a value that a test can build, and a value that carries
/// a secret key is a value that gets copied into a trace.
pub fn step(state: State, event: Event, secret: *const SecretKey) Step {
    return switch (state) {
        .awaiting_relay => |path| switch (event) {
            .frame => |message| switch (message) {
                // The whole point of the key-material path: a confirmation
                // with no challenge in between, and nothing left to send.
                .server_confirms_auth => .{
                    .state = .{ .established = switch (path) {
                        .key_material => .key_material,
                        .signed_challenge => .unauthenticated,
                    } },
                    .action = null,
                },
                .server_denies_auth => |denial| .{
                    .state = .{ .denied = denial },
                    .action = .close,
                },
                // Normal operation, not a failure: the relay could not verify
                // the export, has no exporter, or never got the header. The
                // client cannot tell these apart and does not need to — it
                // signs the challenge and moves on.
                .server_challenge => |challenge| .{
                    .state = .awaiting_verdict,
                    .action = .{ .send_client_auth = signChallenge(secret, challenge) },
                },
                // The eleven frames the handshake does not name, which is
                // every frame of the send/recv protocol and the one the other
                // direction sends. The `else` is the rule rather than a
                // shortcut: a frame this state does not name is out of order,
                // whatever it is.
                else => fail(.{ .unexpected_frame = std.meta.activeTag(message) }),
            },
            .stream_ended => fail(.stream_ended),
        },
        .awaiting_verdict => switch (event) {
            .frame => |message| switch (message) {
                .server_confirms_auth => .{
                    .state = .{ .established = .signed_challenge },
                    .action = null,
                },
                .server_denies_auth => |denial| .{
                    .state = .{ .denied = denial },
                    .action = .close,
                },
                // A second challenge is out of order, and the tolerance the
                // first read shows is exactly the tolerance the second read
                // does not: upstream reads for a verdict only
                // (`handshake.rs:360`).
                else => fail(.{ .unexpected_frame = std.meta.activeTag(message) }),
            },
            .stream_ended => fail(.stream_ended),
        },
        // A finished handshake is a dead end by design. Upstream's
        // `clientside` has returned by the time any of these is reached, and
        // the frames that follow belong to the connection rather than to the
        // handshake, so folding one in does nothing instead of panicking on a
        // state that cannot occur.
        .established => |admitted| .{ .state = .{ .established = admitted }, .action = null },
        .denied => |denial| .{ .state = .{ .denied = denial }, .action = null },
        .failed => |failure| .{ .state = .{ .failed = failure }, .action = null },
    };
}

fn fail(failure: Failure) Step {
    return .{ .state = .{ .failed = failure }, .action = .close };
}

/// Upstream `PING_TIMEOUT` (`ping_tracker.rs:5`): the longest a pong may take
/// before the connection is treated as dead, and `PingTracker::default()`'s
/// ceiling.
pub const default_max_timeout: Nanos = 5 * std.time.ns_per_s;

/// Upstream `MIN_HEALTH_CHECK_TIMEOUT` (`ping_tracker.rs:8`).
///
/// A health check that fires sooner than this measures its own scheduling
/// jitter rather than the relay's health.
pub const min_health_check_timeout: Nanos = 500 * std.time.ns_per_ms;

/// Upstream `PING_INTERVAL` (`protos/relay.rs:36`): how often the server
/// pings an otherwise idle connection. The client answers without tracking
/// one, which is why the interval is here and not in the client's own state.
pub const ping_interval: Nanos = 15 * std.time.ns_per_s;

comptime {
    // `pingTimeout` clamps into `[min, max]`, and `std.math.clamp` asserts
    // its bounds are ordered. A default ceiling under the floor would turn
    // the first ping into an assertion failure instead of a value.
    if (default_max_timeout < min_health_check_timeout) {
        @compileError("the default ping ceiling is below the health-check floor");
    }
}

/// A ping that is out and not yet answered.
pub const Pending = struct {
    /// The 8 payload bytes the relay will echo back.
    data: [8]u8,
    /// When it went out, on the caller's timeline.
    sent_at: Nanos,
    /// When it stops counting.
    deadline: Nanos,
};

/// Tracks pings on one relay connection.
///
/// Upstream `PingTracker` (`ping_tracker.rs:14-105`), with the two properties
/// that make it a rule rather than a scheduler: only the most recent ping
/// matters, and the next deadline is three times the last round trip clamped
/// into a fixed band. Both are testable without a relay, and both are the
/// kind of thing that is otherwise only ever verified by waiting.
pub const PingTracker = struct {
    pending: ?Pending,
    max_timeout: Nanos,
    /// The last measured round trip, and the only input to the next deadline.
    last_rtt: ?Nanos,

    pub const InitError = error{
        /// A ceiling under the floor would make every clamp an assertion
        /// failure. Upstream panics in the same place
        /// (`Duration::clamp`), one layer deeper and without a name.
        MaxTimeoutBelowFloor,
    };

    /// Upstream `PingTracker::new`.
    pub fn init(max_timeout: Nanos) InitError!PingTracker {
        if (max_timeout < min_health_check_timeout) return error.MaxTimeoutBelowFloor;
        return .{ .pending = null, .max_timeout = max_timeout, .last_rtt = null };
    }

    /// Upstream `PingTracker::default`.
    pub fn withDefaults() PingTracker {
        return .{
            .pending = null,
            .max_timeout = default_max_timeout,
            .last_rtt = null,
        };
    }

    /// The deadline for the next ping. Upstream `ping_tracker.rs:87-91`.
    ///
    /// `clamp(3 × last_rtt, 500 ms, max_timeout)`, and `max_timeout` itself
    /// until a round trip has been measured: a connection that has never been
    /// timed gets the longest leash, not the shortest.
    pub fn pingTimeout(self: PingTracker) Nanos {
        const rtt = self.last_rtt orelse return self.max_timeout;
        const tripled = std.math.mul(Nanos, rtt, 3) catch std.math.maxInt(Nanos);
        return std.math.clamp(tripled, min_health_check_timeout, self.max_timeout);
    }

    /// Upstream `PingTracker::new_ping` (`ping_tracker.rs:50-66`), which
    /// upstream reaches through `new_ping_with_timeout`. That second
    /// function is folded in here: nothing upstream calls it except
    /// `new_ping`, and a public function whose one caller is itself and
    /// whose extra argument nobody sets is a knob nobody has turned.
    ///
    /// `data` is the 8 payload bytes. Upstream draws them with
    /// `rand::random()`; a process-global RNG is what `base` forbids, so the
    /// caller supplies them and the tracker stays a value.
    pub fn newPing(self: *PingTracker, now: Nanos, data: [8]u8) [8]u8 {
        self.pending = .{
            .data = data,
            .sent_at = now,
            // The deadline is read before the assignment, so it is the
            // previous round trip that sets it.
            .deadline = now +| self.pingTimeout(),
        };
        return data;
    }

    /// Upstream `PingTracker::pong_received`.
    ///
    /// Only the pong of the most recent ping does anything. Upstream calls
    /// feeding any other pong harmless, and it is harmless — but it is not
    /// harmless to *count* one, because a pong for a superseded ping measures
    /// a round trip that spans two pings, which is the average this rule
    /// exists to refuse.
    pub fn pongReceived(self: *PingTracker, now: Nanos, data: [8]u8) void {
        const pending = self.pending orelse return;
        if (!std.mem.eql(u8, &pending.data, &data)) return;
        // A timeline that went backwards yields a zero round trip, which
        // clamps to the floor rather than to a huge one.
        self.last_rtt = now -| pending.sent_at;
        self.pending = null;
    }

    /// What the connection actor should do about the outstanding ping.
    /// Upstream `ping_tracker.rs:96-105`, without the sleep.
    pub const Timeout = union(enum) {
        /// Nothing is outstanding. Upstream's `pending()`, which is to say it
        /// never returns.
        idle,
        /// A ping is outstanding and this is how much of its deadline is
        /// left.
        pending: Nanos,
        /// The most recent ping went unanswered. Upstream clears `inner` when
        /// its sleep completes, and the connection actor breaks out of its
        /// loop on the frame.
        expired: [8]u8,
    };

    /// Upstream `PingTracker::timeout`. The deadline is compared, never
    /// waited on, so a test can be at it in one step.
    pub fn timeout(self: *PingTracker, now: Nanos) Timeout {
        const pending = self.pending orelse return .idle;
        if (now < pending.deadline) return .{ .pending = pending.deadline - now };
        self.pending = null;
        return .{ .expired = pending.data };
    }
};

const t = std.testing;

/// A key from a fixed seed, so every signature below is reproducible.
///
/// The only failure `fromSeed` has is a degenerate seed, and finding one
/// takes a specific byte pattern rather than any uniform fill.
fn testSecret(seed: u8) SecretKey {
    return SecretKey.fromSeed([_]u8{seed} ** SecretKey.seed_length) catch unreachable;
}

test "the message signed for a challenge is derived, not the challenge" {
    const challenge = frame.ServerChallenge{ .challenge = @splat(0x11) };
    const message = messageToSign(challenge);

    // The point of deriving: a relay that picks the challenge must not be
    // able to collect a signature over bytes it chose.
    try t.expect(!std.mem.eql(u8, &message, &challenge.challenge));

    // Both halves of upstream's rule (`handshake.rs:52` and `:210-220`): the
    // context is the domain separation string and the key material is the
    // challenge, so a different context or a different challenge gives a
    // different message.
    try t.expect(!std.mem.eql(
        u8,
        &message,
        &messageToSign(.{ .challenge = @splat(0x12) }),
    ));
    var wrong_context = std.crypto.hash.Blake3.initKdf(key_material_label, .{});
    wrong_context.update(&challenge.challenge);
    var other: [32]u8 = undefined;
    wrong_context.final(&other);
    try t.expect(!std.mem.eql(u8, &message, &other));

    // Deterministic, so a test can pin a signature.
    try t.expectEqual(message, messageToSign(challenge));
}

test "a client that offered key material is admitted without another frame" {
    const secret = testSecret(1);
    const stepped = step(
        start(.key_material),
        .{ .frame = .server_confirms_auth },
        &secret,
    );
    try t.expectEqual(@as(?Action, null), stepped.action);
    try t.expectEqual(Admitted.key_material, stepped.state.established);
}

test "a challenge after key material is normal operation, not a failure" {
    const secret = testSecret(2);

    // This is the whole load-bearing detail: the relay could not verify the
    // export, and the client signs the challenge instead. Upstream's own test
    // for it is `handshake.rs:775-786`, where mismatched shared secrets end
    // on the challenge path and the client is none the worse.
    const answered = step(
        start(.key_material),
        .{ .frame = .{ .server_challenge = .{ .challenge = @splat(0x21) } } },
        &secret,
    );
    const sent = switch (answered.action orelse return error.TestUnexpectedResult) {
        .send_client_auth => |auth| auth,
        .close => return error.TestUnexpectedResult,
    };
    try t.expectEqual(secret.nodeId(), sent.node_id);
    try verifyClientAuth(sent, .{ .challenge = @splat(0x21) });
    try t.expectEqual(State.awaiting_verdict, answered.state);

    const confirmed = step(answered.state, .{ .frame = .server_confirms_auth }, &secret);
    try t.expectEqual(@as(?Action, null), confirmed.action);
    try t.expectEqual(Admitted.signed_challenge, confirmed.state.established);
}

test "the key material credential is a signature over half the export" {
    const secret = testSecret(3);
    // Two distinguishable halves: a uniform export would let a signature
    // over the first half verify against the second one as well.
    var material: KeyMaterial = @splat(0x33);
    @memset(material[signed_prefix..], 0x44);

    const auth = KeyMaterialAuth.create(&secret, material) orelse
        return error.TestUnexpectedResult;
    try t.expectEqual(secret.nodeId(), auth.node_id);
    // The last half is passed through untouched, and it is what lets the
    // relay tell a broken proxy from a broken client.
    try t.expectEqualSlices(u8, material[16..], &auth.key_material_suffix);
    // The first half is what the signature covers, and it is a signature
    // under the claimed node id rather than a copy of the export.
    try auth.signature.verify(material[0..16], auth.node_id);
    try t.expectError(
        error.BadSignature,
        auth.signature.verify(material[16..], auth.node_id),
    );
    try auth.verify(material);

    // No exporter is the browser case, and it is a null credential rather
    // than a failure.
    try t.expect(KeyMaterialAuth.create(&secret, null) == null);
    try t.expectError(error.NoKeyingMaterial, auth.verify(null));
}

test "a failed key material verify names which half disagreed" {
    const secret = testSecret(4);
    const material: KeyMaterial = @splat(0x44);
    const auth = KeyMaterialAuth.create(&secret, material) orelse
        return error.TestUnexpectedResult;

    // A different export breaks the suffix first, which is the transport's
    // fault and the one worth reporting.
    try t.expectError(error.MismatchedSuffix, auth.verify(@splat(0x55)));

    // The same export with the signature of a different key is a client
    // fault, and it is reported as such rather than as a proxy problem.
    const other = testSecret(5);
    const tampered = KeyMaterialAuth{
        .node_id = auth.node_id,
        .signature = other.sign(material[0..16]),
        .key_material_suffix = auth.key_material_suffix,
    };
    try t.expectError(error.SignatureInvalid, tampered.verify(material));
}

test "a client with no credential still signs the challenge" {
    const secret = testSecret(6);
    const challenge = frame.ServerChallenge{ .challenge = @splat(0x66) };
    const answered = step(
        start(.signed_challenge),
        .{ .frame = .{ .server_challenge = challenge } },
        &secret,
    );
    const sent = switch (answered.action orelse return error.TestUnexpectedResult) {
        .send_client_auth => |auth| auth,
        .close => return error.TestUnexpectedResult,
    };
    try verifyClientAuth(sent, challenge);
    const confirmed = step(answered.state, .{ .frame = .server_confirms_auth }, &secret);
    try t.expectEqual(Admitted.signed_challenge, confirmed.state.established);
}

test "a relay that confirms a client with no credential admits nobody" {
    const secret = testSecret(7);
    // Upstream accepts this, so the machine names it rather than refusing
    // it: the outcome is real, and a log line that cannot tell it from an
    // authenticated admission is a log line that cannot be trusted.
    const stepped = step(
        start(.signed_challenge),
        .{ .frame = .server_confirms_auth },
        &secret,
    );
    try t.expectEqual(@as(?Action, null), stepped.action);
    try t.expectEqual(Admitted.unauthenticated, stepped.state.established);
}

test "a denial is an outcome, and the connection goes with it" {
    const secret = testSecret(8);
    const denial = frame.ServerDeniesAuth{ .reason = "signature invalid" };

    // Refused on the first read, which is what a relay that could not verify
    // the export and had already given up on this client looks like.
    const first = step(
        start(.key_material),
        .{ .frame = .{ .server_denies_auth = denial } },
        &secret,
    );
    try t.expectEqual(Action.close, first.action.?);
    try t.expectEqualStrings("signature invalid", first.state.denied.reason);

    // And refused after a challenge was answered, which is the branch that
    // spends a round trip first. Both are the same outcome: the client
    // authenticated nothing, the relay said so, the connection goes.
    const answered = step(
        start(.key_material),
        .{ .frame = .{ .server_challenge = .{ .challenge = @splat(0x77) } } },
        &secret,
    );
    const second = step(
        answered.state,
        .{ .frame = .{ .server_denies_auth = denial } },
        &secret,
    );
    try t.expectEqual(Action.close, second.action.?);
    try t.expectEqualStrings("signature invalid", second.state.denied.reason);
}

test "the first read names three frames and the rest are out of order" {
    const secret = testSecret(9);
    // The whole send/recv protocol, plus a second challenge, is what a
    // handshake that did not ask for it can be sent. Upstream accepts the
    // same three and rejects the rest with `UnexpectedFrameType`
    // (`handshake.rs:344-350`).
    const out_of_order = [_]frame.Message{
        .{ .client_to_relay_datagram = undefined },
        .{ .ping = @splat(0x01) },
        .{ .status = .rate_limited },
        .{ .restarting = .{ .reconnect_in_ms = 1, .try_for_ms = 2 } },
    };
    for (out_of_order) |message| {
        const stepped = step(start(.key_material), .{ .frame = message }, &secret);
        try t.expectEqual(Action.close, stepped.action.?);
        try t.expectEqual(
            Failure{ .unexpected_frame = std.meta.activeTag(message) },
            stepped.state.failed,
        );
    }
}

test "a second challenge is out of order where a first one was not" {
    const secret = testSecret(10);
    const answered = step(
        start(.key_material),
        .{ .frame = .{ .server_challenge = .{ .challenge = @splat(0x01) } } },
        &secret,
    );
    // Upstream reads a second time for a verdict only
    // (`handshake.rs:360`), so the tolerance the first read shows is exactly
    // the tolerance the second read does not.
    const stepped = step(
        answered.state,
        .{ .frame = .{ .server_challenge = .{ .challenge = @splat(0x02) } } },
        &secret,
    );
    try t.expectEqual(Action.close, stepped.action.?);
    try t.expectEqual(
        Failure{ .unexpected_frame = .server_challenge },
        stepped.state.failed,
    );
}

test "a stream that ends mid-handshake fails, wherever it ends" {
    const secret = testSecret(11);
    const opened = step(start(.key_material), .stream_ended, &secret);
    try t.expectEqual(Action.close, opened.action.?);
    try t.expectEqual(Failure.stream_ended, opened.state.failed);

    const answered = step(
        start(.key_material),
        .{ .frame = .{ .server_challenge = .{ .challenge = @splat(0x03) } } },
        &secret,
    );
    const after_auth = step(answered.state, .stream_ended, &secret);
    try t.expectEqual(Failure.stream_ended, after_auth.state.failed);
}

test "a finished handshake ignores whatever arrives next" {
    const secret = testSecret(12);
    const finished = [_]State{
        .{ .established = .key_material },
        .{ .denied = .{ .reason = "not authorized" } },
        .{ .failed = .stream_ended },
    };
    for (finished) |state| {
        const stepped = step(state, .{ .frame = .server_confirms_auth }, &secret);
        try t.expectEqual(@as(?Action, null), stepped.action);
        try t.expectEqual(state, stepped.state);
    }
}

test "the ping deadline is three round trips, clamped at both ends" {
    // Below the floor: 3 × 100 ms is under 500 ms, so the floor answers.
    var fast = try PingTracker.init(std.time.ns_per_s * 5);
    _ = fast.newPing(0, @splat(0x01));
    fast.pongReceived(std.time.ns_per_ms * 100, @splat(0x01));
    try t.expectEqual(min_health_check_timeout, fast.pingTimeout());

    // Inside the band: 3 × 300 ms is 900 ms, which is the answer.
    var middle = try PingTracker.init(std.time.ns_per_s * 5);
    _ = middle.newPing(0, @splat(0x02));
    middle.pongReceived(std.time.ns_per_ms * 300, @splat(0x02));
    try t.expectEqual(std.time.ns_per_ms * 900, middle.pingTimeout());

    // Above the ceiling: 3 × 4 s is 12 s against a 5 s ceiling, so the
    // ceiling answers and the connection is given up on when upstream would
    // have given up on it.
    var slow = PingTracker.withDefaults();
    _ = slow.newPing(0, @splat(0x03));
    slow.pongReceived(std.time.ns_per_s * 4, @splat(0x03));
    try t.expectEqual(default_max_timeout, slow.pingTimeout());
}

test "an untimed connection gets the longest leash" {
    // Upstream's `unwrap_or(self.max_timeout)`: with no round trip measured
    // there is nothing to be jittery about, and clamping to the floor would
    // ping a relay that is merely slow to answer its first ping.
    var tracker = PingTracker.withDefaults();
    try t.expectEqual(default_max_timeout, tracker.pingTimeout());
    try t.expectEqual(@as(?Nanos, null), tracker.last_rtt);
}

test "the newest ping wins, and a pong for an older one is ignored" {
    var tracker = PingTracker.withDefaults();

    const first = tracker.newPing(std.time.ns_per_ms * 100, @splat(0xaa));
    try t.expectEqual(@as(u8, 0xaa), tracker.pending.?.data[0]);
    const second = tracker.newPing(std.time.ns_per_ms * 200, @splat(0xbb));
    try t.expect(!std.mem.eql(u8, &first, &second));

    // A pong for the superseded ping measures a round trip that spans both
    // pings. Counting it would be the average this tracker refuses to keep.
    tracker.pongReceived(std.time.ns_per_ms * 250, first);
    try t.expectEqual(@as(?Nanos, null), tracker.last_rtt);
    try t.expect(tracker.pending != null);

    // The most recent ping's pong is the only one that counts, and it
    // measures from the most recent send.
    tracker.pongReceived(std.time.ns_per_ms * 260, second);
    try t.expectEqual(@as(?Nanos, std.time.ns_per_ms * 60), tracker.last_rtt);
    try t.expectEqual(@as(?Pending, null), tracker.pending);
}

test "a timeout is due at its deadline and not before" {
    var tracker = PingTracker.withDefaults();
    try t.expectEqual(PingTracker.Timeout.idle, tracker.timeout(0));

    const data = tracker.newPing(std.time.ns_per_ms * 10, @splat(0xcc));
    const deadline = std.time.ns_per_ms * 10 + default_max_timeout;
    try t.expectEqual(
        PingTracker.Timeout{ .pending = deadline - std.time.ns_per_ms * 10 },
        tracker.timeout(std.time.ns_per_ms * 10),
    );
    try t.expectEqual(PingTracker.Timeout{ .expired = data }, tracker.timeout(deadline));
    // Upstream clears the outstanding ping when its sleep completes, and the
    // connection actor breaks out of its loop rather than re-arming.
    try t.expectEqual(PingTracker.Timeout.idle, tracker.timeout(deadline + 1));
}

test "a ceiling below the floor is refused rather than asserted" {
    try t.expectError(
        error.MaxTimeoutBelowFloor,
        PingTracker.init(min_health_check_timeout - 1),
    );
    try t.expect((try PingTracker.init(min_health_check_timeout)).max_timeout ==
        min_health_check_timeout);
}
