//! The relay server's handshake machine: the states a connection's admission
//! passes through, the event that moves each of them, and the one action the
//! caller owes after every step.
//!
//! Captured 2026-09-30 from n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8: `handshake::serverside` and
//! `SuccessfulAuthentication::authorize_with` from
//! `iroh-relay/src/protos/handshake.rs`. Each is named where it is reproduced.
//!
//! **One of three halves of a relay server.** This is the one that admits a
//! client: `relay/server_registry.zig` holds the clients it admitted, and
//! `relay/server_queue.zig` holds the two queues each one writes from. Nothing
//! here opens a socket, reads a clock, or allocates. The frames come from
//! `relay/frame_types.zig`; the key material and the challenge come in as
//! arguments. That is the only way the fallback in this file can be tested:
//! upstream reaches it through a TLS session where the exporter happens to
//! disagree across a proxy, and it is a branch that has to work on the first
//! try of a real deployment.

const std = @import("std");
const key = @import("../base/key.zig");
const frame = @import("frame_types.zig");
const client = @import("client.zig");

const NodeId = key.NodeId;

/// The reason a relay sends when access control denies without giving one.
/// Upstream `handshake.rs:543`.
///
/// Fourteen bytes, so it is always inside `frame.max_text_length` and a denial
/// carrying it can always be encoded: the default reason is the one answer that
/// cannot be too long. A comptime literal, so it has static lifetime.
pub const default_denial = "not authorized";

/// The reason a relay sends when a client signed a challenge wrongly. Upstream
/// `handshake.rs:461`, and the only reason the challenge path can produce: a
/// signature either verifies or it does not.
///
/// Seventeen bytes, inside `frame.max_text_length` for the same reason
/// `default_denial` is. A comptime literal, so it has static lifetime and is
/// never freed.
pub const invalid_signature_reason = "signature invalid";

/// How a client proved it owns the node id it claimed. Upstream `Mechanism`
/// (`handshake.rs:399-404`).
///
/// **The machine records this and never branches on it.** Which mechanism let a
/// client in is the access control's business and its logs', and no branch of
/// `step` decides anything differently because of it.
pub const Mechanism = enum {
    /// Verified against keying material exported from the TLS session. The
    /// credential rode on the upgrade request, so nothing was written before
    /// the confirmation.
    signed_key_material,
    /// Verified against a signature of a challenge the relay sent. One extra
    /// round trip, and the only path a browser has.
    signed_challenge,
};

/// A client that proved its identity and is waiting to be let in. Upstream's
/// `SuccessfulAuthentication` (`handshake.rs:388-393`), which is `#[must_use]`
/// upstream for the same reason the next event exists here.
///
/// A value and not a handle: it is copied into `State` and out of it, and nothing
/// in it borrows. The caller reads it to decide access, and is the one who turns
/// the `node_id` into a `ConnectionId` at `Registry.admit`.
pub const Proof = struct {
    /// The authenticated client's node id.
    node_id: NodeId,
    /// How it was authenticated.
    mechanism: Mechanism,
};

/// The client auth header, as the HTTP layer decoded it.
///
/// **The three arms are three different answers, and the caller picks between
/// them where the header is**, which is the HTTP layer and not this file: absent
/// is `.none` and takes the challenge path, undecodable is `.malformed` and
/// closes the connection, and decoded is `.key_material` whatever the material
/// turns out to verify against. `.malformed` must not be softened into `.none` on
/// the way in — the two differ in whether the client's own bytes were wrong, and
/// only one of them is a fault the relay can name.
pub const Credential = union(enum) {
    /// The client sent no such header. A browser, or a client whose TLS stack
    /// has no exporter. Upstream skips the whole block
    /// (`handshake.rs:425-450`).
    none,
    /// The header was sent and did not decode. Upstream refuses the
    /// connection with `Error::ClientAuthHeaderInvalid`
    /// (`handshake.rs:426-439`) rather than falling back, and so does this
    /// machine: a relay that challenged a client whose header was garbage
    /// would be indistinguishable from one that challenged a client whose
    /// header it could not verify, and only the second is a client's fault.
    malformed,
    /// The header decoded. Upstream's `Ok` arm.
    key_material: client.KeyMaterialAuth,
};

/// The upgrade request, and everything the relay needs to answer it.
///
/// **This is the one struct the caller fills in on the relay's side.** All three
/// fields are read before `step` returns and only one of them survives it, as a
/// value:
///
/// - `credential` is the header, already decoded or already refused, and it is
///   what decides which path this connection takes.
/// - `material` is this end's export, and **null is not "no opinion": it is the
///   answer `error.NoKeyingMaterial`**, which takes the challenge path even for a
///   client that sent a sound credential. That is upstream's position and this
///   machine's — a relay behind a plain HTTP listener has no exporter at all,
///   and neither has the browser talking to it.
/// - `challenge` is drawn by the caller **whether or not it will be used**,
///   because deciding which path is taken is the machine's job and not the
///   caller's. It is sixteen bytes from a CSPRNG, read only on the challenge
///   path, and copied into both the state and the frame, so the caller may zero
///   its own copy on return.
pub const Offer = struct {
    /// Whatever the client put on the `iroh-relay-key-material-auth` header.
    credential: Credential,
    /// What this end's TLS exporter produced for the same session, or null
    /// when this end has no exporter — the ordinary case for a relay behind a
    /// plain HTTP listener, and the case a browser client is talking to.
    material: ?client.KeyMaterial,
    /// The challenge to answer with, if this offer does not carry the
    /// handshake. Drawn by the caller whatever turns out to be needed:
    /// deciding whether the challenge path is taken is this machine's job,
    /// and a machine that draws randomness is not pure.
    challenge: frame.ServerChallenge,
};

/// Upstream's `Access` (`server.rs:350-357`).
///
/// **This is the one decision a consumer supplies, and the one borrow it
/// creates.** The operator's access control is not called from here: it runs in
/// the caller's own code, its answer arrives as `Event.access`, and this module
/// never calls back into anything. Three obligations follow, and all three are
/// the caller's:
///
/// - `.allow` is only an answer from the `.authenticated` state. The same event
///   anywhere else is `Failure.out_of_order`, so an access decision cannot be
///   queued ahead of the proof it decides about.
/// - `.deny` with no reason is a decision to let the relay speak for itself, and
///   the text the peer reads is then `default_denial`. It is not the same as
///   choosing those words: nothing distinguishes the two on the wire, and a
///   caller that wants the difference in a log has to keep it.
/// - **A reason is borrowed, and the borrow outlives the call.** The `Step` this
///   event produces holds it twice — in `State.denied.reason` and in
///   `Action.write.server_denies_auth.reason` — and `encode` reads it after that.
///   So the text must stay alive and unmutated from the decision until the denial
///   has been written, a buffer the caller is about to reuse for the next
///   connection's decision must not be the one this denial names, and a reason
///   over `frame.max_text_length` is `error.TextTooLong` at that `encode` with
///   nothing written.
pub const Access = union(enum) {
    allow,
    /// Deny, with the reason to send back, or null for `default_denial`.
    deny: ?[]const u8,
};

/// Why a handshake cannot finish.
///
/// Every arm is terminal: `State.failed` keeps it and `step` folds any later event
/// into itself, so a caller that keeps stepping a failed handshake is told nothing
/// new rather than handed a second outcome.
pub const Failure = union(enum) {
    /// A frame arrived that this state cannot accept. Upstream
    /// `Error::UnexpectedFrameType`.
    unexpected_frame: frame.FrameType,
    /// The stream ended before the handshake finished. Upstream
    /// `Error::UnexpectedEnd`.
    stream_ended,
    /// The client auth header did not decode. Upstream
    /// `Error::ClientAuthHeaderInvalid`.
    malformed_credential,
    /// The upgrade request arrived twice, or access control was asked about
    /// a client that has proved nothing.
    ///
    /// There is no frame to name, because the event that arrived is not one
    /// that carries a frame. The handshake is a strict sequence, and this is
    /// the arm that says so.
    out_of_order,
};

/// A challenge that is on the wire, and why the credential did not carry the
/// handshake.
///
/// Both fields are values, so this state borrows nothing, copying it is free, and
/// a caller may keep one for a log line for as long as it likes. It is not
/// terminal: only a `ClientAuth` may come next, and anything else closes the
/// connection.
pub const Challenged = struct {
    challenge: frame.ServerChallenge,
    /// The verify failure that sent us down this path, or null when the
    /// client offered no credential at all.
    ///
    /// Upstream logs it and drops it (`handshake.rs:448-450`). It is kept
    /// because the three failures are three different things to go and look
    /// at: a `MismatchedSuffix` is a proxy that does not middle-man the
    /// exporter, and it is the one case where the client is blameless.
    key_material_failure: ?client.VerifyError,
};

/// The relay half of the handshake.
///
/// **Three of the six are terminal**, and a terminal state absorbs whatever
/// arrives after it: `step` returns the same state with no action, so a caller
/// that keeps feeding a finished handshake is not an error and gets no second
/// outcome. `.opened`, `.challenged` and `.authenticated` are the three that can
/// still move.
///
/// A state is a value and safe to copy, with one borrow anywhere inside it:
/// `denied` names the access-control text or one of the two constants above, and
/// nothing else in this union points at anything. `step` takes the state by value
/// and returns a new one, so the caller's copy is its own to keep or drop.
pub const State = union(enum) {
    /// The upgrade request is in and nothing has been sent.
    opened,
    /// A challenge is on the wire. Only a `ClientAuth` can come next.
    challenged: Challenged,
    /// The client proved it owns the node id it claims. Nothing has been
    /// sent: upstream holds this as `SuccessfulAuthentication` and waits for
    /// the access decision before confirming anything.
    authenticated: Proof,
    /// Access was granted and a confirmation is owed. The guard is owed too,
    /// and both are the caller's to take from here.
    admitted: Proof,
    /// The client was refused. Terminal.
    denied: frame.ServerDeniesAuth,
    /// The handshake cannot finish. Terminal.
    failed: Failure,
};

/// What the caller must do after a step.
///
/// **One action, and the caller must do it before stepping again.** The machine
/// holds no queue and remembers nothing, so an action that was not written is not
/// written later, and the next `step` describes a state that assumed it had been.
/// `close` means drop the connection writing nothing; it is not a suggestion, and
/// the state that arrived with it says why.
///
/// **The frame is a value with one borrow in it.** `server_challenge` is sixteen
/// bytes copied out of the offer, and `server_denies_auth` names the text access
/// control decided, so a `Step` produced by an `access` event borrows that text
/// until `encode` has written the denial. Both of those frames, and the
/// confirmation, are emittable in either protocol version, so the version a relay
/// answers with never refuses one of them.
pub const Action = union(enum) {
    /// Write this frame. Upstream `write_frame`.
    write: frame.Message,
    /// Drop the connection without writing. Upstream returns the error and
    /// the caller closes the stream.
    close,
};

/// One step: the next state, and the one thing to do about it.
///
/// The two fields are read separately on purpose: `state` is what to store and
/// `action` is what to do, and `action == null` means nothing to do *now* — a
/// handshake waiting for the next frame, not a handshake that has ended. The state
/// says which of the two it is.
pub const Step = struct {
    state: State,
    action: ?Action,
};

/// One step of the relay handshake.
///
/// **Pure, and free of every hidden input.** No clock, no allocator, no global,
/// no I/O, and no call back into the caller: the two things a handshake needs that
/// are not on the wire — the challenge's randomness and the key material — arrive
/// in the `Event` as values, so this is a function of its two arguments and
/// nothing else. It is reentrant and callable from any thread, as long as neither
/// argument is being written underneath the call: an `Event` borrowed from a
/// buffer another thread is decoding into must not be stepped.
///
/// **No `Step` borrows a frame's payload.** Every frame it writes is a value or
/// one of the two comptime strings, and every state it returns is a value or one
/// of those strings, so the borrows a `frame.Message` carries die with the
/// caller's read buffer rather than with the state. The one borrow a `Step` can
/// hold is the `Access.deny` reason, which is the caller's own text.
pub fn step(state: State, event: Event) Step {
    return switch (state) {
        .opened => switch (event) {
            .offered => |offer| admit(offer),
            // Nothing is read from the stream before the credential has been
            // dealt with upstream (`handshake.rs:452-456`), so a frame here is
            // a client talking past the handshake.
            .frame => |message| fail(.{ .unexpected_frame = std.meta.activeTag(message) }),
            // Access control cannot be asked about a client that has proved
            // nothing, and upstream cannot reach this state at all: the guard
            // is minted in it.
            .access => fail(.out_of_order),
            .stream_ended => fail(.stream_ended),
        },
        .challenged => |challenged| switch (event) {
            .frame => |message| switch (message) {
                .client_auth => |auth| verifySigned(auth, challenged.challenge) catch |failure|
                    switch (failure) {
                        // The one failure the challenge path has. Upstream writes
                        // the denial and returns `ServerDeniedAuth`
                        // (`handshake.rs:458-466`).
                        error.SignatureInvalid => denied(invalid_signature_reason),
                    },
                else => fail(.{ .unexpected_frame = std.meta.activeTag(message) }),
            },
            .access, .offered => fail(.out_of_order),
            .stream_ended => fail(.stream_ended),
        },
        .authenticated => |proof| switch (event) {
            .access => |access| switch (access) {
                // The guard is minted before the confirmation is written, so
                // a confirmation that fails to write still ends in exactly
                // one disconnect report. Upstream's order in
                // `authorize_with` (`handshake.rs:495-500`) is this order.
                .allow => .{
                    .state = .{ .admitted = proof },
                    .action = .{ .write = .server_confirms_auth },
                },
                .deny => |reason| denied(reason orelse default_denial),
            },
            .frame => |message| fail(.{ .unexpected_frame = std.meta.activeTag(message) }),
            .offered => fail(.out_of_order),
            .stream_ended => fail(.stream_ended),
        },
        // Upstream has returned by the time any of these is reached, so a
        // frame that arrives now belongs to the connection rather than to the
        // handshake and is folded in as nothing.
        .admitted => |proof| .{ .state = .{ .admitted = proof }, .action = null },
        .denied => |denial| .{ .state = .{ .denied = denial }, .action = null },
        .failed => |failure| .{ .state = .{ .failed = failure }, .action = null },
    };
}

/// What happened on the relay side between two steps.
///
/// **A `frame` event carries the borrow its `Message` carries**, so the buffer it
/// was decoded from must stay put for as long as the event is used — which is
/// until the `step` that consumed it returns, and no longer, because no `Step`
/// keeps a frame's payload. The other three arms hold values: `offered` is filled
/// in by the caller, `access` is a decision whose one borrow is the caller's text,
/// and `stream_ended` is nothing at all.
pub const Event = union(enum) {
    /// The upgrade request completed.
    offered: Offer,
    /// A frame arrived, decoded.
    frame: frame.Message,
    /// Access control has decided. Upstream `AccessControl::on_connect`, run
    /// between the two halves of `serverside` and `authorize_if`.
    access: Access,
    /// The stream ended before the handshake finished.
    stream_ended,
};

/// The decision the whole file turns on: does the credential carry the
/// handshake, or does a challenge.
/// ```ignore
/// if client_auth.verify(io).is_ok() {
///     return Ok(SuccessfulAuthentication { .. });
/// }
/// // Verification not succeeding is part of normal operation: The TLS
/// // exporter isn't required to match. We'll fall back to verification that
/// // takes another round trip.
/// let challenge = ServerChallenge::new(&mut rand::rng());
/// write_frame(io, &challenge).await?;
/// ```
///
/// Every failure below is that comment. None of them is an error, and a
/// machine that propagated one would fail exactly the connection the protocol
/// exists to rescue.
fn admit(offer: Offer) Step {
    const credential = switch (offer.credential) {
        .none => return challenge(offer.challenge, null),
        .malformed => return fail(.malformed_credential),
        .key_material => |auth| auth,
    };
    credential.verify(offer.material) catch |failure| {
        return challenge(offer.challenge, failure);
    };
    return authenticated(credential.node_id, .signed_key_material);
}

/// The state after a credential has been verified, before access control has
/// been asked. Shared by both paths, because the only thing that differs
/// between them is how the client proved it and how many frames it cost.
fn authenticated(node_id: NodeId, mechanism: Mechanism) Step {
    return .{
        .state = .{ .authenticated = .{ .node_id = node_id, .mechanism = mechanism } },
        .action = null,
    };
}

/// The state after a signed challenge has been verified, which is the same
/// state the key-material path reaches with one frame already spent.
fn verifySigned(
    auth: frame.ClientAuth,
    issued: frame.ServerChallenge,
) client.ChallengeError!Step {
    try client.verifyClientAuth(auth, issued);
    return authenticated(auth.node_id, .signed_challenge);
}

fn challenge(issued: frame.ServerChallenge, failure: ?client.VerifyError) Step {
    return .{
        .state = .{ .challenged = .{
            .challenge = issued,
            .key_material_failure = failure,
        } },
        .action = .{ .write = .{ .server_challenge = issued } },
    };
}

fn denied(reason: []const u8) Step {
    return .{
        .state = .{ .denied = .{ .reason = reason } },
        .action = .{ .write = .{ .server_denies_auth = .{ .reason = reason } } },
    };
}

fn fail(failure: Failure) Step {
    return .{ .state = .{ .failed = failure }, .action = .close };
}

const t = std.testing;

/// A key from a fixed seed, so the node ids below name the same nodes on
/// every run.
///
/// `fromSeed` fails only on a degenerate seed, which a uniform fill is not.
/// The error is propagated rather than asserted away anyway: a seed that was
/// somehow not accepted fails the test that named it, not the whole run.
fn testSecret(seed: u8) !key.SecretKey {
    return key.SecretKey.fromSeed([_]u8{seed} ** key.SecretKey.seed_length);
}

/// The node id that key claims.
fn testNodeId(seed: u8) !NodeId {
    return (try testSecret(seed)).nodeId();
}

/// A challenge from a fixed pattern. Upstream draws these from a CSPRNG; the
/// machine is handed one instead, which is the same reason the relay is
/// handed the key material it will export.
const test_challenge: frame.ServerChallenge = .{ .challenge = @splat(0x5a) };

/// A stand-in for a TLS exporter, of the shape upstream's own test uses
/// (`handshake.rs:640-657`): two ends handed the same number derive the same
/// bytes. What the matrix below checks is what happens when they do not.
fn exported(shared: u64) client.KeyMaterial {
    var out: client.KeyMaterial = undefined;
    std.crypto.hash.Blake3.hash(std.mem.asBytes(&shared), &out, .{});
    return out;
}

test "key material carries the handshake without a frame in between" {
    const secret = try testSecret(1);
    const material = exported(42);
    const credential = client.KeyMaterialAuth.create(&secret, material) orelse
        return error.TestUnexpectedResult;

    // The credential is on the upgrade request, so the first thing the relay
    // does with it is nothing at all: no challenge, no round trip.
    const offered = step(.opened, .{ .offered = .{
        .credential = .{ .key_material = credential },
        .material = material,
        .challenge = test_challenge,
    } });
    try t.expectEqual(@as(?Action, null), offered.action);
    try t.expectEqual(Mechanism.signed_key_material, offered.state.authenticated.mechanism);
    try t.expectEqual(secret.nodeId(), offered.state.authenticated.node_id);

    // And the one frame the relay writes is the confirmation, after the
    // access decision.
    const allowed = step(offered.state, .{ .access = .allow });
    try t.expectEqual(Action{ .write = .server_confirms_auth }, allowed.action.?);
    try t.expectEqual(Mechanism.signed_key_material, allowed.state.admitted.mechanism);
}

test "a key material verify that fails falls back instead of failing" {
    const secret = try testSecret(2);
    const credential = client.KeyMaterialAuth.create(&secret, exported(10)) orelse
        return error.TestUnexpectedResult;

    // The case upstream calls out by name: an HTTPS proxy that does not
    // middle-man the exporter, so the two ends exported different material.
    // `handshake.rs:775-786` is upstream's test of exactly this, and the
    // client comes out authenticated by challenge.
    const offered = step(.opened, .{ .offered = .{
        .credential = .{ .key_material = credential },
        .material = exported(99),
        .challenge = test_challenge,
    } });
    try t.expectEqual(
        Action{ .write = .{ .server_challenge = test_challenge } },
        offered.action.?,
    );
    try t.expectEqualSlices(
        u8,
        &test_challenge.challenge,
        &offered.state.challenged.challenge.challenge,
    );
    try t.expectEqual(
        @as(?client.VerifyError, error.MismatchedSuffix),
        offered.state.challenged.key_material_failure,
    );

    // The challenge still authenticates the client.
    const answered = step(offered.state, .{ .frame = .{
        .client_auth = client.signChallenge(&secret, test_challenge),
    } });
    try t.expectEqual(@as(?Action, null), answered.action);
    try t.expectEqual(Mechanism.signed_challenge, answered.state.authenticated.mechanism);
}

test "every failed key material verify falls back, and says which it was" {
    const secret = try testSecret(3);
    const material = exported(7);
    const credential = client.KeyMaterialAuth.create(&secret, material) orelse
        return error.TestUnexpectedResult;

    // No exporter on this end at all: a relay behind a plain HTTP listener.
    const no_exporter = step(.opened, .{ .offered = .{
        .credential = .{ .key_material = credential },
        .material = null,
        .challenge = test_challenge,
    } });
    try t.expectEqual(
        @as(?client.VerifyError, error.NoKeyingMaterial),
        no_exporter.state.challenged.key_material_failure,
    );

    // A well-formed credential whose signature does not verify: a client
    // with a broken key, not a broken proxy.
    const wrong = try testSecret(4);
    const forged: client.KeyMaterialAuth = .{
        .node_id = credential.node_id,
        .signature = wrong.sign(material[0..16]),
        .key_material_suffix = credential.key_material_suffix,
    };
    const bad_signature = step(.opened, .{ .offered = .{
        .credential = .{ .key_material = forged },
        .material = material,
        .challenge = test_challenge,
    } });
    try t.expectEqual(
        @as(?client.VerifyError, error.SignatureInvalid),
        bad_signature.state.challenged.key_material_failure,
    );
    // Falling back to a challenge is the right answer here too: the client
    // can still prove the key, and only a challenge asks it to.
    try t.expectEqual(
        Action{ .write = .{ .server_challenge = test_challenge } },
        bad_signature.action.?,
    );
}

test "a header that does not decode is refused rather than fallen back from" {
    const refused = step(.opened, .{ .offered = .{
        .credential = .malformed,
        .material = exported(1),
        .challenge = test_challenge,
    } });
    try t.expectEqual(Action.close, refused.action.?);
    try t.expectEqual(Failure.malformed_credential, refused.state.failed);
}

test "no credential is a challenge, and is not a failure" {
    const offered = step(.opened, .{ .offered = .{
        .credential = .none,
        .material = exported(1),
        .challenge = test_challenge,
    } });
    try t.expectEqual(
        Action{ .write = .{ .server_challenge = test_challenge } },
        offered.action.?,
    );
    try t.expectEqual(
        @as(?client.VerifyError, null),
        offered.state.challenged.key_material_failure,
    );
}

test "a challenge answered with a bad signature is denied, not retried" {
    const wrong = try testSecret(5);
    const offered = step(.opened, .{ .offered = .{
        .credential = .none,
        .material = null,
        .challenge = test_challenge,
    } });
    // Claiming one node id and signing with another: the relay verifies the
    // signature under the claimed id, so this is the only shape of a bad
    // answer, and it is the one upstream's `ClientAuth::verify` rejects.
    const forged: frame.ClientAuth = .{
        .node_id = try testNodeId(20),
        .signature = wrong.sign(&client.messageToSign(test_challenge)),
    };
    const refused = step(offered.state, .{ .frame = .{ .client_auth = forged } });
    try t.expectEqual(
        Action{ .write = .{ .server_denies_auth = .{ .reason = invalid_signature_reason } } },
        refused.action.?,
    );
    try t.expectEqualStrings(invalid_signature_reason, refused.state.denied.reason);
}

test "access control decides, and a bare denial carries the default reason" {
    const secret = try testSecret(6);
    const proof: Proof = .{ .node_id = secret.nodeId(), .mechanism = .signed_challenge };
    const with_reason = step(.{ .authenticated = proof }, .{ .access = .{ .deny = "no" } });
    try t.expectEqualStrings("no", with_reason.state.denied.reason);
    try t.expectEqualStrings("no", with_reason.action.?.write.server_denies_auth.reason);

    const without = step(.{ .authenticated = proof }, .{ .access = .{ .deny = null } });
    try t.expectEqualStrings(default_denial, without.state.denied.reason);
    try t.expectEqualStrings(default_denial, without.action.?.write.server_denies_auth.reason);
}

test "a relay reads nothing before the credential, and asks nobody before a proof" {
    const early_frame = step(.opened, .{ .frame = .{ .ping = @splat(1) } });
    try t.expectEqual(Action.close, early_frame.action.?);
    try t.expectEqual(
        Failure{ .unexpected_frame = .ping },
        early_frame.state.failed,
    );

    // Access control cannot be asked about a client that has proved nothing,
    // and upstream cannot reach this state at all: the guard is minted in it.
    const early_access = step(.opened, .{ .access = .allow });
    try t.expectEqual(Action.close, early_access.action.?);
    try t.expectEqual(Failure.out_of_order, early_access.state.failed);

    const challenged: State = .{ .challenged = .{
        .challenge = test_challenge,
        .key_material_failure = null,
    } };
    try t.expectEqual(Failure.out_of_order, step(challenged, .{ .access = .allow }).state.failed);
    try t.expectEqual(
        Failure.out_of_order,
        step(challenged, .{ .offered = .{
            .credential = .none,
            .material = null,
            .challenge = test_challenge,
        } }).state.failed,
    );
    // And a frame the challenge did not ask for.
    const wrong_frame = step(challenged, .{ .frame = .{ .server_confirms_auth = {} } });
    try t.expectEqual(
        Failure{ .unexpected_frame = .server_confirms_auth },
        wrong_frame.state.failed,
    );

    // A proof is not an open door either: between proving and the access
    // decision upstream is holding a `SuccessfulAuthentication` and reading
    // nothing, so a frame or a second upgrade request arriving here is out
    // of order for the same reason it is one step earlier.
    const proof: Proof = .{ .node_id = try testNodeId(21), .mechanism = .signed_challenge };
    const proved: State = .{ .authenticated = proof };
    try t.expectEqual(
        Failure{ .unexpected_frame = .pong },
        step(proved, .{ .frame = .{ .pong = @splat(1) } }).state.failed,
    );
    try t.expectEqual(
        Failure.out_of_order,
        step(proved, .{ .offered = .{
            .credential = .none,
            .material = null,
            .challenge = test_challenge,
        } }).state.failed,
    );
}

test "a stream that ends at any unfinished point fails" {
    const challenged: State = .{ .challenged = .{
        .challenge = test_challenge,
        .key_material_failure = null,
    } };
    const proof: Proof = .{ .node_id = try testNodeId(21), .mechanism = .signed_key_material };
    for ([_]State{ .opened, challenged, .{ .authenticated = proof } }) |state| {
        const stepped = step(state, .stream_ended);
        try t.expectEqual(Action.close, stepped.action.?);
        try t.expectEqual(Failure.stream_ended, stepped.state.failed);
    }
}

test "a finished relay handshake ignores whatever arrives next" {
    const secret = try testSecret(7);
    const proof: Proof = .{ .node_id = secret.nodeId(), .mechanism = .signed_key_material };
    const finished = [_]State{
        .{ .admitted = proof },
        .{ .denied = .{ .reason = default_denial } },
        .{ .failed = .stream_ended },
    };
    for (finished) |state| {
        const stepped = step(state, .{ .frame = .{ .pong = @splat(1) } });
        try t.expectEqual(@as(?Action, null), stepped.action);
        try t.expectEqual(state, stepped.state);
    }
}

/// Both ends of a handshake, driven against each other with no I/O.
const Loopback = struct {
    client: client.State,
    server: State,
    /// How many frames the relay wrote. The key-material path is one.
    relay_writes: usize,
    /// How many frames the client wrote. The challenge path is one.
    client_writes: usize,
};

/// The frame an action would put on the wire, or null when it would put
/// nothing there. A `close` is a refusal rather than a frame, and the
/// loopback has no channel to close.
fn written(action: ?Action) error{HandshakeRefused}!?frame.Message {
    const decided = action orelse return null;
    return switch (decided) {
        .write => |message| message,
        .close => error.HandshakeRefused,
    };
}

/// A client and a relay, run against each other until neither has anything
/// left to say.
///
/// Upstream's `simulate_handshake` (`handshake.rs:699-743`) puts a `duplex`
/// pair between two futures and asserts that the pair agrees. The transport
/// is the only thing missing here, and it is missing on purpose: what is
/// checked is that two machines which never see each other's state produce
/// one protocol.
///
/// The success path only. A denial ends the client's half and is a test of
/// its own.
fn loopback(
    secret: *const key.SecretKey,
    client_material: ?client.KeyMaterial,
    server_material: ?client.KeyMaterial,
) !Loopback {
    // Two machines and a bounded protocol: the offer, the access decision,
    // and at most one challenge round trip. Nine is the ceiling with steps to
    // spare, and reaching it is a failure rather than a hang.
    const max_steps = 9;

    var client_state = client.start(if (client_material == null)
        .signed_challenge
    else
        .key_material);

    // The offer is the one event that comes from neither machine: the HTTP
    // upgrade request and the header on it.
    const offered = step(.opened, .{ .offered = .{
        .credential = if (client.KeyMaterialAuth.create(secret, client_material)) |credential|
            .{ .key_material = credential }
        else
            .none,
        .material = server_material,
        .challenge = test_challenge,
    } });
    var server_state = offered.state;
    var to_client = try written(offered.action);
    var to_server: ?frame.Message = null;
    var relay_writes: usize = @intFromBool(to_client != null);
    var client_writes: usize = 0;
    var decided = false;
    var steps: usize = 0;

    while (true) {
        steps += 1;
        if (steps > max_steps) return error.HandshakeStalled;
        if (to_client) |message| {
            to_client = null;
            const answered = client.step(client_state, .{ .frame = message }, secret);
            client_state = answered.state;
            // A frame that needs no answer is the end of the protocol, not a
            // stall: the confirmation is the last thing either side writes.
            if (answered.action) |action| switch (action) {
                .send_client_auth => |auth| {
                    to_server = .{ .client_auth = auth };
                    client_writes += 1;
                },
                .close => return error.HandshakeRefused,
            };
        } else if (to_server) |message| {
            to_server = null;
            const replied = step(server_state, .{ .frame = message });
            server_state = replied.state;
            to_client = try written(replied.action);
            relay_writes += @intFromBool(to_client != null);
        } else if (!decided) {
            // Nothing is in flight, which in a working handshake happens
            // exactly once: the relay has a proof and the operator has not
            // answered yet.
            const allowed = step(server_state, .{ .access = .allow });
            server_state = allowed.state;
            to_client = try written(allowed.action);
            relay_writes += @intFromBool(to_client != null);
            decided = true;
        } else break;
    }

    return .{
        .client = client_state,
        .server = server_state,
        .relay_writes = relay_writes,
        .client_writes = client_writes,
    };
}

test "the two halves of the handshake agree, in every key material case" {
    const secret = try testSecret(8);
    const matching = exported(42);

    // Upstream's four scenarios (`handshake.rs:747-800`). The one that
    // matters is the third: a verify that fails is normal operation, the
    // handshake falls back, and the client is authenticated all the same.
    const cases = [_]struct {
        client_material: ?client.KeyMaterial,
        server_material: ?client.KeyMaterial,
        mechanism: Mechanism,
        admitted: client.Admitted,
        relay_writes: usize,
        client_writes: usize,
    }{
        .{
            .client_material = matching,
            .server_material = matching,
            .mechanism = .signed_key_material,
            .admitted = .key_material,
            .relay_writes = 1,
            .client_writes = 0,
        },
        .{
            .client_material = null,
            .server_material = null,
            .mechanism = .signed_challenge,
            .admitted = .signed_challenge,
            .relay_writes = 2,
            .client_writes = 1,
        },
        .{
            .client_material = exported(10),
            .server_material = exported(99),
            .mechanism = .signed_challenge,
            .admitted = .signed_challenge,
            .relay_writes = 2,
            .client_writes = 1,
        },
        .{
            .client_material = null,
            .server_material = exported(99),
            .mechanism = .signed_challenge,
            .admitted = .signed_challenge,
            .relay_writes = 2,
            .client_writes = 1,
        },
    };

    for (cases) |case| {
        const both = try loopback(&secret, case.client_material, case.server_material);
        // The client learns which path it took, and it is the one the relay
        // recorded: no frame is written twice, and none is invented.
        try t.expectEqual(case.mechanism, both.server.admitted.mechanism);
        try t.expectEqual(case.admitted, both.client.established);
        try t.expectEqual(secret.nodeId(), both.server.admitted.node_id);
        try t.expectEqual(case.relay_writes, both.relay_writes);
        try t.expectEqual(case.client_writes, both.client_writes);
    }
}