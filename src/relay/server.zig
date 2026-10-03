//! The relay server's pure half: the handshake it authenticates a client
//! with, the registry that holds the clients it admitted, and the two queues
//! each connection writes from.
//!
//! Captured 2026-09-30 from n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8: `handshake::serverside` and
//! `SuccessfulAuthentication::authorize_with` from
//! `iroh-relay/src/protos/handshake.rs`; `OnDisconnectGuard`, `Access` and
//! `ConnectionId` from `iroh-relay/src/server.rs`; `Clients::register` and
//! `Clients::unregister` from `iroh-relay/src/server/clients.rs`; the two
//! channels and the `biased` select that drains them from
//! `iroh-relay/src/server/client.rs`; `PER_CLIENT_SEND_QUEUE_DEPTH` from
//! `iroh-relay/src/protos/relay.rs`. Each is named where it is reproduced.
//!
//! Nothing here opens a socket, reads a clock, or allocates. The frames come
//! from `relay/frame.zig`; the key material and the challenge come in as
//! arguments. That is the only way the fallback in this file can be tested:
//! upstream reaches it through a TLS session where the exporter happens to
//! disagree across a proxy, and it is a branch that has to work on the first
//! try of a real deployment.

const std = @import("std");
const key = @import("../base/key.zig");
const frame = @import("frame.zig");
const client = @import("client.zig");

const NodeId = key.NodeId;

/// A process-unique identifier for one relay client connection.
///
/// Upstream `ConnectionId(u64)` (`server.rs:175`), drawn from a process-global
/// atomic (`server.rs:179-182`). The value is an argument here: a
/// process-global counter is what `base` forbids, and a per-registry counter
/// would hand two relays in one process the same id, which is the one thing
/// upstream says the id must not do — it exists so an access-control
/// implementation can pair `on_connect` with `on_disconnect`.
///
/// **Uniqueness is the caller's, and that is why the value is an argument rather
/// than a counter in here.** Two live connections of one process must not share
/// one, because `OnDisconnectGuard.deinit` tells a departure from a displacement
/// by comparing it against the entry's active connection
/// (`server/clients.rs:110-121`), and a clash turns one of them into a silent
/// double report. The value is copied into the entry and into the handle, so
/// nothing borrows it and a number may be reused once `deinit` has answered.
pub const ConnectionId = u64;

/// A connection's departure, as access control is told of it. Upstream
/// `AccessControl::on_disconnect(endpoint_id, connection_id)`
/// (`server.rs:302`).
///
/// **It is reported at most once per connection, and only by the registry.** It
/// comes back from `OnDisconnectGuard.deinit` in exactly the arms that mean the
/// connection really ended — `Unregister.disconnected`, `.duplicate` and
/// `.promoted` — and never from `.already_gone`. It is the one value access
/// control is told about, so a relay running none counts it instead of dropping
/// it; nothing in this module reads it.
pub const Disconnection = struct {
    /// The node id the connection proved, and the first thing access control is
    /// told: it is the entry's key, so one node id's connections are told apart by
    /// `connection_id` and not by this.
    node_id: NodeId,
    /// Which connection it was, which is the whole of what told a departure from
    /// a displacement when the entry was left with another connection in it.
    connection_id: ConnectionId,
};

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

/// A datagram queued for one client. Upstream `server::client::Packet`
/// (`server/client.rs:41-46`).
///
/// **The storage contract is the whole of this type.** `src` is a value and
/// `data` is borrowed from whoever copied the datagram out of its read buffer —
/// a ring slot of the caller's own in this repo's relay, a `Bytes` upstream's —
/// and the queue copies nothing:
///
/// - the bytes must stay alive and unmutated from the `push` until the item is
///   popped, which is the whole of "the relay has room for what it forwarded";
/// - a popped `Packet` is a copy of the item and not of its bytes: the queue has
///   released that slot, so the bytes are the caller's to keep for as long as it
///   likes. The ring writes that slot again only once it has wrapped all the way
///   around to it, which is the very next `push` when the queue was full at the
///   `pop` and `capacity()` pushes later when it was not;
/// - `peek` removes nothing, so the bytes it names are still the queue's own.
pub const Packet = struct {
    /// The node the datagram came from. Upstream `src`.
    src: NodeId,
    /// The datagram, borrowed from whoever decoded it. The queue's storage is
    /// the caller's, so the bytes have to outlive their time in the queue,
    /// which is the same rule as any other borrow and a good deal cheaper
    /// than a copy per datagram per hop on the relay's hottest path.
    data: []const u8,
};

/// A message queued for one client that is not a datagram.
///
/// Upstream calls these "messages" and the other kind "packets"
/// (`server/client.rs:108-111`). Both arms are values the registry's own
/// actions produce, which is what makes the two queues worth having: they are
/// written to from the same few places and they are drained under different
/// rules.
///
/// **Nothing here borrows**, which is the difference from `Packet` and the reason
/// one of the two queues can be a bounded table of values: a queued `Control` is
/// self-contained, outlives whatever buffer the event that produced it was read
/// from, and needs no ring slot to live in.
pub const Control = union(enum) {
    /// `FrameType::EndpointGone` (8): a peer this client has sent to is gone.
    /// Upstream `RelayToClientMsg::EndpointGone`.
    peer_gone: NodeId,
    /// The relay's one-way declaration of the connection's health. Upstream's
    /// `Status` for a v2 client and `Health` for a v1 one — the same event in
    /// two encodings, and which encoding goes on the wire is the negotiated
    /// version's business (`server/client.rs:214-225`).
    status: frame.Status,
};

/// A bounded FIFO over storage the caller owns.
///
/// Upstream's `mpsc::channel(channel_capacity)`, with the two properties that
/// matter kept: bounded, so one slow client cannot grow the relay's heap, and
/// non-blocking on push, so a full queue refuses rather than stalling the
/// relay behind a client that will never read. Capacity is the length of the
/// storage, so there is no second number to keep in step with the first.
///
/// **The consumer supplies two things and the queue calls out to neither**: the
/// item type, and the `storage` slice this is instantiated over. Everything it
/// stores is the item's own value, so the queue is exactly as pure as its items
/// are — a queue of `Packet` inherits `Packet`'s borrow and a queue of `Control`
/// inherits nothing.
///
/// **The bound is `storage.len`, and reaching it is a refusal and not an
/// eviction.** A `push` into a full queue is `error.QueueFull`, leaves the queue
/// exactly as it was, and writes the item nowhere, so nothing the caller still
/// believes it holds has been overwritten. Zero-length storage is a queue that
/// refuses every push and is never indexed, which is what makes the arithmetic
/// below total rather than a division by zero.
///
/// **Where an item sits, and when its bytes move.** Item *n* of the queue lives
/// in `storage[(head + n) % storage.len]` and is not written again until it is
/// popped, so an item that borrows points at storage that stays put while it is
/// queued. `pop` releases that slot, and the ring reaches it again only after
/// every other slot has been filled once. `storage`, `head` and `count` are public
/// because a caller that places borrowed bytes per queue position has to compute
/// the same index this will — and that arithmetic is only valid while nothing
/// pushes between the two steps, which is the caller's discipline to keep.
///
/// Nothing here is synchronized, so two threads sharing one queue are a race the
/// caller has to prevent, and there is no `deinit` because there is nothing to
/// free: the storage is the caller's from the first instruction to the last.
pub fn Queue(comptime Item: type) type {
    return struct {
        const Self = @This();

        /// The caller's storage. Its length is the queue's capacity.
        storage: []Item,
        /// Index of the front item.
        head: usize,
        /// How many items are queued.
        count: usize,

        pub const PushError = error{
            /// The queue is at capacity and the item was dropped.
            ///
            /// Upstream's `TrySendError::Full`, and the relay drops the
            /// datagram on it (`server/clients.rs:218-224`).
            ///
            /// **The queue is unchanged and the item is dropped**, which is the
            /// caller's cue to count it: the datagram that did not fit is not
            /// waiting behind the ones that did, so a relay cannot report a
            /// backlog it is not holding.
            QueueFull,
        };

        /// Takes the caller's storage and borrows it: nothing is read from it,
        /// nothing is written to it here, and it is not freed here either, so a
        /// zeroed or otherwise undefined buffer is a valid one to hand over and
        /// the buffer must outlive this queue.
        ///
        /// The length is the capacity, so a queue with no storage is not a
        /// malformed one — it is the one that refuses everything.
        pub fn init(storage: []Item) Self {
            return .{ .storage = storage, .head = 0, .count = 0 };
        }

        /// Adds an item at the back, or refuses.
        ///
        /// The refusal is `error.QueueFull` and it is decided before anything is
        /// written, so the queue and every item in it are exactly as they were.
        /// The item is a value: a caller holding the only copy of something the
        /// item borrows is the one who has to keep it alive until the pop.
        pub fn push(self: *Self, item: Item) PushError!void {
            // This check is also what makes the modulo below safe: a queue
            // with no storage is always full and never indexes.
            if (self.count == self.storage.len) return error.QueueFull;
            self.storage[(self.head + self.count) % self.storage.len] = item;
            self.count += 1;
        }

        /// The front item, removed, or null when the queue is empty.
        ///
        /// **The item is a copy of what was stored, and not of what that item
        /// borrows.** For a `Packet` the datagram bytes belong to the caller's
        /// storage, this queue has released the slot, and the ring overwrites
        /// those bytes only when it wraps back around to that slot — which is the
        /// next `push` if the queue was full and `capacity()` pushes later if it
        /// was not.
        pub fn pop(self: *Self) ?Item {
            if (self.count == 0) return null;
            const item = self.storage[self.head];
            self.head = (self.head + 1) % self.storage.len;
            self.count -= 1;
            return item;
        }

        /// The next item, without removing it.
        ///
        /// It removes nothing, so the item stays at the front and the storage an
        /// item borrows cannot be overwritten until it is popped.
        pub fn peek(self: Self) ?Item {
            if (self.count == 0) return null;
            return self.storage[self.head];
        }

        /// How many items are queued, which is `count` and never the capacity:
        /// a queue of capacity two holding one is `len() == 1`.
        pub fn len(self: Self) usize {
            return self.count;
        }

        /// How many pushes this queue accepts before it refuses.
        ///
        /// This is the bound `push` refuses at, and it is the length of the
        /// caller's storage rather than a number of this file's own, so the two
        /// cannot disagree.
        pub fn capacity(self: Self) usize {
            return self.storage.len;
        }

        /// Whether the next `push` is a refusal, which is a stronger statement
        /// than `len() == capacity()` only because it is the answer to the
        /// question a caller actually asks.
        pub fn isFull(self: Self) bool {
            return self.count == self.storage.len;
        }
    };
}

/// How many datagrams and control messages one connection may have queued.
///
/// Upstream's default `channel_capacity` is
/// `PER_CLIENT_SEND_QUEUE_DEPTH = 512` (`relay.rs:40`), and both channels
/// get it (`server/client.rs:139-140`). The 512 is the number invariant 9 is
/// about: merged, a `Status` sits behind 512 datagrams for a client that has
/// stopped reading, which is a client that most needs to be told.
///
/// **It is a default, not a limit anything here enforces.** Nothing in this
/// module sizes a queue — the caller owns the storage — so the depth is the
/// caller's number and this one is upstream's to start from. A caller that picks
/// a smaller depth refuses sooner and holds fewer bytes per client; one that
/// picks a larger one holds more datagrams for as long as a client stops reading.
/// At whatever depth it picks, reaching it is `error.QueueFull` and the datagram
/// is dropped (`server/clients.rs:218-224`), which is why the control queue is a
/// second queue rather than a longer first one.
pub const per_client_send_queue_depth = 512;

/// The two queues one connection writes from.
///
/// Upstream's `Client` (`server/client.rs:99-114`) holds exactly these two
/// senders, and the connection actor drains them with a `biased` select that
/// takes packets first (`server/client.rs:381-423`). Keeping them apart is
/// what lets a control message be accepted while the datagram queue is full,
/// which is the whole of `docs/ARCHITECTURE.md` invariant 9.
///
/// **The two queues have separate storage and separate bounds, so one of them
/// being full never refuses the other.** That is invariant 9, and it is what lets
/// a `Status` reach a client whose datagram backlog is exhausted. Nothing here
/// allocates and there is no `deinit`; what the caller owns, `init` says.
pub const Connection = struct {
    data: Queue(Packet),
    control: Queue(Control),

    /// Both buffers are the caller's, are borrowed rather than copied, and must
    /// outlive the `Connection`. Their lengths are the capacities, so a caller
    /// that wants a smaller depth passes shorter slices rather than setting a
    /// field — and a caller that passes an empty one has built a connection that
    /// can be said nothing to.
    pub fn init(data_storage: []Packet, control_storage: []Control) Connection {
        return .{
            .data = Queue(Packet).init(data_storage),
            .control = Queue(Control).init(control_storage),
        };
    }

    /// Whether both queues are full, which is the state in which a control
    /// message is the only thing that can still be said to this client.
    ///
    /// **Both full is the state a control message cannot escape**, and one full is
    /// a slow client rather than a lost one: `peer_gone` and every `status` still
    /// fit while the datagram queue refuses.
    pub fn isSaturated(self: Connection) bool {
        return self.data.isFull() and self.control.isFull();
    }
};

/// A connection's departure, or its replacement by another.
///
/// Upstream `Clients::unregister` (`server/clients.rs:109-170`) has exactly
/// these arms, and the connection id it requires is what tells them apart:
/// `remove_if_mut` compares it against the entry's active connection, and a
/// mismatch means this connection is one of the displaced ones.
///
/// **This is what `OnDisconnectGuard.deinit` answers, and it is the only source of
/// a `Disconnection`.** Two arms report and two do not: `.disconnected` and
/// `.duplicate` are a connection that ended, and `.promoted` is one that ended
/// *and* handed its node id to another, so the caller reports the `ended` in it
/// and then tells the connection named by `took_over` that it is healthy — a frame
/// on that connection's control queue, which is the caller's. `.already_gone` is
/// the second `deinit`, and it is what keeps that from being a double report.
pub const Unregister = union(enum) {
    /// No connection with this id is in the table, so there is nothing to
    /// report. This is the arm a second exit reaches, and it is the reason a
    /// disconnect is reported exactly once: the report is the registry's, and
    /// the registry reports only for a connection it still holds.
    already_gone,
    /// The connection ended and nothing took its place, so the entry goes
    /// with it. Upstream's last arm, without the peer-gone fanout: that is a
    /// second index keyed by sender, and it belongs with the forwarding path
    /// rather than with the lifecycle this milestone is about.
    disconnected: Disconnection,
    /// The connection was one this node id's later connections had displaced.
    /// It ends and access control is told, and the entry survives with its
    /// active connection untouched. Upstream's `retain` arm
    /// (`server/clients.rs:136-144`).
    duplicate: Disconnection,
    /// The active connection ended and the newest displaced one took over.
    /// Upstream pops the last inactive, promotes it, and tells it
    /// `Status::Healthy` (`server/clients.rs:122-129`).
    promoted: struct { ended: Disconnection, took_over: ConnectionId },
};

/// A registry of the clients one relay has admitted.
///
/// Upstream is a `DashMap<EndpointId, ClientState>` behind an `Arc`
/// (`server/clients.rs:29-43`); this is the same map with the concurrency
/// taken out, as an open-addressed table over storage the caller owns.
/// Admitting a client allocates nothing, which is what lets a relay's whole
/// client set be a value a test can hold on the stack.
///
/// There is one entry per node id, and there is always exactly one entry per
/// node id with a connection in it. A second connection from a node id that
/// already has one does not make a second entry: it takes the entry, and the
/// connection it displaced is remembered so that a departure can hand the node
/// id back. That is upstream's behaviour (`server/clients.rs:81-101`) and it
/// is the same fact as invariant 10's "admit once".
///
/// `inactive_depth` is how many displaced connections a node id may
/// accumulate. Upstream's `Vec` grows without bound, and a bound has to be
/// somewhere; the caller is the only one who knows what a relay should shed
/// first. A connection past the depth is refused rather than silently dropped,
/// so the caller can log it.
///
/// **The caller owns the slots and the registry borrows them**: `init` writes
/// `.empty` over every one and nothing grows the array afterwards, so the storage
/// must outlive the registry and the registry needs no `deinit`.
///
/// **Two bounds, and both are refusals that leave the table as it was.** The slot
/// count is the caller's, and a table with no free slot is `error.NoFreeSlot`.
/// `inactive_depth` is how many displaced connections one node id may hold, and
/// the next is `error.TooManyDuplicateConnections` — checked before the active id
/// moves, so the entry keeps its active connection and its displaced list. **A
/// refused `admit` admits nothing**: that connection has no handle, is not in the
/// table, and is the caller's to close.
///
/// The table rehashes itself at three quarters full, tombstones included, so a
/// relay that churns connections does not probe through its own history; the
/// rebuild keeps every entry and clears the tombstones.
///
/// **No synchronization.** Every method takes `*Self` over a plain table, so two
/// threads sharing one registry are a race; the relay's loop is the only writer,
/// which is the discipline `Connection`'s queues are under too.
pub fn Registry(comptime inactive_depth: usize) type {
    return struct {
        const Self = @This();

        /// One cell of the table. The caller owns the array of them and never
        /// reads it: `init` writes every one, so nothing here is ever `undefined`
        /// and a slot the caller never filled is not a slot with no valid tag.
        pub const Slot = union(enum) {
            /// Never used, and never held a neighbour's entry.
            empty,
            /// Held an entry that has gone. Probing walks past it, so a
            /// removal cannot hide the entry behind it, and `rehash` is what
            /// stops a long-lived relay from spending its whole table on
            /// them.
            tombstone,
            occupied: Entry,
        };

        /// What the registry knows about one node id. Upstream `ClientState`
        /// (`server/clients.rs:40-43`).
        pub const Entry = struct {
            /// The node id, which is also the table key.
            node_id: NodeId,
            /// The connection datagrams are forwarded to. Upstream `active`.
            active: ConnectionId,
            /// Connections this node id opened that a later one displaced,
            /// newest last. Upstream `inactive: Vec<Client>`.
            inactive: struct {
                // Registry already defines Self; that alias is ambiguous here.
                // ziglint-ignore: Z022
                const Inactive = @This();

                /// The displaced connections, newest last, up to the depth the
                /// caller's `Registry(inactive_depth)` bound the list at. Only
                /// `[0..len]` is ever read — `admit` leaves the rest `undefined`
                /// — so nothing outside this file may look at them, and a caller
                /// that kept more displaced connections than this holds has lost
                /// them to a bound it chose rather than to a write it can see.
                ids: [inactive_depth]ConnectionId,
                /// How many of `ids` are in use, and never a capacity: a list of
                /// depth four holding one is `len == 1`.
                len: usize,

                fn pop(self: *Inactive) ?ConnectionId {
                    if (self.len == 0) return null;
                    self.len -= 1;
                    return self.ids[self.len];
                }

                fn push(self: *Inactive, id: ConnectionId) error{TooManyDuplicateConnections}!void {
                    if (self.len == self.ids.len) return error.TooManyDuplicateConnections;
                    self.ids[self.len] = id;
                    self.len += 1;
                }

                fn holds(self: Inactive, id: ConnectionId) bool {
                    for (self.ids[0..self.len]) |candidate| {
                        if (candidate == id) return true;
                    }
                    return false;
                }

                fn forget(self: *Inactive, id: ConnectionId) void {
                    for (self.ids[0..self.len], 0..) |*candidate, offset| {
                        if (candidate.* != id) continue;
                        // Newest last, and the order is what decides which
                        // one is promoted next.
                        std.mem.copyForwards(
                            ConnectionId,
                            self.ids[offset..self.len],
                            self.ids[offset + 1 .. self.len],
                        );
                        self.len -= 1;
                        return;
                    }
                }
            },
        };

        slots: []Slot,
        /// How many slots hold an entry.
        len: usize,
        /// How many hold one that has gone.
        tombstones: usize,

        pub const AdmitError = error{
            /// The table has no slot left. The operator sized it, and a relay
            /// that fills it has to shed connections; this is where it finds
            /// out.
            NoFreeSlot,
            /// This node id already has `inactive_depth` displaced
            /// connections.
            ///
            /// **The table is unchanged**: the entry keeps its active connection
            /// and its displaced list, and the connection that was refused has no
            /// handle and is not in it. Nothing is evicted to make room, so a
            /// caller sees the refusal rather than a client it did not choose to
            /// lose.
            TooManyDuplicateConnections,
        };

        /// What admitting a connection did.
        pub const Admit = union(enum) {
            /// The node id was free and this connection owns it.
            fresh,
            /// Another connection owned it. Upstream deactivates that one,
            /// tells it `Status::SameEndpointIdConnected` over its control
            /// queue, and remembers it as inactive.
            ///
            /// The two outcomes differ only in what the caller still owes: a
            /// `fresh` owes nothing, and a `replaced` owes a
            /// `Status::SameEndpointIdConnected` over the displaced connection's
            /// own control queue, which is the caller's queue and not this file's.
            replaced: ConnectionId,
        };

        /// A connection that has been admitted, and the handle that ends it.
        ///
        /// The two fields are read once, together: the handle ends the connection
        /// and the outcome says what is still owed. Copying it copies the handle,
        /// which is safe because `deinit` reports once, and the handle points
        /// into the registry that handed it out.
        pub const Admitted = struct {
            guard: OnDisconnectGuard,
            admit: Admit,
        };

        /// The handle that ends a connection, and the only way to remove it.
        ///
        /// Upstream `OnDisconnectGuard` (`server.rs:375-425`) reports in
        /// `Drop`, and holds an `Option<Arc<dyn DynAccessControl>>` so a guard
        /// with no access control attached reports nothing. Zig has no `Drop`,
        /// so the report moves to `deinit` and every guarantee the move was
        /// carrying is restated in Zig terms:
        ///
        /// - `admit` is the only way into the table and it hands the handle
        ///   back, so no connection is ever admitted without one and no
        ///   caller can forget to take it.
        /// - `deinit` marks the handle before it reports, so a second call on
        ///   the same handle does nothing.
        /// - The report is the registry's, and the registry reports only for a
        ///   connection it still holds, so even a handle that was copied
        ///   before it was deinited reports once.
        ///
        /// The registry must outlive every handle, because `deinit` reaches
        /// into it. That is the half of "the connection actor must never
        /// outlive the guard" a type can carry; the other half is a discipline,
        /// and it is recorded in `docs/ARCHITECTURE.md` rather than pretended
        /// away — Zig has no move semantics, so a struct can always be copied.
        ///
        /// **`deinit` reports by returning and calls nothing.** It frees no
        /// memory, closes no socket, and does not reach the caller's access
        /// control; the caller receives an `Unregister` and acts on it. It is the
        /// only exit, so a connection dropped without it stays in the table until
        /// the registry itself is discarded — which is how a relay that tears its
        /// table down early loses exactly those connections' reports.
        pub const OnDisconnectGuard = struct {
            registry: *Self,
            node_id: NodeId,
            connection_id: ConnectionId,
            reported: bool,

            /// The single exit path.
            ///
            /// It hands back what the registry did, because the caller still
            /// has to act on a promotion. Upstream's `unregister` sends the
            /// `Status::Healthy` itself; here that is a frame the caller
            /// writes, because the queue it goes on is the caller's.
            pub fn deinit(self: *OnDisconnectGuard) Unregister {
                if (self.reported) return .already_gone;
                self.reported = true;
                return self.registry.unregister(self.node_id, self.connection_id);
            }
        };

        /// Builds a registry over storage the caller owns. `slots` is sized
        /// by the caller and is never grown. A power of two is faster to
        /// probe, and any size is correct.
        ///
        /// `slots` is marked empty in place and never read otherwise, so it may
        /// be `undefined` on the way in and must outlive the registry. Zero slots
        /// is degenerate rather than broken — every `admit` is
        /// `error.NoFreeSlot` and every lookup is null — and it is why the probing
        /// and the insertion both answer before dividing by `slots.len`.
        pub fn init(slots: []Slot) Self {
            for (slots) |*slot| slot.* = .empty;
            return .{ .slots = slots, .len = 0, .tombstones = 0 };
        }

        /// Upstream `Clients::register`, gated on upstream's access check:
        /// nothing is admitted before access control has allowed it, and the
        /// handle comes back with the entry.
        ///
        /// **The handle comes back only on success**, so a refused `admit` leaves
        /// the caller with a connection it has not admitted and must close; that
        /// error is also the only place a relay learns to log
        /// `TooManyDuplicateConnections` instead of dropping a client silently.
        ///
        /// `connection_id` is the caller's number and is unique across the
        /// process rather than across this registry, because the table compares it
        /// against an entry that another registry may also hold.
        pub fn admit(
            self: *Self,
            node_id: NodeId,
            connection_id: ConnectionId,
        ) AdmitError!Admitted {
            if (self.find(node_id)) |index| {
                // The node id already has an owner. Upstream replaces the
                // active connection, tells the old one it has been
                // superseded, and pushes it onto the inactive list
                // (`server/clients.rs:82-94`).
                const entry = self.entryAt(index);
                const displaced = entry.active;
                // Checked before the active id moves, so a refusal leaves
                // the entry exactly as it was.
                try entry.inactive.push(displaced);
                entry.active = connection_id;
                return .{
                    .guard = .{
                        .registry = self,
                        .node_id = node_id,
                        .connection_id = connection_id,
                        .reported = false,
                    },
                    .admit = .{ .replaced = displaced },
                };
            }
            try self.insert(.{
                .node_id = node_id,
                .active = connection_id,
                .inactive = .{ .ids = undefined, .len = 0 },
            });
            return .{
                .guard = .{
                    .registry = self,
                    .node_id = node_id,
                    .connection_id = connection_id,
                    .reported = false,
                },
                .admit = .fresh,
            };
        }

        /// The connection datagrams for this node id are forwarded to.
        ///
        /// Null means no entry holds this node id, which is what a relay answers
        /// with `Control.peer_gone` — this is only the lookup, and the frame is the
        /// caller's to send. The id is a value, so nothing here borrows and a
        /// lookup keeps no connection alive.
        pub fn activeConnectionId(self: *const Self, node_id: NodeId) ?ConnectionId {
            const index = self.find(node_id) orelse return null;
            return self.slots[index].occupied.active;
        }

        /// How many node ids the registry holds, which is the number of
        /// entries and not the number of connections.
        ///
        /// One node id is one entry however many of its connections are
        /// displaced, so this is a count of clients the relay can reach and not
        /// of connections it is holding.
        pub fn nodeCount(self: *const Self) usize {
            return self.len;
        }

        /// Upstream `Clients::unregister`. Not public: the guard's `deinit`
        /// is the only exit, which is invariant 10 restated as a visibility
        /// rule.
        fn unregister(
            self: *Self,
            node_id: NodeId,
            connection_id: ConnectionId,
        ) Unregister {
            const index = self.find(node_id) orelse return .already_gone;
            const entry = self.entryAt(index);
            const ended: Disconnection = .{ .node_id = node_id, .connection_id = connection_id };

            // The connection id is what tells the three cases apart, and it is
            // why upstream passes one (`server/clients.rs:110-121`).
            if (entry.active == connection_id) {
                if (entry.inactive.pop()) |promoted| {
                    entry.active = promoted;
                    return .{ .promoted = .{ .ended = ended, .took_over = promoted } };
                }
                self.slots[index] = .tombstone;
                self.len -= 1;
                self.tombstones += 1;
                return .{ .disconnected = ended };
            }
            if (entry.inactive.holds(connection_id)) {
                // The displaced connection is forgotten; the entry and its
                // active connection are untouched.
                entry.inactive.forget(connection_id);
                return .{ .duplicate = ended };
            }
            // The registry holds no such connection, which is what a second
            // exit finds. Reporting here would be the double report.
            return .already_gone;
        }

        fn entryAt(self: *Self, index: usize) *Entry {
            return &self.slots[index].occupied;
        }

        /// Where this node id's probe starts.
        fn start(self: *const Self, node_id: NodeId) usize {
            return @intCast(std.hash.Wyhash.hash(0, &node_id.toBytes()) % self.slots.len);
        }

        fn find(self: *const Self, node_id: NodeId) ?usize {
            if (self.slots.len == 0) return null;
            var probes: usize = 0;
            while (probes < self.slots.len) : (probes += 1) {
                const index = (self.start(node_id) + probes) % self.slots.len;
                switch (self.slots[index]) {
                    .empty => return null,
                    .tombstone => continue,
                    .occupied => |entry| {
                        if (node_id.order(entry.node_id) == .eq) return index;
                    },
                }
            }
            // A full table of entries with no `empty` in it: every probe
            // landed on an entry, so this node id is not in any of them.
            return null;
        }

        fn insert(self: *Self, entry: Entry) AdmitError!void {
            if (self.len == self.slots.len) return error.NoFreeSlot;
            // Three quarters full, tombstones included: a relay that churns
            // connections would otherwise probe through its own history.
            if ((self.len + self.tombstones + 1) * 4 > self.slots.len * 3) {
                try self.rehash();
            }
            try self.place(entry);
            self.len += 1;
        }

        /// Probes for a slot and writes the entry there, with no load
        /// bookkeeping of its own. `rehash` uses this directly, so a rebuild
        /// cannot ask for another rebuild.
        fn place(self: *Self, entry: Entry) AdmitError!void {
            var probes: usize = 0;
            while (probes < self.slots.len) : (probes += 1) {
                const index = (self.start(entry.node_id) + probes) % self.slots.len;
                switch (self.slots[index]) {
                    .occupied => continue,
                    .tombstone => self.tombstones -= 1,
                    .empty => {},
                }
                self.slots[index] = .{ .occupied = entry };
                return;
            }
            // Not reachable: `insert` and `rehash` both establish that
            // `len < slots.len` first, which is an `empty` to find. It is
            // here so the function has no exit that is not accounted for.
            return error.NoFreeSlot;
        }

        /// Puts every entry back, clearing the tombstones.
        fn rehash(self: *Self) AdmitError!void {
            var index: usize = 0;
            while (index < self.slots.len) : (index += 1) {
                const entry = switch (self.slots[index]) {
                    .occupied => |entry| entry,
                    else => continue,
                };
                // The slot is emptied before the entry goes back in, so no
                // entry is ever in two places. The entry may land at or after
                // `index`, in which case this loop meets it again and moves
                // it once more; one copy survives either way.
                self.slots[index] = .tombstone;
                self.tombstones += 1;
                try self.place(entry);
            }
            var remaining: usize = 0;
            for (self.slots) |slot| {
                if (std.meta.activeTag(slot) == .tombstone) remaining += 1;
            }
            self.tombstones = remaining;
        }
    };
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

test "a second connection takes the node id and does not make a second entry" {
    // `Registry` is a generic factory: the binding holds the struct type it
    // returns, and a type binding is PascalCase rather than a value.
    // zwanzig-disable-next-line: identifier-style
    const Reg = Registry(4);
    var slots: [4]Reg.Slot = undefined;
    var registry = Reg.init(&slots);
    const node_id = try testNodeId(1);

    const first = try registry.admit(node_id, 1);
    try t.expectEqual(Reg.Admit.fresh, first.admit);
    try t.expectEqual(@as(usize, 1), registry.nodeCount());
    try t.expectEqual(@as(?ConnectionId, 1), registry.activeConnectionId(node_id));

    const second = try registry.admit(node_id, 2);
    try t.expectEqual(Reg.Admit{ .replaced = 1 }, second.admit);
    // One entry, and the new connection owns it. The displaced one is
    // remembered rather than dropped, which is what lets a departure hand the
    // node id back.
    try t.expectEqual(@as(usize, 1), registry.nodeCount());
    try t.expectEqual(@as(?ConnectionId, 2), registry.activeConnectionId(node_id));

    // A different node id is a different entry, and the table holds both.
    const other = try registry.admit(try testNodeId(2), 3);
    try t.expectEqual(Reg.Admit.fresh, other.admit);
    try t.expectEqual(@as(usize, 2), registry.nodeCount());
    try t.expectEqual(@as(?ConnectionId, 2), registry.activeConnectionId(node_id));
    try t.expectEqual(@as(?ConnectionId, 3), registry.activeConnectionId(try testNodeId(2)));
    try t.expectEqual(@as(?ConnectionId, null), registry.activeConnectionId(try testNodeId(3)));
}

test "a departing connection hands its node id to the newest one it displaced" {
    // `Registry` is a generic factory: the binding holds the struct type it
    // returns, and a type binding is PascalCase rather than a value.
    // zwanzig-disable-next-line: identifier-style
    const Reg = Registry(4);
    var slots: [4]Reg.Slot = undefined;
    var registry = Reg.init(&slots);
    const node_id = try testNodeId(4);

    var first = (try registry.admit(node_id, 1)).guard;
    var second = (try registry.admit(node_id, 2)).guard;
    var third = (try registry.admit(node_id, 3)).guard;
    try t.expectEqual(@as(usize, 1), registry.nodeCount());

    // The newest displaced connection takes over, and is told it is healthy.
    switch (third.deinit()) {
        .promoted => |promotion| try t.expectEqual(@as(ConnectionId, 2), promotion.took_over),
        else => return error.TestUnexpectedResult,
    }
    try t.expectEqual(@as(?ConnectionId, 2), registry.activeConnectionId(node_id));
    try t.expectEqual(@as(usize, 1), registry.nodeCount());

    // And then the one before it.
    switch (second.deinit()) {
        .promoted => |promotion| try t.expectEqual(@as(ConnectionId, 1), promotion.took_over),
        else => return error.TestUnexpectedResult,
    }
    try t.expectEqual(@as(?ConnectionId, 1), registry.activeConnectionId(node_id));

    // The last one leaves and the entry goes with it, because a node id with
    // no connection in it is not a client.
    switch (first.deinit()) {
        .disconnected => |ended| try t.expectEqual(@as(ConnectionId, 1), ended.connection_id),
        else => return error.TestUnexpectedResult,
    }
    try t.expectEqual(@as(usize, 0), registry.nodeCount());
    try t.expectEqual(@as(?ConnectionId, null), registry.activeConnectionId(node_id));
}

test "a displaced connection's own departure leaves the active one alone" {
    // `Registry` is a generic factory: the binding holds the struct type it
    // returns, and a type binding is PascalCase rather than a value.
    // zwanzig-disable-next-line: identifier-style
    const Reg = Registry(4);
    var slots: [4]Reg.Slot = undefined;
    var registry = Reg.init(&slots);
    const node_id = try testNodeId(5);

    // The second connection takes the node id, so the first is the displaced
    // one and the second is the one that owns it.
    var displaced = (try registry.admit(node_id, 1)).guard;
    var active = (try registry.admit(node_id, 2)).guard;

    // The displaced connection ends. Upstream retains the entry and leaves
    // the active connection alone (`server/clients.rs:136-144`), so the
    // connection that still owns the node id is still the one that owns it.
    switch (displaced.deinit()) {
        .duplicate => |ended| try t.expectEqual(@as(ConnectionId, 1), ended.connection_id),
        else => return error.TestUnexpectedResult,
    }
    try t.expectEqual(@as(?ConnectionId, 2), registry.activeConnectionId(node_id));
    try t.expectEqual(@as(usize, 1), registry.nodeCount());

    switch (active.deinit()) {
        .disconnected => |ended| try t.expectEqual(@as(ConnectionId, 2), ended.connection_id),
        else => return error.TestUnexpectedResult,
    }
    try t.expectEqual(@as(?ConnectionId, null), registry.activeConnectionId(node_id));
}

test "a disconnect is reported once, whichever way the connection ends" {
    // `Registry` is a generic factory: the binding holds the struct type it
    // returns, and a type binding is PascalCase rather than a value.
    // zwanzig-disable-next-line: identifier-style
    const Reg = Registry(4);
    var slots: [4]Reg.Slot = undefined;
    var registry = Reg.init(&slots);
    const node_id = try testNodeId(6);

    var admitted = try registry.admit(node_id, 1);

    // The path that could double-report: a handle is a plain struct, so it
    // can be copied, where upstream's guard is moved into the connection
    // actor so that it cannot be. Both copies are deinited, and only the one
    // the registry still holds reports.
    var copy = admitted.guard;
    try t.expect(admitted.guard.deinit() == .disconnected);
    try t.expectEqual(Unregister.already_gone, copy.deinit());
    try t.expectEqual(@as(usize, 0), registry.nodeCount());

    // The other half: one handle, deinited twice. The mark is set before the
    // report, so the second call finds nothing to do.
    var guard = (try registry.admit(node_id, 2)).guard;
    try t.expect(guard.deinit() == .disconnected);
    try t.expectEqual(Unregister.already_gone, guard.deinit());

    // And a handle for a connection that was never admitted.
    var stranger: Reg.OnDisconnectGuard = .{
        .registry = &registry,
        .node_id = node_id,
        .connection_id = 99,
        .reported = false,
    };
    try t.expectEqual(Unregister.already_gone, stranger.deinit());
}

test "a registry refuses what the caller sized it for" {
    // One slot and one displaced connection: neither is generous.
    // `Registry` is a generic factory: the binding holds the struct type it
    // returns, and a type binding is PascalCase rather than a value.
    // zwanzig-disable-next-line: identifier-style
    const Reg = Registry(1);
    var slots: [1]Reg.Slot = undefined;
    var registry = Reg.init(&slots);
    var first = try registry.admit(try testNodeId(7), 1);
    try t.expectError(error.NoFreeSlot, registry.admit(try testNodeId(8), 2));
    // One displaced connection fits; the second does not.
    try t.expectEqual(
        Reg.Admit{ .replaced = 1 },
        (try registry.admit(try testNodeId(7), 3)).admit,
    );
    try t.expectError(
        error.TooManyDuplicateConnections,
        registry.admit(try testNodeId(7), 4),
    );
    // The two refusals changed nothing, which is the other half of a refusal
    // being safe. Connection 3 is the one that did get in.
    try t.expectEqual(@as(usize, 1), registry.nodeCount());
    try t.expectEqual(@as(?ConnectionId, 3), registry.activeConnectionId(try testNodeId(7)));
    try t.expect(first.guard.deinit() == .duplicate);
}

test "an empty registry holds nothing and refuses everything" {
    // Zero slots is degenerate rather than broken: every admission is refused
    // and every lookup is empty, with no indexing anywhere.
    // `Registry` is a generic factory: the binding holds the struct type it
    // returns, and a type binding is PascalCase rather than a value.
    // zwanzig-disable-next-line: identifier-style
    const Reg = Registry(1);
    var registry = Reg.init(&.{});
    try t.expectError(error.NoFreeSlot, registry.admit(try testNodeId(9), 1));
    try t.expectEqual(@as(?ConnectionId, null), registry.activeConnectionId(try testNodeId(9)));
    try t.expectEqual(@as(usize, 0), registry.nodeCount());
}

test "a removed entry does not hide the one behind it" {
    // A table with room for two, and two node ids in it. Whether their
    // probes collide is up to the hash; what must hold either way is that a
    // removal leaves the other findable, which is what a tombstone is for.
    // `Registry` is a generic factory: the binding holds the struct type it
    // returns, and a type binding is PascalCase rather than a value.
    // zwanzig-disable-next-line: identifier-style
    const Reg = Registry(2);
    var slots: [2]Reg.Slot = undefined;
    var registry = Reg.init(&slots);
    const first_node = try testNodeId(10);
    const second_node = try testNodeId(11);

    var first = try registry.admit(first_node, 1);
    var second = try registry.admit(second_node, 2);
    try t.expectEqual(@as(?ConnectionId, 1), registry.activeConnectionId(first_node));
    try t.expectEqual(@as(?ConnectionId, 2), registry.activeConnectionId(second_node));

    try t.expect(first.guard.deinit() == .disconnected);
    try t.expectEqual(@as(?ConnectionId, null), registry.activeConnectionId(first_node));
    try t.expectEqual(@as(?ConnectionId, 2), registry.activeConnectionId(second_node));
    try t.expect(second.guard.deinit() == .disconnected);
    try t.expectEqual(@as(usize, 0), registry.nodeCount());
    // And the table is reusable after the tombstones, which is what `rehash`
    // is for.
    try t.expect((try registry.admit(first_node, 3)).admit == .fresh);
    try t.expectEqual(@as(?ConnectionId, 3), registry.activeConnectionId(first_node));
}

test "a status is not refused by a full datagram backlog" {
    // A connection with room for two datagrams and two control messages.
    var data_storage: [2]Packet = undefined;
    var control_storage: [2]Control = undefined;
    var connection = Connection.init(&data_storage, &control_storage);
    const node_id = try testNodeId(12);
    const datagram: Packet = .{ .src = node_id, .data = "ozai" };

    // Fill the datagram queue, which is what a client that has stopped
    // reading looks like from here.
    try connection.data.push(datagram);
    try connection.data.push(datagram);
    try connection.control.push(.{ .peer_gone = node_id });
    try connection.control.push(.{ .status = .same_endpoint_id_connected });
    try t.expect(connection.control.isFull());
    try t.expect(connection.data.isFull());
    try t.expect(connection.isSaturated());
    try t.expectError(error.QueueFull, connection.data.push(datagram));

    // Both queues are full and the two of them still answer separately: the
    // control queue hands over what it holds while the datagram queue is
    // exactly as full as it was.
    try t.expectEqual(Control{ .peer_gone = node_id }, connection.control.pop().?);
    try t.expect(connection.data.isFull());
    try t.expectEqual(@as(usize, 2), connection.data.len());

    // And one freed control slot is all it takes to say the thing that
    // matters, without the datagram queue ever having moved.
    try connection.control.push(.{ .status = .rate_limited });
    try t.expectEqual(
        Control{ .status = .same_endpoint_id_connected },
        connection.control.peek().?,
    );
    try t.expectEqual(@as(usize, 2), connection.data.len());
    try t.expectError(error.QueueFull, connection.data.push(datagram));
    try t.expectEqual(
        Control{ .status = .same_endpoint_id_connected },
        connection.control.pop().?,
    );
    try t.expectEqual(Control{ .status = .rate_limited }, connection.control.pop().?);
    try t.expectEqual(@as(?Control, null), connection.control.pop());
}

test "merging the two queues loses the status, which is the point of them" {
    // The same two datagrams, at the same capacity, in one queue. This is the
    // merged shape invariant 9 rules out, and it is worth running rather than
    // describing: the control message is refused, and a client that is being
    // superseded is a client that never hears it.
    var merged_storage: [2]Packet = undefined;
    var merged = Queue(Packet).init(&merged_storage);
    const datagram: Packet = .{ .src = try testNodeId(13), .data = "ozai" };
    try merged.push(datagram);
    try merged.push(datagram);
    try t.expectError(error.QueueFull, merged.push(datagram));
    try t.expectEqual(@as(usize, 2), merged.capacity());
}

test "a registry action lands on a saturated connection's control queue" {
    // The two halves together, which is the shape invariant 9 is really
    // about: a second connection arrives for a node id whose first connection
    // has a full datagram backlog.
    // `Registry` is a generic factory: the binding holds the struct type it
    // returns, and a type binding is PascalCase rather than a value.
    // zwanzig-disable-next-line: identifier-style
    const Reg = Registry(2);
    var slots: [2]Reg.Slot = undefined;
    var registry = Reg.init(&slots);
    const node_id = try testNodeId(14);

    var data_storage: [1]Packet = undefined;
    var control_storage: [1]Control = undefined;
    var connection = Connection.init(&data_storage, &control_storage);
    try connection.data.push(.{ .src = node_id, .data = "ozai" });

    var first = try registry.admit(node_id, 1);
    var second = try registry.admit(node_id, 2);
    try t.expectEqual(Reg.Admit{ .replaced = 1 }, second.admit);

    // Upstream's `old_client.try_send_health(Status::SameEndpointIdConnected)`
    // (`server/clients.rs:90-91`), over the control queue, which is not full.
    try connection.control.push(.{ .status = .same_endpoint_id_connected });
    try t.expectEqual(
        Control{ .status = .same_endpoint_id_connected },
        connection.control.pop().?,
    );
    // The datagram queue is still refusing, which is what the second queue is
    // for.
    try t.expectError(
        error.QueueFull,
        connection.data.push(.{ .src = node_id, .data = "ozai" }),
    );
    try t.expect(first.guard.deinit() == .duplicate);
    try t.expect(second.guard.deinit() == .disconnected);
}
