//! The command line one `ozai-interop-peer` run is started with.
//!
//! Pure over bytes: it reads arguments and hands back values, and it opens no
//! socket, reads no clock and touches no file. That split is
//! `src/node/cli.zig`'s, and the reason for it is the same — a grammar that can
//! fail by name is a grammar a reader can be told about, so a run's exit code
//! says whether the exchange failed or was never asked.
//!
//! # The partner's flags, and why they are this program's flags
//!
//! `test/rust_partner/src/main.rs` is the other end of this exchange and its
//! command line is the contract between the two. So the names here are that
//! program's names, its role rules are its role rules — `--send-bi` belongs to
//! a dialer and `--response-bi` to a listener — and the protocol both ends fall
//! back on is the one it registers when nothing was named. A run here that
//! disagreed with the partner would not be testing interoperability; it would
//! be testing this file's defaults.
//!
//! One thing is deliberately *stricter*: a flag given twice is refused. Last
//! value winning is fine for a program with no scenarios, and it is exactly how
//! a scenario silently loses a payload without anyone reading a line that says
//! so.
//!
//! # A run that declares nothing is a legal thing to ask for
//!
//! Nothing here insists a payload was declared. A run with no `--send-*` and
//! no `--expect-*` is a handshake and an ALPN and nothing else, which is a
//! legitimate thing to want from a partner. What such a run is not is a
//! transfer, so `interop_peer.zig` reports only what was declared rather than
//! printing zeroes that read as an exchange that happened.

const std = @import("std");
const ozai = @import("ozai");

const config_mod = ozai.transport_quic_config;
const NodeId = ozai.NodeId;
const SecretKey = ozai.SecretKey;
const SocketAddr = ozai.SocketAddr;

/// Which half of the exchange this run is.
///
/// Not symmetric, and that is the point: a listener answers and a dialer asks,
/// which is what decides which of the two bidirectional payload flags each one
/// may carry.
pub const Role = enum {
    listen,
    dial,

    pub fn text(self: Role) []const u8 {
        return @tagName(self);
    }
};

/// The protocol both ends speak when neither says otherwise.
///
/// **The partner's default rather than this project's.** `iroh-partner`
/// registers `/ozai/1` when no `--alpn` was given, so naming something else
/// here as the default would offer a protocol the peer does not speak and turn
/// every run that forgot the flag into a handshake failure this file
/// manufactured.
pub const default_alpn = "/ozai/1";

/// The most protocols one run may offer: `config_mod.max_alpns`, the same bound
/// `Bridge.create` refuses a longer list by, named here so this file is not the
/// one that decides it.
pub const max_alpns = config_mod.max_alpns;

/// The most bytes one declared payload may be.
///
/// The partner reads a stream with `read_to_end(64 * 1024)`, so a longer
/// payload is one the peer would truncate before this end could see the
/// difference — and the mismatch report would then name a truncation as though
/// it were a wire fault. Refused here, by name, instead.
pub const max_payload: usize = 64 * 1024;

/// How long a run waits for its declared scenario before failing, in
/// milliseconds. Long enough for a handshake and a Retry on a loaded machine,
/// short enough that a stall reads as a stall.
pub const default_timeout_ms: u64 = 30_000;

/// How many peer-initiated unidirectional streams one run admits, as the
/// number `Config.initial_max_streams_uni` takes.
///
/// **Not one.** The scenario needs exactly one, but `Conn.openUni` *refuses*
/// against this number rather than queueing, so a limit of one would turn a
/// second stream into a refusal instead of a limit that grows — and the run
/// would report a protocol fault for what is really this consumer having
/// narrowed the core's own default. Four is the bound, and it is a number
/// rather than null so that a run's grant is stated rather than inherited.
pub const max_uni_streams: u64 = 4;

/// A command line this program will not run.
///
/// Every name here is a decision a reader can disagree with, which is why none
/// of them is a bare "invalid": a refusal that says only that makes the caller
/// guess which half of its own command line was wrong.
pub const Rejection = error{
    /// A flag this program does not have.
    UnknownFlag,
    /// A flag whose value was not on the command line after it.
    MissingValue,
    /// A flag given twice. The last value would otherwise win silently.
    DuplicateFlag,
    /// No `--mode`, so nothing said which half of the exchange to run.
    MissingMode,
    /// `--mode` named a word that is neither `listen` nor `dial`.
    UnknownMode,
    /// `--dial` with no `@`, so nothing said which peer it names.
    DialWithoutPeer,
    /// A node id that is not 64 hex digits.
    NodeIdNotHex,
    /// A `--secret-key` that is not 32 bytes of hex.
    SecretKeyNotHex,
    /// A payload with an odd number of hex digits, so it names no whole bytes.
    OddHexLength,
    /// A payload carrying a character that is not a hex digit.
    NotHex,
    /// A payload longer than `max_payload`.
    PayloadTooLong,
    /// `ip:port` with no port, a port that is not a number, or a host that is
    /// neither a v4 nor a v6 literal.
    AddressNotReachable,
    /// A `--timeout-ms` that is not a number, or is zero.
    TimeoutNotMilliseconds,
    /// `--mode listen` with no `--listen`.
    ListenWithoutAddress,
    /// `--mode dial` with no `--dial`.
    DialWithoutAddress,
    /// `--dial` on a listener: the half that asks and the half that waits are
    /// different ends, and a line carrying both is a caller that mixed them up.
    DialNeedsDialMode,
    /// Both `--send-bi` and `--response-bi`. One run asks and one run answers.
    BothBidirectionalFlags,
    /// `--send-bi` on a listener, which is the end that answers.
    SendBiNeedsDial,
    /// `--response-bi` on a dialer, which is the end that asks.
    ResponseBiNeedsListen,
    /// `--expect-bi` on a dialer that did not ask, so there is no stream for
    /// the expectation to be about.
    ExpectBiNeedsSendBi,
    /// `--require-retry` on a dialer. A Retry is something a server answers
    /// with; there is nothing here to answer.
    RetryNeedsListen,
    /// `--expect-remote` naming a different peer than `--dial` named.
    PinDisagreesWithDial,
    /// A run offering no protocol at all.
    NoAlpn,
    /// More protocols than `max_alpns`.
    TooManyAlpns,
};

/// Everything `parse` can be refused with: this file's own names, the key
/// constructors' (a node id is only a node id if it is on the curve), the
/// allocator, and the writer `usage` prints through.
pub const ParseError = Rejection || ozai.KeyError || std.mem.Allocator.Error ||
    std.Io.Writer.Error;

/// Everything a command line asked for.
///
/// Every payload is bytes decoded from hex and owned by the arena `parse` was
/// handed, so a run may keep one for as long as it lives while the argument
/// bytes behind it go. `secret` is a value rather than a borrow for the same
/// reason `SecretKey` is one.
pub const Options = struct {
    role: Role,
    /// Where to bind. Required in `listen`; in `dial` it pins the local port
    /// when it is not zero and is absent otherwise.
    listen: ?SocketAddr,
    /// The peer a dial is pinned to, and the address it is dialled at.
    dial_id: ?NodeId,
    dial_addr: ?SocketAddr,
    /// This run's long-term identity. Null draws one from `io.randomSecure`.
    secret: ?SecretKey,
    /// The peer this run insists on, whichever half it is. On a listener this
    /// is the pin `Config.expect_peer` enforces; on a dialer it is a
    /// second statement of the `--dial` pin, and `parse` refuses the two
    /// disagreeing.
    expect_remote: ?NodeId,
    /// The protocols this run offers, in preference order.
    alpns: []const []const u8,
    /// The bidirectional request, on the end that asks.
    send_bi: ?[]const u8,
    /// The bidirectional answer, on the end that answers. Written only once
    /// this run's own expectations are verified, which is the partner's
    /// barrier and the only thing that makes an answer proof that a request
    /// arrived.
    response_bi: ?[]const u8,
    send_uni: ?[]const u8,
    expect_uni: ?[]const u8,
    send_datagram: ?[]const u8,
    expect_datagram: ?[]const u8,
    /// What this run requires to read on the one bidirectional stream it owns:
    /// on a dialer its own request's stream, on a listener the requester's.
    expect_bi: ?[]const u8,
    /// The whole-scenario deadline, in milliseconds from the first pass.
    timeout_ms: u64,
    /// Answer an Initial with a Retry rather than accepting it. A listener's
    /// flag, because that is the end that answers.
    require_retry: bool,
    /// Where to tee the real datagrams, or null for no capture.
    capture: ?[]const u8,
};

/// What a command line turned out to be. A refusal is a value rather than an
/// error return so the program can print the reason and the flag list beside
/// it, and exit with the code the partner exits with for the same mistake.
pub const Outcome = union(enum) {
    help,
    run: Options,
    rejected: Rejection,
};

/// Read one command line into `Options`.
///
/// `usage` is where the flag list goes, and it is written on `--help` and on
/// every refusal: the caller that got a command line wrong is the one reading
/// this, and a reason with no list beside it is a reason with no fix.
pub fn parse(
    arena: std.mem.Allocator,
    args: []const [:0]const u8,
    usage: *std.Io.Writer,
) ParseError!Outcome {
    if (args.len == 0) return reject(usage, error.MissingMode);

    var mode: ?[]const u8 = null;
    var listen: ?SocketAddr = null;
    var dial_id: ?NodeId = null;
    var dial_addr: ?SocketAddr = null;
    var secret: ?SecretKey = null;
    var expect_remote: ?NodeId = null;
    var alpns: std.ArrayList([]const u8) = .empty;
    var send_bi: ?[]const u8 = null;
    var response_bi: ?[]const u8 = null;
    var send_uni: ?[]const u8 = null;
    var expect_uni: ?[]const u8 = null;
    var send_datagram: ?[]const u8 = null;
    var expect_datagram: ?[]const u8 = null;
    var expect_bi: ?[]const u8 = null;
    var timeout_ms: u64 = default_timeout_ms;
    var timeout_seen = false;
    var require_retry = false;
    var capture: ?[]const u8 = null;

    var index: usize = 1; // argv[0] is this program's own path.
    while (index < args.len) : (index += 1) {
        const flag = args[index];
        if (std.mem.eql(u8, flag, "-h") or std.mem.eql(u8, flag, "--help")) {
            try usage.writeAll(usage_text);
            return .help;
        }
        // The one flag that carries no value, so it is answered before the
        // value-taking dispatch asks for one it would consume as its own.
        if (std.mem.eql(u8, flag, "--require-retry")) {
            if (require_retry) return reject(usage, error.DuplicateFlag);
            require_retry = true;
            continue;
        }
        const value = takeValue(args, &index) catch |err| return reject(usage, err);
        if (std.mem.eql(u8, flag, "--mode")) {
            if (mode != null) return reject(usage, error.DuplicateFlag);
            mode = value;
        } else if (std.mem.eql(u8, flag, "--listen")) {
            if (listen != null) return reject(usage, error.DuplicateFlag);
            listen = parseSocketAddress(value) catch |err| return reject(usage, err);
        } else if (std.mem.eql(u8, flag, "--dial")) {
            if (dial_id != null) return reject(usage, error.DuplicateFlag);
            const target = parsePeer(value) catch |err| return reject(usage, err);
            dial_id = target.id;
            dial_addr = target.addr;
        } else if (std.mem.eql(u8, flag, "--secret-key")) {
            if (secret != null) return reject(usage, error.DuplicateFlag);
            secret = try decodeSecret(value);
        } else if (std.mem.eql(u8, flag, "--expect-remote")) {
            if (expect_remote != null) return reject(usage, error.DuplicateFlag);
            expect_remote = try decodeNodeId(value);
        } else if (std.mem.eql(u8, flag, "--alpn")) {
            try alpns.append(arena, value);
        } else if (std.mem.eql(u8, flag, "--send-bi")) {
            if (send_bi != null) return reject(usage, error.DuplicateFlag);
            send_bi = try decodePayload(arena, value);
        } else if (std.mem.eql(u8, flag, "--response-bi")) {
            if (response_bi != null) return reject(usage, error.DuplicateFlag);
            response_bi = try decodePayload(arena, value);
        } else if (std.mem.eql(u8, flag, "--expect-bi")) {
            if (expect_bi != null) return reject(usage, error.DuplicateFlag);
            expect_bi = try decodePayload(arena, value);
        } else if (std.mem.eql(u8, flag, "--send-uni")) {
            if (send_uni != null) return reject(usage, error.DuplicateFlag);
            send_uni = try decodePayload(arena, value);
        } else if (std.mem.eql(u8, flag, "--expect-uni")) {
            if (expect_uni != null) return reject(usage, error.DuplicateFlag);
            expect_uni = try decodePayload(arena, value);
        } else if (std.mem.eql(u8, flag, "--send-datagram")) {
            if (send_datagram != null) return reject(usage, error.DuplicateFlag);
            send_datagram = try decodePayload(arena, value);
        } else if (std.mem.eql(u8, flag, "--expect-datagram")) {
            if (expect_datagram != null) return reject(usage, error.DuplicateFlag);
            expect_datagram = try decodePayload(arena, value);
        } else if (std.mem.eql(u8, flag, "--timeout-ms")) {
            if (timeout_seen) return reject(usage, error.DuplicateFlag);
            timeout_seen = true;
            timeout_ms = std.fmt.parseInt(u64, value, 10) catch
                return reject(usage, error.TimeoutNotMilliseconds);
            if (timeout_ms == 0) return reject(usage, error.TimeoutNotMilliseconds);
        } else if (std.mem.eql(u8, flag, "--capture")) {
            if (capture != null) return reject(usage, error.DuplicateFlag);
            capture = value;
        } else {
            return reject(usage, error.UnknownFlag);
        }
    }

    const role = roleFrom(mode) catch |err| return reject(usage, err);
    const offered = try offeredAlpns(arena, alpns.items);
    if (offered.len > max_alpns) return reject(usage, error.TooManyAlpns);
    checkRoles(role, .{
        .listen = listen,
        .dial_id = dial_id,
        .send_bi = send_bi != null,
        .response_bi = response_bi != null,
        .expect_bi = expect_bi != null,
        .require_retry = require_retry,
        .pin = expect_remote,
        .dial_pin = dial_id,
    }) catch |err| return reject(usage, err);

    return .{ .run = .{
        .role = role,
        .listen = listen,
        .dial_id = dial_id,
        .dial_addr = dial_addr,
        .secret = secret,
        .expect_remote = expect_remote,
        .alpns = offered,
        .send_bi = send_bi,
        .response_bi = response_bi,
        .send_uni = send_uni,
        .expect_uni = expect_uni,
        .send_datagram = send_datagram,
        .expect_datagram = expect_datagram,
        .expect_bi = expect_bi,
        .timeout_ms = timeout_ms,
        .require_retry = require_retry,
        .capture = capture,
    } };
}

/// What the role rules are decided against: the flags, and nothing else. A
/// struct so a rule reads as a claim about named things rather than as a line
/// of positional arguments in a loop.
const RoleInput = struct {
    listen: ?SocketAddr,
    dial_id: ?NodeId,
    send_bi: bool,
    response_bi: bool,
    expect_bi: bool,
    require_retry: bool,
    pin: ?NodeId,
    dial_pin: ?NodeId,
};

/// Every rule that depends on which half this run is, in one place.
///
/// A dialer asks and a listener answers, so a payload flag belongs to one of
/// them and the other's use of it is a caller that has mixed up the two ends of
/// its own scenario. Collected here rather than written into the flag loop so
/// that the whole of "what is legal in which role" is one readable list, which
/// is the thing a caller comparing two command lines actually needs.
fn checkRoles(
    role: Role,
    input: RoleInput,
) Rejection!void {
    switch (role) {
        .listen => {
            if (input.listen == null) return error.ListenWithoutAddress;
            if (input.dial_id != null) return error.DialNeedsDialMode;
            if (input.send_bi) return error.SendBiNeedsDial;
        },
        .dial => {
            if (input.dial_id == null) return error.DialWithoutAddress;
            if (input.response_bi) return error.ResponseBiNeedsListen;
            if (input.expect_bi and !input.send_bi) {
                return error.ExpectBiNeedsSendBi;
            }
            if (input.require_retry) return error.RetryNeedsListen;
        },
    }
    if (input.send_bi and input.response_bi) {
        return error.BothBidirectionalFlags;
    }
    // Two pins that disagree are worse than one, so the second is refused
    // rather than quietly overwritten: a run that names two peers has not said
    // which one it meant to talk to.
    if (input.pin) |pin| {
        if (input.dial_pin) |asked| {
            if (pin.order(asked) != .eq) return error.PinDisagreesWithDial;
        }
    }
}

/// The one protocol list this run offers: what was named, or the partner's
/// default when nothing was.
fn offeredAlpns(
    arena: std.mem.Allocator,
    named: []const []const u8,
) std.mem.Allocator.Error![]const []const u8 {
    if (named.len != 0) return arena.dupe([]const u8, named);
    const one = try arena.alloc([]const u8, 1);
    one[0] = default_alpn;
    return one;
}

/// `--mode`'s word, as a role.
fn roleFrom(mode: ?[]const u8) Rejection!Role {
    const word = mode orelse return error.MissingMode;
    if (std.mem.eql(u8, word, "listen")) return .listen;
    if (std.mem.eql(u8, word, "dial")) return .dial;
    return error.UnknownMode;
}

/// The argument after a value-taking flag, and the step past it.
///
/// A flag at the end of the command line is `error.MissingValue` and not an
/// empty string, so a caller cannot discover the mistake by watching a parse
/// succeed against nothing.
fn takeValue(args: []const [:0]const u8, index: *usize) Rejection![]const u8 {
    if (index.* + 1 >= args.len) return error.MissingValue;
    index.* += 1;
    return args[index.*];
}

/// `<HEX64>@<ip:port>`: who to reach, and where.
const Peer = struct { id: NodeId, addr: SocketAddr };

fn parsePeer(text: []const u8) Rejection!Peer {
    const at = std.mem.indexOfScalar(u8, text, '@') orelse return error.DialWithoutPeer;
    return .{
        .id = try decodeNodeId(text[0..at]),
        .addr = try parseSocketAddress(text[at + 1 ..]),
    };
}

fn decodeNodeId(text: []const u8) Rejection!NodeId {
    if (text.len != NodeId.hex_length) return error.NodeIdNotHex;
    return NodeId.parseHex(text) catch return error.NodeIdNotHex;
}

fn decodeSecret(text: []const u8) (Rejection || ozai.KeyError)!SecretKey {
    if (text.len != SecretKey.seed_length * 2) return error.SecretKeyNotHex;
    // A local, not a payload. `fromSeed` copies the seed into the key it
    // returns and keeps nothing behind it, so these bytes are dead the moment
    // this returns — which is why they are a stack array rather than another
    // claim on the arena the payloads outlive.
    var raw: [SecretKey.seed_length]u8 = undefined;
    _ = std.fmt.hexToBytes(&raw, text) catch return error.SecretKeyNotHex;
    // The partner's `--secret-key` is 32 bytes of seed, and `fromSeed` is the
    // only constructor here that agrees with it: deriving the seed from the
    // full 64-byte encoding would make the two ends present different keys
    // from the same command line.
    return SecretKey.fromSeed(raw);
}

fn decodePayload(arena: std.mem.Allocator, text: []const u8) ParseError![]const u8 {
    if (text.len % 2 != 0) return error.OddHexLength;
    if (text.len / 2 > max_payload) return error.PayloadTooLong;
    const raw = try arena.alloc(u8, text.len / 2);
    _ = std.fmt.hexToBytes(raw, text) catch return error.NotHex;
    return raw;
}

fn parseSocketAddress(text: []const u8) Rejection!SocketAddr {
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse
        return error.AddressNotReachable;
    const port = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch
        return error.AddressNotReachable;
    var host = text[0..colon];
    // A v6 literal is bracketed, because a bare v6 literal's last colon is not
    // the one before the port.
    if (std.mem.startsWith(u8, host, "[") and std.mem.endsWith(u8, host, "]")) {
        host = host[1 .. host.len - 1];
    }
    return .{
        .ip = ozai.IpAddress.parse(host) orelse return error.AddressNotReachable,
        .port = port,
    };
}

/// Say what was wrong and print the flag list beside it.
fn reject(usage: *std.Io.Writer, err: Rejection) ParseError!Outcome {
    try usage.print("error: {t}\n", .{err});
    try usage.writeAll(usage_text);
    return .{ .rejected = err };
}

/// The flag list, and the grammar it describes.
///
/// A `--secret-key` of 32 bytes is the only way to fix an identity, and it is
/// the same fix on both ends: the partner derives the same node id from the
/// same 32 bytes, which is what lets a command line name the peer it expects
/// before that peer has been started.
const usage_text =
    \\
    \\ozai-interop-peer — one end of a live exchange with the Rust partner.
    \\
    \\  --mode listen|dial            which half of the exchange to run
    \\  --listen <ip:port>            bind here; required to listen, and pins
    \\                                the local port when dialling
    \\  --dial <HEX64>@<ip:port>      the peer to reach; required to dial
    \\  --secret-key <HEX64>          32 bytes of seed; drawn from the CSPRNG
    \\                                when absent
    \\  --expect-remote <HEX64>       the peer this run insists on; on a dialer
    \\                                it must agree with --dial
    \\  --alpn <name>                 repeatable, in preference order
    \\                                (default /ozai/1)
    \\  --send-bi <HEX>               the bidirectional request; a dialer
    \\  --expect-bi <HEX>             what must be read on this run's stream
    \\  --response-bi <HEX>           the bidirectional answer; a listener
    \\  --send-uni <HEX>              a unidirectional payload; either role
    \\  --expect-uni <HEX>            what must arrive unidirectionally
    \\  --send-datagram <HEX>         a DATAGRAM payload; either role
    \\  --expect-datagram <HEX>       what must arrive as a DATAGRAM
    \\  --require-retry               answer an Initial with a Retry; a
    \\                                listener's flag
    \\  --timeout-ms <n>              the whole-scenario deadline (default 30000)
    \\  --capture <dir>               tee the real datagrams and a manifest
    \\  -h, --help                    this text
    \\
    \\Every payload is lower- or upper-case hex and is compared byte for byte.
    \\
;
