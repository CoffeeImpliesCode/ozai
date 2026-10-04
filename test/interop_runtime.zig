//! The real UDP harness under one `ozai-interop-peer` run: a socket, a
//! `Bridge`, a `Dialer` for the half that asks, and the pass that moves
//! datagrams between them and the kernel.
//!
//! # What this is for, given `loopback_link.zig` exists
//!
//! `test/loopback_link.zig` proved the seam above `transport/socket.zig` fits
//! itself: two bridges, two sockets, one loopback interface. It did it with
//! **virtual time and two ends in one process**, which buys a great deal and
//! hides exactly the two things a partner on the other side of a kernel does
//! not share. Here there is one end, one socket, and a clock that moves on its
//! own, so a retransmission timer that expires is a timer that expired rather
//! than an instant this file chose to jump to, and a scenario that ends is a
//! scenario the peer finished rather than one both sides agreed to stop.
//!
//! # The pass, and why the drain comes before the wait
//!
//! One pass is: drain every connection to the socket, wait up to
//! `poll_interval_ms` for a datagram and hand it to the bridge, drain again,
//! then run the timers. **The first drain is not tidiness — it is what puts the
//! first Initial on the wire.** A dialled connection has been built but has
//! sent nothing until something drains it, so a loop that waited first would
//! sit on a socket nothing had ever written to and time out against a peer that
//! had not been spoken to. The second drain is for the same reason one pass
//! later: the datagram just handed to the bridge produced an acknowledgement,
//! and a core that owes an ACK should write it now rather than at the end of
//! the next wait.
//!
//! # The capture is a tee on this socket, taken before anything parses
//!
//! `--capture` writes every datagram this socket sends or receives to disk
//! verbatim, and a manifest beside it naming the role, the addresses, the
//! instant, the length and the long-header fields. **Nothing synthesises those
//! bytes and nothing edits them**: a datagram is read off the descriptor or
//! handed to `sendmsg` exactly as it went, and the copy is taken before
//! `Bridge.recv` is asked anything, because a decoder built from these files
//! has to be able to start where the wire did rather than where the core
//! happened to be when it looked.
//!
//! The manifest also carries the connection-id the Initial keys are derived
//! from, because getting that wrong is the single way a captured QUIC flight
//! fails to decode and the failure looks like a wire fault. It is the **client
//! flight's first Initial DCID** on both ends — not the connection id a server
//! packet happens to carry, which is the client's *source* id and derives
//! nothing — and a Retry replaces it with that Retry's source connection id
//! (RFC 9000 §17.2.5, RFC 9001 §5.2). `Capture` keeps that map as the flight
//! runs, so each record states the map as it stood when those bytes went out or
//! came in, and **the manifest is append-only: a row already written keeps the
//! value the map held then.** That is why a Retry costs the file nothing — the
//! client's original choice is still on the rows that precede it — and why a
//! second column for it would be the same fact twice.
//!
//! There is no TLS key log and no production hook: the ciphertext is captured
//! as ciphertext, which is what a wire vector is, and this file adds nothing
//! to the library to get it.
//!
//! # Teardown order is load-bearing
//!
//! A dialled connection's TLS handshake points at its dialer's own seed,
//! certificate chain and ALPN list, so `Dialer.destroy` refuses while one is
//! still in the bridge's table. `windDown` therefore walks the table
//! **backwards** — `removeConnection` swap-removes, and a forward walk skips an
//! entry and leaves a freed one behind — sweeps, frees the dialer, then the
//! bridge, then the socket. It is `loopback_link.zig`'s `closeDialed` with the
//! bridge and the socket added, and for the same reason.

const std = @import("std");
const ozai = @import("ozai");

const addr_map = ozai.addr_map;
const batch = ozai.transport_batch;
const bridge = ozai.transport_quic_bridge;
const conn_mod = ozai.transport_quic_conn;
const config_mod = ozai.transport_quic_config;
const error_mod = ozai.transport_quic_error;
// `dial_mod` rather than `dial`: `Peer.dial` below is a method of the same
// name, and a bare `dial` inside the struct would be ambiguous between them.
const dial_mod = ozai.transport_dial;
const socket_mod = ozai.transport_socket;

pub const Bridge = bridge.Bridge;
pub const Conn = conn_mod.Conn;
pub const Egress = conn_mod.Egress;
pub const Instant = conn_mod.Instant;
pub const Dialer = dial_mod.Dialer;
pub const NodeId = ozai.NodeId;
pub const SecretKey = ozai.SecretKey;
pub const SocketAddr = ozai.SocketAddr;
pub const TransportAddr = ozai.TransportAddr;

const MappedAddrs = addr_map.MappedAddrs;
const Socket = socket_mod.Socket;
const ControlBuffer = socket_mod.ControlBuffer;

/// A seeded generator's engine, kept beside every value handed out from it:
/// `std.Random` is an interface over a pointer to the engine, so the engine has
/// to outlive the bridge it seeds.
pub const Prng = std.Random.DefaultPrng;

/// The largest datagram a path is expected to carry, the same bound
/// `quic_bridge.zig` and `loopback_link.zig` use.
pub const max_datagram: usize = 1500;

/// How many socket writes one drain may hand back before the room is too
/// small. A whole flight fits; a caller that wants less learns it from
/// `error.NoRoom`.
pub const max_egress: usize = 8;

/// Room for every datagram one drain may produce.
pub const send_room: usize = max_egress * max_datagram;

/// The core's own buffer: `Bridge.recv` copies the datagram into its front and
/// writes a stateless reply behind it, which is its contract and the reason it
/// is twice a datagram.
pub const scratch_room: usize = 2 * max_datagram;

/// Room for the largest list the kernel may coalesce into one read. A receive
/// buffer too small for the largest list arrives at this seam as
/// `error.MessageTooLarge` rather than as a short datagram.
pub const receive_room: usize = @as(usize, max_datagram) * batch.max_gro_segments_linux;

/// How long one wait for a datagram may block, in milliseconds.
///
/// **A bound, not a delay.** A pass that gets nothing hands the loop back to
/// the timers, which is what a QUIC stack does between packets; what ends a run
/// is the scenario completing or the caller's deadline, never this number
/// elapsing.
pub const poll_interval_ms: i32 = 250;

/// The DATAGRAM transport parameter both ends advertise.
///
/// RFC 9221 §3, and the same value `test/loopback_datagram_test.zig` uses.
/// **It is on the bridge and on the dialer**, because support comes up only
/// when both ends advertise one (`connection.zig:3382`) and a datagram scenario
/// against a bridge alone would find the extension off for the whole
/// connection.
pub const datagram_frame_size: u64 = 65536;

/// The most bytes one connection id may be, so a captured header cannot make
/// the capture walk off a short datagram (RFC 9000 §17.2).
pub const max_connection_id: usize = 20;

/// Why the clock could not answer, which is the one refusal of this file's own
/// rather than the transport's.
pub const ClockError = error{
    /// The monotonic clock could not be read, or read a value `Instant` cannot
    /// hold.
    NoClock,
};

/// What the capture tee can be refused with: the directory and file seams plus
/// the writer the manifest lines are formatted through.
pub const CaptureError = std.Io.Dir.OpenError || std.Io.Dir.CreateDirPathError ||
    std.Io.File.OpenError || std.Io.File.Writer.Error ||
    std.mem.Allocator.Error || std.Io.Writer.Error;

/// Everything one run of this harness can be refused with: the two transports'
/// own sets, the allocator, the runtime's secure draw, the capture, and the
/// clock. Named as one set so a caller does not have to collect six.
pub const Error = config_mod.CreateError || error_mod.Error ||
    socket_mod.OpenError || socket_mod.SendError || socket_mod.ReceiveError ||
    dial_mod.Error || dial_mod.DestroyError ||
    std.mem.Allocator.Error || std.Io.RandomSecureError || ozai.KeyError ||
    CaptureError || ClockError;

/// Where the run binds. Port zero lets the kernel choose, so two runs on one
/// machine never collide and nothing has to be reconfigured when the last one
/// chose differently.
pub const loopback: SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 };

/// The monotonic clock as the core is driven at, in nanoseconds.
///
/// `Clock.awake` rather than `.real`, for `src/node/main.zig`'s reason: a QUIC
/// timer must not jump because NTP moved the wall clock. The transport reads
/// no clock at all, so this is the only place an instant comes from.
pub fn nowNs(io: std.Io) ClockError!Instant {
    const stamp = std.Io.Clock.awake.now(io);
    return std.math.cast(Instant, stamp.nanoseconds) orelse error.NoClock;
}

/// Which end of a datagram this run was looking at.
///
/// Named for what the tee can honestly claim about the bytes. In an
/// interoperability run the peer on the other end of the socket is the Rust
/// partner, so `peer-inbound` is that partner's output and `local-outbound` is
/// this project's; naming the *direction* rather than the language keeps the
/// column true for a run whose peer is anything else.
pub const Direction = enum {
    inbound,
    outbound,

    pub fn tag(self: Direction) []const u8 {
        return switch (self) {
            .inbound => "peer-inbound",
            .outbound => "local-outbound",
        };
    }
};

/// A QUIC long header, as far as a captured datagram can be read without
/// decrypting anything.
///
/// Only the fields that are in the clear before the payload are named: the
/// form, the type, the version and the two connection ids. A short header
/// carries none of them, which is why `form` is a value of its own and not a
/// boolean — "this was a short header" and "this was too short to say" are
/// different facts about a capture.
pub const Header = struct {
    /// Whether this is a long header, a short one, or a datagram too short to
    /// hold even a first byte.
    pub const Form = enum { long, short, truncated };
    /// The long-header type. `short` is the short header's only value: a short
    /// header carries no type.
    pub const Type = enum { initial, zero_rtt, handshake, retry, version_negotiation, short, truncated };
    pub const Value = union(enum) {
        long: Long,
        short: void,
        truncated: void,
    };
    pub const Long = struct {
        packet_type: Type,
        version: u32,
        dcid: []const u8,
        scid: []const u8,
    };

    value: Value,

    /// The header of one datagram, or `truncated` when the bytes do not hold
    /// one.
    ///
    /// Every length read here is checked against what is left before it is
    /// used, because the input is a datagram off a socket and the first thing
    /// that can be wrong about it is that it is not what was expected. A
    /// capture that stopped at the first surprise would lose exactly the
    /// datagram worth keeping.
    pub fn parse(bytes: []const u8) Header {
        if (bytes.len == 0) return .{ .value = .truncated };
        if (bytes[0] & 0x80 == 0) return .{ .value = .short };
        if (bytes.len < 6) return .{ .value = .truncated };
        const version = std.mem.readInt(u32, bytes[1..5], .big);
        const packet_type: Type = if (version == 0)
            .version_negotiation
        else switch (bytes[0] >> 4 & 0b11) {
            0b00 => .initial,
            0b01 => .zero_rtt,
            0b10 => .handshake,
            else => .retry,
        };
        const dcid_len = bytes[5];
        if (bytes.len < 6 + dcid_len + 1) return .{ .value = .truncated };
        const dcid = bytes[6 .. 6 + dcid_len];
        const scid_len = bytes[6 + dcid_len];
        if (bytes.len < 7 + dcid_len + scid_len) return .{ .value = .truncated };
        const scid = bytes[7 + dcid_len .. 7 + dcid_len + scid_len];
        return .{ .value = .{ .long = .{
            .packet_type = packet_type,
            .version = version,
            .dcid = dcid,
            .scid = scid,
        } } };
    }

    pub fn form(self: Header) Form {
        return switch (self.value) {
            .long => .long,
            .short => .short,
            .truncated => .truncated,
        };
    }
};

/// The verbatim record of everything one run's socket carried.
///
/// Two files: `wire.manifest`, which is one self-describing line per datagram,
/// and `datagrams/`, which is one file per datagram holding exactly the bytes
/// that went out or came in. One file per datagram rather than one stream
/// because these artifacts get promoted, reviewed and replayed individually,
/// and a length prefix in a header would be this file's invention sitting
/// between a reader and the wire.
pub const Capture = struct {
    io: std.Io,
    datagrams: std.Io.Dir,
    manifest: std.Io.File,
    /// The half of the exchange this run is, on every manifest line.
    role: []const u8,
    /// This run's own node id, on every manifest line, so a file promoted out
    /// of one machine says which end wrote it.
    node: [NodeId.hex_length]u8,
    records: u32 = 0,
    /// The connection id the Initial keys are derived from, as the flight
    /// stood. Null until the client flight's first Initial has been seen in
    /// either direction.
    initial_dcid: ?[max_connection_id]u8 = null,
    initial_dcid_len: u8 = 0,
    /// Set once a Retry has been seen, so the manifest can say whether the
    /// current `initial_dcid` is the client's original choice or the one a
    /// Retry replaced.
    retried: bool = false,

    pub const manifest_name = "wire.manifest";
    pub const datagram_directory = "datagrams";

    /// Open a capture under `path`, creating what is not there.
    pub fn open(
        io: std.Io,
        path: []const u8,
        role: []const u8,
        node: NodeId,
    ) CaptureError!Capture {
        try std.Io.Dir.cwd().createDirPath(io, path);
        // The `defer` on the next line closes this on the return below and on
        // every `try` that unwinds first; the engine does not follow a `defer`
        // to the scope exit it arms.
        // zwanzig-disable-next-line: store-violations-engine
        const root = try std.Io.Dir.cwd().openDir(io, path, .{});
        defer root.close(io);
        try root.createDirPath(io, datagram_directory);
        const datagrams = try root.openDir(io, datagram_directory, .{});
        errdefer datagrams.close(io);
        const manifest = try root.createFile(io, manifest_name, .{ .truncate = true });
        errdefer manifest.close(io);
        var self: Capture = .{
            .io = io,
            .datagrams = datagrams,
            .manifest = manifest,
            .role = role,
            .node = node.toHex(),
        };
        try self.manifest.writeStreamingAll(io, manifest_header);
        return self;
    }

    /// Record one datagram, verbatim, and the one manifest line describing it.
    ///
    /// `client` says which side of this connection wrote a first Initial, which
    /// is what decides whether an Initial this run carried is the one that set
    /// the key map. On the dialling end the client is this run; on the
    /// accepting end it is the peer.
    pub fn record(
        self: *Capture,
        direction: Direction,
        at: Instant,
        from: SocketAddr,
        local: SocketAddr,
        bytes: []const u8,
        client: bool,
    ) CaptureError!void {
        const sequence = self.records;
        self.records +%= 1;
        const header = Header.parse(bytes);
        self.noteInitialKeys(direction, header, client);

        var name_buffer: [datagram_directory.len + 32]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buffer, "{d:0>6}-{s}.bin", .{
            sequence,
            direction.tag(),
        }) catch return error.OutOfMemory;
        // The `defer` on the next line closes this datagram file on the append
        // below and on every `try` that unwinds first; the engine does not
        // follow a `defer` to the scope exit it arms.
        // zwanzig-disable-next-line: store-violations-engine
        const file = try self.datagrams.createFile(self.io, name, .{});
        defer file.close(self.io);
        try file.writeStreamingAll(self.io, bytes);

        var line: [2 * SocketAddr.max_text_length + 320]u8 = undefined;
        var out = std.Io.Writer.fixed(&line);
        try out.print("{d}\t{s}\t{s}\t{s}\t", .{ sequence, direction.tag(), self.role, self.node[0..] });
        try from.format(&out);
        try out.writeAll("\t");
        try local.format(&out);
        try out.print("\t{d}\t{d}\t", .{ at, bytes.len });
        try self.writeHeader(&out, header);
        try out.print("\t{s}\t{s}\n", .{ name, if (self.retried) "retried" else "initial" });
        try self.manifest.writeStreamingAll(self.io, out.buffered());
    }

    /// Note the connection id the Initial keys are derived from, as this
    /// datagram changes it.
    ///
    /// **The client's first Initial DCID, on both ends.** On the dialling side
    /// that is the DCID this run chose in the Initial it sent first; on the
    /// accepting side it is the DCID of the first Initial the peer sent. Neither
    /// is a server packet's DCID, which is the client's *source* id and derives
    /// no key. A Retry replaces it with that Retry's source connection id, which
    /// is what makes the client's next Initial decryptable at all.
    fn noteInitialKeys(
        self: *Capture,
        direction: Direction,
        header: Header,
        client: bool,
    ) void {
        const long = switch (header.value) {
            .long => |long| long,
            else => return,
        };
        // A Version Negotiation carries the same type bits as a 0-RTT and is
        // told apart by its zero version; it has no connection ids worth
        // mapping and would otherwise be read as a 0-RTT with no DCID.
        if (long.version == 0) return;
        if (long.packet_type == .retry) {
            if (long.scid.len == 0 or long.scid.len > max_connection_id) return;
            self.initial_dcid = [_]u8{0} ** max_connection_id;
            @memcpy(self.initial_dcid.?[0..long.scid.len], long.scid);
            self.initial_dcid_len = @intCast(long.scid.len);
            self.retried = true;
            return;
        }
        if (long.packet_type != .initial) return;
        if (long.dcid.len == 0 or long.dcid.len > max_connection_id) return;
        const ours = (direction == .outbound) == client;
        if (!ours) return;
        if (self.initial_dcid != null and !self.retried) return;
        self.initial_dcid = [_]u8{0} ** max_connection_id;
        @memcpy(self.initial_dcid.?[0..long.dcid.len], long.dcid);
        self.initial_dcid_len = @intCast(long.dcid.len);
    }

    /// The manifest's columns for one datagram's header, plus the key map as it
    /// stood — which is the column a decoder cannot reconstruct for itself
    /// after a Retry, and the reason this file keeps the map at all.
    fn writeHeader(self: *const Capture, out: *std.Io.Writer, header: Header) CaptureError!void {
        switch (header.value) {
            .short => try out.writeAll("short\t-\tshort\t-\t-\t-"),
            .truncated => try out.writeAll("truncated\t-\ttruncated\t-\t-\t-"),
            .long => |long| {
                try out.print(
                    "long\t{x:0>8}\t{s}\t",
                    .{ long.version, @tagName(long.packet_type) },
                );
                try writeId(out, long.dcid);
                try out.writeAll("\t");
                try writeId(out, long.scid);
                try out.writeAll("\t");
                try self.writeInitialDcid(out);
            },
        }
    }

    fn writeInitialDcid(self: *const Capture, out: *std.Io.Writer) CaptureError!void {
        const id = self.initial_dcid orelse return out.writeAll("-");
        return writeId(out, id[0..self.initial_dcid_len]);
    }

    /// The manifest's first line, so a file promoted on its own says what its
    /// columns are.
    fn close(self: *Capture) void {
        self.manifest.close(self.io);
        self.datagrams.close(self.io);
    }
};

/// One connection id as hex, or `-` for the zero-length id a client may
/// choose for its first Initial.
fn writeId(out: *std.Io.Writer, id: []const u8) CaptureError!void {
    if (id.len == 0) return out.writeAll("-");
    return out.print("{x}", .{id});
}

/// One datagram out of a `batch.Send`, which may hold several.
///
/// Cut here rather than recorded whole because a record has to be one datagram:
/// the manifest's `length` is then the number of bytes that were on the wire,
/// and a promoted file is replayable without knowing the run's segmentation.
fn datagramAt(send: batch.Send, index: usize) []const u8 {
    const size = send.segment_size orelse return send.contents;
    const start = index * @as(usize, size);
    if (start >= send.contents.len) return send.contents[start..start];
    return send.contents[start..@min(start + @as(usize, size), send.contents.len)];
}

/// What one run's socket and bridge did, in numbers a caller could not get any
/// other way.
///
/// Counted rather than inferred: a run that moved no traffic and a run whose
/// traffic was all refused read the same from any other source, and only the
/// counts say which happened.
pub const Stats = struct {
    datagrams_in: usize = 0,
    datagrams_out: usize = 0,
    /// Sends the socket could not segment and had to split.
    sends_degraded: usize = 0,
    /// Datagrams that went out without the codepoint the core asked for.
    ecn_lost: usize = 0,
    ingress_processed: usize = 0,
    ingress_dropped: usize = 0,
    ingress_foreign: usize = 0,
    /// Stateless replies: Retry, Version Negotiation, a stateless reset.
    replies: usize = 0,
    polls: usize = 0,
    /// Polls that ended because the wait expired rather than a datagram.
    timeouts: usize = 0,
    /// Connections the core declared finished.
    connections_finished: usize = 0,
};

/// What one end of the exchange is built with.
pub const Config = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    /// Where to bind.
    listen: SocketAddr,
    secret: SecretKey,
    /// The peer this run insists on before the handshake, or null to demand a
    /// certificate without pinning one.
    expect_peer: ?NodeId,
    /// The protocols to offer. Borrowed for the bridge's whole life, because
    /// that is what the core's TLS configuration points at.
    alpns: []const []const u8,
    /// How long a connection may sit idle. The run's own deadline is the
    /// scenario's; this is the transport's, and a scenario that outlives its
    /// deadline should not also be waiting for the core to notice.
    idle_timeout_ms: u64 = 30_000,
    /// Answer an Initial with a Retry rather than accepting it.
    require_retry: bool = false,
    retry_threshold: ?usize = null,
    /// How many peer-initiated unidirectional streams to admit, and the send
    /// window to grant on each. Both are named because a scenario that needs a
    /// unidirectional stream in each direction has to reach them, and a bound
    /// that is left at the core's default is a bound nothing measures.
    initial_max_streams_uni: ?u64 = null,
    initial_max_stream_data_uni: ?u64 = null,
    /// Where to tee the real datagrams, or null for no capture.
    capture_path: ?[]const u8 = null,
    /// The half of the exchange this run is, written onto every capture line.
    role: []const u8,
};

/// One end of the exchange: an identity, a socket, the bridge that runs its
/// connections, and the buffers both seams need.
///
/// The buffers are on the heap because the receive one is tens of kilobytes and
/// every one of them is the caller's by the seams' own contracts.
pub const Peer = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    socket: Socket,
    bridge: *Bridge,
    /// Set by `dial`, and freed by `windDown` before the bridge.
    dialer: ?*Dialer = null,
    map: MappedAddrs,
    engine: Prng,
    egress: []Egress,
    out: []u8,
    scratch: []u8,
    buf: []u8,
    control: ControlBuffer,
    capture: ?Capture = null,
    stats: Stats = .{},
    /// This run's own identity and offers, kept because the dialer is built
    /// later and needs both again. The ALPN slice is borrowed from the command
    /// line's arena and the seed is zeroed by `windDown`.
    secret: SecretKey,
    alpns: []const []const u8,
    idle_timeout_ms: u64,
    /// The unidirectional grants, kept beside the offers because the dialer is
    /// built later and needs the same two numbers the bridge was given.
    /// **On both, because a stream this end opens is paid for by the peer's
    /// limit and a stream the peer opens is paid for by this end's** — a grant
    /// on one side alone leaves the other half of the scenario refused for a
    /// reason that reads as a wire fault rather than as a missing limit.
    grant_streams_uni: ?u64,
    grant_stream_data_uni: ?u64,

    pub fn init(self: *Peer, config: Config) Error!void {
        self.* = .{
            .io = config.io,
            .gpa = config.gpa,
            .socket = undefined,
            .bridge = undefined,
            .map = MappedAddrs.init(),
            .engine = Prng.init(engineSeed(config.secret)),
            .egress = &.{},
            .out = &.{},
            .scratch = &.{},
            .buf = &.{},
            .control = undefined,
            .secret = config.secret,
            .alpns = config.alpns,
            .idle_timeout_ms = config.idle_timeout_ms,
            .grant_streams_uni = config.initial_max_streams_uni,
            .grant_stream_data_uni = config.initial_max_stream_data_uni,
        };
        errdefer self.map.deinit(config.gpa);
        // The bind happens inside `create`, so the address this end is
        // reachable at is only known once the socket exists. That is why the
        // banner is printed after `init` rather than before it.
        self.socket = try Socket.create(config.listen, .{});
        errdefer self.socket.close();
        if (config.capture_path) |path| {
            self.capture = try Capture.open(config.io, path, config.role, config.secret.nodeId());
            errdefer if (self.capture) |*capture| capture.close();
        }
        self.bridge = try Bridge.create(config.gpa, config.io, .{
            .secret = config.secret,
            .expect_peer = config.expect_peer,
            .alpns = config.alpns,
            .idle_timeout_ms = config.idle_timeout_ms,
            .max_datagram_frame_size = datagram_frame_size,
            .initial_max_streams_uni = config.initial_max_streams_uni,
            .initial_max_stream_data_uni = config.initial_max_stream_data_uni,
            .require_retry = config.require_retry,
            .retry_threshold = config.retry_threshold,
        }, self.random());
        errdefer self.bridge.destroy();
        self.egress = try config.gpa.alloc(Egress, max_egress);
        errdefer config.gpa.free(self.egress);
        self.out = try config.gpa.alloc(u8, send_room);
        errdefer config.gpa.free(self.out);
        self.scratch = try config.gpa.alloc(u8, scratch_room);
        errdefer config.gpa.free(self.scratch);
        self.buf = try config.gpa.alloc(u8, receive_room);
        errdefer config.gpa.free(self.buf);
    }

    /// Take the dialled connections out of the bridge, then free everything in
    /// the one order `Dialer.destroy` refuses to invert.
    ///
    /// **Released, not invalidated — `deinit` owns the poison.** Every handle
    /// in `self` is freed on both paths, the refusing one included, so a
    /// caller that reached past `deinit` would be holding a value whose
    /// handles are all gone. `deinit` is the entry that leaves the value
    /// unusable, and the only caller.
    ///
    /// `destroy` returns before it frees, so a refusal leaves the dialer
    /// allocated and the caller sees it in this error rather than in a leak
    /// trace with no reason attached. The walk below is what keeps that
    /// refusal from arising: it unlinks every entry a dialled handshake could
    /// still be borrowing and `sweep` frees them, so what is left in the
    /// table is a server entry this dialer never owned.
    pub fn windDown(self: *Peer) Error!void {
        var refusal: ?dial_mod.DestroyError = null;
        if (self.dialer) |dialer| {
            // Backwards, because `removeConnection` swap-removes and a forward
            // walk would skip an entry and leave a freed one behind.
            var index = self.bridge.manager.entries.items.len;
            while (index > 0) {
                index -= 1;
                const entry = self.bridge.manager.entries.items[index];
                if (!entry.conn.is_server) self.bridge.manager.removeConnection(entry);
            }
            self.bridge.sweep();
            dialer.destroy() catch |err| {
                refusal = err;
            };
            self.dialer = null;
        }
        self.bridge.destroy();
        if (self.capture) |*capture| capture.close();
        self.capture = null;
        self.secret.deinit();
        self.gpa.free(self.buf);
        self.gpa.free(self.scratch);
        self.gpa.free(self.out);
        self.gpa.free(self.egress);
        self.map.deinit(self.gpa);
        self.socket.close();
        if (refusal) |err| return err;
    }

    /// Wind down and say what could not be released, on a path that has no
    /// caller to return it to.
    pub fn deinit(self: *Peer) void {
        self.windDown() catch |err| std.log.err(
            "interop peer teardown: the dialer was not freed: {t}",
            .{err},
        );
        // The poison belongs to the function the type names rather than to
        // `windDown`, so the guarantee that everything is released exactly
        // once is stated where it is asked for: a second `deinit` reads
        // released bytes instead of releasing them again.
        self.* = undefined;
    }

    /// A generator over this end's own engine, good until the next call.
    pub fn random(self: *Peer) std.Random {
        return self.engine.random();
    }

    /// Open a pinned connection to `target` and take the dialer with it.
    ///
    /// `expect` is both the pin and the address map's key: a dial that names a
    /// peer whose certificate does not carry those bytes does not reach
    /// `established`, which is how a wrong pin fails without a refusal being
    /// invented for it.
    pub fn dial(
        self: *Peer,
        target: TransportAddr,
        expect: ?NodeId,
        at: Instant,
    ) Error!Conn {
        // Both ends must advertise the DATAGRAM parameter and both must grant
        // unidirectional streams, or the scenario that needs them is refused
        // for a reason that reads as a wire fault rather than as a missing
        // grant.
        self.dialer = try Dialer.create(self.gpa, self.bridge, .{
            .secret = self.secret,
            .alpns = self.alpns,
            .idle_timeout_ms = self.idle_timeout_ms,
            .max_datagram_frame_size = datagram_frame_size,
            .initial_max_streams_uni = self.grant_streams_uni,
            .initial_max_stream_data_uni = self.grant_stream_data_uni,
        });
        return (try self.dialer.?.dial(
            target,
            expect,
            self.socket.address,
            &self.map,
            at,
            self.random(),
        )).conn;
    }

    /// One pass: drain, wait, drain again, then the timers.
    ///
    /// The reason for the two drains is the module doc's. `wait_ms` bounds only
    /// the wait; a pass that gets nothing returns normally, because a quiet
    /// socket is a fact the scenario acts on and not a fault.
    pub fn pass(self: *Peer, at: Instant, wait_ms: i32) Error!void {
        try self.drain(at);
        try self.take(at, wait_ms);
        try self.drain(at);
        self.tick(at);
    }

    /// Everything the core wants sent at `at`, out of this end's socket.
    pub fn drain(self: *Peer, at: Instant) Error!void {
        // Found by index and never by a remembered handle: `sweep` frees an
        // entry the core has declared finished, so a handle kept across a pass
        // would read freed memory.
        var index: usize = 0;
        while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
            for (try conn.drain(self.egress, self.out, at, self.random())) |egress| {
                const report = try self.socket.send(self.io, egress.to, egress.send);
                // The report is read, not dropped: a codepoint that did not
                // survive and a send the socket had to split are both facts
                // about what left this machine, and `_ = try` would throw away
                // the only place they are said.
                var position: usize = 0;
                while (position < egress.send.datagramCount()) : (position += 1) {
                    try self.record(at, .outbound, egress.to, datagramAt(egress.send, position), report);
                }
            }
        }
    }

    /// Wait for a datagram and hand everything the read carried to the bridge.
    pub fn take(self: *Peer, at: Instant, wait_ms: i32) Error!void {
        const got = self.socket.receive(self.io, self.buf, &self.control, wait_ms) catch |err| switch (err) {
            // The wait expired with nothing to read. The core's timers are what
            // the drain after this is for, so a pass ending here has still done
            // its work.
            error.WouldBlock => {
                self.stats.polls += 1;
                self.stats.timeouts += 1;
                return;
            },
            // A stop raised by `requestStop`, forwarded rather than absorbed:
            // the caller's loop has to know it was signalled.
            error.Canceled => return error.Canceled,
            else => |other| return other,
        };
        self.stats.polls += 1;
        const recv = try got.toRecv();
        self.stats.datagrams_in += recv.datagramCount();
        var position: usize = 0;
        while (position < recv.datagramCount()) : (position += 1) {
            // zwanzig-disable-next-line: optional-unwrap
            const bytes = recv.datagram(position).?;
            // **Before the bridge is asked anything.** `Bridge.recv` copies the
            // datagram into its own scratch and decrypts there, but the point
            // is not where it decrypts: a capture taken afterwards would be a
            // capture of whatever the core happened to be looking at, and a
            // decoder built from it would start somewhere the wire never was.
            try self.record(at, .inbound, got.from, bytes, null);
            const ingress = try self.bridge.recv(&self.map, .{
                .bytes = bytes,
                .from = got.from,
                .local = self.socket.address,
                .ecn = recv.ecn,
            }, self.scratch, at, self.random());
            switch (ingress.outcome) {
                // Nothing to do here: whatever this datagram produced is
                // drained by the pass's next drain, which finds the connection
                // by index.
                .processed => self.stats.ingress_processed += 1,
                .dropped => self.stats.ingress_dropped += 1,
                .foreign => self.stats.ingress_foreign += 1,
                // A stateless reply is a send, so it goes back out of the same
                // socket to the address the datagram came from.
                .reply => |reply| {
                    self.stats.replies += 1;
                    const report = try self.socket.send(self.io, ingress.source.socket, reply);
                    try self.record(at, .outbound, ingress.source.socket, reply.contents, report);
                },
            }
        }
    }

    /// Run every connection's timers, then free what the core declared finished.
    fn tick(self: *Peer, at: Instant) void {
        // Timers after the sends, so a connection that owes a retransmission
        // gets the chance to produce one in this pass rather than the next.
        var index: usize = 0;
        while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
            if (self.bridge.tick(conn, at, self.random()) == .finished) {
                self.stats.connections_finished += 1;
            }
        }
        self.bridge.sweep();
    }

    /// One datagram written to the capture, and this run's counters, when a
    /// capture is open.
    ///
    /// A send is counted once per `sendmsg` and recorded once per datagram, so
    /// a segmented flight does not read as one datagram that was several, and
    /// the two numbers are not silently the same thing.
    fn record(
        self: *Peer,
        at: Instant,
        direction: Direction,
        peer: SocketAddr,
        bytes: []const u8,
        report: ?batch.Report,
    ) Error!void {
        if (report) |sent| {
            self.stats.datagrams_out += 1;
            if (sent.degraded) self.stats.sends_degraded += 1;
            if (!sent.ecnSurvived()) self.stats.ecn_lost += 1;
        }
        if (self.capture) |*capture| {
            // This end is the client of the connection it opened and not the
            // client of the one it accepted, and which is which is what decides
            // whose first Initial sets the key map.
            try capture.record(direction, at, peer, self.socket.address, bytes, self.dialer != null);
        }
    }

    /// The established connection to exchange bytes on, or null.
    ///
    /// `dialled` names which end of this process the connection belongs to, so
    /// an end that accepts while it also dialled cannot mistake a peer's
    /// connection for its own.
    pub fn liveConn(self: *const Peer, dialled: bool) ?Conn {
        var index: usize = 0;
        while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
            if (conn.entry.conn.is_server != dialled and conn.established()) return conn;
        }
        return null;
    }

    /// Ask a pass's wait to end early.
    ///
    /// `Socket.stop` raises the wake a blocked `receive` polls for, so a
    /// supervisor's signal is acted on at the next pass rather than at the next
    /// datagram.
    pub fn requestStop(self: *Peer) void {
        self.socket.stop();
    }
};

/// The node id the peer's certificate carried, read off the handshake rather
/// than off the pin.
///
/// **Two different facts, and only this one is an observation.** The pin says
/// what was asked for; this says what the peer proved, and the two are equal
/// because the core compared them — a mismatch ended the handshake before it
/// completed (`tls13.zig`'s `peerNodeId`). So a report built from this is a
/// report about the peer, and a report built from the pin would only be
/// repeating what the caller already knew.
///
/// Null is a value and not a fault: it is what a connection with no
/// certificate to read answers, which is a peer that presented none rather than
/// a peer whose id is unknown.
pub fn authenticatedPeerId(conn: Conn) ozai.KeyError!?NodeId {
    const handshake = conn.entry.conn.tls13_hs orelse return null;
    const raw = handshake.peerNodeId() orelse return null;
    const node_id = try NodeId.fromBytes(raw);
    return node_id;
}

/// The protocol the handshake settled on, or the empty slice when it has not.
///
/// Read off the connection the core is running, which is `node.zig`'s own read
/// rather than a second opinion: the core negotiated one of the offered names
/// and this is where its answer lives.
pub fn negotiatedAlpn(conn: Conn) []const u8 {
    return conn.entry.conn.negotiatedAlpn();
}

/// This end's generator seed, derived from its own identity.
///
/// **Not a global and not a constant.** The core is seeded once per bridge, and
/// a fixed seed would make two runs of the same scenario share connection ids
/// and packet numbers — so a failure that moves would be a failure that depends
/// on what ran before it. Deriving it from the secret key gives every identity
/// its own engine and the same identity the same engine, which is what makes
/// `--secret-key` reproducible without making the wire identical.
fn engineSeed(secret: SecretKey) u64 {
    const encoded = secret.toBytes();
    return std.hash.Wyhash.hash(0, &encoded);
}

/// The manifest's own header, written when the capture opens.
///
/// Every column named, in order, so a file promoted out of one machine and read
/// on another says what its fields are without this file alongside it.
const manifest_header =
    \\# ozai-interop-peer wire capture
    \\# columns: sequence  direction  role  node  from  local  at_ns  length
    \\#          form  version  type  dcid  scid  initial_dcid  file  keys
    \\# direction: peer-inbound is what the peer emitted; local-outbound is what
    \\#            this run wrote. `form` is long, short, or truncated.
    \\# version and the connection ids are hex, or - where the header carries
    \\# none. `initial_dcid` is the connection id the QUIC Initial keys are
    \\# derived from as this datagram went out or came in (RFC 9001 5.2): the
    \\# client flight's first Initial DCID, replaced by a Retry's source
    \\# connection id, and `keys` says which of those the current value is.
    \\
;
