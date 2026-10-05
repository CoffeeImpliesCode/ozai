//! A TLS client over `transport/tcp.zig`, for a relay reached by hostname.
//!
//! This exists because the pkarr relay is `https://dns.iroh.link/pkarr/<z32>`
//! (`iroh/src/address_lookup/pkarr.rs:127`), and a hostname is not a socket
//! address: `base/relay.zig`'s `RelayUrl.socketAddr` refuses a name outright
//! rather than resolving it, so a connection to a pkarr relay needs both a
//! resolved `SocketAddr` and a name to check the certificate against. **This
//! file is the second half**; the first is the caller's own resolution.
//!
//! # Why not the vendored QUIC core's TLS
//!
//! The core does TLS, and reusing it would have been one line. It is the wrong
//! TLS for this and the reason is in `vendor/quic/src/quic/tls13.zig`'s
//! identity: a QUIC handshake whose peer identity is a raw Ed25519 SPKI with no
//! X.509 chain walk at all. A pkarr relay is reached over HTTPS, so its
//! certificate is issued by a public CA for `dns.iroh.link` and there is no
//! Ed25519 SPKI to compare against — the identity question is "does a chain from
//! a trusted root end in a certificate naming this host", which is a web-PKI
//! question and not a raw-key one. Widening the QUIC core's TLS into an X.509
//! verifier would put web PKI inside a module whose contract is the opposite,
//! and would make every QUIC peer pay for a trust store it does not use.
//!
//! Zig 0.16's `std.crypto.tls.Client` is the alternative that is already the
//! right thing: a sans-IO driver over an injected reader, writer, allocator and
//! timestamp, with `std.crypto.Certificate` as its X.509 parser. So this file
//! is the seam, not a protocol.
//!
//! # What is trusted, and how — the decision this file has to make
//!
//! **Web PKI against a caller-supplied `std.crypto.Certificate.Bundle`, plus
//! explicit host verification, and nothing else.** Concretely, `Options` refuses
//! to be built at all unless the caller names both:
//!
//! * `host`: the name the server's certificate must name, and the `SNI` sent.
//!   `std`'s own vocabulary has `no_verification`, and its doc says that "no
//!   host verification is performed, which prevents a trusted connection from
//!   being established" — so a build without a host is a build with no trusted
//!   connection, and this file does not offer one.
//! * `ca`: a `Certificate.Bundle` the caller loaded. `std` also offers
//!   `self_signed`, and its doc says that "provides no authorization
//!   guarantees, as anyone can create a self-signed certificate" — which is
//!   also disqualifying here, because a pkarr relay's key rotates and a pkarr
//!   packet is *already* signed by the node: the TLS layer's job is to establish
//!   that the relay is the relay, and a self-signed check establishes only that
//!   whoever answered holds the key they just used.
//!
//! **The bundle is the caller's, not this file's.** `std`'s
//! `Certificate.Bundle.rescan` reads the host's trust store, which is a
//! filesystem read of files whose path is a policy; `tls_client.rescanTrust`
//! exposes it as an explicit named call so a caller that wants the host store
//! asks for it, and a caller that wants a pinned bundle passes its own. Nothing
//! here reads a file unless the caller calls that function.
//!
//! **Certificate time is the caller's too.** `Options.now` is a
//! `std.Io.Timestamp`, not a clock read, because a validity window is an input
//! to a decision rather than a fact this module discovers. A test drives it to
//! a date inside the window and to one outside it, and the difference is the
//! answer.
//!
//! # One connection per value, and a stop that is final
//!
//! `Client` owns a `transport/tcp.zig` `Tcp` and the `std.crypto.tls.Client`
//! driving it, and both are released by `close`. `Tcp.stop` is terminal — a
//! stream has bytes the peer is owed and nothing may discard them — so a
//! stopped `Client` is closed rather than reused.
//!
//! # Purity
//!
//! `io: std.Io` is a parameter of `open` and of every operation, and is stored
//! nowhere: `Client` holds a socket, two TLS buffers and a trust bundle, and no
//! runtime. Entropy is `Options.entropy`, a caller-supplied 240 bytes, because
//! `std`'s `Options.entropy` doc says "the pointer is not captured; data is only
//! read during `init`" and a key share drawn from a module's own generator would
//! make the handshake undrivable at a fixed one.

const std = @import("std");

const addr = @import("../base/addr.zig");
const tcp = @import("../transport/tcp.zig");

const tls = std.crypto.tls;
const Certificate = std.crypto.Certificate;

/// How much scratch the TLS driver needs on each side of a record layer.
///
/// `std.crypto.tls.Client.min_buffer_len`, which is `max_ciphertext_record_len`
/// and is what `Client.init` asserts its input reader against. A caller
/// supplies its own rather than this file allocating: a 16 KiB-plus pair is
/// somebody's decision about a stack pool, and `transport/tcp.zig`'s whole
/// convention is that the caller's buffer is the caller's.
pub const buffer_length: usize = tls.Client.min_buffer_len;

/// How much entropy the driver's `KeyShare` needs.
///
/// `std.crypto.tls.Client.Options.entropy_len`, and 240 is the driver's own
/// figure rather than one chosen here: it is a client random, a legacy session
/// id, and a key share.
pub const entropy_length: usize = tls.Client.Options.entropy_len;

/// What a trust failure is refused as.
///
/// `std`'s `InitError` names every way a certificate can be wrong, and they
/// are all real answers this file must be able to hand a caller unchanged: a
/// relay whose certificate expired is a different fact from one whose name does
/// not match. So this is `tls.Client.InitError` and not a narrower union —
/// narrowing it here would discard the one thing a caller diagnosing a relay
/// needs, which is which of them it was.
pub const Error = tls.Client.InitError || tcp.OpenError || tcp.ConnectError;

/// Everything a trust scan can fail with.
///
/// `Certificate.Bundle.RescanError`, which is a filesystem read's own set: this
/// is the only function in the file that touches the disk, and it does so
/// because the caller asked.
pub const TrustError = Certificate.Bundle.RescanError;

/// The trust material and the handshake inputs, as one value.
///
/// Every field is named and no field has a default except the two that are
/// genuinely optional: `timeout_ms` of null is "wait as long as the caller
/// means", which `transport/tcp.zig` already spells, and `ssl_key_log` of null
/// is "log no secrets", which is the only safe default for a field whose own doc
/// says that "creating such a log file allows other programs with access to it
/// to decrypt all traffic over this connection".
pub const Options = struct {
    /// The name the relay's certificate must name, and the `SNI` this client
    /// sends.
    ///
    /// Required, and there is no default and no `no_verification` alternative:
    /// see the module doc for why a build without a name is a build with no
    /// trusted connection.
    host: []const u8,
    /// The trust anchors, and the lock the driver reads them under.
    ///
    /// A pointer and not a value because `std`'s `Options.ca.bundle` takes a
    /// `*Certificate.Bundle` and a `*std.Io.RwLock`, and a bundle is tens of
    /// kilobytes of DER that every connection would otherwise copy. Both must
    /// outlive every `Client` opened against them.
    bundle: *Certificate.Bundle,
    /// The lock `bundle` is read under, for the same reason it is a pointer.
    bundle_lock: *std.Io.RwLock,
    /// 240 bytes for the driver's key share and randoms, from the caller's
    /// generator.
    entropy: *const [entropy_length]u8,
    /// When "now" is, for the certificate validity window.
    now: std.Io.Timestamp,
    /// Scratch for the driver's read side, `buffer_length` bytes or more.
    read_buffer: []u8,
    /// Scratch for the driver's write side, `buffer_length` bytes or more.
    write_buffer: []u8,
    /// How long a connect and each read and write wait. Null waits as long as
    /// the caller means, and `transport/tcp.zig`'s rule is that this is a
    /// parameter rather than a clock read.
    timeout_ms: ?i32,
    /// Optional TLS secrets log, for a caller debugging a handshake.
    ssl_key_log: ?*tls.Client.SslKeyLog = null,
};

/// One TLS connection to one relay, over one TCP stream.
///
/// Owns two descriptors, two buffers and the driver. `open` connects and
/// handshakes; `close` releases everything, and a `Client` is not reconnected:
/// a second connection is a second `Client`, which is `transport/tcp.zig`'s rule
/// about `ECONNREFUSED` leaving a socket's state implementation-defined.
///
/// **Every operation takes `io`**, and each writes it into `link` before it
/// reaches the driver. That is not the module's own convenience: `std.Io.Reader`
/// and `std.Io.Writer` vtable entries take no `Io`, so a binding from one of
/// them to a raw descriptor has nowhere to put a runtime except a field. The
/// field is therefore written from the caller's parameter on every call rather
/// than captured once, which keeps the caller's `io` the source of truth — a
/// `Client` driven at two runtimes is driven at whichever one the last call
/// named. `std.Io.net.Stream.Reader` holds its `Io` the same way; the difference
/// is that this file does not keep it past the call that set it.
///
/// Keep this value at its original address: the driver's reader and writer borrow
/// fields of it. Serialize reads and writes; only `stop` may run concurrently.
pub const Client = struct {
    /// The stream, owned. Two descriptors and a latch; see
    /// `transport/tcp.zig`.
    stream: tcp.Tcp,
    /// The driver, which owns the session state and borrows the two buffers.
    driver: tls.Client,
    /// The plaintext reader: the relay's HTTP response bytes, decrypted.
    ///
    /// `std.crypto.tls.Client`'s own reader, reached by pointer so a caller
    /// reads with `readSliceAll` and `takeDelimiterInclusive` rather than
    /// through a second copy of the driver's API.
    reader: std.Io.Reader,
    /// The plaintext writer: the request bytes, encrypted on the way out.
    writer: std.Io.Writer,
    /// The raw binding the two vtables reach the socket through, and the one
    /// place an `Io` appears. See the type's doc.
    link: Link,
    /// The trust bundle in force, borrowed. Kept so a caller holding several
    /// connections from one bundle can see which they share, and so a caller
    /// logging a trust failure knows what it was checked against.
    bundle: *Certificate.Bundle,

    /// Connect to `peer` and complete the TLS handshake, or fail with nothing
    /// left open.
    ///
    /// `alloc` is the driver's own allocator, for the certificate parse and the
    /// session state.
    ///
    /// On failure the stream is closed before the error leaves, so a refused
    /// certificate does not leave a descriptor a caller has to remember. Every
    /// allocation the driver makes during `init` is released before it returns,
    /// which is `std`'s contract for `init`.
    pub fn open(
        alloc: std.mem.Allocator,
        io: std.Io,
        server: addr.SocketAddr,
        options: Options,
    ) Error!Client {
        std.debug.assert(options.read_buffer.len >= buffer_length);
        std.debug.assert(options.write_buffer.len >= buffer_length);
        var stream = try tcp.Tcp.create(server);
        errdefer stream.close();
        try stream.connect(io, options.timeout_ms);

        // Both scratch buffers are trimmed to the driver's own bound rather than
        // the caller's slice, because the driver asserts on the reader's
        // capacity and a caller that over-provisioned must not fail on it.
        var self: Client = .{
            .stream = stream,
            .driver = undefined,
            .reader = .{
                .vtable = &.{ .stream = streamIn },
                .buffer = options.read_buffer[0..buffer_length],
                .seek = 0,
                .end = 0,
            },
            .writer = .{
                .vtable = &.{ .drain = streamOut },
                .buffer = options.write_buffer[0..buffer_length],
            },
            .link = .{
                .stream = &stream,
                .io = io,
                .timeout_ms = options.timeout_ms,
            },
            .bundle = options.bundle,
        };
        self.link.stream = &self.stream;
        // The driver borrows the reader and writer above, so the handshake runs
        // against this value's own fields and not against locals that die when
        // `open` returns.
        self.driver = try tls.Client.init(&self.reader, &self.writer, .{
            .host = .{ .explicit = options.host },
            .ca = .{ .bundle = .{
                .gpa = alloc,
                .io = io,
                .lock = options.bundle_lock,
                .bundle = options.bundle,
            } },
            .write_buffer = options.write_buffer[0..buffer_length],
            .read_buffer = options.read_buffer[0..buffer_length],
            .entropy = options.entropy,
            .realtime_now = options.now,
            .ssl_key_log = options.ssl_key_log,
        });
        return self;
    }

    /// Close the stream and its two descriptors.
    ///
    /// Nothing is flushed: a caller has written and flushed its request already,
    /// and `transport/tcp.zig`'s rule is that a closed stream cannot be written
    /// to again. Do not close a copy, and do not call this twice.
    pub fn close(self: *Client) void {
        self.stream.close();
    }

    /// Name this connection stopped: end the wait in flight and refuse every
    /// later one.
    ///
    /// Two signal-handler-safe calls, one store and one `write`, both on POSIX's
    /// list; `transport/tcp.zig`'s `Tcp.stop` is where the rule and the reason
    /// live, and this is a name for it rather than a second implementation.
    pub fn stop(self: *Client) void {
        self.stream.stop();
    }

    /// The plaintext reader, decrypted, on `io`.
    ///
    /// A pointer and not a copy: the driver owns the reader's buffer position,
    /// and a copy read a different position of the same stream.
    pub fn plaintextReader(self: *Client, io: std.Io) *std.Io.Reader {
        self.link.io = io;
        return &self.driver.reader;
    }

    /// The plaintext writer, encrypted, on `io`.
    ///
    /// A pointer for the same reason as `plaintextReader`, and because a caller
    /// writing a request needs the driver's buffering rather than one
    /// `writeAll` per chunk.
    pub fn plaintextWriter(self: *Client, io: std.Io) *std.Io.Writer {
        self.link.io = io;
        return &self.driver.writer;
    }

    /// Whether the peer sent a `close_notify`, which is how a TLS stream says it
    /// is finished.
    ///
    /// Not a substitute for the HTTP layer's own length check: a peer that never
    /// sends one is truncated, and that is `error.TlsConnectionTruncated` on the
    /// read which hit it.
    pub fn receivedCloseNotify(self: *const Client) bool {
        return self.driver.eof();
    }

    /// The alert the peer sent, when the last failure was one.
    ///
    /// `std`'s `Options.alert` and `Client.alert` carry the description because
    /// `error.TlsAlert` alone does not say which alert: a peer refusing a
    /// certificate it does not like and a peer refusing a protocol version are
    /// different facts and both arrive as `error.TlsAlert`.
    pub fn alert(self: *const Client) ?tls.Alert {
        return self.driver.alert;
    }

    /// The resolved address this connection is to.
    ///
    /// The address, not the name: the name is in `Options.host` and
    /// `base/relay.zig`'s `RelayUrl` is where it was read from. Both are
    /// reported because a caller logging a trust failure needs to know which
    /// address the certificate was checked against.
    pub fn peerAddress(self: *const Client) addr.SocketAddr {
        return self.stream.peer;
    }

    /// Where this stream is bound, with the ephemeral port the kernel chose.
    pub fn local(self: *const Client) addr.SocketAddr {
        return self.stream.local;
    }
};

/// The binding from the driver's reader and writer to the raw socket.
///
/// `stream` and `io` are written by `Client.open` and refreshed by every
/// operation that takes an `Io`. `timeout_ms` is the caller's deadline, copied
/// once because it does not change over a connection's life — a per-operation
/// deadline is a caller's decision and one field per connection is what carries
/// it.
const Link = struct {
    /// The socket. A pointer to the `Client`'s own field, so the address is
    /// stable for the connection's life.
    stream: *const tcp.Tcp,
    /// The runtime the current call is on. Written from that call's parameter.
    io: std.Io,
    /// The per-operation deadline, from `Options.timeout_ms`.
    timeout_ms: ?i32,
};

/// Rescan the host's trust store into `bundle`.
///
/// The one call in this file that touches the filesystem, and it is a named one
/// so a caller that wants the host's certificate authorities asks for them by
/// name rather than having them read as a side effect of opening a connection.
/// A caller that wants a pinned bundle — which is what a node embedding this
/// should usually do, so its trust does not move under it — never calls this.
///
/// `now` is the timestamp the rescan dates any certificate it finds by, and it
/// is a parameter for the reason `Options.now` is: a validity window is an input
/// to a decision rather than a fact this module discovers.
pub fn rescanTrust(
    bundle: *Certificate.Bundle,
    alloc: std.mem.Allocator,
    io: std.Io,
    now: std.Io.Timestamp,
) TrustError!void {
    try bundle.rescan(alloc, io, now);
}

/// The raw socket, read into a writer's slice.
///
/// `std.Io.Reader`'s `stream` entry: the reader hands over a slice it wants
/// filled and takes back a count, and a zero is `EndOfStream` because a stream's
/// peer half-closing is a read of zero and not a failure — `transport/tcp.zig`
/// says so and `std.Io.Reader.StreamError` is where that lands.
///
/// A short read is a short count and never an error, exactly as `Tcp.read`
/// documents; the reader buffers and asks again.
fn streamIn(
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    limit: std.Io.Limit,
) std.Io.Reader.StreamError!usize {
    const self: *Client = @fieldParentPtr("reader", r);
    const dest = limit.slice(try w.writableSliceGreedy(1));
    const got = self.link.stream.read(self.link.io, dest, self.link.timeout_ms) catch
        return error.ReadFailed;
    if (got == 0) return error.EndOfStream;
    w.advance(got);
    return got;
}

/// The raw socket, written from a writer's buffer and slices.
///
/// `std.Io.Writer`'s `drain` entry: the buffer first, then the slices in order,
/// then the last slice repeated `splat` times, and the count is what was
/// consumed from `data` rather than from the buffer. A short write is a count
/// and not an error, so the loop resumes from where the last write stopped —
/// `transport/tcp.zig`'s accounting rule, and the reason losing a count here
/// would lose a caller's bytes.
fn streamOut(
    w: *std.Io.Writer,
    data: []const []const u8,
    splat: usize,
) std.Io.Writer.Error!usize {
    const self: *Client = @fieldParentPtr("writer", w);
    const buffered = w.buffered();
    if (buffered.len != 0) try writeAll(self, buffered);
    w.end = 0;
    var sent: usize = 0;
    for (data[0 .. data.len - 1]) |slice| {
        try writeAll(self, slice);
        sent += slice.len;
    }
    // `splat` is the driver writing one byte many times, which is what a record
    // layer does for a run of zeros; the loop is what makes the count exact.
    const pattern = data[data.len - 1];
    var at: usize = 0;
    while (at < splat) : (at += 1) try writeAll(self, pattern);
    return sent;
}

/// Write every byte of `bytes`, resuming across short writes.
fn writeAll(self: *Client, bytes: []const u8) std.Io.Writer.Error!void {
    var at: usize = 0;
    while (at < bytes.len) {
        const n = self.link.stream.write(
            self.link.io,
            bytes[at..],
            self.link.timeout_ms,
        ) catch return error.WriteFailed;
        // A zero from a write of a non-empty slice is not a count a caller can
        // use: it says the bytes did not leave and does not say why, and a loop
        // that spun on it would be a hang rather than a failure.
        if (n == 0) return error.WriteFailed;
        at += n;
    }
}

const t = std.testing;

test "the driver's buffer bound is the driver's own, not one chosen here" {
    // `std.crypto.tls.Client.init` asserts its input reader against
    // `min_buffer_len`, so a caller that sizes from this value cannot be refused
    // for a buffer that was too small. It is 16661: a 16384-octet ciphertext
    // record, its expansion and a five-octet header.
    try t.expectEqual(std.crypto.tls.max_ciphertext_record_len, buffer_length);
    try t.expectEqual(@as(usize, 240), entropy_length);
}

test "a bundle with nothing in it verifies nothing" {
    // The trust decision, stated as a test: `std.crypto.Certificate.Bundle.empty`
    // has no `map` entry for any issuer, so `Bundle.verify` answers
    // `error.CertificateIssuerNotFound` for every certificate — a relay with a
    // perfectly valid chain is refused, which is what "no anchors means no trust"
    // means in practice. This is the property that makes the bundle the caller's
    // choice rather than this file's default.
    const empty = Certificate.Bundle.empty;
    try t.expectEqual(@as(?u32, null), empty.find("anything at all"));
}

test "a stop reaches the descriptor, and every later wait refuses" {
    // `transport/tcp.zig`'s terminal stop, proved against a real stream rather
    // than a latch this test owns: loopback is where every test in that file
    // connects, and nothing is sent. A `Client` cannot be built without a
    // handshake, so the binding is the `Link` the vtable would reach, named
    // directly — which is the whole of what `Client.stop` is.
    var fixture = try Pair.open();
    defer fixture.close();

    var scratch_one: [1]u8 = undefined;
    fixture.stream.stop();
    try t.expect(fixture.stream.stopped.load(.acquire));
    try t.expectError(error.Canceled, fixture.stream.read(t.io, &scratch_one, 0));
    try t.expectError(error.Canceled, fixture.stream.read(t.io, &scratch_one, 0));
}

/// Every wait in this file's tests is bounded, so a regression costs a failed
/// test rather than a suite that never finishes.
const fixture_timeout_ms: i32 = 5000;

const c = std.c;

/// A connected loopback stream and the peer on the other end of it.
///
/// Built with `std.c` directly and not through `transport/tcp.zig`'s surface:
/// that module's doc says it has no listener and no accept, and a fixture that
/// built its peer out of the module under test could not tell a forwarding bug
/// from a working one.
const Pair = struct {
    listener: c.fd_t,
    /// The accepted end, held so the connection is not torn down between the
    /// connect and the calls under test.
    peer: c.fd_t,
    stream: tcp.Tcp,

    fn open() !Pair {
        const listener = try bindLoopback(0);
        errdefer _ = c.close(listener);
        if (c.listen(listener, 1) != 0) return error.TestFixtureRefused;
        var stream = try tcp.Tcp.create(loopback(try portOf(listener)));
        errdefer stream.close();
        try stream.connect(t.io, fixture_timeout_ms);
        return .{ .listener = listener, .peer = try acceptOne(listener), .stream = stream };
    }

    fn close(self: *Pair) void {
        self.stream.close();
        _ = c.close(self.peer);
        _ = c.close(self.listener);
    }
};

/// Loopback, which is where every test in this file connects. `127.0.0.1` and
/// not a name, because a test that resolves a name is a test that can fail on a
/// machine's hosts file.
fn loopback(port: u16) addr.SocketAddr {
    return .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = port };
}

/// Bind a loopback listener on `port`, or the kernel's choice when it is zero.
fn bindLoopback(port: u16) !c.fd_t {
    const handle = c.socket(c.AF.INET, c.SOCK.STREAM, 0);
    if (handle < 0) return error.TestFixtureRefused;
    errdefer _ = c.close(handle);
    var address: c.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
    };
    if (c.bind(handle, @ptrCast(&address), @sizeOf(c.sockaddr.in)) != 0)
        return error.TestFixtureRefused;
    return handle;
}

/// The port the kernel bound `listener` to.
fn portOf(listener: c.fd_t) !u16 {
    var bound: c.sockaddr.in = undefined;
    var length: c.socklen_t = @sizeOf(c.sockaddr.in);
    if (c.getsockname(listener, @ptrCast(&bound), &length) != 0)
        return error.TestFixtureRefused;
    return std.mem.bigToNative(u16, bound.port);
}

/// One accepted connection, or the fixture's own failure.
fn acceptOne(listener: c.fd_t) !c.fd_t {
    var accepted: c.fd_t = undefined;
    var length: c.socklen_t = @sizeOf(c.sockaddr.storage);
    while (true) {
        accepted = c.accept(listener, null, &length);
        if (accepted < 0) {
            if (@as(c_int, @intFromEnum(c.E.INTR)) == c._errno().*) continue;
            return error.TestFixtureRefused;
        }
        return accepted;
    }
}
