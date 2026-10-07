//! The stand-ins a caller supplies: a protocol handler that records what the
//! router called it for, two filters that answer fixed ways, and an attempt off
//! the direct path and off a relay.
//!
//! Split out of `src/endpoint/endpoint.zig`, which is now the facade over it
//! and two other named modules. It is named for what it stands in for rather
//! than for being test-only, and it is deliberately the only one of the three
//! that holds no logic of the loop's own: the filter is application code, the
//! handler is a protocol, and an attempt is an address — the loop names all
//! three and calls none of them, which is exactly the property its docs claim.

const router = @import("../router/router.zig");
const base_addr = @import("../base/addr.zig");
const base_ula = @import("../base/ula.zig");
const filter = @import("incoming_filter.zig");

const Incoming = filter.Incoming;
const IncomingFilter = filter.IncomingFilter;

/// A handler that records what the router called it for, and can fail on
/// demand. Every test owns one, so the context pointer is the observable
/// "which handler won".
pub const Handler = struct {
    on_accepting_calls: usize = 0,
    accept_calls: usize = 0,
    shutdown_calls: usize = 0,
    accept_error: ?router.AcceptError = null,

    fn onAccepting(
        ctx: *anyopaque,
        accepting: router.Accepting,
    ) router.AcceptError!router.Connection {
        const self: *Handler = @ptrCast(@alignCast(ctx));
        _ = accepting;
        self.on_accepting_calls += 1;
        return .{ .ptr = ctx };
    }

    fn accept(ctx: *anyopaque, connection: router.Connection) router.AcceptError!void {
        _ = connection;
        const self: *Handler = @ptrCast(@alignCast(ctx));
        self.accept_calls += 1;
        if (self.accept_error) |err| return err;
    }

    fn shutdown(ctx: *anyopaque) void {
        const self: *Handler = @ptrCast(@alignCast(ctx));
        self.shutdown_calls += 1;
    }

    pub fn handler(self: *Handler) router.ProtocolHandler {
        return .{
            .ptr = self,
            .on_accepting = Handler.onAccepting,
            .accept = Handler.accept,
            .shutdown = Handler.shutdown,
        };
    }
};

/// A table with one handler for `alpn`, and the handler behind it.
pub fn oneHandler(
    alpn: []const u8,
    entries: []router.Entry,
    handler: *Handler,
) !router.Router {
    var builder = router.Builder.init(entries);
    _ = try builder.accept(alpn, handler.handler());
    return builder.build();
}

/// A filter that answers a fixed way, so each of the four can be walked through
/// the loop on its own.
pub const Recorder = struct {
    answer: filter.Answer,
    calls: usize = 0,
    asked: ?Incoming = null,

    fn decide(ctx: *anyopaque, incoming: Incoming) filter.Answer {
        const self: *Recorder = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        self.asked = incoming;
        return self.answer;
    }

    pub fn filterer(self: *Recorder) IncomingFilter {
        return .{ .ptr = self, .filter = Recorder.decide };
    }
};

/// A filter written the way an application writes one: let the connection in
/// only once the address it came from has been proved. It is the filter that
/// shows the two meanings of a retry are not one fact, because the direct path
/// it is asked about can reach the state it wants and the relay path cannot.
pub const Proving = struct {
    calls: usize = 0,

    fn decide(ctx: *anyopaque, incoming: Incoming) filter.Answer {
        const self: *Proving = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        return switch (incoming.validation) {
            .validated => .accept,
            // A relayed flow that cooperated has proved nothing, so asking again
            // is what this filter does, and QUIC will not answer it twice.
            .unvalidated, .cooperated => .retry,
        };
    }

    pub fn filterer(self: *Proving) IncomingFilter {
        return .{ .ptr = self, .filter = Proving.decide };
    }

    /// What this filter answers for `incoming`, asked directly.
    pub fn asks(self: *Proving, incoming: Incoming) filter.Answer {
        return filter.ask(self.filterer(), incoming);
    }
};

/// A direct-path attempt: a real socket address, nothing proved.
pub fn direct(id: u64) Incoming {
    const remote: base_addr.SocketAddr = .{
        .ip = .{ .v4 = .{ 192, 0, 2, @intCast(id) } },
        .port = 443,
    };
    return .{
        .id = id,
        .remote = remote,
        .local = base_ula.socketAddrFor(.any_path, host(id)),
        .classification = base_ula.classify(remote),
        .validation = .unvalidated,
    };
}

/// The same attempt one hop away, through a relay.
pub fn relayed(id: u64) Incoming {
    const remote = base_ula.socketAddrFor(.relay, host(id));
    return .{
        .id = id,
        .remote = remote,
        .local = base_ula.socketAddrFor(.any_path, host(id)),
        .classification = base_ula.classify(remote),
        .validation = .unvalidated,
    };
}

/// The eight host bits a test attempt's own address is built from, so the
/// address carries the attempt's id and two attempts are two addresses.
fn host(id: u64) base_ula.HostBits {
    return .{ 0, 0, 0, 0, 0, 0, 0, @intCast(id) };
}

/// The second attempt on a flow, carrying the token the first one was sent.
pub fn withToken(previous: Incoming) Incoming {
    var next = previous;
    next.validation = filter.proved(next.classification, next.remote);
    return next;
}
