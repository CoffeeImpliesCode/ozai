const std = @import("std");
const process = @import("nat_process.zig");
const counter_summary = @import("nat_counters.zig");
pub const Counters = counter_summary.Counters;

pub fn counters(text: []const u8) counter_summary.Error!Counters {
    return counter_summary.counters(text);
}

test "blocked counter evidence rejects missing and malformed counters" {
    try std.testing.expectEqual(@as(u64, 7), try blockedPackets(
        "counter blocked_peer_udp { packets 7 bytes 448 }"));
    try std.testing.expectError(error.MissingBlockedCounter, blockedPackets("packets 7"));
    try std.testing.expectError(error.InvalidBlockedCounter,
        blockedPackets("counter blocked_peer_udp { packets nope bytes 4 }"));
}

test "initial router rules preserve masquerade and reject non relay UDP" {
    var storage: [4096]u8 = undefined;
    const rules = try routerRules(&storage, "10.78.1.0/24");
    try std.testing.expect(std.mem.indexOf(u8, rules, "masquerade") != null);
    try std.testing.expect(std.mem.indexOf(u8, rules, "dnat") == null);
    try std.testing.expect(std.mem.indexOf(u8, rules, "tcp dport 3340 accept") != null);
    try std.testing.expect(std.mem.indexOf(u8, rules, "udp dport 3341 accept") != null);
    try std.testing.expect(std.mem.indexOf(u8, rules,
        "ip daddr != 10.77.0.1 ip saddr != 10.77.0.1 jump peer_udp") != null);
    try std.testing.expect(std.mem.indexOf(u8, rules,
        "counter name blocked_peer_udp reject") != null);
}

test "keeper cleanup rejects forced kills and abnormal termination" {
    try std.testing.expect(validKeeperTerm(.{ .exited = 0 }));
    try std.testing.expect(validKeeperTerm(.{ .signal = .TERM }));
    try std.testing.expect(!validKeeperTerm(.{ .signal = .KILL }));
    try std.testing.expect(!validKeeperTerm(.{ .exited = 1 }));
    try std.testing.expect(!validKeeperTerm(.{ .stopped = .STOP }));
    try std.testing.expect(!validKeeperTerm(.{ .unknown = 0 }));
}

fn validKeeperTerm(term: std.process.Child.Term) bool {
    return switch (term) {
        .exited => |code| code == 0,
        .signal => |signal| signal == .TERM,
        else => false,
    };
}

const Keeper = struct {
    out: [512]u8 = undefined,
    err: [4096]u8 = undefined,
    child: process.Process = undefined,
};

pub const Topology = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    keepers: [4]?*Keeper = @splat(null),
    alice_pid: std.process.Child.Id = undefined,
    bob_pid: std.process.Child.Id = undefined,
    direct_open: bool = false,

    pub fn init(io: std.Io, gpa: std.mem.Allocator, self: []const u8,
        baseline: process.Baseline) !Topology
    {
        try process.assertPrivate(io, baseline);
        const keeper_argv = [_][]const u8{ self, "--keeper", "--original-netns",
            baseline.net, "--original-userns", baseline.user };
        var topology: Topology = .{ .io = io, .gpa = gpa };
        errdefer topology.deinit();
        for (&topology.keepers) |*slot| {
            const keeper = try gpa.create(Keeper);
            keeper.* = .{};
            keeper.child.init(&keeper.out, &keeper.err);
            slot.* = keeper;
            try keeper.child.spawnAs(io, &.{ "unshare", "--net", "--", self, "--keeper",
                "--original-netns", baseline.net, "--original-userns", baseline.user },
                &keeper_argv);
            const start = std.Io.Timestamp.now(io, .awake);
            while (true) {
                try keeper.child.pump(io);
                if (std.mem.indexOf(u8, keeper.child.stdout(), "KEEPER_READY\n") != null) break;
                if (try keeper.child.exited(io)) return error.KeeperExited;
                try pause(io, start, 5000);
            }
            try verifyKeeper(io, keeper.child.pid.?);
        }
        topology.alice_pid = topology.pid(2);
        topology.bob_pid = topology.pid(3);
        try topology.ip(null, &.{ "link", "add", "ozwan", "type", "bridge" });
        try topology.ip(null, &.{ "addr", "add", "10.77.0.1/24", "dev", "ozwan" });
        try topology.ip(null, &.{ "link", "set", "ozwan", "up" });
        try topology.side(0, 2, "ozwa", "10.77.0.2/24",
            "10.78.1.1/24", "10.78.1.2/24", "10.78.1.1", "10.78.1.0/24");
        try topology.side(1, 3, "ozwb", "10.77.0.3/24",
            "10.78.2.1/24", "10.78.2.2/24", "10.78.2.1", "10.78.2.0/24");
        return topology;
    }

    fn pid(topology: *const Topology, index: usize) std.process.Child.Id {
        return topology.keepers[index].?.child.pid.?;
    }

    fn side(topology: *Topology, router: usize, peer: usize, wan: []const u8,
        public: []const u8, gateway: []const u8, private: []const u8,
        route: []const u8, subnet: []const u8) !void
    {
        var buffer: [32]u8 = undefined;
        const router_pid = try std.fmt.bufPrint(&buffer, "{d}", .{topology.pid(router)});
        try topology.ip(null, &.{ "link", "add", wan, "type", "veth",
            "peer", "name", "wan", "netns", router_pid });
        try topology.ip(null, &.{ "link", "set", wan, "master", "ozwan" });
        try topology.ip(null, &.{ "link", "set", wan, "up" });
        const peer_pid = try std.fmt.bufPrint(&buffer, "{d}", .{topology.pid(peer)});
        try topology.ip(router, &.{ "link", "add", "lan", "type", "veth",
            "peer", "name", "peer", "netns", peer_pid });
        try topology.ip(router, &.{ "addr", "add", public, "dev", "wan" });
        try topology.ip(router, &.{ "addr", "add", gateway, "dev", "lan" });
        for ([_][]const u8{ "wan", "lan", "lo" }) |device|
            try topology.ip(router, &.{ "link", "set", device, "up" });
        try topology.ip(peer, &.{ "addr", "add", private, "dev", "peer" });
        for ([_][]const u8{ "peer", "lo" }) |device|
            try topology.ip(peer, &.{ "link", "set", device, "up" });
        try topology.ip(peer, &.{ "route", "add", "default", "via", route });
        var rules: [4096]u8 = undefined;
        try topology.nft(router, try routerRules(&rules, subnet));
    }

    fn ip(topology: *Topology, namespace: ?usize, args: []const []const u8) !void {
        const output = try topology.command(namespace, "ip", args, null);
        topology.gpa.free(output);
    }

    fn nft(topology: *Topology, namespace: usize, rules: []const u8) !void {
        const output = try topology.command(namespace, "nft", &.{ "-f", "-" }, rules);
        topology.gpa.free(output);
    }

    /// Parent drives this transition only after both authenticated relay proofs.
    pub fn openDirect(topology: *Topology) !void {
        if (topology.direct_open) return error.DirectAlreadyOpen;
        for (0..2) |router| try topology.nft(router,
            "flush chain inet ozai peer_udp\n" ++
            "add rule inet ozai peer_udp counter name direct_peer_udp accept\n");
        topology.direct_open = true;
    }

    pub fn blockDirect(topology: *Topology) !void {
        for (0..2) |router| try topology.nft(router,
            "flush chain inet ozai peer_udp\n" ++
            "add rule inet ozai peer_udp counter name blocked_peer_udp reject\n");
        topology.direct_open = false;
    }

    /// Caller owns this <=64KiB raw evidence, including all namespace routes.
    pub fn snapshot(topology: *Topology) ![]u8 {
        var evidence: std.ArrayList(u8) = .empty;
        errdefer evidence.deinit(topology.gpa);
        for (0..5) |index| {
            const namespace: ?usize = if (index == 4) null else index;
            const labels = [_][]const u8{ "router_alice\n", "router_bob\n",
                "alice\n", "bob\n", "wan\n" };
            try appendEvidence(topology.gpa, &evidence, labels[index]);
            const address = try topology.command(namespace, "ip", &.{ "-details", "addr" }, null);
            defer topology.gpa.free(address);
            const routes = try topology.command(namespace, "ip", &.{"route"}, null);
            defer topology.gpa.free(routes);
            try appendEvidence(topology.gpa, &evidence, address);
            try appendEvidence(topology.gpa, &evidence, routes);
            if (index < 2) {
                const rules = try topology.command(namespace, "nft",
                    &.{ "list", "table", "inet", "ozai" }, null);
                defer topology.gpa.free(rules);
                try appendEvidence(topology.gpa, &evidence, rules);
            }
        }
        _ = try counters(evidence.items);
        return evidence.toOwnedSlice(topology.gpa);
    }

    fn command(topology: *Topology, namespace: ?usize, tool: []const u8,
        args: []const []const u8, input: ?[]const u8) ![]u8
    {
        var storage: [32][]const u8 = undefined;
        var argv = std.ArrayList([]const u8).initBuffer(&storage);
        var namespace_buffer: [64]u8 = undefined;
        if (namespace) |index| {
            const net = try std.fmt.bufPrint(&namespace_buffer, "--net=/proc/{d}/ns/net",
                .{topology.pid(index)});
            argv.appendSliceAssumeCapacity(&.{ "nsenter", net, "--" });
        }
        argv.appendAssumeCapacity(tool);
        if (args.len > storage.len - argv.items.len) return error.CommandOverflow;
        argv.appendSliceAssumeCapacity(args);
        var stdout: [32768]u8 = undefined;
        var stderr: [4096]u8 = undefined;
        var child: process.Process = undefined;
        child.init(&stdout, &stderr);
        defer {
            if (child.child != null) {
                _ = child.finish(topology.io) catch |err| {
                    std.log.err("NAT command cleanup: {s}", .{@errorName(err)});
                };
            }
        }
        if (namespace != null) {
            try child.spawnAs(topology.io, argv.items, argv.items[3..]);
        } else {
            try child.spawn(topology.io, argv.items);
        }
        try child.writeInput(topology.io, input orelse "");
        const start = std.Io.Timestamp.now(topology.io, .awake);
        while (true) {
            try child.pump(topology.io);
            if (try child.exited(topology.io)) break;
            try pause(topology.io, start, 10000);
        }
        switch (try child.finish(topology.io)) {
            .exited => |code| if (code != 0) {
                std.log.err("NAT command {s}: {s}", .{ tool, child.stderr() });
                return error.TopologyCommandFailed;
            },
            else => return error.TopologyCommandFailed,
        }
        return topology.gpa.dupe(u8, child.stdout());
    }

    pub fn close(topology: *Topology) (process.Error || error{KeeperFailed})!void {
        var failure: ?(process.Error || error{KeeperFailed}) = null;
        for (&topology.keepers) |*slot| {
            const keeper = slot.* orelse continue;
            const term = keeper.child.finish(topology.io) catch |err| {
                if (failure == null) failure = err;
                continue;
            };
            if (!validKeeperTerm(term) and failure == null) failure = error.KeeperFailed;
            topology.gpa.destroy(keeper);
            slot.* = null;
        }
        if (failure) |err| return err;
    }

    pub fn deinit(topology: *Topology) void {
        // Only owned children are signalled; namespaces reclaim their links.
        for (&topology.keepers) |*slot| {
            if (slot.*) |keeper| {
                if (keeper.child.child != null) {
                    _ = keeper.child.finish(topology.io) catch |err| {
                        std.log.err("NAT keeper cleanup: {s}", .{@errorName(err)});
                    };
                }
                topology.gpa.destroy(keeper);
                slot.* = null;
            }
        }
    }
};

fn pause(io: std.Io, start: std.Io.Timestamp, timeout_ms: u32) !void {
    if (std.Io.Timestamp.now(io, .awake).nanoseconds - start.nanoseconds >
        @as(i96, timeout_ms) * std.time.ns_per_ms) return error.CommandTimeout;
    try std.Io.sleep(io, .fromMilliseconds(5), .awake);
}

fn verifyKeeper(io: std.Io, pid: std.process.Child.Id) !void {
    var current: [128]u8 = undefined;
    var child: [128]u8 = undefined;
    const current_pid: std.process.Child.Id = @intCast(std.os.linux.getpid());
    const user = try process.namespaceIdentity(io, current_pid, .user, &current);
    const keeper_user = try process.namespaceIdentity(io, pid, .user, &child);
    if (!std.mem.eql(u8, user, keeper_user)) return error.UnsafeNamespace;
    const net = try process.namespaceIdentity(io, current_pid, .net, &current);
    const keeper_net = try process.namespaceIdentity(io, pid, .net, &child);
    if (std.mem.eql(u8, net, keeper_net)) return error.UnsafeNamespace;
}

fn appendEvidence(gpa: std.mem.Allocator, evidence: *std.ArrayList(u8), bytes: []const u8) !void {
    if (bytes.len > 65536 - evidence.items.len) return error.EvidenceOverflow;
    try evidence.appendSlice(gpa, bytes);
}

pub fn blockedPackets(text: []const u8) !u64 {
    const start = std.mem.indexOf(u8, text, "counter blocked_peer_udp") orelse
        return error.MissingBlockedCounter;
    const end = std.mem.indexOfScalar(u8, text[start..], '}') orelse
        return error.InvalidBlockedCounter;
    var tokens = std.mem.tokenizeAny(u8, text[start..][0..end], " \t\r\n{");
    while (tokens.next()) |token| {
        if (std.mem.eql(u8, token, "packets")) {
            return std.fmt.parseInt(u64, tokens.next() orelse
                return error.InvalidBlockedCounter, 10) catch error.InvalidBlockedCounter;
        }
    }
    return error.InvalidBlockedCounter;
}

fn routerRules(buffer: []u8, subnet: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buffer,
        "table inet ozai {{\n" ++
        " counter blocked_peer_udp {{ }}\n counter direct_peer_udp {{ }}\n" ++
        " counter masqueraded {{ }}\n" ++
        " chain peer_udp {{\n counter name blocked_peer_udp reject\n }}\n" ++
        " chain forward {{ type filter hook forward priority 0; policy drop;\n" ++
        "  ip protocol udp ip daddr != 10.77.0.1 ip saddr != 10.77.0.1 jump peer_udp\n" ++
        "  ct state established,related accept\n" ++
        "  iifname \"lan\" ip daddr 10.77.0.1 tcp dport 3340 accept\n" ++
        "  iifname \"lan\" ip daddr 10.77.0.1 udp dport 3341 accept\n" ++
        " }}\n" ++
        " chain postrouting {{ type nat hook postrouting priority 100; policy accept;\n" ++
        "  ip saddr {s} oifname \"wan\" counter name masqueraded masquerade\n }}\n}}\n",
        .{subnet});
}
