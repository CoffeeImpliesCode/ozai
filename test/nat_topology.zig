const std = @import("std");
const process = @import("nat_process.zig");
const counter_summary = @import("nat_counters.zig");
pub const Counters = counter_summary.Counters;

pub fn counters(text: []const u8) counter_summary.Error!Counters {
    return counter_summary.counters(text);
}

test "blocked counter evidence rejects missing and malformed counters" {
    try std.testing.expectEqual(
        @as(u64, 7),
        try blockedPackets("counter blocked_peer_udp { packets 7 bytes 448 }"),
    );
    try std.testing.expectError(error.MissingBlockedCounter, blockedPackets("packets 7"));
    try std.testing.expectError(
        error.InvalidBlockedCounter,
        blockedPackets("counter blocked_peer_udp { packets nope bytes 4 }"),
    );
    try std.testing.expectError(
        error.InvalidBlockedCounter,
        blockedPackets("counter blocked_peer_udp { packets 7 bytes 4 }\n" ++
            "counter blocked_peer_udp { packets 8 bytes 4 }"),
    );
}

test "router rules allow candidate UDP to reach source NAT before the WAN gate" {
    const sides = [_]struct { subnet: []const u8, public: []const u8, address: []const u8 }{
        .{ .subnet = "10.78.1.0/24", .public = "10.77.0.2/24", .address = "10.77.0.2" },
        .{ .subnet = "10.78.2.0/24", .public = "10.77.0.3/24", .address = "10.77.0.3" },
    };
    for (sides) |side| {
        var storage: [4096]u8 = undefined;
        const rules = try routerRules(&storage, side.subnet, side.public);
        var expected_storage: [256]u8 = undefined;
        const expected = try std.fmt.bufPrint(
            &expected_storage,
            "ip saddr {s} oifname \"wan\" udp sport 4444 " ++
                "counter name translated snat ip to {s}:4444\n",
            .{ side.subnet, side.address },
        );
        try std.testing.expect(std.mem.find(u8, rules, expected) != null);
        const relay_snat = try std.fmt.bufPrint(
            &expected_storage,
            "ip saddr {s} oifname \"wan\" snat ip to {s}\n",
            .{ side.subnet, side.address },
        );
        try std.testing.expect(std.mem.find(u8, rules, relay_snat) != null);
        try std.testing.expect(std.mem.find(u8, rules, "masquerade") == null);
        try std.testing.expect(std.mem.find(u8, rules, "dnat") == null);
        try std.testing.expect(std.mem.find(u8, rules, "tcp dport 3340 accept") != null);
        try std.testing.expect(std.mem.find(u8, rules, "udp dport 3341 accept") != null);
        const candidate = try std.fmt.bufPrint(
            &expected_storage,
            "iifname \"lan\" oifname \"wan\" ip saddr {s} ip daddr {s} " ++
                "udp sport 4444 udp dport 4444 accept\n",
            .{
                side.subnet,
                if (std.mem.eql(u8, side.address, "10.77.0.2")) "10.77.0.3" else "10.77.0.2",
            },
        );
        try std.testing.expect(std.mem.find(u8, rules, candidate) != null);
        try std.testing.expect(std.mem.find(u8, rules, "peer_udp") == null);
        try std.testing.expect(std.mem.find(u8, rules, "reject") == null);
        try std.testing.expect(std.mem.find(
            u8,
            rules,
            "ct state established,related accept",
        ) != null);
    }
}

test "shared bridge gates only reciprocal post SNAT candidate frames" {
    try std.testing.expect(std.mem.find(u8, bridge_rules, "table bridge ozai_wan") != null);
    try std.testing.expect(std.mem.find(
        u8,
        bridge_rules,
        "type filter hook forward priority 0; policy accept;",
    ) != null);
    for ([_][]const u8{
        "iifname \"ozwa\" oifname \"ozwb\" ether type ip " ++
            "ip saddr 10.77.0.2 ip daddr 10.77.0.3 " ++
            "udp sport 4444 udp dport 4444 jump peer_udp",
        "iifname \"ozwb\" oifname \"ozwa\" ether type ip " ++
            "ip saddr 10.77.0.3 ip daddr 10.77.0.2 " ++
            "udp sport 4444 udp dport 4444 jump peer_udp",
    }) |candidate| {
        try std.testing.expect(std.mem.find(u8, bridge_rules, candidate) != null);
    }
    try std.testing.expect(std.mem.find(
        u8,
        bridge_rules,
        "counter name blocked_peer_udp drop",
    ) != null);
    try std.testing.expect(std.mem.find(u8, bridge_rules, "reject") == null);
    try std.testing.expectEqualStrings("flush chain bridge ozai_wan peer_udp\n" ++
        "add rule bridge ozai_wan peer_udp counter name direct_peer_udp accept\n", open_gate_rules);
    try std.testing.expectEqualStrings("flush chain bridge ozai_wan peer_udp\n" ++
        "add rule bridge ozai_wan peer_udp counter name blocked_peer_udp drop\n", block_gate_rules);
}

test "router rules reject mismatched or forged WAN addresses" {
    var storage: [4096]u8 = undefined;
    for ([_][]const u8{
        "10.77.0.3/24",                                    "10.77.0.2", "10.77.0.2/16",
        "10.77.0.2/24\nadd rule inet ozai forward accept",
    }) |public| {
        try std.testing.expectError(
            error.InvalidRouterAddress,
            routerRules(&storage, "10.78.1.0/24", public),
        );
    }
    try std.testing.expectError(
        error.InvalidRouterAddress,
        routerRules(&storage, "10.78.2.0/24", "10.77.0.2/24"),
    );
    try std.testing.expectError(
        error.InvalidRouterAddress,
        routerRules(&storage, "10.78.3.0/24", "10.77.0.3/24"),
    );
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
    controller_bridge: bool = false,
    controller_firewall: bool = false,
    controller_ports: [2]bool = @splat(false),

    pub fn init(
        gpa: std.mem.Allocator,
        io: std.Io,
        self: []const u8,
        baseline: process.Baseline,
    ) !Topology {
        try process.assertPrivate(io, baseline);
        const keeper_argv = [_][]const u8{
            self, "--keeper", "--original-netns", baseline.net, "--original-userns", baseline.user,
        };
        var topology: Topology = .{ .io = io, .gpa = gpa };
        errdefer topology.deinit();
        for (&topology.keepers) |*slot| {
            const keeper = try gpa.create(Keeper);
            keeper.* = .{};
            keeper.child.init(&keeper.out, &keeper.err);
            slot.* = keeper;
            try keeper.child.spawnAs(io, &.{
                "unshare",          "--net",      "--",                self,          "--keeper",
                "--original-netns", baseline.net, "--original-userns", baseline.user,
            }, &keeper_argv);
            const start = std.Io.Timestamp.now(io, .awake);
            while (true) {
                try keeper.child.pump(io);
                if (std.mem.find(u8, keeper.child.stdout(), "KEEPER_READY\n") != null) break;
                if (try keeper.child.exited(io)) return error.KeeperExited;
                try pause(io, start, 5000);
            }
            const keeper_pid = keeper.child.pid orelse return error.KeeperNotStarted;
            try verifyKeeper(io, keeper_pid);
        }
        topology.alice_pid = try topology.pid(2);
        topology.bob_pid = try topology.pid(3);
        try topology.ip(null, &.{ "link", "add", "ozwan", "type", "bridge" });
        topology.controller_bridge = true;
        try topology.ip(null, &.{ "addr", "add", "10.77.0.1/24", "dev", "ozwan" });
        try topology.ip(null, &.{ "link", "set", "ozwan", "up" });
        try topology.nft(null, bridge_rules);
        topology.controller_firewall = true;
        try topology.side(
            0,
            2,
            "ozwa",
            "10.77.0.2/24",
            "10.78.1.1/24",
            "10.78.1.2/24",
            "10.78.1.1",
            "10.78.1.0/24",
        );
        try topology.side(
            1,
            3,
            "ozwb",
            "10.77.0.3/24",
            "10.78.2.1/24",
            "10.78.2.2/24",
            "10.78.2.1",
            "10.78.2.0/24",
        );
        return topology;
    }

    fn pid(topology: *const Topology, index: usize) error{KeeperNotStarted}!std.process.Child.Id {
        const keeper = topology.keepers[index] orelse return error.KeeperNotStarted;
        return keeper.child.pid orelse return error.KeeperNotStarted;
    }

    fn side(
        topology: *Topology,
        router: usize,
        peer: usize,
        wan: []const u8,
        public: []const u8,
        gateway: []const u8,
        private: []const u8,
        route: []const u8,
        subnet: []const u8,
    ) !void {
        var rules: [4096]u8 = undefined;
        const rendered_rules = try routerRules(&rules, subnet, public);
        var buffer: [32]u8 = undefined;
        const router_pid = try std.fmt.bufPrint(&buffer, "{d}", .{try topology.pid(router)});
        const port_index: usize = if (std.mem.eql(u8, wan, "ozwa"))
            0
        else if (std.mem.eql(u8, wan, "ozwb"))
            1
        else
            return error.InvalidControllerPort;
        try topology.ip(null, &.{
            "link", "add", wan, "type", "veth", "peer", "name", "wan", "netns", router_pid,
        });
        topology.controller_ports[port_index] = true;
        try topology.ip(null, &.{ "link", "set", wan, "master", "ozwan" });
        try topology.ip(null, &.{ "link", "set", wan, "up" });
        const peer_pid = try std.fmt.bufPrint(&buffer, "{d}", .{try topology.pid(peer)});
        try topology.ip(router, &.{
            "link", "add", "lan", "type", "veth", "peer", "name", "peer", "netns", peer_pid,
        });
        try topology.ip(router, &.{ "addr", "add", public, "dev", "wan" });
        try topology.ip(router, &.{ "addr", "add", gateway, "dev", "lan" });
        for ([_][]const u8{ "wan", "lan", "lo" }) |device|
            try topology.ip(router, &.{ "link", "set", device, "up" });
        try topology.ip(peer, &.{ "addr", "add", private, "dev", "peer" });
        for ([_][]const u8{ "peer", "lo" }) |device|
            try topology.ip(peer, &.{ "link", "set", device, "up" });
        try topology.ip(peer, &.{ "route", "add", "default", "via", route });
        try topology.nft(router, rendered_rules);
    }

    fn ip(topology: *Topology, namespace: ?usize, args: []const []const u8) !void {
        const output = try topology.command(namespace, "ip", args, null);
        topology.gpa.free(output);
    }

    fn nft(topology: *Topology, namespace: ?usize, rules: []const u8) !void {
        const output = try topology.command(namespace, "nft", &.{ "-f", "-" }, rules);
        topology.gpa.free(output);
    }

    /// Parent opens the post-SNAT gate only after authenticated relay and blocked probe evidence.
    pub fn openDirect(topology: *Topology) !void {
        if (topology.direct_open) return error.DirectAlreadyOpen;
        try topology.nft(null, open_gate_rules);
        topology.direct_open = true;
    }

    pub fn blockDirect(topology: *Topology) !void {
        try topology.nft(null, block_gate_rules);
        topology.direct_open = false;
    }

    /// Caller owns this <=64KiB raw evidence, including routes and the post-SNAT bridge gate.
    pub fn snapshot(topology: *Topology) ![]u8 {
        var evidence: std.ArrayList(u8) = .empty;
        errdefer evidence.deinit(topology.gpa);
        for (0..5) |index| {
            const namespace: ?usize = if (index == 4) null else index;
            const labels = [_][]const u8{
                "router_alice\n", "router_bob\n", "alice\n", "bob\n", "wan\n",
            };
            try appendEvidence(topology.gpa, &evidence, labels[index]);
            const address = try topology.command(namespace, "ip", &.{ "-details", "addr" }, null);
            defer topology.gpa.free(address);
            const routes = try topology.command(namespace, "ip", &.{"route"}, null);
            defer topology.gpa.free(routes);
            try appendEvidence(topology.gpa, &evidence, address);
            try appendEvidence(topology.gpa, &evidence, routes);
            if (index < 2) {
                const rules = try topology.command(
                    namespace,
                    "nft",
                    &.{ "list", "table", "inet", "ozai" },
                    null,
                );
                defer topology.gpa.free(rules);
                try appendEvidence(topology.gpa, &evidence, rules);
            } else if (index == 4) {
                const rules = try topology.command(
                    null,
                    "nft",
                    &.{ "list", "table", "bridge", "ozai_wan" },
                    null,
                );
                defer topology.gpa.free(rules);
                try appendEvidence(topology.gpa, &evidence, rules);
            }
        }
        _ = try counters(evidence.items);
        return evidence.toOwnedSlice(topology.gpa);
    }

    fn command(
        topology: *Topology,
        namespace: ?usize,
        tool: []const u8,
        args: []const []const u8,
        input: ?[]const u8,
    ) ![]u8 {
        var storage: [32][]const u8 = undefined;
        var argv = std.ArrayList([]const u8).initBuffer(&storage);
        var namespace_buffer: [64]u8 = undefined;
        if (namespace) |index| {
            const net = try std.fmt.bufPrint(
                &namespace_buffer,
                "--net=/proc/{d}/ns/net",
                .{try topology.pid(index)},
            );
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

    pub fn close(topology: *Topology) (process.Error || error{
        KeeperFailed,
        ControllerNetworkCleanupFailed,
    })!void {
        var failure: ?(process.Error || error{
            KeeperFailed,
            ControllerNetworkCleanupFailed,
        }) = null;
        topology.removeControllerNetwork() catch |err| {
            std.log.err("NAT controller network cleanup: {s}", .{@errorName(err)});
            failure = error.ControllerNetworkCleanupFailed;
        };
        for (&topology.keepers) |*slot| {
            const keeper = slot.* orelse continue;
            const term = keeper.child.finish(topology.io) catch |err| {
                if (failure == null) failure = err;
                continue;
            };
            if (!validKeeperTerm(term) and failure == null) failure = error.KeeperFailed;
            slot.* = null;
            topology.gpa.destroy(keeper);
        }
        if (failure) |err| return err;
    }

    // Failed cleanup must retain live keeper PIDs and network ownership for a safe retry.
    // ziglint-ignore: Z030
    pub fn deinit(topology: *Topology) void {
        topology.removeControllerNetwork() catch |err| {
            std.log.err("NAT controller network cleanup: {s}", .{@errorName(err)});
        };
        for (&topology.keepers) |*slot| {
            if (slot.*) |keeper| {
                if (keeper.child.child != null) {
                    _ = keeper.child.finish(topology.io) catch |err| {
                        std.log.err("NAT keeper cleanup: {s}", .{@errorName(err)});
                        if (keeper.child.term == null) continue;
                    };
                }
                slot.* = null;
                topology.gpa.destroy(keeper);
            }
        }
        // Failed cleanup retains ownership for a retry; successful cleanup destroys the topology.
        for (topology.keepers) |keeper| {
            if (keeper != null) return;
        }
        if (topology.controller_bridge or topology.controller_firewall) return;
        for (topology.controller_ports) |created| {
            if (created) return;
        }
        topology.* = undefined;
    }

    fn removeControllerNetwork(topology: *Topology) !void {
        var failure: ?anyerror = null;
        if (topology.controller_firewall) {
            if (topology.command(
                null,
                "nft",
                &.{ "delete", "table", "bridge", "ozai_wan" },
                null,
            )) |output| {
                topology.gpa.free(output);
                topology.controller_firewall = false;
            } else |err| {
                if (failure == null) failure = err;
            }
        }
        const names = [_][]const u8{ "ozwa", "ozwb" };
        for (&topology.controller_ports, 0..) |*created, index| {
            if (!created.*) continue;
            topology.ip(null, &.{ "link", "del", names[index] }) catch |err| {
                if (failure == null) failure = err;
                continue;
            };
            created.* = false;
        }
        if (topology.controller_bridge) {
            if (topology.ip(null, &.{ "link", "del", "ozwan" })) |_| {
                topology.controller_bridge = false;
            } else |err| {
                if (failure == null) failure = err;
            }
        }
        if (failure) |err| return err;
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
    if (std.mem.find(u8, text, "counter blocked_peer_udp {") == null)
        return error.MissingBlockedCounter;
    return counter_summary.single(text, "blocked_peer_udp") catch error.InvalidBlockedCounter;
}

// Router postrouting has already committed source NAT before these WAN frames arrive.
const bridge_rules =
    "table bridge ozai_wan {\n" ++
    " counter blocked_peer_udp { }\n counter direct_peer_udp { }\n" ++
    " chain peer_udp {\n counter name blocked_peer_udp drop\n }\n" ++
    " chain forward { type filter hook forward priority 0; policy accept;\n" ++
    "  iifname \"ozwa\" oifname \"ozwb\" ether type ip " ++
    "ip saddr 10.77.0.2 ip daddr 10.77.0.3 " ++
    "udp sport 4444 udp dport 4444 jump peer_udp\n" ++
    "  iifname \"ozwb\" oifname \"ozwa\" ether type ip " ++
    "ip saddr 10.77.0.3 ip daddr 10.77.0.2 " ++
    "udp sport 4444 udp dport 4444 jump peer_udp\n }\n}\n";

const open_gate_rules =
    "flush chain bridge ozai_wan peer_udp\n" ++
    "add rule bridge ozai_wan peer_udp counter name direct_peer_udp accept\n";
const block_gate_rules =
    "flush chain bridge ozai_wan peer_udp\n" ++
    "add rule bridge ozai_wan peer_udp counter name blocked_peer_udp drop\n";

fn routerRules(buffer: []u8, subnet: []const u8, public: []const u8) ![]const u8 {
    const valid_alice = std.mem.eql(u8, subnet, "10.78.1.0/24") and
        std.mem.eql(u8, public, "10.77.0.2/24");
    const valid_bob = std.mem.eql(u8, subnet, "10.78.2.0/24") and
        std.mem.eql(u8, public, "10.77.0.3/24");
    if (!valid_alice and !valid_bob) return error.InvalidRouterAddress;
    const address = public[0 .. public.len - "/24".len];
    const candidate = if (valid_alice) "10.77.0.3" else "10.77.0.2";
    return std.fmt.bufPrint(
        buffer,
        "table inet ozai {{\n" ++
            " counter translated {{ }}\n" ++
            " chain forward {{ type filter hook forward priority 0; policy drop;\n" ++
            // Candidate probes must reach postrouting even while the WAN gate is closed.
            "  iifname \"lan\" oifname \"wan\" ip saddr {s} ip daddr {s} " ++
            "udp sport 4444 udp dport 4444 accept\n" ++
            "  ct state established,related accept\n" ++
            "  iifname \"lan\" ip daddr 10.77.0.1 tcp dport 3340 accept\n" ++
            "  iifname \"lan\" ip daddr 10.77.0.1 udp dport 3341 accept\n" ++
            " }}\n" ++
            " chain postrouting {{ type nat hook postrouting priority 100; policy accept;\n" ++
            // Fix the peer's source endpoint across destinations without opening inbound NAT.
            "  ip saddr {s} oifname \"wan\" udp sport 4444 " ++
            "counter name translated snat ip to {s}:4444\n" ++
            // Relay TCP still needs source address translation, but not the UDP port constraint.
            "  ip saddr {s} oifname \"wan\" snat ip to {s}\n }}\n}}\n",
        .{ subnet, candidate, subnet, address, subnet, address },
    );
}
