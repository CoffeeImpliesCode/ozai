//! A swarm under test, and what one broadcast round cost it.
//!
//! Upstream `proto::sim::Simulator`. `bootstrap` brings the swarm up the way
//! upstream's does and `gossipRound` broadcasts from one node and counts who
//! got it. `RoundStats` keeps upstream's three fields that measure this port
//! against upstream's numbers — which it cannot be — and drops the rest: what
//! is left is what a port can be held to.
const std = @import("std");
const harness = @import("sim_harness.zig");
const net = @import("sim_network.zig");

const Allocator = std.mem.Allocator;
const max_peers = harness.max_peers;
const HarnessError = harness.HarnessError;
const NetworkConfig = harness.NetworkConfig;
const SimulatorConfig = harness.SimulatorConfig;
const BootstrapMode = harness.BootstrapMode;
const Network = net.Network;

/// What one broadcast round cost. Upstream's `RoundStats` without its three
/// ratios: those measure a run against upstream's numbers, and this port's
/// numbers are not comparable — see the determinism note on `sim`. What is
/// left is what a port can be held to.
pub const RoundStats = struct {
    /// Nodes that were supposed to get the message.
    expected: usize,
    /// Nodes that did, counted once each.
    delivered: usize,
    /// `Received` events for a node that already had one. Upstream treats
    /// this as a panic, because deduplication is supposed to make it
    /// impossible; here it is a number a test asserts is zero, which is the
    /// same statement without taking the process down.
    duplicated: usize,
    /// The furthest a message got, in hops from its origin.
    max_round: u16,
};

/// A swarm under test. Upstream `proto::sim::Simulator`.
pub const Simulator = struct {
    network: Network,
    config: SimulatorConfig,

    // ziglint-ignore: Z012 Z015
    pub fn init(
        gpa: Allocator,
        config: SimulatorConfig,
        network_config: NetworkConfig,
    ) HarnessError!Simulator {
        return .{
            .network = try Network.init(gpa, network_config, config.rng_seed),
            .config = config,
        };
    }

    pub fn deinit(self: *Simulator) void {
        self.network.deinit();
        self.* = undefined;
    }

    // ziglint-ignore: Z012 Z015
    /// Bring the swarm up. Upstream `Simulator::bootstrap`.
    pub fn bootstrap(self: *Simulator, mode: BootstrapMode) HarnessError!void {
        const count = self.config.peers;
        switch (mode) {
            .single => {
                try self.network.insertAndJoin(0, &[_]u8{});
                var index: u8 = 1;
                while (index < count) : (index += 1) {
                    try self.network.insertAndJoin(index, &[_]u8{0});
                }
                try self.network.runTrips(20);
            },
            .core => {
                const core = @min(mode.core, count);
                try self.network.insertAndJoin(0, &[_]u8{});
                var index: u8 = 1;
                while (index < core) : (index += 1) {
                    try self.network.insertAndJoin(index, &[_]u8{0});
                }
                try self.network.runTrips(7);
                while (index < count) : (index += 1) {
                    const contact: u8 = @intCast(
                        self.network.rng.below(@as(usize, core)),
                    );
                    try self.network.insertAndJoin(index, &[_]u8{contact});
                }
                try self.network.runTrips(20);
            },
        }
    }

    // ziglint-ignore: Z012 Z015
    /// Broadcast from one node and count who got it. Upstream
    /// `Simulator::gossip_round`, reduced to a single sender: the
    /// multiple-sender case differs only in how many messages are in
    /// flight, and this port's iTree is the thing under test.
    pub fn gossipRound(
        self: *Simulator,
        from: u8,
        content: []const u8,
    ) HarnessError!RoundStats {
        const expected = if (self.network.peer_count > 0) self.network.peer_count - 1 else 0;
        var stats: RoundStats = .{
            .expected = expected,
            .delivered = 0,
            .duplicated = 0,
            .max_round = 0,
        };
        var seen = [_]bool{false} ** max_peers;
        self.network.events.clearRetainingCapacity();
        try self.network.command(from, .{
            .broadcast = .{ .content = content, .scope = .swarm },
        });
        self.harvest(&stats, &seen);
        const end = self.network.time + self.config.gossip_round_timeout;
        while (stats.delivered < expected) {
            const at = self.network.nextTime() orelse break;
            if (at > end) break;
            try self.network.tick();
            self.harvest(&stats, &seen);
        }
        return stats;
    }

    fn harvest(self: *Simulator, stats: *RoundStats, seen: *[max_peers]bool) void {
        for (self.network.events.items) |event| {
            switch (event.event) {
                .received => |received| {
                    if (seen[event.peer]) stats.duplicated += 1;
                    seen[event.peer] = true;
                    stats.delivered += 1;
                    stats.max_round = switch (received.scope) {
                        .swarm => |round| @max(stats.max_round, round.value),
                        .neighbors => stats.max_round,
                    };
                },
                else => {},
            }
        }
        self.network.events.clearRetainingCapacity();
    }
};
