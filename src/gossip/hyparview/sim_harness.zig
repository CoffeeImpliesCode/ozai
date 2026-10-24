//! The simulator's fixed sizes, its failure modes, and how a swarm is brought
//! up and configured.
//!
//! Upstream `proto/sim.rs`'s vocabulary: `nodeIdFor` mints a real key per
//! simulated node, `LatencyConfig` says how long a message takes to cross a
//! link, and `BootstrapMode` says how the swarm comes up. `HarnessError` is
//! every way the harness itself can fail, which is deliberately separate from
//! the protocol's own `Error`: none of it is a protocol refusal.
//!
//! `Network` and `Simulator` are the two things that use all of this; they are
//! `sim_network.zig` and `sim_simulator.zig`.
const std = @import("std");
const key = @import("../../base/key.zig");
const plumtree = @import("../plumtree.zig");
const bounds = @import("bounds.zig");
const topic_id = @import("topic_id.zig");
const entropy = @import("rng.zig");
const settings = @import("config.zig");
const topic_mod = @import("topic.zig");

const Allocator = std.mem.Allocator;
const NodeId = key.NodeId;
const Nanos = plumtree.Nanos;
const nanos_per_milli = plumtree.nanos_per_milli;
const nanos_per_second = plumtree.nanos_per_second;
const Error = bounds.Error;
const topic_id_length = bounds.topic_id_length;
const TopicId = topic_id.TopicId;
const Rng = entropy.Rng;
const Config = settings.Config;
const AppEvent = topic_mod.AppEvent;
const TopicConfig = topic_mod.TopicConfig;

pub const max_peers = 12;
/// An undirected link is one unordered pair, so this is the ceiling on how
/// many can exist.
pub const max_conns = max_peers * (max_peers - 1) / 2;
/// Enough for every link to be torn down inside one tick.
pub const max_kills = max_conns;
/// A microsecond, which is upstream's own grace period. The comment
/// upstream gives it is the reason it exists: an event queued at the
/// current instant must land before the disconnect that follows it, so a
/// node is not removed while a message is on its way to it.
pub const disconnect_grace: Nanos = 1_000;
/// The topic the simulator runs: 32 zero bytes, which is upstream's
/// `sim::TOPIC` and a fixture rather than a value anyone would choose.
pub const topic: TopicId = TopicId.fromBytes(@as([topic_id_length]u8, @splat(0)));
/// The number of neighbour events one `neighbourEvents` buffer holds.
/// Sized for a swarm that reshuffles several times over, which is several
/// times the node count.
pub const max_neighbour_events = max_peers * 8;

/// Everything that can go wrong in the harness rather than in the
/// protocol. Separate from `Error` because none of it is a protocol
/// refusal: a simulator asked to add a thirteenth node, or to add one
/// twice, has been asked something impossible.
pub const SimError = error{
    PeerIndexOutOfRange,
    DuplicatePeer,
    TooManyDisconnects,
};

/// Every way this harness can fail, over both layers. `key.KeyError` is
/// here because `nodeIdFor` mints a real key from a seed, and a seed that
/// derives the identity point is a harness input like any other.
pub const HarnessError = Error || plumtree.Error || SimError ||
    key.KeyError || Allocator.Error;

/// A node's identity, from a fixed seed. A `NodeId` cannot be made from
/// arbitrary bytes — `NodeId.fromBytes` rejects anything that is not a
/// point on the curve — so a simulator of `u64` peer ids has to mint real
/// keys, deterministically.
///
/// Fallible because `SecretKey.fromSeed` refuses a seed that derives the
/// identity point, and a `0x5c` fill says nothing about the twelve
/// indices a swarm holds. A harness caller reports it, a test fails on
/// it, and both name the seed; `unreachable` could do neither and would
/// have taken the process down instead.
pub fn nodeIdFor(index: u8) key.KeyError!NodeId {
    var seed: [key.SecretKey.seed_length]u8 = undefined;
    @memset(&seed, 0x5c);
    seed[0] = index;
    return (try key.SecretKey.fromSeed(seed)).nodeId();
}

/// How long a message takes to cross a link. Upstream `LatencyConfig`.
pub const LatencyConfig = union(enum) {
    /// The same on every link. Upstream `LatencyConfig::Static`.
    fixed: Nanos,
    /// Drawn once per link. Upstream `LatencyConfig::Dynamic`.
    drawn: struct { min: Nanos, max: Nanos },

    pub const default_fixed: LatencyConfig = .{ .fixed = 50 * nanos_per_milli };
    pub const default_drawn: LatencyConfig = .{
        .drawn = .{ .min = 10 * nanos_per_milli, .max = 100 * nanos_per_milli },
    };

    pub fn maxLatency(self: LatencyConfig) Nanos {
        return switch (self) {
            .fixed => |value| value,
            .drawn => |range| range.max,
        };
    }

    pub fn draw(self: LatencyConfig, rng: *Rng) Nanos {
        return switch (self) {
            .fixed => |value| value,
            .drawn => |range| rng.range(range.min, range.max),
        };
    }
};

pub const NetworkConfig = struct {
    latency: LatencyConfig = LatencyConfig.default_drawn,
    membership: Config = .{},
    broadcast: plumtree.Config = .{},

    // ziglint-ignore: Z012
    pub fn topicConfig(self: NetworkConfig) TopicConfig {
        return .{ .membership = self.membership, .broadcast = self.broadcast };
    }
};

pub const SimulatorConfig = struct {
    /// The one seed that fixes the whole run.
    rng_seed: u64 = 0,
    peers: u8 = 8,
    gossip_round_timeout: Nanos = 5 * nanos_per_second,
};

/// How a swarm is brought up. Upstream `sim::BootstrapMode`.
pub const BootstrapMode = union(enum) {
    /// Every peer joins one peer.
    single,
    /// The first `count` form a core; the rest join a random core member.
    core: u8,
};

/// Something the application saw. Upstream's is a `(PI, TopicId, Event)`
/// triple; a simulated node is on one topic, so the topic is not repeated.
pub const SimEvent = struct {
    peer: u8,
    event: AppEvent,
};

/// A neighbour change, reduced to two indices and a direction, so a test
/// can hold a run against upstream's expected event lists.
pub const NeighbourEvent = struct {
    up: bool,
    a: u8,
    b: u8,
};
