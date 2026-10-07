const std = @import("std");
const process = @import("nat_process.zig");
const safety = @import("nat_proc_safety.zig");
const topology = @import("nat_topology.zig");
const evidence = @import("nat_evidence.zig");
const options = @import("nat_options.zig");
const runtime = @import("nat_runtime.zig");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len >= 2 and std.mem.eql(u8, args[1], "--keeper")) {
        const baseline = try keeperBaseline(args[1..]);
        try process.assertPrivate(init.io, baseline);
        var identity_buffer: [128]u8 = undefined;
        const identity = try process.namespaceIdentity(init.io, std.c.getpid(),
            .net, &identity_buffer);
        try process.setPrivateForwarding(init.io, baseline, identity);
        try std.Io.File.stdout().writeStreamingAll(init.io, "KEEPER_READY\n");
        // The owner normally reaps this child; the finite lease bounds failure survival.
        try std.Io.sleep(init.io, .fromMilliseconds(600000), .awake);
        return;
    }
    const config = options.parse(args[1..]) catch |err| {
        try std.Io.File.stderr().writeStreamingAll(init.io,
            "usage: unshare -Urn -- ozai-nat-fixture --node-peer ABS --rust-relay ABS " ++
            "--evidence-dir ABS " ++
            "--original-netns 'net:[N]' --original-userns 'user:[N]' " ++
            "[--endpoint-a-role server|client|both] [--for-ms 45000]\n" ++
            "Source ~/.local/lib/host-scratch.sh first. Capture your own net/user " ++
            "namespace identities before unshare. Existing evidence directory must be " ++
            "caller-owned, canonical, under /tmp/scratch/.\n");
        return err;
    };
    try process.assertPrivate(init.io, config.baseline);
    var records = try evidence.Evidence.open(init.io, config.evidence_dir);
    defer records.close(init.io);
    var mapping_buffer: [256]u8 = undefined;
    const mapping = try safety.procRead(std.c.getpid(), "uid_map", &mapping_buffer);
    try records.save(init.io, "uid-map.txt", mapping);
    try records.save(init.io, "original-netns.txt", config.baseline.net);
    try records.save(init.io, "original-userns.txt", config.baseline.user);
    var namespace_buffer: [128]u8 = undefined;
    const current_net = try process.namespaceIdentity(init.io, std.c.getpid(),
        .net, &namespace_buffer);
    try records.save(init.io, "controller-netns.txt", current_net);
    const current_user = try process.namespaceIdentity(init.io, std.c.getpid(),
        .user, &namespace_buffer);
    try records.save(init.io, "controller-userns.txt", current_user);
    try records.save(init.io, "supervisor.txt",
        "Linux caller-owned user+netns; PID keepers; conntrack source SNAT only; " ++
        "UDP 4444 preserves each configured WAN endpoint; no DNAT; translated counters. " ++
        "phase1 exact authenticated peer output gates forwarding. " ++
        "Two independent Node/Noq endpoints; stock Rust relay only, QAD disabled. " ++
        "WAN candidate provenance=configured; actual port-preserving SNAT sources.\n");
    const self = try std.Io.Dir.cwd().realPathFileAlloc(init.io, args[0], init.gpa);
    defer init.gpa.free(self);
    var network = try topology.Topology.init(init.io, init.gpa, self, config.baseline);
    defer network.deinit();
    if (config.role != .client)
        try runtime.run(init.io, init.gpa, config, &network, &records, .server);
    if (config.role != .server)
        try runtime.run(init.io, init.gpa, config, &network, &records, .client);
    try network.close();
    try records.save(init.io, "namespace-exits.txt",
        "All four caller-owned namespace keepers reaped; exits zero or owned TERM.\n");
    try std.Io.File.stdout().writeStreamingAll(init.io,
        "nat-cleanup: four owned namespace keepers reaped; evidence preserved\n");
}

fn keeperBaseline(args: []const []const u8) error{InvalidArguments}!process.Baseline {
    if (args.len != 5 or !std.mem.eql(u8, args[0], "--keeper") or
        !std.mem.eql(u8, args[1], "--original-netns") or
        !std.mem.eql(u8, args[3], "--original-userns")) return error.InvalidArguments;
    const baseline: process.Baseline = .{ .net = args[2], .user = args[4] };
    process.validateBaseline(baseline) catch return error.InvalidArguments;
    return baseline;
}

test "keeper invocation without real namespace baselines fails closed" {
    try std.testing.expectError(error.InvalidArguments, keeperBaseline(&.{"--keeper"}));
    try std.testing.expectError(error.InvalidArguments, keeperBaseline(&.{
        "--keeper", "--original-netns", "net:[0]", "--original-userns", "user:[2]",
    }));
    const baseline = try keeperBaseline(&.{
        "--keeper", "--original-netns", "net:[123]", "--original-userns", "user:[456]",
    });
    try std.testing.expectEqualStrings("net:[123]", baseline.net);
}

test {
    std.testing.refAllDecls(@import("nat_proof.zig"));
    std.testing.refAllDecls(options);
    std.testing.refAllDecls(runtime);
}
