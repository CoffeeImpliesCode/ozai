const std = @import("std");
const process = @import("nat_process.zig");
const safety = @import("nat_proc_safety.zig");
const topology = @import("nat_topology.zig");
const evidence = @import("nat_evidence.zig");
const options = @import("nat_options.zig");
const runtime = @import("nat_runtime.zig");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len == 2 and std.mem.eql(u8, args[1], "--keeper")) {
        try process.assertPrivate(init.io);
        var identity_buffer: [128]u8 = undefined;
        const identity = try process.namespaceIdentity(init.io, std.c.getpid(),
            .net, &identity_buffer);
        try process.setPrivateForwarding(init.io, identity);
        try std.Io.File.stdout().writeStreamingAll(init.io, "KEEPER_READY\n");
        // The owner normally reaps this child; the finite lease bounds failure survival.
        try std.Io.sleep(init.io, .fromMilliseconds(600000), .awake);
        return;
    }
    const config = options.parse(args[1..]) catch |err| {
        try std.Io.File.stderr().writeStreamingAll(init.io,
            "usage: unshare -Urn -- ozai-nat-fixture --zig-peer ABS --rust-peer ABS " ++
            "--evidence-dir ABS --qad-cert ABS.der --qad-key ABS.pkcs8.der " ++
            "[--zig-role server|client|both] [--for-ms 45000]\n" ++
            "Source ~/.local/lib/host-scratch.sh first. Existing evidence directory " ++
            "must be caller-owned, canonical, under /tmp/scratch/.\n");
        return err;
    };
    try process.assertPrivate(init.io);
    var records = try evidence.Evidence.open(init.io, config.evidence_dir);
    defer records.close(init.io);
    var mapping_buffer: [256]u8 = undefined;
    const mapping = try safety.procRead(std.c.getpid(), "uid_map", &mapping_buffer);
    try records.save(init.io, "uid-map.txt", mapping);
    try records.save(init.io, "supervisor.txt",
        "Linux caller-owned user+netns; PID keepers; masquerade only; " ++
        "phase1 exact authenticated peer output gates forwarding. " ++
        "Zig WAN candidate provenance=configured; Rust real QAD certificate.\n");
    const self = try std.Io.Dir.cwd().realPathFileAlloc(init.io, args[0], init.gpa);
    defer init.gpa.free(self);
    var network = try topology.Topology.init(init.io, init.gpa, self);
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

test {
    std.testing.refAllDecls(@import("nat_proof.zig"));
    std.testing.refAllDecls(options);
}
