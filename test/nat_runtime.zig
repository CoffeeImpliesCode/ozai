const std = @import("std");
const processes = @import("nat_process.zig");
const topology = @import("nat_topology.zig");
const evidence = @import("nat_evidence.zig");
const options = @import("nat_options.zig");
const proof = @import("nat_proof.zig");

const endpoint_a_seed = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
const endpoint_b_seed = "6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c";
const message = "ozai-rootless-nat-same-connection";
pub const Role = enum { server, client };

test "WAN gate opens only after blocked source NAT probes and no direct frames" {
    const baseline: topology.Counters = .{ .blocked = 4, .direct = 2, .translated = 6 };
    try std.testing.expect(!try relayGateReady(baseline, baseline));
    try std.testing.expect(!try relayGateReady(
        baseline,
        .{ .blocked = 5, .direct = 2, .translated = 6 },
    ));
    try std.testing.expect(!try relayGateReady(
        baseline,
        .{ .blocked = 4, .direct = 2, .translated = 7 },
    ));
    try std.testing.expect(try relayGateReady(
        baseline,
        .{ .blocked = 5, .direct = 2, .translated = 7 },
    ));
    try std.testing.expectError(
        error.InitialUdpNotBlocked,
        relayGateReady(baseline, .{ .blocked = 5, .direct = 3, .translated = 7 }),
    );
}

fn relayGateReady(baseline: topology.Counters, current: topology.Counters) !bool {
    if (current.direct != baseline.direct) return error.InitialUdpNotBlocked;
    return current.blocked > baseline.blocked and current.translated > baseline.translated;
}

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    config: options.Options,
    network: *topology.Topology,
    records: *evidence.Evidence,
    role: Role,
) !void {
    const label = @tagName(role);
    // Match SecretKey.fromSeed in the Node fixture, not another implementation's pin.
    const endpoint_a_pin = try seedPin(endpoint_a_seed);
    const endpoint_b_pin = try seedPin(endpoint_b_seed);
    var output: [3][65536]u8 = undefined;
    var errors: [3][65536]u8 = undefined;
    var children: [3]processes.Process = undefined;
    for (&children, 0..) |*child, index| child.init(&output[index], &errors[index]);
    var cleaned = false;
    defer if (!cleaned) {
        cleanup(io, &children, records, label) catch |err| {
            std.log.err("NAT owned-process cleanup/evidence failed: {s}", .{@errorName(err)});
        };
    };
    // Retain actual post-transition counters before peers and namespaces are reaped.
    errdefer {
        if (snapshot(gpa, io, network, records, label, "failed")) |_| {} else |err| {
            std.log.err("NAT failure topology evidence failed: {s}", .{@errorName(err)});
        }
    }
    try network.blockDirect();
    const baseline = try snapshot(gpa, io, network, records, label, "initial");
    var duration_buffer: [16]u8 = undefined;
    const duration = try std.fmt.bufPrint(&duration_buffer, "{d}", .{config.duration_ms});
    var relay_duration_buffer: [16]u8 = undefined;
    const relay_duration = try std.fmt.bufPrint(
        &relay_duration_buffer,
        "{d}",
        .{config.duration_ms + 5000},
    );
    try children[0].spawn(io, &.{
        config.rust_relay,
        "--protocol",
        "relay",
        "--tls",
        "iroh",
        "--role",
        "server",
        "--bind",
        "0.0.0.0:3340",
        "--seed-hex",
        "4444444444444444444444444444444444444444444444444444444444444444",
        "--for",
        relay_duration,
    });
    const deadline = now(io) + @as(i96, config.duration_ms) * std.time.ns_per_ms;
    try ready(io, &children[0], "relay-ready: url http://0.0.0.0:3340/ qad disabled\n", deadline);
    const endpoint_a_args = [_][]const u8{
        config.node_peer,
        "--protocol",
        "relay-endpoint",
        "--tls",
        "iroh",
        "--role",
        label,
        "--bind",
        "10.78.1.2:4444",
        "--seed-hex",
        endpoint_a_seed,
        "--expect-peer",
        &endpoint_b_pin,
        "--relay-url",
        "http://10.77.0.1:3340/",
        "--message",
        message,
        "--for",
        duration,
        "--local-candidate",
        "10.77.0.2:4444",
    };
    const endpoint_b_args = [_][]const u8{
        config.node_peer,
        "--protocol",
        "relay-endpoint",
        "--tls",
        "iroh",
        "--role",
        if (role == .server) "client" else "server",
        "--bind",
        "10.78.2.2:4444",
        "--seed-hex",
        endpoint_b_seed,
        "--expect-peer",
        &endpoint_a_pin,
        "--relay-url",
        "http://10.77.0.1:3340/",
        "--message",
        message,
        "--for",
        duration,
        "--local-candidate",
        "10.77.0.3:4444",
    };
    const server: usize = if (role == .server) 1 else 2;
    const client: usize = if (role == .server) 2 else 1;
    try spawnPeer(
        io,
        &children[server],
        if (server == 1) network.alice_pid else network.bob_pid,
        if (server == 1) &endpoint_a_args else &endpoint_b_args,
    );
    var ready_buffer: [128]u8 = undefined;
    const server_marker = try std.fmt.bufPrint(
        &ready_buffer,
        "relay-endpoint-ready: remote_id {s}\n",
        .{if (server == 1) &endpoint_b_pin else &endpoint_a_pin},
    );
    try ready(io, &children[server], server_marker, deadline);
    try spawnPeer(
        io,
        &children[client],
        if (client == 1) network.alice_pid else network.bob_pid,
        if (client == 1) &endpoint_a_args else &endpoint_b_args,
    );
    var scans: [2]proof.Scan = .{ .{}, .{} };
    var opened = false;
    const ticks_max = config.duration_ms / 10 + 2;
    for (0..ticks_max) |_| {
        if (now(io) >= deadline) return error.PhaseDeadline;
        for (&children, 0..) |*child, index| {
            try child.pump(io);
            const exited = try child.exited(io);
            if (index == 0 and exited) return error.RelayExitedEarly;
            if (index != 0) {
                try scans[index - 1].consume(
                    child.stdout(),
                    if (index == 1) &endpoint_b_pin else &endpoint_a_pin,
                    message,
                );
                if (exited) {
                    try child.assertSuccess();
                    if (scans[index - 1].phase2 == null) return error.PeerExitedEarly;
                }
            }
        }
        if (!opened and (scans[0].phase2 != null or scans[1].phase2 != null))
            return error.DirectBeforeTransition;
        if (!opened and scans[0].phase1 != null and scans[1].phase1 != null) {
            // Keep the gate closed until native probes have created source NAT mappings.
            const relay_evidence = try network.snapshot();
            defer gpa.free(relay_evidence);
            const relay_counters = try topology.counters(relay_evidence);
            if (try relayGateReady(baseline, relay_counters)) {
                var name_buffer: [128]u8 = undefined;
                const name = try std.fmt.bufPrint(
                    &name_buffer,
                    "{s}-relay-authenticated-topology.txt",
                    .{label},
                );
                try records.save(io, name, relay_evidence);
                try network.openDirect();
                opened = true;
            }
        }
        if (scans[0].phase2 != null and scans[1].phase2 != null and
            children[1].term != null and children[2].term != null)
        {
            if (!opened) return error.DirectBeforeTransition;
            const counters = try snapshot(gpa, io, network, records, label, "direct-authenticated");
            if (counters.direct <= baseline.direct or
                counters.translated <= baseline.translated) return error.NoPhysicalForwarding;
            try children[1].assertSuccess();
            try children[2].assertSuccess();
            try (scans[0].counts orelse return error.MissingConnectionCounts)
                .validate(role == .server);
            try (scans[1].counts orelse return error.MissingConnectionCounts)
                .validate(role != .server);
            const relay_term = try children[0].finish(io);
            switch (relay_term) {
                .signal => |signal| if (signal != std.posix.SIG.TERM)
                    return error.RelayCleanupFailed,
                .exited => |code| if (code != 0) return error.RelayCleanupFailed,
                else => return error.RelayCleanupFailed,
            }
            var summary_buffer: [1024]u8 = undefined;
            const phase_a = scans[0].phase1 orelse return error.MissingRelayPhase;
            const phase_b = scans[1].phase1 orelse return error.MissingRelayPhase;
            const summary = try std.fmt.bufPrint(
                &summary_buffer,
                "nat-smoke: endpoint_a_role {s} endpoint_a_stable_id {d} " ++
                    "endpoint_b_stable_id {d} endpoint_a_pin {s} endpoint_b_pin {s} " ++
                    "route relay->direct bytes {d} " ++
                    "payload {s} peer_exits 0,0 relay_owned_exit {s} " ++
                    "blocked_packets {d} direct_packets {d} translated_packets {d}\n",
                .{
                    label,           phase_a.stable_id,    phase_b.stable_id,
                    endpoint_a_pin,  endpoint_b_pin,       message.len,
                    message,         @tagName(relay_term), counters.blocked,
                    counters.direct, counters.translated,
                },
            );
            try std.Io.File.stdout().writeStreamingAll(io, children[1].stdout());
            try std.Io.File.stdout().writeStreamingAll(io, children[2].stdout());
            try std.Io.File.stdout().writeStreamingAll(io, summary);
            var name_buffer: [128]u8 = undefined;
            const name = try std.fmt.bufPrint(&name_buffer, "{s}-summary.txt", .{label});
            try records.save(io, name, summary);
            cleaned = true;
            try cleanup(io, &children, records, label);
            return;
        }
        try std.Io.sleep(io, .fromMilliseconds(10), .awake);
    }
    return error.PhaseDeadline;
}

fn seedPin(seed_hex: []const u8) ![64]u8 {
    var seed: [32]u8 = undefined;
    const bytes = try std.fmt.hexToBytes(&seed, seed_hex);
    if (bytes.len != seed.len) return error.InvalidSeed;
    const pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    return std.fmt.bytesToHex(&pair.public_key.toBytes(), .lower);
}

test "Node NAT pins derive from the actual fixture seeds" {
    try std.testing.expectEqualStrings(
        "0d7550754e0800a5d237eef5826035766b9b3e5a15868a940ab289958788e3b0",
        &try seedPin(endpoint_a_seed),
    );
    try std.testing.expectEqualStrings(
        "6d44f939f829d43598bcdedda90de01db69faa50caa33e8c6c328a4b900d4dac",
        &try seedPin(endpoint_b_seed),
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &try seedPin(endpoint_a_seed),
        &try seedPin(endpoint_b_seed),
    ));
}

fn spawnPeer(
    io: std.Io,
    child: *processes.Process,
    pid: std.process.Child.Id,
    args: []const []const u8,
) !void {
    var pid_buffer: [16]u8 = undefined;
    const pid_text = try std.fmt.bufPrint(&pid_buffer, "{d}", .{pid});
    var wrapper: [40][]const u8 = undefined;
    const prefix = [_][]const u8{ "nsenter", "--target", pid_text, "--net", "--no-fork", "--" };
    if (prefix.len + args.len > wrapper.len) return error.ArgumentsOverflow;
    @memcpy(wrapper[0..prefix.len], &prefix);
    @memcpy(wrapper[prefix.len..][0..args.len], args);
    try child.spawnAs(io, wrapper[0 .. prefix.len + args.len], args);
}

fn ready(io: std.Io, child: *processes.Process, marker: []const u8, deadline: i96) !void {
    for (0..12001) |_| {
        try child.pump(io);
        if (try child.exited(io)) return error.ReadinessProcessExited;
        if (std.mem.find(u8, child.stdout(), marker)) |offset| {
            if (offset == 0 or child.stdout()[offset - 1] == '\n') return;
        }
        if (now(io) >= deadline) return error.ReadinessDeadline;
        try std.Io.sleep(io, .fromMilliseconds(10), .awake);
    }
    return error.ReadinessDeadline;
}

fn snapshot(
    gpa: std.mem.Allocator,
    io: std.Io,
    network: *topology.Topology,
    records: *evidence.Evidence,
    label: []const u8,
    phase: []const u8,
) !topology.Counters {
    const bytes = try network.snapshot();
    defer gpa.free(bytes);
    var name_buffer: [128]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buffer, "{s}-{s}-topology.txt", .{ label, phase });
    try records.save(io, name, bytes);
    return topology.counters(bytes);
}

fn cleanup(
    io: std.Io,
    children: *[3]processes.Process,
    records: *evidence.Evidence,
    label: []const u8,
) !void {
    var failure: ?anyerror = null;
    for (0..children.len) |index| {
        // zbc does not infer the reverse-loop bound that keeps this subtraction positive.
        // zbc-disable-next-line: index-minus-one-without-zero-guard
        const child = &children[children.len - index - 1];
        const pid = child.pid orelse continue;
        var cleanup_error: ?anyerror = null;
        const term: ?std.process.Child.Term = child.finish(io) catch |err| failed: {
            failure = err;
            cleanup_error = err;
            break :failed child.term;
        };
        var name_buffer: [128]u8 = undefined;
        var status_buffer: [128]u8 = undefined;
        const identity = children.len - index - 1;
        const stdout_name = try std.fmt.bufPrint(
            &name_buffer,
            "{s}-process{d}-stdout.txt",
            .{ label, identity },
        );
        records.save(io, stdout_name, child.stdout()) catch |err| {
            failure = err;
        };
        const stderr_name = try std.fmt.bufPrint(
            &name_buffer,
            "{s}-process{d}-stderr.txt",
            .{ label, identity },
        );
        records.save(io, stderr_name, child.stderr()) catch |err| {
            failure = err;
        };
        const status = if (term) |value|
            try std.fmt.bufPrint(
                &status_buffer,
                "pid {d} term {s} value {d} cleanup_error {s}\n",
                .{
                    pid,
                    @tagName(value),
                    switch (value) {
                        .exited => |code| @as(u32, code),
                        .signal => |signal| @backingInt(signal),
                        .stopped => |signal| @backingInt(signal),
                        .unknown => |code| @as(u32, code),
                    },
                    if (cleanup_error) |err| @errorName(err) else "none",
                },
            )
        else
            try std.fmt.bufPrint(
                &status_buffer,
                "pid {d} cleanup_error {s}\n",
                .{ pid, @errorName(cleanup_error orelse return error.MissingCleanupError) },
            );
        const exit_name = try std.fmt.bufPrint(
            &name_buffer,
            "{s}-process{d}-exit.txt",
            .{ label, identity },
        );
        records.save(io, exit_name, status) catch |err| {
            failure = err;
        };
    }
    if (failure) |err| return err;
}

fn now(io: std.Io) i96 {
    return std.Io.Timestamp.now(io, .awake).nanoseconds;
}
