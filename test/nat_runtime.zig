const std = @import("std");
const processes = @import("nat_process.zig");
const topology = @import("nat_topology.zig");
const evidence = @import("nat_evidence.zig");
const options = @import("nat_options.zig");
const proof = @import("nat_proof.zig");

const zig_pin = "0d7550754e0800a5d237eef5826035766b9b3e5a15868a940ab289958788e3b0";
const rust_pin = "6d44f939f829d43598bcdedda90de01db69faa50caa33e8c6c328a4b900d4dac";
const message = "ozai-rootless-nat-same-connection";
const Role = enum { server, client };

pub fn run(io: std.Io, gpa: std.mem.Allocator, config: options.Options,
    network: *topology.Topology, records: *evidence.Evidence, role: Role) !void
{
    const label = @tagName(role);
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
        if (snapshot(io, gpa, network, records, label, "failed")) |_| {} else |err| {
            std.log.err("NAT failure topology evidence failed: {s}", .{@errorName(err)});
        }
    }
    try network.blockDirect();
    const baseline = try snapshot(io, gpa, network, records, label, "initial");
    var duration_buffer: [16]u8 = undefined;
    const duration = try std.fmt.bufPrint(&duration_buffer, "{d}", .{config.duration_ms});
    var relay_duration_buffer: [16]u8 = undefined;
    const relay_duration = try std.fmt.bufPrint(&relay_duration_buffer, "{d}",
        .{config.duration_ms + 5000});
    try children[0].spawn(io, &.{ config.rust_peer, "--protocol", "relay", "--tls",
        "iroh", "--role", "server", "--bind", "0.0.0.0:3340", "--seed-hex",
        "44" ** 32, "--for", relay_duration, "--relay-qad-bind", "0.0.0.0:3341",
        "--relay-qad-cert", config.qad_cert, "--relay-qad-key", config.qad_key });
    const deadline = now(io) + @as(i96, config.duration_ms) * std.time.ns_per_ms;
    try ready(io, &children[0],
        "relay-ready: url http://0.0.0.0:3340/ qad 0.0.0.0:3341\n", deadline);
    const zig_args = [_][]const u8{ config.zig_peer, "--protocol", "relay-endpoint",
        "--tls", "iroh", "--role", label, "--bind", "10.78.1.2:4444", "--seed-hex",
        "5a" ** 32, "--expect-peer", rust_pin, "--relay-url", "http://10.77.0.1:3340/",
        "--message", message, "--for", duration, "--local-candidate", "10.77.0.2:4444" };
    const rust_args = [_][]const u8{ config.rust_peer, "--protocol", "relay-endpoint",
        "--tls", "iroh", "--role", if (role == .server) "client" else "server",
        "--bind", "10.78.2.2:4444", "--seed-hex", "6c" ** 32, "--expect-peer", zig_pin,
        "--relay-url", "http://10.77.0.1:3340/", "--message", message, "--for", duration,
        "--relay-qad-bind", "10.77.0.1:3341", "--relay-qad-cert", config.qad_cert };
    const server: usize = if (role == .server) 1 else 2;
    const client: usize = if (role == .server) 2 else 1;
    try spawnPeer(io, &children[server], if (server == 1) network.alice_pid else
        network.bob_pid, if (server == 1) &zig_args else &rust_args);
    try ready(io, &children[server], if (server == 1)
        "relay-endpoint-ready: remote_id " ++ rust_pin ++ "\n" else
        "relay-endpoint-ready: remote_id " ++ zig_pin ++ "\n", deadline);
    try spawnPeer(io, &children[client], if (client == 1) network.alice_pid else
        network.bob_pid, if (client == 1) &zig_args else &rust_args);
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
                try scans[index - 1].consume(child.stdout(),
                    if (index == 1) rust_pin else zig_pin, message);
                if (exited) {
                    try child.assertSuccess();
                    if (scans[index - 1].phase2 == null) return error.PeerExitedEarly;
                }
            }
        }
        if (!opened and (scans[0].phase2 != null or scans[1].phase2 != null))
            return error.DirectBeforeTransition;
        if (!opened and scans[0].phase1 != null and scans[1].phase1 != null) {
            const relay_counters = try snapshot(io, gpa, network, records,
                label, "relay-authenticated");
            if (relay_counters.direct != baseline.direct) return error.InitialUdpNotBlocked;
            try network.openDirect();
            opened = true;
        }
        if (scans[0].phase2 != null and scans[1].phase2 != null and
            children[1].term != null and children[2].term != null) {
            if (!opened) return error.DirectBeforeTransition;
            const counters = try snapshot(io, gpa, network, records,
                label, "direct-authenticated");
            if (counters.direct <= baseline.direct or
                counters.masqueraded <= baseline.masqueraded) return error.NoPhysicalForwarding;
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
            const summary = try std.fmt.bufPrint(&summary_buffer,
                "nat-smoke: zig_role {s} zig_stable_id {d} rust_stable_id {d} " ++
                "zig_pin {s} rust_pin {s} route relay->direct bytes {d} " ++
                "payload {s} peer_exits 0,0 relay_owned_exit {s} " ++
                "blocked_packets {d} direct_packets {d} masqueraded_packets {d}\n",
                .{ label, scans[0].phase1.?.stable_id, scans[1].phase1.?.stable_id,
                    zig_pin, rust_pin, message.len, message, @tagName(relay_term),
                    counters.blocked, counters.direct, counters.masqueraded });
            try std.Io.File.stdout().writeStreamingAll(io, children[1].stdout());
            try std.Io.File.stdout().writeStreamingAll(io, children[2].stdout());
            try std.Io.File.stdout().writeStreamingAll(io, summary);
            var name_buffer: [128]u8 = undefined;
            try records.save(io, try std.fmt.bufPrint(&name_buffer,
                "{s}-summary.txt", .{label}), summary);
            cleaned = true;
            try cleanup(io, &children, records, label);
            return;
        }
        try std.Io.sleep(io, .fromMilliseconds(10), .awake);
    }
    return error.PhaseDeadline;
}

fn spawnPeer(io: std.Io, child: *processes.Process, pid: std.process.Child.Id,
    args: []const []const u8) !void
{
    var pid_buffer: [16]u8 = undefined;
    const pid_text = try std.fmt.bufPrint(&pid_buffer, "{d}", .{pid});
    var wrapper: [40][]const u8 = undefined;
    const prefix = [_][]const u8{ "nsenter", "--target", pid_text,
        "--net", "--no-fork", "--" };
    if (prefix.len + args.len > wrapper.len) return error.ArgumentsOverflow;
    @memcpy(wrapper[0..prefix.len], &prefix);
    @memcpy(wrapper[prefix.len..][0..args.len], args);
    try child.spawnAs(io, wrapper[0 .. prefix.len + args.len], args);
}

fn ready(io: std.Io, child: *processes.Process, marker: []const u8, deadline: i96) !void {
    for (0..12001) |_| {
        try child.pump(io);
        if (try child.exited(io)) return error.ReadinessProcessExited;
        if (std.mem.indexOf(u8, child.stdout(), marker)) |offset| {
            if (offset == 0 or child.stdout()[offset - 1] == '\n') return;
        }
        if (now(io) >= deadline) return error.ReadinessDeadline;
        try std.Io.sleep(io, .fromMilliseconds(10), .awake);
    }
    return error.ReadinessDeadline;
}

fn snapshot(io: std.Io, gpa: std.mem.Allocator, network: *topology.Topology,
    records: *evidence.Evidence, label: []const u8, phase: []const u8) !topology.Counters
{
    const bytes = try network.snapshot();
    defer gpa.free(bytes);
    var name_buffer: [128]u8 = undefined;
    try records.save(io, try std.fmt.bufPrint(&name_buffer,
        "{s}-{s}-topology.txt", .{ label, phase }), bytes);
    return topology.counters(bytes);
}

fn cleanup(io: std.Io, children: *[3]processes.Process, records: *evidence.Evidence,
    label: []const u8) !void
{
    var failure: ?anyerror = null;
    for (0..children.len) |index| {
        const child = &children[children.len - index - 1];
        if (child.pid == null) continue;
        var cleanup_error: ?anyerror = null;
        const term: ?std.process.Child.Term = child.finish(io) catch |err| failed: {
            failure = err;
            cleanup_error = err;
            break :failed child.term;
        };
        var name_buffer: [128]u8 = undefined;
        var status_buffer: [128]u8 = undefined;
        const identity = children.len - index - 1;
        records.save(io, try std.fmt.bufPrint(&name_buffer,
            "{s}-process{d}-stdout.txt", .{ label, identity }), child.stdout()) catch |err| {
            failure = err;
        };
        records.save(io, try std.fmt.bufPrint(&name_buffer,
            "{s}-process{d}-stderr.txt", .{ label, identity }), child.stderr()) catch |err| {
            failure = err;
        };
        const status = if (term) |value| try std.fmt.bufPrint(&status_buffer,
            "pid {d} term {s} value {d} cleanup_error {s}\n",
            .{ child.pid.?, @tagName(value),
                switch (value) {
                    .exited => |code| @as(u32, code),
                    .signal => |signal| @intFromEnum(signal),
                    .stopped => |signal| @intFromEnum(signal),
                    .unknown => |code| @as(u32, code),
                }, if (cleanup_error) |err| @errorName(err) else "none" })
            else try std.fmt.bufPrint(&status_buffer,
            "pid {d} cleanup_error {s}\n", .{ child.pid.?, @errorName(cleanup_error.?) });
        records.save(io, try std.fmt.bufPrint(&name_buffer,
            "{s}-process{d}-exit.txt", .{ label, identity }), status) catch |err| {
            failure = err;
        };
    }
    if (failure) |err| return err;
}

fn now(io: std.Io) i96 {
    return std.Io.Timestamp.now(io, .awake).nanoseconds;
}
