const std = @import("std");
const process = @import("nat_process.zig");

pub const Options = struct {
    zig_peer: []const u8,
    rust_peer: []const u8,
    evidence_dir: []const u8,
    qad_cert: []const u8,
    qad_key: []const u8,
    baseline: process.Baseline,
    role: enum { server, client, both } = .both,
    duration_ms: u32 = 45000,
};

test "options reject unknown missing and unbounded arguments" {
    try std.testing.expectError(error.InvalidArguments, parse(&.{"--unknown"}));
    try std.testing.expectError(error.InvalidArguments, parse(&.{"--zig-peer"}));
    try std.testing.expectError(error.InvalidArguments, parse(&.{"--for-ms", "0"}));
}

test "options require both explicit outside namespace baselines" {
    const paths = [_][]const u8{
        "--zig-peer", "/zig", "--rust-peer", "/rust", "--evidence-dir", "/evidence",
        "--qad-cert", "/cert", "--qad-key", "/key",
    };
    try std.testing.expectError(error.InvalidArguments, parse(&paths));
    try std.testing.expectError(error.InvalidArguments,
        parse(&(paths ++ .{ "--original-netns", "net:[1]" })));
    try std.testing.expectError(error.InvalidArguments,
        parse(&(paths ++ .{ "--original-userns", "user:[2]" })));
    const parsed = try parse(&(paths ++ .{
        "--original-netns", "net:[1]", "--original-userns", "user:[2]",
        "--zig-role", "server", "--for-ms", "1000",
    }));
    try std.testing.expectEqualStrings("net:[1]", parsed.baseline.net);
    try std.testing.expectEqualStrings("user:[2]", parsed.baseline.user);
}

test "options reject malformed namespace flags and duplicate flags" {
    const paths = [_][]const u8{
        "--zig-peer", "/zig", "--rust-peer", "/rust", "--evidence-dir", "/evidence",
        "--qad-cert", "/cert", "--qad-key", "/key",
    };
    var arguments = paths ++ .{
        "--original-netns", "net:[1]", "--original-userns", "user:[2]",
    };
    for ([_][]const u8{ "", "net:[0]", "net:[01]", "net:[+1]", "net:[1]\n",
        "net:[18446744073709551616]", "user:[1]" }) |net| {
        arguments[11] = net;
        try std.testing.expectError(error.InvalidArguments, parse(&arguments));
    }
    arguments[11] = "net:[1]";
    for ([_][]const u8{ "", "user:[0]", "user:[02]", "user:[ 2]", "net:[2]" }) |user| {
        arguments[13] = user;
        try std.testing.expectError(error.InvalidArguments, parse(&arguments));
    }
    const required = paths ++ .{ "--original-netns", "net:[1]", "--original-userns", "user:[2]" };
    var duplicate = required ++ .{ "--original-netns", "net:[3]" };
    for ([_][]const u8{ "--original-netns", "--original-userns" }) |flag| {
        duplicate[14] = flag;
        try std.testing.expectError(error.InvalidArguments, parse(&duplicate));
    }
    try std.testing.expectError(error.InvalidArguments,
        parse(&(required ++ .{ "--zig-role", "server", "--zig-role", "client" })));
    try std.testing.expectError(error.InvalidArguments,
        parse(&(required ++ .{ "--for-ms", "1000", "--for-ms", "2000" })));
}

pub fn parse(args: []const []const u8) error{InvalidArguments}!Options {
    var zig_peer: ?[]const u8 = null;
    var rust_peer: ?[]const u8 = null;
    var evidence_dir: ?[]const u8 = null;
    var qad_cert: ?[]const u8 = null;
    var qad_key: ?[]const u8 = null;
    var original_netns: ?[]const u8 = null;
    var original_userns: ?[]const u8 = null;
    var role: @FieldType(Options, "role") = .both;
    var duration_ms: u32 = 45000;
    var role_seen = false;
    var duration_seen = false;
    if (args.len > 18 or args.len % 2 != 0) return error.InvalidArguments;
    var index: usize = 0;
    while (index < args.len) : (index += 2) {
        const key = args[index];
        const value = args[index + 1];
        if (std.mem.eql(u8, key, "--zig-peer")) {
            if (zig_peer != null) return error.InvalidArguments;
            zig_peer = try absolute(value);
        } else if (std.mem.eql(u8, key, "--rust-peer")) {
            if (rust_peer != null) return error.InvalidArguments;
            rust_peer = try absolute(value);
        } else if (std.mem.eql(u8, key, "--evidence-dir")) {
            if (evidence_dir != null) return error.InvalidArguments;
            evidence_dir = try absolute(value);
        } else if (std.mem.eql(u8, key, "--qad-cert")) {
            if (qad_cert != null) return error.InvalidArguments;
            qad_cert = try absolute(value);
        } else if (std.mem.eql(u8, key, "--qad-key")) {
            if (qad_key != null) return error.InvalidArguments;
            qad_key = try absolute(value);
        } else if (std.mem.eql(u8, key, "--original-netns")) {
            if (original_netns != null) return error.InvalidArguments;
            original_netns = value;
        } else if (std.mem.eql(u8, key, "--original-userns")) {
            if (original_userns != null) return error.InvalidArguments;
            original_userns = value;
        } else if (std.mem.eql(u8, key, "--zig-role")) {
            if (role_seen) return error.InvalidArguments;
            role_seen = true;
            role = std.meta.stringToEnum(@FieldType(Options, "role"), value) orelse
                return error.InvalidArguments;
        } else if (std.mem.eql(u8, key, "--for-ms")) {
            if (duration_seen) return error.InvalidArguments;
            duration_seen = true;
            duration_ms = std.fmt.parseInt(u32, value, 10) catch return error.InvalidArguments;
            if (duration_ms < 1000 or duration_ms > 120000) return error.InvalidArguments;
        } else return error.InvalidArguments;
    }
    const baseline: process.Baseline = .{
        .net = original_netns orelse return error.InvalidArguments,
        .user = original_userns orelse return error.InvalidArguments,
    };
    process.validateBaseline(baseline) catch return error.InvalidArguments;
    return .{
        .zig_peer = zig_peer orelse return error.InvalidArguments,
        .rust_peer = rust_peer orelse return error.InvalidArguments,
        .evidence_dir = evidence_dir orelse return error.InvalidArguments,
        .qad_cert = qad_cert orelse return error.InvalidArguments,
        .qad_key = qad_key orelse return error.InvalidArguments,
        .baseline = baseline,
        .role = role,
        .duration_ms = duration_ms,
    };
}

fn absolute(value: []const u8) error{InvalidArguments}![]const u8 {
    if (!std.fs.path.isAbsolute(value) or value.len > 4096 or
        std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidArguments;
    return value;
}
