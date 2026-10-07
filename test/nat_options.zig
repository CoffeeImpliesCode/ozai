const std = @import("std");

pub const Options = struct {
    zig_peer: []const u8,
    rust_peer: []const u8,
    evidence_dir: []const u8,
    qad_cert: []const u8,
    qad_key: []const u8,
    role: enum { server, client, both } = .both,
    duration_ms: u32 = 45000,
};

test "options reject unknown missing and unbounded arguments" {
    try std.testing.expectError(error.InvalidArguments, parse(&.{"--unknown"}));
    try std.testing.expectError(error.InvalidArguments, parse(&.{"--zig-peer"}));
    try std.testing.expectError(error.InvalidArguments, parse(&.{"--for-ms", "0"}));
}

pub fn parse(args: []const []const u8) error{InvalidArguments}!Options {
    var zig_peer: ?[]const u8 = null;
    var rust_peer: ?[]const u8 = null;
    var evidence_dir: ?[]const u8 = null;
    var qad_cert: ?[]const u8 = null;
    var qad_key: ?[]const u8 = null;
    var role: @FieldType(Options, "role") = .both;
    var duration_ms: u32 = 45000;
    if (args.len > 14 or args.len % 2 != 0) return error.InvalidArguments;
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
        } else if (std.mem.eql(u8, key, "--zig-role")) {
            role = std.meta.stringToEnum(@FieldType(Options, "role"), value) orelse
                return error.InvalidArguments;
        } else if (std.mem.eql(u8, key, "--for-ms")) {
            duration_ms = std.fmt.parseInt(u32, value, 10) catch return error.InvalidArguments;
            if (duration_ms < 1000 or duration_ms > 120000) return error.InvalidArguments;
        } else return error.InvalidArguments;
    }
    return .{
        .zig_peer = zig_peer orelse return error.InvalidArguments,
        .rust_peer = rust_peer orelse return error.InvalidArguments,
        .evidence_dir = evidence_dir orelse return error.InvalidArguments,
        .qad_cert = qad_cert orelse return error.InvalidArguments,
        .qad_key = qad_key orelse return error.InvalidArguments,
        .role = role,
        .duration_ms = duration_ms,
    };
}

fn absolute(value: []const u8) error{InvalidArguments}![]const u8 {
    if (!std.fs.path.isAbsolute(value) or value.len > 4096 or
        std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidArguments;
    return value;
}
