const std = @import("std");
const files = @import("gate_files.zig");
const inventory = @import("gate_sources.zig");

pub const Allocator = std.mem.Allocator;
pub const Source = inventory.Source;
pub const Artifact = files.Artifact;
pub const readFile = files.readFile;
pub const hashBytes = files.hashBytes;
pub const artifact = files.artifact;
pub const sources = inventory.sources;
pub const sourceDigest = inventory.sourceDigest;
pub const createRoot = @import("gate_scratch.zig").createRoot;
pub const validateRoot = @import("gate_scratch.zig").validateRoot;

pub const Runner = struct {
    gpa: Allocator,
    io: std.Io,
    environment: *std.process.Environ.Map,
    root: []const u8,

    pub fn path(self: Runner, relative: []const u8) ![]const u8 {
        return std.fs.path.join(self.gpa, &.{ self.root, relative });
    }

    pub fn run(self: Runner, label: []const u8, argv: []const []const u8) !std.process.RunResult {
        const result = try std.process.run(self.gpa, self.io, .{
            .argv = argv,
            .environ_map = self.environment,
            .expand_arg0 = .expand,
        });
        errdefer {
            self.gpa.free(result.stdout);
            self.gpa.free(result.stderr);
        }
        try self.writeLog(label, "stdout", result.stdout);
        try self.writeLog(label, "stderr", result.stderr);
        const command = try std.json.Stringify.valueAlloc(self.gpa, argv, .{});
        defer self.gpa.free(command);
        try self.writeLog(label, "command.json", command);
        switch (result.term) {
            .exited => |code| if (code != 0) {
                std.log.err("{s} failed (exit {d}); retained evidence: {s}", .{
                    label, code, self.root,
                });
                return error.CommandFailed;
            },
            else => return error.CommandFailed,
        }
        return result;
    }

    fn writeLog(self: Runner, label: []const u8, suffix: []const u8, data: []const u8) !void {
        const name = try std.fmt.allocPrint(self.gpa, "{s}.{s}", .{ label, suffix });
        defer self.gpa.free(name);
        const destination = try self.path(name);
        defer self.gpa.free(destination);
        try std.Io.Dir.cwd().writeFile(self.io, .{ .sub_path = destination, .data = data });
    }
};

test "runner paths place process evidence in its retained root" {
    const runner: Runner = .{
        .gpa = std.testing.allocator,
        .io = undefined,
        .environment = undefined,
        .root = "/approved/evidence",
    };
    const destination = try runner.path("compiler.stdout");
    defer std.testing.allocator.free(destination);
    try std.testing.expectEqualStrings("/approved/evidence/compiler.stdout", destination);
}
