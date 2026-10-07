const std = @import("std");
const Dir = std.Io.Dir;

// Re-source the host policy, then prove ownership and the selected physical mount.
// Positional arguments prevent shell interpretation of environment paths.
const validate_script =
    \\set -eu
    \\expected=$1
    \\helper=$2
    \\[ -f "$helper" ] && [ -r "$helper" ]
    \\. "$helper"
    \\[ "${HOST_SCRATCH_ROOT:-}" = "$expected" ]
    \\[ -d "$expected" ] && [ -O "$expected" ] && [ -w "$expected" ]
    \\[ ! -L "$expected" ]
    \\base=$(dirname -- "$expected")
    \\case "$base" in /home/tmp2|/home/tmp|/vol/tmp2|/vol/tmp) ;; *) exit 1;; esac
    \\[ -d "$base" ] && [ -w "$base" ] && mountpoint -q -- "$base"
    \\physical_base=$(realpath -e -- "$base")
    \\physical_root=$(realpath -e -- "$expected")
    \\[ "$(dirname -- "$physical_root")" = "$physical_base" ]
    \\mount=$(findmnt -n -o TARGET --target "$physical_root")
    \\[ "$(realpath -e -- "$mount")" = "$physical_base" ]
    \\filesystem=$(findmnt -n -o FSTYPE --target "$physical_root")
    \\case "$filesystem" in ''|nfs|nfs4) exit 1;; esac
    \\scratch="$expected/scratch"
    \\[ -d "$scratch" ] && [ -O "$scratch" ] && [ -w "$scratch" ]
    \\[ ! -L "$scratch" ]
    \\physical_scratch=$(realpath -e -- "$scratch")
    \\[ "$(dirname -- "$physical_scratch")" = "$physical_root" ]
    \\target=$3
    \\if [ -n "$target" ]; then
    \\    [ -d "$target" ] && [ ! -L "$target" ]
    \\    physical_target=$(realpath -e -- "$target")
    \\    case "$physical_target" in "$physical_scratch"/*) ;; *) exit 1;; esac
    \\    target_mount=$(findmnt -n -o TARGET --target "$physical_target")
    \\    [ "$(realpath -e -- "$target_mount")" = "$physical_base" ]
    \\    current=$physical_target
    \\    remaining=256
    \\    while [ "$current" != "$physical_scratch" ]; do
    \\        [ "$remaining" -gt 0 ] || exit 1
    \\        [ -d "$current" ] && [ -O "$current" ] && [ -w "$current" ]
    \\        current=$(dirname -- "$current")
    \\        remaining=$((remaining - 1))
    \\    done
    \\fi
    \\printf '%s\n' "$physical_scratch"
;

fn validatedScratch(gpa: std.mem.Allocator, io: std.Io,
    environment: *const std.process.Environ.Map, target: []const u8) ![]const u8
{
    const selected = environment.get("HOST_SCRATCH_ROOT") orelse return error.MissingScratch;
    if (!std.fs.path.isAbsolute(selected)) return error.UnapprovedScratch;
    const home = environment.get("HOME") orelse return error.MissingHome;
    if (!std.fs.path.isAbsolute(home)) return error.MissingHome;
    const helper = try std.fs.path.join(gpa, &.{ home, ".local", "lib", "host-scratch.sh" });
    defer gpa.free(helper);
    const checked = try std.process.run(gpa, io, .{
        .argv = &.{ "bash", "-c", validate_script, "gate-scratch", selected, helper, target },
        .environ_map = environment,
        .expand_arg0 = .expand,
    });
    defer gpa.free(checked.stdout);
    defer gpa.free(checked.stderr);
    switch (checked.term) {
        .exited => |code| if (code != 0) {
            std.log.err("host scratch validation failed: {s}", .{checked.stderr});
            return error.UnapprovedScratch;
        },
        else => return error.UnapprovedScratch,
    }
    const scratch = std.mem.trim(u8, checked.stdout, "\r\n");
    if (!std.fs.path.isAbsolute(scratch) or std.mem.indexOfScalar(u8, scratch, '\n') != null)
        return error.UnapprovedScratch;
    return gpa.dupe(u8, scratch);
}

pub fn validateRoot(gpa: std.mem.Allocator, io: std.Io,
    environment: *const std.process.Environ.Map, path: []const u8) !void
{
    if (!std.fs.path.isAbsolute(path)) return error.UnapprovedScratch;
    const scratch = try validatedScratch(gpa, io, environment, path);
    defer gpa.free(scratch);
}

pub fn createRoot(init: std.process.Init, environment: *std.process.Environ.Map) ![]const u8 {
    const gpa = init.arena.allocator();
    const scratch = try validatedScratch(gpa, init.io, environment, "");
    defer gpa.free(scratch);
    // Forward the proven scratch directory, never a caller-supplied alternative.
    try environment.put("GATE_SCRATCH", scratch);
    var random: [16]u8 = undefined;
    try init.io.randomSecure(&random);
    const name = try std.fmt.allocPrint(gpa, "ozai-gate-{s}", .{
        std.fmt.bytesToHex(random, .lower),
    });
    defer gpa.free(name);
    const root = try std.fs.path.join(gpa, &.{ scratch, name });
    errdefer gpa.free(root);
    // Exclusive creation avoids accepting a pre-existing directory or symlink.
    try Dir.cwd().createDir(init.io, root, .fromMode(0o700));
    std.log.info("retained gate evidence: {s}", .{root});
    return root;
}
