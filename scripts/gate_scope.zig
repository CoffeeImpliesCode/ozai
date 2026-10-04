//! What the gate measures: the exact file list every scoped command gets, the
//! roots that must sweep declarations, the compiler it runs, and the hashes
//! that make a receipt replayable.
//!
//! Nothing here reads the environment to decide what the source is. The file
//! list is walked from the working directory, each file is read exactly once to
//! digest it, and every command that is scoped is handed that same list — so
//! "which files" and "which bytes of which files" are answers the receipt can
//! carry rather than conventions a tool re-derives for itself.

const std = @import("std");
const proc = @import("gate_child.zig");

/// Build output, version-control metadata and the toolchain store. Named,
/// because this walk is what gives `ast-check`, the lint scopes and the
/// receipts their file list.
const skipped_dirs = [_][]const u8{
    ".git",
    ".jj",
    ".zig-cache",
    "zig-cache",
    "zig-global-cache",
    "zig-out",
};

/// A walk that cannot stop growing is not a walk. Exceeding either bound is a
/// refusal, never a quietly truncated scope.
const max_source_files = 4096;
const max_walk_depth = 8;

/// Roots whose job includes reaching declarations nothing else references. A
/// root that dropped its sweep still compiles, still runs, and still exits 0,
/// so its presence is checked by name rather than assumed.
pub const sweep_roots = [_][]const u8{
    "src/root.zig",
    "src/portable_test.zig",
    "vendor/quic/src/test_all.zig",
};

/// The compiler this gate runs, as facts a receipt can carry.
pub const Compiler = struct {
    /// What the caller asked for, kept beside what was actually resolved.
    requested: []const u8,
    path: []const u8,
    bin_dir: []const u8,
    lib_dir: []const u8,
    version: []const u8,
    pin: []const u8,
};

/// One hashed file: the path as the gate names it, and its content digest.
pub const Hashed = struct {
    path: []const u8,
    sha256: [64]u8,
};

pub const Scope = struct {
    /// Every `.zig` file in the tree, sorted, relative to the working
    /// directory. Compiled, formatted and syntax-checked from this list.
    all: []const []const u8,
    /// The same list without `vendor/`. The vendored tree is third-party source
    /// that is compiled and checked like everything else; the *text* linters
    /// are the ones this repository holds itself to, and they are the ones that
    /// exclude it, with the decision recorded in `devenv.nix` and `README.md`.
    first_party: []const []const u8,
    /// Parallel to `all`, and read while walking it: the scope's content
    /// digests, so no second pass over the tree is needed to fill a receipt.
    hashes: []const Hashed,

    pub fn collect(gpa: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !Scope {
        var all: std.ArrayList([]const u8) = .empty;
        try walk(gpa, io, dir, "", 0, &all);
        std.mem.sort([]const u8, all.items, {}, lessThanPath);
        var hashes: std.ArrayList(Hashed) = .empty;
        for (all.items) |path| try hashes.append(gpa, try hashFile(io, dir, path));
        var first_party: std.ArrayList([]const u8) = .empty;
        for (all.items) |path| {
            if (std.mem.startsWith(u8, path, "vendor/")) continue;
            try first_party.append(gpa, path);
        }
        return .{
            .all = all.items,
            .first_party = first_party.items,
            .hashes = hashes.items,
        };
    }

    /// The digest this run read for `path`, or null when the path is not part
    /// of the scope. A null here means the file is one the gate never read, so
    /// nothing about it can be asserted.
    pub fn digestOf(self: Scope, path: []const u8) ?[64]u8 {
        const index = std.sort.binarySearch(
            []const u8,
            self.all,
            path,
            digestOfCallback,
        ) orelse return null;
        return self.hashes[index].sha256;
    }
};

fn lessThanPath(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.lessThan(u8, left, right);
}

fn digestOfCallback(path: []const u8, candidate: []const u8) std.math.Order {
    return std.mem.order(u8, path, candidate);
}

fn walk(
    gpa: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    prefix: []const u8,
    depth: usize,
    out: *std.ArrayList([]const u8),
) !void {
    if (depth > max_walk_depth) return error.SourceTreeTooDeep;
    var entries = dir.iterate();
    while (try entries.next(io)) |entry| {
        if (out.items.len >= max_source_files) return error.SourceTreeTooLarge;
        if (entry.kind == .directory) {
            if (isSkipped(entry.name)) continue;
            var sub = try dir.openDir(io, entry.name, .{ .iterate = true });
            defer sub.close(io);
            try walk(gpa, io, sub, try std.fmt.allocPrint(gpa, "{s}{s}/", .{
                prefix,
                entry.name,
            }), depth + 1, out);
            continue;
        }
        if (!std.mem.endsWith(u8, entry.name, ".zig")) continue;
        try out.append(gpa, try std.fmt.allocPrint(gpa, "{s}{s}", .{ prefix, entry.name }));
    }
}

fn isSkipped(name: []const u8) bool {
    for (skipped_dirs) |skipped| {
        if (std.mem.eql(u8, skipped, name)) return true;
    }
    return false;
}

/// Whether a root reaches declarations. Parsed rather than grepped, so a
/// mention of the name in a comment is not mistaken for the call.
pub fn sweepsDecls(gpa: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8) !bool {
    const source = try dir.readFileAlloc(io, path, gpa, .limited(1 << 22));
    var ast = try std.zig.Ast.parse(gpa, try gpa.dupeZ(u8, source), .zig);
    defer ast.deinit(gpa);
    for (ast.tokens.items(.tag), 0..) |tag, index| {
        if (tag != .identifier) continue;
        if (std.mem.eql(u8, ast.tokenSlice(@intCast(index)), "refAllDecls")) return true;
    }
    return false;
}

pub fn sha256Hex(bytes: []const u8) [64]u8 {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

/// A content digest read in fixed-size chunks: the compiler is tens of
/// megabytes, and a receipt that could only be produced by holding one in
/// memory would be a receipt nobody runs.
pub fn hashFile(io: std.Io, dir: std.Io.Dir, path: []const u8) !Hashed {
    // The handle is closed by the `defer` on the next line when the loop below
    // ends and when any `try` in it unwinds, so the file is released on every
    // path; the engine does not follow a `defer` to the scope exit it arms.
    // zwanzig-disable-next-line: store-violations-engine
    var file = try dir.openFile(io, path, .{});
    defer file.close(io);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    while (true) {
        const got = file.readStreaming(io, &.{&buffer}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        hasher.update(buffer[0..got]);
    }
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    hasher.final(&digest);
    return .{ .path = path, .sha256 = std.fmt.bytesToHex(digest, .lower) };
}

/// A compiler named by path is that file; a bare name is looked up in PATH, so
/// a receipt naming the compiler names the file that ran rather than whatever
/// the name happened to resolve to on another host.
pub fn resolveOnPath(
    gpa: std.mem.Allocator,
    io: std.Io,
    requested: []const u8,
    search: ?[]const u8,
) ![]const u8 {
    const cwd = std.Io.Dir.cwd();
    if (std.mem.indexOfScalar(u8, requested, '/') != null or search == null) {
        return cwd.realPathFileAlloc(io, requested, gpa);
    }
    var directories = std.mem.splitScalar(u8, search.?, ':');
    while (directories.next()) |directory| {
        if (directory.len == 0) continue;
        const candidate = try std.Io.Dir.path.join(gpa, &.{ directory, requested });
        if (cwd.realPathFileAlloc(io, candidate, gpa)) |resolved| return resolved else |_| {}
    }
    return error.ToolNotFound;
}

/// `.minimum_zig_version`, read from the manifest the build itself is pinned by
/// rather than from a second copy of the pin kept for the gate to check.
pub fn minimumZigVersion(gpa: std.mem.Allocator, io: std.Io) ![]const u8 {
    const manifest = try std.Io.Dir.cwd().readFileAlloc(
        io,
        "build.zig.zon",
        gpa,
        .limited(1 << 16),
    );
    const key = ".minimum_zig_version = \"";
    const start = std.mem.indexOf(u8, manifest, key) orelse return error.NoVersionPin;
    const rest = manifest[start + key.len ..];
    const end = std.mem.indexOfScalar(u8, rest, '"') orelse return error.NoVersionPin;
    return gpa.dupe(u8, rest[0..end]);
}

/// The compiler's own answer to `zig version`. A shim that cannot extract its
/// toolchain exits 1 having printed nothing, which is a refusal here rather
/// than an empty version string to be compared against.
pub fn readVersion(gpa: std.mem.Allocator, io: std.Io, zig: []const u8) ![]const u8 {
    var child = try std.process.spawn(io, .{ .argv = &.{ zig, "version" }, .stdout = .pipe });
    var buffer: [256]u8 = undefined;
    // `.stdout = .pipe` is named in the `spawn` on the line above, so the
    // optional is null only if that option changed; a null here would mean the
    // reader below had nothing to read, which is a defect rather than a
    // shape of answer.
    // zwanzig-disable-next-line: optional-unwrap
    var reader = child.stdout.?.readerStreaming(io, &buffer);
    // The child is this function's from the spawn onward: a version read that
    // gives up — on the limit, or on a wait that could not be waited for —
    // still has to terminate the probe it started, or the refusal below is
    // recorded over a process nothing reaps.
    const printed = reader.interface.allocRemaining(gpa, .limited(64)) catch |err| {
        proc.dispose(io, &child);
        return err;
    };
    const code = switch (try proc.wait(io, &child)) {
        .exited => |status| status,
        else => return error.CompilerUnresolved,
    };
    if (code != 0) return error.CompilerUnresolved;
    const version = std.mem.trim(u8, printed, " \t\r\n");
    if (version.len == 0) return error.CompilerUnresolved;
    return version;
}
