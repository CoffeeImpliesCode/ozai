//! Where a gate run is allowed to write anything.
//!
//! House rules: never inside the source repository, never through a network
//! mount, never in one of the small system temporaries. The compiler picks its
//! own default for every one of those locations, and its defaults are not the
//! house convention, so this module is where a run is told which roots it has
//! and where it is told no.
//!
//! Every check here runs before a single child is spawned. A gate that notices
//! it has been building into the repository only after the suite finished has
//! already done the thing it was supposed to prevent, and what it leaves behind
//! is a dirty tree rather than a refusal.
//!
//! Every rule is decided on where a path lands, not on how it is written: each
//! one is resolved through every ancestor that exists before it is compared
//! against a root, because a prefix of the spelling stops being a prefix of
//! the location the moment a symlink or a `..` is in it. A `..` component is
//! still refused rather than resolved — a rule about a resolved path cannot
//! report what the caller actually wrote.

const std = @import("std");

/// What a child inherits that decides where a build lands. Unset is a refusal,
/// not a warning: the fallback for each of these is a location this repository
/// does not use, and a warning about it is how a run ends up there anyway.
pub const required_variables = [_][]const u8{
    "TMPDIR",
    "TMP",
    "TEMP",
    "ZIG_GLOBAL_CACHE_DIR",
    "ZIG_LOCAL_CACHE_DIR",
};

/// The host convention's scratch root (`host-scratch.sh`). When this machine
/// exports it, nothing this gate writes may sit outside it.
pub const scratch_root_variable = "HOST_SCRATCH_ROOT";

/// Everything the receipt carries from the environment: the variables this
/// module refuses a run over, plus the host convention's root and the PATH the
/// external tools were resolved through.
pub const recorded_variables = required_variables ++ [_][]const u8{
    scratch_root_variable,
    "PATH",
};

/// The two system temporaries the house rules name outright. Everything else is
/// covered by the rules that need no list: a path inside the source repository,
/// a path outside the approved local root, and a path on a network mount are
/// each refused by containment, not by being named here.
pub const denied_roots = [_][]const u8{ "/tmp", "/var/tmp" };

/// Filesystem types a cache must never be written through: a shared network
/// cache is not a cache, it is a lock every user on the mount contends for.
pub const denied_filesystems = [_][]const u8{
    "nfs",  "nfs4", "nfsd",  "9p",
    "cifs", "smb3", "smbfs", "sshfs",
    "ceph",
};

pub const Layout = struct {
    /// The approved local scratch root this run may write into.
    scratch: []const u8,
    /// Where `zig build` writes its artifacts.
    prefix: []const u8,
    /// Where this run's receipt is written.
    receipts: []const u8,
    /// Whether the host published its mount table. Recorded because a refusal
    /// that rested on a check which could not run has to say which rules it did
    /// not get to apply.
    mount_types_checked: bool,
};

pub const Refusal = struct {
    /// The variable, or the flag the caller used, that is not allowed.
    subject: []const u8,
    /// Why, in the words the caller needs to fix it.
    reason: []const u8,
};

pub const Plan = union(enum) {
    ok: Layout,
    refused: Refusal,
};

/// The roots a run is measured against, resolved once.
const Rulings = struct {
    /// The source repository, canonical: nothing may land in it.
    repo: []const u8,
    /// The mount table, for the network-filesystem rule.
    mounts: Mounts,
    /// The host convention's root, canonical, when this host exports one.
    host_scratch: ?[]const u8,
};

/// Where a path lands, and the first rule that forbids it if any does.
const Landing = struct {
    canonical: []const u8,
    reason: ?[]const u8,
};

/// The deepest existing directory a path reaches, and the part of it that does
/// not exist yet.
const Walk = struct {
    dir: std.Io.Dir,
    tail: []const u8,
};

/// Decide where this run writes, or name the first thing that forbids it.
/// `--scratch` is the root; `--prefix` and `--receipts` are honoured only
/// inside it, because an output path outside the approved root is exactly the
/// thing this module exists to prevent.
pub fn plan(
    gpa: std.mem.Allocator,
    io: std.Io,
    scratch: ?[]const u8,
    prefix: ?[]const u8,
    receipts: ?[]const u8,
    environ: *const std.process.Environ.Map,
) !Plan {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    // The handle is closed by the `defer` on the next line, on every path out
    // of this function — including the refusals below, which return rather
    // than branch around it. The engine does not follow a `defer` to the scope
    // exit it arms, so the site carries its own disposition.
    // zwanzig-disable-next-line: store-violations-engine
    var repo_dir = try std.Io.Dir.cwd().openDir(io, ".", .{});
    defer repo_dir.close(io);
    const repo_len = try repo_dir.realPath(io, &buffer);
    const rulings: Rulings = .{
        .repo = buffer[0..repo_len],
        .mounts = try readMounts(gpa, io),
        .host_scratch = try hostRoot(gpa, io, environ),
    };

    for (required_variables) |name| {
        const value = environ.get(name) orelse return refuse(
            name,
            "unset; the compiler's own default for it is not this repository's convention",
        );
        const verdict = try land(gpa, io, rulings, value);
        if (verdict.reason) |reason| return refuse(name, reason);
    }

    const root = scratch orelse return refuse(
        "--scratch",
        "required: name the approved local scratch root this run may write into",
    );
    const scratch_verdict = try land(gpa, io, rulings, root);
    if (scratch_verdict.reason) |reason| return refuse("--scratch", reason);
    const approved = scratch_verdict.canonical;

    const build_prefix = prefix orelse try under(gpa, approved, "build");
    const prefix_verdict = try land(gpa, io, rulings, build_prefix);
    if (prefix_verdict.reason) |reason| return refuse("--prefix", reason);
    if (!within(prefix_verdict.canonical, approved)) {
        return refuse("--prefix", "must name a path inside --scratch");
    }

    const receipt = receipts orelse try under(gpa, approved, "receipts.json");
    const receipt_verdict = try land(gpa, io, rulings, receipt);
    if (receipt_verdict.reason) |reason| return refuse("--receipts", reason);
    if (!within(receipt_verdict.canonical, approved)) {
        return refuse("--receipts", "must name a path inside --scratch");
    }

    // Nothing is created until every path above has been resolved and ruled on,
    // so the one directory this gate makes for itself is one it was told it may
    // write into.
    try std.Io.Dir.cwd().createDirPath(io, approved);
    return .{ .ok = .{
        .scratch = approved,
        .prefix = prefix_verdict.canonical,
        .receipts = receipt_verdict.canonical,
        .mount_types_checked = rulings.mounts.available,
    } };
}

fn refuse(subject: []const u8, reason: []const u8) Plan {
    return .{ .refused = .{ .subject = subject, .reason = reason } };
}

/// A refusal and the path it was decided on, which is empty when the spelling
/// alone was refused and nothing on disk was consulted.
fn blocked(canonical: []const u8, reason: []const u8) Landing {
    return .{ .canonical = canonical, .reason = reason };
}

/// Where a flag falls back to when the caller did not name one.
fn under(gpa: std.mem.Allocator, approved: []const u8, name: []const u8) ![]u8 {
    return std.fs.path.join(gpa, &.{ approved, name });
}

/// The host's own scratch root, resolved so paths can be compared against it.
/// A relative value names no root, so it is kept as written: every absolute
/// path then falls outside it, which is the refusal the host asked for.
fn hostRoot(
    gpa: std.mem.Allocator,
    io: std.Io,
    environ: *const std.process.Environ.Map,
) !?[]const u8 {
    const host = environ.get(scratch_root_variable) orelse return null;
    if (!std.fs.path.isAbsolute(host)) return host;
    const canonical = try canonicalPath(gpa, io, host);
    return canonical;
}

/// Where this path lands, and the first rule that forbids it. Each answer names
/// the rule rather than "unsafe", so a caller can fix it without reading this
/// file. Spelling is refused before the filesystem is consulted, because a
/// rule about a resolved path cannot report what the caller wrote.
fn land(
    gpa: std.mem.Allocator,
    io: std.Io,
    rulings: Rulings,
    path: []const u8,
) !Landing {
    if (path.len == 0) return blocked("", "empty");
    if (!std.fs.path.isAbsolute(path)) return blocked("", "not an absolute path");
    if (hasParentComponent(path)) return blocked("", "contains a `..` component");
    const canonical = canonicalPath(gpa, io, path) catch |err| switch (err) {
        error.SymlinkIsNotADirectory => return blocked(
            "",
            "resolves through a symlink that is not a directory; name the target itself",
        ),
        else => |other| return other,
    };
    if (within(canonical, rulings.repo)) return blocked(canonical, "inside the source repository");
    for (denied_roots) |denied| {
        if (within(canonical, denied)) return blocked(canonical, "under a system temporary root");
    }
    if (rulings.host_scratch) |host| {
        if (!within(canonical, host)) {
            return blocked(canonical, "outside the host scratch root this machine exports");
        }
    }
    if (onDeniedFilesystem(rulings.mounts, canonical)) {
        return blocked(canonical, "on a network filesystem");
    }
    return .{ .canonical = canonical, .reason = null };
}

/// Whether any component of `path` is exactly `..`. Only whole components
/// count: `cache..v2` is a directory name, `cache/../evidence` is a traversal.
fn hasParentComponent(path: []const u8) bool {
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return true;
    }
    return false;
}

/// Whether `path` is `root`, or sits under it. Both sides have been resolved
/// through their symlinks, so a shared prefix is a shared location here and not
/// a shared spelling.
fn within(path: []const u8, root: []const u8) bool {
    if (root.len == 0 or path.len < root.len) return false;
    if (!std.mem.eql(u8, path[0..root.len], root)) return false;
    if (path.len == root.len) return true;
    if (root[root.len - 1] == '/') return true;
    return path[root.len] == '/';
}

/// The canonical form of `path`, owned by `gpa`: every ancestor that exists
/// resolved through its real symlinks, and the part that does not exist yet
/// spelled on the end. This is what the path *is*, which is the only thing a
/// prefix rule can be about.
fn canonicalPath(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    var real_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var link_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = try std.Io.Dir.openDirAbsolute(io, "/", .{});
    const walk = try openDeepest(io, root, path, &link_buffer);
    defer walk.dir.close(io);
    const real_len = try walk.dir.realPath(io, &real_buffer);
    if (walk.tail.len == 0) return gpa.dupe(u8, real_buffer[0..real_len]);
    return std.fs.path.join(gpa, &.{ real_buffer[0..real_len], walk.tail });
}

/// Walk `path` one component at a time until a component is not an existing
/// directory. Opening each component is what resolves a symlink: the kernel
/// follows it, and the handle that comes back is the real directory.
fn openDeepest(io: std.Io, start_dir: std.Io.Dir, path: []const u8, link_buffer: []u8) !Walk {
    var dir = start_dir;
    // `dir` is replaced on every hop and an `errdefer` reads the handle that is
    // live when this scope exits, so it is the only close the walk needs.
    errdefer dir.close(io);
    var offset: usize = 0;
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        const start = offset;
        offset += component.len + 1;
        if (component.len == 0) continue;
        const deeper = try openComponent(io, dir, component, link_buffer) orelse
            return .{ .dir = dir, .tail = path[start..] };
        dir.close(io);
        dir = deeper;
    }
    return .{ .dir = dir, .tail = "" };
}

/// The directory one component in, or null when the walk stops here because
/// this component is not an existing directory.
fn openComponent(
    io: std.Io,
    dir: std.Io.Dir,
    component: []const u8,
    link_buffer: []u8,
) !?std.Io.Dir {
    const deeper = dir.openDir(io, component, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => null,
        else => |other| return other,
    };
    if (deeper != null) return deeper;
    // Missing, or present as something that is not a directory. A symlink in
    // either position is refused rather than spelled on: its target is a path
    // no rule below has resolved, so containment would be decided on a name
    // that does not say where the bytes land.
    const link = dir.readLink(io, component, link_buffer) catch |err| switch (err) {
        error.NotLink, error.FileNotFound, error.NotDir => null,
        else => |other| return other,
    };
    if (link != null) return error.SymlinkIsNotADirectory;
    return null;
}

const Entry = struct { point: []const u8, kind: []const u8 };

const Mounts = struct { entries: []const Entry, available: bool };

/// The mount table, longest prefix wins: a bind mount under a network export is
/// only as local as the export it sits in.
fn onDeniedFilesystem(mounts: Mounts, path: []const u8) bool {
    var longest: usize = 0;
    var kind: []const u8 = "";
    for (mounts.entries) |entry| {
        if (entry.point.len <= longest or !within(path, entry.point)) continue;
        longest = entry.point.len;
        kind = entry.kind;
    }
    for (denied_filesystems) |denied| {
        if (std.mem.eql(u8, kind, denied)) return true;
    }
    return false;
}

/// `/proc/mounts`: `device mount-point fstype options dump pass`. A host that
/// publishes no mount table is recorded rather than assumed safe — the receipt
/// carries `mount_types_checked: false`, so the gap is visible in the evidence
/// instead of hidden in the decision.
fn readMounts(gpa: std.mem.Allocator, io: std.Io) !Mounts {
    const text = std.Io.Dir.cwd().readFileAlloc(io, "/proc/mounts", gpa, .limited(1 << 20)) catch |err| switch (err) {
        error.FileNotFound, error.NotDir, error.AccessDenied => return .{
            .entries = &.{},
            .available = false,
        },
        else => |other| return other,
    };
    var entries: std.ArrayList(Entry) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeAny(u8, line, " \t");
        _ = fields.next() orelse continue;
        const point = fields.next() orelse continue;
        const kind = fields.next() orelse continue;
        try entries.append(gpa, .{ .point = point, .kind = kind });
    }
    return .{ .entries = entries.items, .available = true };
}
