//! The n0 defaults a node runs on when the operator names none: the two DNS
//! TXT origins, the two pkarr relay base URLs, the relay lists, and what a
//! node publishes about itself under each.
//!
//! Upstream, captured 2026-09-30 at n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8 (`iroh` 1.3.0 as published): the
//! origins at `iroh-dns/src/dns.rs:36` and `:38`, which `discovery/dns.zig`
//! already owns and this file aliases; the two pkarr relay URLs at
//! `iroh/src/address_lookup/pkarr.rs:127` and `:134`; the relay hostnames at
//! `iroh/src/defaults.rs:27`-`:33` and `:94`-`:96`; and the bundle upstream
//! reads them out of at `iroh/src/endpoint/presets.rs`.
//!
//! Two of these are this project's decisions rather than upstream's, and each
//! argues itself where it is declared instead of here: `Publication.relay_only`
//! as the default, and staging as a value a caller names where upstream reads
//! an environment variable (`iroh/src/endpoint.rs:2044`).
//!
//! Nothing here reads a clock, an environment variable or an allocator: every
//! declaration is a constant or a pure function over the caller's buffer, so a
//! node that takes a preset can still be driven at a fixed time and a fixed key.

const std = @import("std");
const addr = @import("../base/addr.zig");
const dns = @import("dns.zig");

// ---------------------------------------------------------------------------
// DNS TXT origins
// ---------------------------------------------------------------------------

/// The origin a production `_iroh.<z32>` TXT query goes under.
/// `iroh-dns/src/dns.rs:36`.
///
/// **An alias and not a copy.** `discovery/dns.zig` owns this string and the
/// trailing-dot rule that goes with it, and a second spelling of an origin is a
/// second thing to change on the day n0 moves one.
pub const dns_origin_prod: []const u8 = dns.prod_origin;

/// The origin a staging `_iroh.<z32>` TXT query goes under.
/// `iroh-dns/src/dns.rs:38`, the one upstream reaches under `test-utils`.
pub const dns_origin_staging: []const u8 = dns.staging_origin;

// ---------------------------------------------------------------------------
// pkarr relay URLs
// ---------------------------------------------------------------------------

/// Base URL of n0's production pkarr relay: upstream's
/// `N0_DNS_PKARR_RELAY_PROD` at `pkarr.rs:127`.
///
/// **A base and not a node's URL**, because upstream pushes the node's z32 on
/// as one more path segment (`pkarr.rs:631`). That last step is
/// `pkarrNodeUrl` here.
pub const pkarr_relay_prod = "https://dns.iroh.link/pkarr";

/// Base URL of n0's staging pkarr relay: upstream's
/// `N0_DNS_PKARR_RELAY_STAGING` at `pkarr.rs:134`, whose own doc calls that
/// server "not as reliable" and "for more experimental use and testing
/// purposes". It is a preset of its own for that reason and never a fallback.
pub const pkarr_relay_staging = "https://staging-dns.iroh.link/pkarr";

/// Buffer size `pkarrNodeUrl` needs for `base`: the base, the separator, and
/// the one label a z32 occupies.
pub fn pkarrNodeUrlLength(base: []const u8) usize {
    return base.len + 1 + addr.NodeId.z32_length;
}

/// What a pkarr URL cannot be built without.
pub const Error = error{
    /// `out` is shorter than `pkarrNodeUrlLength(base)`. Size it with that.
    BufferTooSmall,
};

/// `base` with one more path segment: the node's z32. This is the URL upstream
/// resolves against (`pkarr.rs:624`-`:635`, the `push(&endpoint_id.to_z32())`
/// at `:631`) and publishes against (`pkarr.rs:665`).
///
/// **One function for both directions because the segment is the same value in
/// both.** A resolver asks under the id it wants an answer about; a publisher
/// pushes the z32 of the key it signed under, and that key is the node id
/// (`discovery/pkarr.zig:230`-`:233`). A z32 and not hex, for the reason
/// `discovery/dns.zig` gives for the same label in a query name: 52 characters
/// where 64 would not fit under RFC 1035 §2.3.4's 63.
///
/// The bytes land in `out` and the result borrows them, so the borrow lives as
/// long as the caller needs the URL and not a moment longer, which is the same
/// borrow `base/addr.zig` argues for `RelayUrl.hostSlice` at greater length.
pub fn pkarrNodeUrl(out: []u8, base: []const u8, node_id: addr.NodeId) Error![]const u8 {
    const need = pkarrNodeUrlLength(base);
    if (out.len < need) return error.BufferTooSmall;
    @memcpy(out[0..base.len], base);
    out[base.len] = '/';
    const label = node_id.toZ32();
    @memcpy(out[base.len + 1 ..][0..label.len], &label);
    return out[0..need];
}

// ---------------------------------------------------------------------------
// Relay lists
// ---------------------------------------------------------------------------

/// n0's production relays, in the order upstream builds its relay map
/// (`defaults.rs:37`-`:42`): NA east (`NA_EAST_RELAY_HOSTNAME`,
/// `defaults.rs:27`), NA west (`:29`), EU (`:31`) and AP (`:33`).
///
/// **The spelling is ozai's rather than upstream's.** Upstream builds these as
/// `format!("https://{NA_EAST_RELAY_HOSTNAME}")` (`defaults.rs:48`), which
/// leaves the port and the path off, while `addr.RelayUrl.format` writes the
/// scheme, the host, a port only when it is not the scheme's default, and a
/// trailing slash (`base/addr.zig:264`-`:272`). A preset whose text differs
/// from the text ozai writes back is a difference a peer sees, because a ticket
/// carries the URL as bytes (`ticket/endpoint_ticket.zig:325`).
///
/// **The order is not a preference.** Nothing selects on it: `net/report.zig`
/// chooses by latency, then instant, then relay URL
/// (`docs/ARCHITECTURE.md:206`-`:210`).
pub const relay_urls_prod: []const []const u8 = &.{
    "https://use1-1.relay.n0.iroh.link./",
    "https://usw1-1.relay.n0.iroh.link./",
    "https://euc1-1.relay.n0.iroh.link./",
    "https://aps1-1.relay.n0.iroh.link./",
};

/// n0's staging relays (`defaults.rs:94` and `:96`, in the map's order at
/// `:100`), NA east then EU.
///
/// Two and not four because upstream has no Asia-Pacific staging relay, and its
/// own module says so (`defaults.rs:86`).
pub const relay_urls_staging: []const []const u8 = &.{
    "https://use1-1.staging-relay.n0.iroh.link./",
    "https://euc1-1.staging-relay.n0.iroh.link./",
};

// ---------------------------------------------------------------------------
// What a node publishes
// ---------------------------------------------------------------------------

/// What a node publishes about itself under a preset.
pub const Publication = enum {
    /// The node is reachable through the relays in `Preset.relays` and publishes
    /// nothing anywhere else: no DNS TXT record, no pkarr packet, no direct
    /// address handed to a third party.
    ///
    /// **This is ozai's default, not upstream's.** Upstream's bundle is
    /// explicit that it "is equivalent to adding a `PkarrPublisher`, a
    /// `PkarrResolver`, and a `DnsAddressLookup`"
    /// (`iroh/src/endpoint/presets.rs`), so upstream publishes because a caller
    /// asked for a publisher, and a node holding only a relay map publishes
    /// only what its relays already know. That is the default here because
    /// publishing to somebody is an egress decision, and a library that made it
    /// on an operator's behalf would be making it in a constructor. A second arm
    /// is a publisher service this build does not have.
    relay_only,
};

/// The four values that make one preset: where a TXT query goes, which pkarr
/// relay answers it, which relays the node is a client of, and what it
/// publishes.
///
/// Every field is named, and no field has a default: a preset that left one to
/// be filled in would be two presets spelled as one value.
pub const Preset = struct {
    /// The origin `_iroh.<z32>` is queried under. `dns_origin_prod` or
    /// `dns_origin_staging`, and nothing else.
    origin: []const u8,
    /// The pkarr relay a node is resolved and published against.
    /// `pkarr_relay_prod` or `pkarr_relay_staging`.
    pkarr_relay: []const u8,
    /// The relay list, in the order upstream's relay map has it: four entries
    /// for production, two for staging.
    relays: []const []const u8,
    /// What this node publishes. See `Publication`.
    publication: Publication,
};

/// n0's production values: upstream's `presets::N0`
/// (`iroh/src/endpoint/presets.rs`) with `Publication` this project's. That
/// bundle also installs the three lookup services; this preset is only the
/// names and the lists, and `discovery/resolve.zig` owns the services.
pub const n0: Preset = .{
    .origin = dns_origin_prod,
    .pkarr_relay = pkarr_relay_prod,
    .relays = relay_urls_prod,
    .publication = .relay_only,
};

/// n0's staging values. Upstream picks these from `IROH_FORCE_STAGING_RELAYS`
/// or the `test-utils` feature (`pkarr.rs:339`, `iroh/src/endpoint.rs:2055`),
/// and ozai reads no environment variable anywhere, so a staging node is one
/// whose configuration names this value.
pub const n0_staging: Preset = .{
    .origin = dns_origin_staging,
    .pkarr_relay = pkarr_relay_staging,
    .relays = relay_urls_staging,
    .publication = .relay_only,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const t = std.testing;
const key = @import("../base/key.zig");

/// The node from upstream's own `test_from_txt_lookup`
/// (`iroh-dns/src/endpoint_info.rs` at the pinned commit), in hex, and the two
/// spellings of it that this file's callers put on the wire: the z32 inside a
/// query name and the z32 as a pkarr path segment.
///
/// Both are upstream's own literals rather than this module's output, so a
/// change to either construction here that kept agreeing with itself would fail
/// these strings instead of passing them.
const captured_id_hex = "1992d53c02cdc04566e5c0edb1ce83305cd550297953a047a445ea3264b54b18";
const captured_z32 = "dgjpkxyn3zyrk3zfads5duwdgbqpkwbjxfj4yt7rezidr3fijccy";
const captured_query_name = "_iroh." ++ captured_z32 ++ ".dns.iroh.link.";
const captured_query_name_staging = "_iroh." ++ captured_z32 ++ ".staging-dns.iroh.link.";
const captured_pkarr_url = "https://dns.iroh.link/pkarr/" ++ captured_z32;

/// The widest `RelayUrl.format` can write: the longest scheme, an RFC 1035 host
/// at its limit, the longest port, and the trailing slash
/// (`base/addr.zig:264`-`:272`).
const relay_text_max = "https://".len + addr.RelayUrl.max_host_length + ":65535".len + 1;

/// The host part of a pkarr base URL: what is between the scheme and the first
/// `/`. The refusal is this test's claim that a base carries a path at all,
/// which both bases here do and a base with none could not answer a node.
fn pkarrHost(base: []const u8) ![]const u8 {
    const after_scheme = base["https://".len..];
    const slash = std.mem.indexOfScalar(u8, after_scheme, '/') orelse
        return error.TestUnexpectedResult;
    return after_scheme[0..slash];
}

test "each preset is the four values it was built from" {
    try t.expectEqualStrings(dns_origin_prod, n0.origin);
    try t.expectEqualStrings(pkarr_relay_prod, n0.pkarr_relay);
    try t.expectEqual(@as(usize, 4), n0.relays.len);
    try t.expectEqualStrings(dns_origin_staging, n0_staging.origin);
    try t.expectEqualStrings(pkarr_relay_staging, n0_staging.pkarr_relay);
    try t.expectEqual(@as(usize, 2), n0_staging.relays.len);
    // Relay-only on both: this is the default the argument on `Publication`
    // makes, and it is a default nothing may quietly opt out of.
    try t.expectEqual(Publication.relay_only, n0.publication);
    try t.expectEqual(Publication.relay_only, n0_staging.publication);
}

test "no preset names one relay twice" {
    // A relay list is a set, and `addr.RelayUrl.order` makes a repeated entry
    // one address a node dialled and reported twice.
    for (n0.relays, 0..) |text, index| {
        for (n0.relays[index + 1 ..]) |other| {
            try t.expect(!std.mem.eql(u8, text, other));
        }
    }
    for (n0_staging.relays, 0..) |text, index| {
        for (n0_staging.relays[index + 1 ..]) |other| {
            try t.expect(!std.mem.eql(u8, text, other));
        }
    }
}

test "a preset's origin is the one upstream's query name is built under" {
    const id = try key.NodeId.parseHex(captured_id_hex);
    // The origins are aliased rather than restated, so this is the check that
    // the alias still names the origin upstream queries: both names are
    // upstream's own strings, not this module's arithmetic.
    var prod: [dns.queryNameLength(n0.origin)]u8 = undefined;
    try t.expectEqualStrings(captured_query_name, dns.queryName(&prod, id, n0.origin));
    var staging: [dns.queryNameLength(n0_staging.origin)]u8 = undefined;
    try t.expectEqualStrings(
        captured_query_name_staging,
        dns.queryName(&staging, id, n0_staging.origin),
    );
}

test "a pkarr relay is served by the host the TXT origin names" {
    // Upstream's own doc for `N0_DNS_PKARR_RELAY_PROD` (`pkarr.rs:120`-`:123`)
    // is that this server "is both a pkarr relay server as well as a DNS
    // resolver", so the two defaults are one host under two spellings: the
    // origin keeps the trailing dot a host name needs and the URL drops it,
    // because a dot inside a URL path segment is not a host.
    try t.expectEqualStrings("dns.iroh.link", try pkarrHost(n0.pkarr_relay));
    try t.expectEqualStrings("staging-dns.iroh.link", try pkarrHost(n0_staging.pkarr_relay));
    try t.expectEqualStrings(n0.origin[0 .. n0.origin.len - 1], try pkarrHost(n0.pkarr_relay));
    try t.expectEqualStrings(
        n0_staging.origin[0 .. n0_staging.origin.len - 1],
        try pkarrHost(n0_staging.pkarr_relay),
    );
}

test "a pkarr URL carries the node's z32 as its last path segment" {
    const id = try key.NodeId.parseHex(captured_id_hex);
    var buffer: [pkarrNodeUrlLength(n0.pkarr_relay)]u8 = undefined;
    const url = try pkarrNodeUrl(&buffer, n0.pkarr_relay, id);
    try t.expectEqualStrings(captured_pkarr_url, url);
    // The length function is both the buffer size and the result's length, so
    // a caller sizing a scratch buffer from it and a caller reading the result
    // cannot be given different answers.
    try t.expectEqual(pkarrNodeUrlLength(n0.pkarr_relay), url.len);
    // The z32 and not the hex, checked against the id's own encoding rather
    // than against a literal: 52 characters, which is what fits a DNS label.
    try t.expectEqualSlices(u8, &id.toZ32(), url[url.len - addr.NodeId.z32_length ..]);
}

test "a pkarr URL is refused rather than truncated" {
    const id = try key.NodeId.parseHex(captured_id_hex);
    var buffer: [pkarrNodeUrlLength(n0.pkarr_relay)]u8 = undefined;
    // One byte short, and the whole URL is refused: a partial one is a request
    // to a path that is not a node's.
    try t.expectError(
        error.BufferTooSmall,
        pkarrNodeUrl(buffer[0 .. buffer.len - 1], n0.pkarr_relay, id),
    );
}

test "every preset relay text is a URL this build writes back unchanged" {
    for (n0.relays) |text| try expectCanonicalRelay(text);
    for (n0_staging.relays) |text| try expectCanonicalRelay(text);
}

/// `text` parses, and formatting the value writes `text` back byte for byte.
///
/// The second half is the property that matters for a preset: a relay text
/// that parsed but re-encoded differently is a relay this build dials and
/// publishes as two different addresses, and a ticket carries the URL as bytes.
fn expectCanonicalRelay(text: []const u8) !void {
    const url = try addr.RelayUrl.parse(text);
    // Fully qualified, because the trailing dot is what stops a host resolver
    // appending a local search domain (`base/addr.zig:160`).
    try t.expect(std.mem.endsWith(u8, url.hostSlice(), "."));
    // Port 443 filled in from the scheme, so this list cannot carry a relay
    // this build would reach on some other port.
    try t.expectEqual(addr.RelayUrl.default_https_port, url.port);
    var buffer: [relay_text_max]u8 = undefined;
    var out = std.Io.Writer.fixed(&buffer);
    try url.format(&out);
    try t.expectEqualStrings(text, buffer[0..out.end]);
}
