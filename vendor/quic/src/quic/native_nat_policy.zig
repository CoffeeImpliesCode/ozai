//! Canonical candidate identity and Noq's default capped retry schedule.
const Address = @import("../address.zig").Address;
const transition = @import("native_nat_transition.zig");
pub const candidate_limit = 32;

pub fn canonicalAddress(address: Address) error{InvalidAddress}!Address {
    return switch (address) {
        .unset => error.InvalidAddress,
        .ipv4 => address,
        .ipv6 => |six| if (address.isIpv4Mapped())
            Address.initIpv4(six.bytes[12..16].*, six.port)
        else
            Address.initIpv6(six.bytes, six.port, 0),
    };
}

/// Socket capability is lifted by the caller, never read from a socket here.
pub fn supportedAddress(address: Address, supported_ipv6: bool) bool {
    const canonical = canonicalAddress(address) catch return false;
    return supported_ipv6 or canonical == .ipv4;
}

pub fn retryDelay(attempt: u8) i64 {
    // Noq 1.3.0 n0_nat_traversal.rs:331-342, default initial RTT 333ms.
    const exponent: u6 = @intCast(if (attempt == 0) 0 else @min(attempt - 1, 7));
    return @min(@as(i64, 33_300_000) << exponent, 2_000_000_000);
}

pub fn canRecordChallenge(
    entries: []const transition.Challenge,
    address: Address,
) bool {
    const canonical = canonicalAddress(address) catch return false;
    if (entries.len == candidate_limit * 9) return false;
    var count: u8 = 0;
    for (entries) |sent| {
        if (Address.eql(sent.address, canonical)) count += 1;
    }
    return count < 9;
}

pub fn snapshot(entries: []const transition.Candidate, out: []Address) []const Address {
    const count = @min(entries.len, out.len);
    for (entries[0..count], out[0..count]) |entry, *address| address.* = entry.address;
    return out[0..count];
}
