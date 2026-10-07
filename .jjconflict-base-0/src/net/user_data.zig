//! The bytes an application attaches to its endpoint and reads back out of
//! a discovery record.
//!
//! Upstream carries this on `EndpointData`, not on the net report, and it was
//! only ever in `report.zig` because the milestone listed the 245-byte DNS TXT
//! limit beside the report. It has nothing to do with a probe round, so it
//! stands here; `report.zig` re-exports it.

/// The most user-defined bytes an endpoint can publish.
///
/// A DNS TXT record is a sequence of character-strings and each one is capped at
/// 255 bytes (RFC 1035 §3.3.14). The attribute is spelled `user-data=`, so ten
/// of those 255 are spent before any of the value exists:
///
/// ```text
///   255  one DNS TXT character-string
///  -  10  the "user-data=" attribute prefix
///  -----
///   245  what is left for the value
/// ```
///
/// The arithmetic is written out because the number is otherwise a magic
/// constant, and because the failure it prevents is not a local one: a publisher
/// that overruns does not get an error, a *resolver* gets a truncated attribute
/// and quietly reads another endpoint's metadata.
pub const max_user_data_length = 245;

/// Why an application's attached metadata could not be built. The single
/// variant is upstream's `MaxLengthExceededError`, whose message is "max length
/// exceeded", and there is no allocator in this type that could fail: the value
/// is inline, so the only way to refuse is a length.
pub const UserDataError = error{
    /// The value is longer than `max_user_data_length` bytes. Upstream's
    /// `MaxLengthExceededError`, whose message is "max length exceeded".
    MaxLengthExceeded,
};

/// Data an application attaches to its endpoint and reads back out of discovery
/// records. Upstream's `UserData`, from `iroh-dns/src/endpoint_info.rs`.
///
/// Nothing here parses it or looks at it, exactly as upstream: it is bytes the
/// application put there and expects to find again. The value is inline rather
/// than borrowed so that a `UserData` can sit in a discovery record without a
/// lifetime attached to it, which is the trap invariant 6 in
/// `docs/ARCHITECTURE.md` is about.
pub const UserData = struct {
    /// The limit, named on the type as well as at module scope because upstream
    /// exposes it as an associated constant and callers reach for it there.
    pub const max_length = max_user_data_length;

    bytes: [max_user_data_length]u8 = undefined,
    len: u8 = 0,

    /// The bytes, up to `max_length` of them, or `error.MaxLengthExceeded`.
    ///
    /// Inline rather than borrowed so a `UserData` can sit inside a discovery
    /// record with no lifetime attached to it, and no allocation is involved.
    /// Nothing here parses the value or looks at it; a caller that needs a
    /// `[]const u8` takes `slice`, whose borrow ends with the value's address.
    ///
    /// An empty input is a `UserData` with `len == 0`, which is a value and not
    /// an absent one: it reads back as empty rather than as unset.
    pub fn init(text: []const u8) UserDataError!UserData {
        // 245 fits a `u8`, so this cast admits nothing the length check did not.
        if (text.len > max_user_data_length) return error.MaxLengthExceeded;
        var result: UserData = .{ .len = @intCast(text.len) };
        @memcpy(result.bytes[0..text.len], text);
        return result;
    }

    /// Pointer receiver for the reason `RelayUrl.hostSlice` takes one: the value
    /// is 246 bytes and a by-value receiver can hand back a slice into a
    /// temporary that is dead the moment it returns.
    pub fn slice(self: *const UserData) []const u8 {
        return self.bytes[0..self.len];
    }
};
