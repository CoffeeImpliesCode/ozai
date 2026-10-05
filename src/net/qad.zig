//! Quic Address Discovery: the OBSERVED_ADDRESS frame and the transport
//! parameter that negotiates it, as pure bytes over a caller's slice.
//!
//! QAD is not a request and not a response. A peer advertises, in the
//! handshake, whether it will report observed addresses and whether it wants
//! them reported; after that the two ends exchange an ack-eliciting probing
//! frame, one per new path and one for the handshake path, carrying a
//! sequence number and the address the sender was seen at. There is no
//! question, no answer and no request id, which is why this module has two
//! halves and no session:
//!
//! - `Role` and `transport_parameter_id` — what the handshake negotiates.
//! - `ObservedAddress`, `encode` and `decode` — what one path's frame holds.
//!
//! # Where the bytes come from
//!
//! Two primary sources, and they agree:
//!
//! - `draft-ietf-quic-address-discovery`, §3 and §4.1: the
//!   `address_discovery` transport parameter `0x9f81a176` carrying a
//!   variable-length integer role, and the OBSERVED_ADDRESS frame whose type
//!   is `0x9f81a6..0x9f81a7` with the least significant bit selecting the
//!   address family, whose body is a sequence number, the address and a
//!   16-bit port in network byte order.
//! - n0-computer/noq, `noq-proto/src/frame.rs` (`FrameType::ObservedIpv4Addr`
//!   = `0x9f81a6`, `FrameType::ObservedIpv6Addr` = `0x9f81a7`, and
//!   `ObservedAddr::read` / `ObservedAddr::encode`, which read and write
//!   `seq_no`, then the address, then `buf.write::<u16>(port)`), and
//!   `noq-proto/src/address_discovery.rs` (`Role`'s three values and their
//!   names `send_only`, `receive_only` and `both`).
//!
//! The draft revision read on 2026-10-05 was
//! `draft-ietf-quic-address-discovery-latest` (15 August 2026); the three
//! constants and the field order above are byte-identical to the `-00`
//! revision of 3 March 2025.
//!
//! # What is pinned here, and what is not
//!
//! **Pinned, by the tests below:** the two frame types and the transport
//! parameter id, each as the exact bytes a QUIC variable-length integer
//! spells them; the field order and the width of each field; both role
//! values and the refusal of every other one; the truncation bound; the
//! buffer bound; and the round trip for both families at every varint width.
//!
//! **Not pinned:** no upstream bytes were captured on this node. The golden
//! frame in `qad.zig` is *derived* — the field order of §4.1 composed with
//! RFC 9000 §16's variable-length integer — and it agrees with noq's own
//! round-trip fixture, which asserts only that its encode and its decode
//! agree and names no bytes. So the layout is pinned against two written
//! specifications and against a peer implementation read, not against a
//! packet. What closes that gap is one golden-vector test carrying bytes
//! captured from a real iroh relay's `/iroh-qad/0` connection; this node has
//! no such capture and no way to make one, so the test that would close it
//! does not exist yet.
//!
//! **Not implemented here, and said here rather than left to be assumed:** the
//! sequence number's monotonicity rule ("ignore an OBSERVED_ADDRESS frame for
//! a path whose sequence number is not greater than the last accepted one for
//! that path", draft §4.1, which noq implements in
//! `PathData::update_observed_addr_report`). That rule is per-path state, so
//! it belongs to whoever holds the paths, not to a codec over bytes.
//!
//! # No socket, no clock, no allocator
//!
//! Every function is a function of its arguments and the caller's slice. The
//! decoded value borrows nothing and owns a fixed 18 bytes, so it can sit in
//! a report entry without a lifetime attached. Encoding writes into the
//! caller's buffer and refuses rather than growing it, which is the same rule
//! `relay/frame_writer.zig` follows and for the same reason.

const std = @import("std");
const addr = @import("../base/addr.zig");

const SocketAddr = addr.SocketAddr;
const IpAddress = addr.IpAddress;

const t = std.testing;

/// The `address_discovery` transport parameter id, draft §3. A QUIC
/// variable-length integer, so it occupies eight bytes on the wire.
///
/// The value is a `Role`, and its absence means the extension is not
/// negotiated at all rather than that the role is "none": `Role` has no
/// disabled arm and this module has no encoding for one.
pub const transport_parameter_id: u64 = 0x9f81a176;

/// The OBSERVED_ADDRESS frame type for an IPv4 address, draft §4.1. Also
/// `noq_proto::FrameType::ObservedIpv4Addr`.
pub const frame_type_ipv4: u64 = 0x9f81a6;

/// The OBSERVED_ADDRESS frame type for an IPv6 address, draft §4.1. Also
/// `noq_proto::FrameType::ObservedIpv6Addr`. One more than the IPv4 type,
/// because the least significant bit of the type is the family.
pub const frame_type_ipv6: u64 = 0x9f81a7;

/// The widest a QUIC variable-length integer is (RFC 9000 §16), and so the
/// widest this frame's type and sequence number can each be.
pub const max_varint_length: usize = 8;

/// The largest sequence number a variable-length integer can carry, and
/// therefore the largest this frame can name. A decoded frame cannot exceed
/// it — the encoding has nowhere to put the 62nd bit — so the check is on
/// the way in only.
pub const max_sequence: u64 = (@as(u64, 1) << 62) - 1;

/// The longest frame `encode` can write: a type, a sequence number, a
/// sixteen-byte address and a two-byte port. Both type constants are
/// four-byte varints, so this is a bound and not a length.
pub const max_frame_length: usize = max_varint_length * 2 + 16 + 2;

/// Everything this codec can refuse, in one closed set. There is no
/// `anyerror` anywhere in this file and no arm that is not reachable from a
/// peer-supplied slice.
pub const Error = error{
    /// The caller's buffer cannot hold the frame. Raised before the bytes
    /// that did fit are meaningful, so a caller that retries must discard
    /// what a failed `encode` wrote.
    NoRoom,
    /// The slice ended inside a field the frame's type promised.
    Truncated,
    /// The frame type is not one this build carries, so the address family
    /// behind it is one this build does not carry.
    ///
    /// **Refused by name, never skipped.** The family is the only thing the
    /// type decides, so a type that is neither of the two constants names a
    /// family this build has no arm for. Returning it as an error is what
    /// stops a caller from treating an unreadable frame as an absent one:
    /// draft §4.1's SHOULD-ignore applies to a *sequence number*, and RFC
    /// 9000 §12.4 makes an unrecognised frame type a connection error rather
    /// than something to step over.
    UnknownAddressFamily,
    /// The sequence number is larger than `max_sequence`, so it has no
    /// variable-length integer spelling and this frame cannot be written.
    SequenceTooLarge,
};

/// Why a transport parameter's value is refused. Separate from `Error` because
/// a handshake parameter and a packet frame are parsed by different peers at
/// different moments, and a caller that handles both wants to tell them apart.
pub const RoleError = error{
    /// The value is not 0, 1 or 2. Draft §3 requires the peer to be failed
    /// with TRANSPORT_PARAMETER_ERROR for any other value, and noq refuses
    /// it as `Error::IllegalValue`.
    UnknownRole,
};

/// What a peer says it will do about address observations, draft §3, and
/// `noq_proto::address_discovery::Role`.
///
/// The values are the wire values, and the enum discriminants are the values
/// rather than positions, so `@intFromEnum` is the parameter's byte and there
/// is no table to keep beside it.
pub const Role = enum(u64) {
    /// 0: willing to report observed addresses, not interested in receiving
    /// them. A relay's role.
    send_only = 0,
    /// 1: interested in receiving observed addresses, not willing to report
    /// them. A probing client's role.
    receive_only = 1,
    /// 2: interested in receiving them and willing to report them.
    both = 2,

    /// Whether this peer may send an OBSERVED_ADDRESS frame to `theirs`.
    ///
    /// Two conditions, not one: this peer must be willing to report, and the
    /// peer on the other end must have asked to receive. Draft §4.1 makes
    /// sending to a peer that did not request receipt a violation, so a
    /// caller that checks only its own role sends frames that close the
    /// connection. This is noq's `Role::should_report`.
    pub fn shouldReport(self: Role, theirs: Role) bool {
        return self != .send_only or self == .both ...
    }
};
