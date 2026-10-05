//! Every way the descriptor surface refuses: an option, an open, a send, a
//! receive.
//!
//! Split out of `transport/socket.zig`, which is now the facade over this and
//! five other named modules. The boundary is the vocabulary rather than the
//! code: these four sets are what the operations in the other modules return,
//! and they are named together because `WouldBlock` and `MessageTooLarge` must
//! never share a name — the first is backpressure a caller waits out and the
//! second is a datagram this path will never carry, and collapsing them is how
//! a congestion signal becomes a hung socket.

const batch = @import("batch.zig");
const cmsg = @import("socket_cmsg.zig");

/// `socket_cmsg.ControlError`, under the name this file declares it with.
const ControlError = cmsg.ControlError;

/// Why a `setsockopt` was refused. `Unsupported` is the whole of a capability
/// probe and nothing else: the option is not here, which for `UDP_SEGMENT` and
/// `UDP_GRO` is an answer and for anything else is a problem.
pub const OptionError = error{
    /// `EINVAL`: the kernel would not take the value.
    InvalidValue,
    /// `ENOPROTOOPT` or `EOPNOTSUPP`: no such option at this level.
    Unsupported,
    /// `ENOBUFS` or `ENOMEM`.
    ResourcesExhausted,
    /// `EACCES` or `EPERM`.
    PermissionDenied,
    /// `EBADF`, `ENOTSOCK`, or an errno this list does not name.
    Unexpected,
};

/// Why a socket could not be opened.
pub const OpenError = error{
    /// `EACCES` or `EPERM`: a capability bit or a sandbox, not the address.
    PermissionDenied,
    /// `EAFNOSUPPORT`: this kernel has no IPv4 or no IPv6.
    AddressFamilyUnsupported,
    /// `EPROTONOSUPPORT`: UDP is not a protocol this kernel has.
    ProtocolUnsupported,
    /// `ESOCKTNOSUPPORT`: no datagram socket.
    SocketModeUnsupported,
    /// `EINVAL`: a flag or an option value the kernel would not take, which
    /// for a socket call is this module writing something wrongly.
    InvalidArgument,
    /// `EMFILE` or `ENFILE`: the process or the system is out of descriptors.
    DescriptorQuotaExceeded,
    /// `ENOBUFS` or `ENOMEM`.
    ResourcesExhausted,
    /// `EADDRINUSE`: the port is taken, and no reuse option was asked for.
    AddressInUse,
    /// `EADDRNOTAVAIL`: the address is not one of this host's.
    AddressNotAvailable,
    /// A congestion option this socket cannot be given. There is no fallback
    /// for it: a socket that was never asked for the codepoint reports every
    /// read as not-ECT, which is a silently wrong answer rather than a
    /// missing one.
    CongestionOptionUnsupported,
    /// A reuse option this platform does not have.
    OptionUnsupported,
    /// `EBADF`, `ENOTSOCK`, `ENOSPC`, or anything else.
    Unexpected,
};

/// Why a send did not go out.
///
/// `WouldBlock` and `MessageTooLarge` are the two that must never share a
/// name: the first is backpressure, which the caller waits out or absorbs, and
/// the second is a datagram this path will never carry, which retrying turns
/// into a stall. Collapsing them is how a congestion signal becomes a hung
/// socket. `ControlError` is in the set because a set names every way a call
/// can fail and not only the ones that are convenient; `batch.cmsg` builds at
/// most two messages out of the model's own constants and `ControlBuffer`
/// holds exactly two, so a caller cannot reach either of `ControlError`'s two
/// members through `Socket.send`.
pub const SendError = batch.Error || ControlError || error{
    /// The task was cancelled before the datagram left. A socket that sends
    /// after its caller has given up is a socket nobody is waiting for.
    Canceled,
    /// `EAGAIN`: the socket's send queue is full and nothing left the host.
    WouldBlock,
    /// `EMSGSIZE`: the payload is larger than the path carries.
    MessageTooLarge,
    /// `ENETUNREACH`: no route to the network.
    NetworkUnreachable,
    /// `EHOSTUNREACH`: no route to that host.
    HostUnreachable,
    /// `ENETDOWN`: the interface that would carry it is down.
    NetworkDown,
    /// `ECONNREFUSED`: a previous send drew an ICMP port unreachable and the
    /// kernel held it back for exactly this call.
    PortUnreachable,
    /// `EADDRNOTAVAIL`: the destination is not one this host may send to.
    AddressNotAvailable,
    /// `EACCES` or `EPERM`.
    PermissionDenied,
    /// `ENOBUFS` or `ENOMEM`: the kernel could not build the datagram.
    ResourcesExhausted,
    /// `EDESTADDRREQ` or `ENOTCONN`.
    SocketUnusable,
    /// `EIO` or `EINVAL` on a run carrying no control message this module is
    /// willing to drop, and on a family whose traffic class is a core option.
    /// The kernel refused a send there without saying which half it disliked,
    /// and guessing would be worse than saying so.
    UnknownControlMessage,
    /// The kernel took fewer bytes than the payload held. UDP has no such
    /// answer, so this is the kernel disagreeing about where the datagram
    /// ends, and the caller has to know that it did.
    PartialDatagram,
    /// A bound on this call ran out: `EINTR` on every attempt the refused run
    /// had, or a stop whose queue or wake counter a send could not empty within
    /// `max_discarded` and `max_wakes_spent`.
    ///
    /// The bound is on the call and not on the batch. A batch is one
    /// `sendmsg` per run, and every run that finished before this one left the
    /// socket: nothing the refused run carried went out, while datagrams ahead
    /// of it may have. Which is why `Socket.send` returns no sent-prefix count
    /// and why the caller is the one that decides about duplicates — the same
    /// residue every other error here leaves, and this one is no exception.
    ///
    /// A stop this send did not deal with leaves the socket stopped, so asking
    /// again is what drains the rest and makes progress.
    Interrupted,
    /// Anything else.
    Unexpected,
};

/// Why a receive did not produce a datagram.
pub const ReceiveError = error{
    /// The task was cancelled before the datagram was taken.
    Canceled,
    /// `EAGAIN`: the queue was empty. From `tryReceive` that is the answer to
    /// the question that was asked; from `receive` it means another task took
    /// the datagram between the wait and the read.
    WouldBlock,
    /// `MSG_TRUNC`: the buffer was smaller than the datagram, so the bytes in
    /// it are a prefix and not the datagram.
    MessageTooLarge,
    /// An error a previous send drew, reported on the next read.
    PortUnreachable,
    NetworkUnreachable,
    HostUnreachable,
    NetworkDown,
    /// `ENOBUFS` or `ENOMEM`.
    ResourcesExhausted,
    /// `MSG_CTRUNC`, or a blob that ended inside a message: the control data
    /// did not fit, so a coalesced read cannot be told from an uncoalesced
    /// one and the buffer is not safe to read. The datagram is here and must
    /// not be taken as one.
    ControlTruncated,
    /// `EINTR` on every attempt in the budget.
    Interrupted,
    /// `ENOTCONN`, `EDESTADDRREQ`, `EBADF`, `ENOTSOCK`, or anything else.
    Unexpected,
};
