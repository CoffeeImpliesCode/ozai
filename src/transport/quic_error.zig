//! Errors shared by the QUIC transport boundary.

const batch = @import("batch.zig");
const quic_datagram = @import("quic_datagram.zig");

/// Includes batch and datagram refusals without duplicating their error sets.
pub const Error = batch.Error || quic_datagram.Error || error{
    /// Output or scratch storage is too small. Refusal occurs before the core
    /// consumes the work; room exhausted between datagrams yields a short drain.
    NoRoom,
    /// CID/reset index growth failed after input may have been processed.
    /// Live connections remain valid; retry the manager's `syncCids` before
    /// sending newly issued CIDs, or abandon the connection.
    OutOfMemory,
    /// Peer stream limits are not yet known or are exhausted. A later handshake
    /// or MAX_STREAMS frame can make opening a stream possible.
    NoStreamRoom,
    /// The active path's address is still unset.
    NoPathAddress,
    /// The core refused an operation other than a named recoverable refusal.
    /// The underlying error is logged rather than exposing `anyerror`.
    CoreRefused,
    /// A unidirectional write exceeds peer flow-control credit. Nothing is
    /// queued; a later MAX_STREAM_DATA frame can permit the write.
    NoSendCredit,
};
