//! Fuzz target for the vendored TLS decoders: DER and `SubjectPublicKeyInfo`,
//! the handshake messages that carry framing and extensions, and the two hello
//! decoders.
//!
//! One target file per decoder family group, and this is the file that owns the
//! Smith driver for the three of them. `zig build fuzz` replays the corpus
//! below; `zig build fuzz --fuzz=N` hands the same corpus to Zig's
//! coverage-guided fuzzer and lets it mutate for N iterations. A fuzz test is a
//! plain test to a plain build, so without `-ffuzz` the runner walks the corpus
//! instead — which is what makes a bare `zig build fuzz` a bounded gate rather
//! than an empty step.
//!
//! # Why the oracles live in three leaves and not here
//!
//! `tls_wire/der.zig` owns the DER and SPKI families, `tls_wire/messages.zig`
//! owns CertificateRequest, Certificate and server_name, and
//! `tls_wire/hello.zig` owns the ClientHello and ServerHello decoders. Those
//! three leaves are independent of each other and each carries a reference
//! decoder of its own; this file owns what they share: the seeds, the window
//! the fuzzer fills, and the call that hands the same bytes to all three.
//!
//! Their arguments differ, and the difference is the point: the two leaves
//! that parse borrowed slices take the bytes alone, and the one that drives a
//! handshake also takes an allocator, because that handshake really allocates.
//! A uniform signature across three leaves would mean either a hidden
//! `std.testing.allocator` inside the two that never allocate or an unused
//! parameter, and both are worse than the asymmetry. See the contract note
//! below the imports and the call site.
//!
//! # What is reached and what is not
//!
//! The public decoders here are `liftEd25519Spki`, `extractEd25519PrivateKey`,
//! `parseCertificateRequest`, `parseCertificateList`,
//! `parseServerNameExtension` and the handshake itself through
//! `Tls13Handshake.provideData` plus `step`. The ClientHello and ServerHello
//! decoders are private methods of `Tls13Handshake`, so the leaf that covers
//! them drives the public constructor, feeds the bytes, and reads the verdict
//! back off `step` — that is the consumer seam, and there is no second one.
//! Publishing `serverProcessClientHello` or `clientProcessServerHello` to make
//! them reachable would be widening the vendored surface for a test, which is
//! the one thing not to do.
//!
//! # The seeds are not captured vectors
//!
//! Every seed below is a shape written here byte for byte from RFC 8446
//! §4.1.2, §4.3.2 and §4.4.2, RFC 6066 §3 and RFC 8410 §3. None of them is a
//! captured Rust vector, and none is labelled as one: this repository has run no
//! live exchange with a Rust peer, so there is nothing captured to embed. The
//! one seed carrying a 44-byte SPKI is that certificate written out from
//! RFC 8410 §3, which is also exactly what `ed25519Spki` produces.

const std = @import("std");

const der = @import("tls_wire/der.zig");
const messages = @import("tls_wire/messages.zig");
const hello = @import("tls_wire/hello.zig");

const t = std.testing;

// The leaves' failure set, as a contract rather than as a type this file
// declares. Each leaf owns its own; `std.testing.expect*` reports through
// `error{TestUnexpectedResult, TestExpectedEqual, TestExpectedError,
// TestUnexpectedError}`, which is the whole vocabulary an oracle here needs. This
// root does not declare the set because it does not consume one: `testOne`
// returns `anyerror!void`, and the three `try`s below are the whole of the
// compatibility check — a leaf whose set this root cannot `try` fails to
// compile, which is the assertion worth having.
//
// `OutOfMemory` is the one arm that is not an oracle verdict, and only
// `hello.zig` may return it. `Tls13Handshake` owns its buffers inline and
// frees only the peer certificate it copied through the allocator the caller
// set, so that leaf is the one that can be asked to allocate and the one that
// can report failing to — which is why it is also the only one handed a `gpa`.
// The DER and message leaves borrow every slice they parse, so they take the
// bytes alone and must not return it.
//
// A refused handshake is a closed production error judged by the oracle that
// checks it: `HandshakeError` names fifteen arms that the hello leaf's verdict
// predicts one for, and every arm a prediction covers is reported as a test
// tag rather than passed on. The one it does not cover is the `.wait` arm —
// a flight that has not all arrived, where `step` owes `wait_for_data` and no
// reason — and that leaf's error set carries `HandshakeError` itself so the
// arm that fired reaches the report instead of being flattened into a tag
// that could not say which. `testOne` returns `anyerror!void`, so the name
// arrives intact.

/// The seeds, one per shape the three families have a rule for.
///
/// The DER seeds are a whole Ed25519 SPKI, one byte short of it, one byte over,
/// a valid shell around the wrong algorithm identifier, and a PKCS#8
/// `OneAsymmetricKey` whose seed is wrapped in the inner `CurvePrivateKey` RFC
/// 8410 allows. The message seeds are a CertificateRequest with no extensions,
/// one with a `signature_algorithms` list, one whose context is not empty, one
/// whose extension length does not close the message, one with the list twice,
/// and Certificate and server_name bodies that are whole, empty, and cut short
/// of the length that names them. The hello seeds are a ClientHello and a
/// ServerHello built out of their own fields — a legacy version, a random, an
/// empty session id, one cipher suite and a two-byte extension block — plus the
/// same shapes with a legacy session id of 33 bytes, with an odd cipher-suite
/// list length, with no key share, with no transport parameters, and with a
/// length past the message.
const corpus = [_][]const u8{
    // DER: SPKI and PKCS#8
    &.{},
    &([_]u8{ 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 } ++
        ([_]u8{0x01} ** 32)), // a whole Ed25519 SPKI (RFC 8410 §3)
    &([_]u8{ 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 } ++
        ([_]u8{0x01} ** 31)), // one byte short of it
    &([_]u8{ 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 } ++
        ([_]u8{0x01} ** 33)), // one byte over
    &([_]u8{ 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x03, 0x21, 0x00 } ++
        ([_]u8{0x01} ** 32)), // a well-formed SPKI naming another algorithm
    &([_]u8{ 0x30, 0x2b, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 } ++
        ([_]u8{0x01} ** 32)), // a length one byte past what follows
    &([_]u8{ 0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20 } ++
        ([_]u8{0x02} ** 32)), // PKCS#8, seed wrapped in the inner CurvePrivateKey
    &([_]u8{ 0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22 } ++
        ([_]u8{0x02} ** 30)), // PKCS#8 with a short seed
    // CertificateRequest bodies: an empty context and an extension block
    &.{},
    &.{ 0x00, 0x00, 0x00 },
    &.{ 0x00, 0x00, 0x04, 0x00, 0x0d, 0x00, 0x02, 0x04, 0x03 },
    &.{ 0x01, 0x00, 0x00 }, // a context that is not empty
    &.{ 0x00, 0x00, 0x05, 0x00, 0x0d, 0x00, 0x02, 0x04, 0x03 }, // a length that does not close it
    &.{ 0x00, 0x00, 0x0a, 0x00, 0x0d, 0x00, 0x02, 0x04, 0x03, 0x00, 0x0d, 0x00, 0x02, 0x04, 0x03 }, // the list twice
    &.{ 0x00, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x02, 0x04, 0x03 }, // odd-length schemes
    // Certificate bodies
    &.{},
    &.{ 0x00, 0x00, 0x00, 0x00 }, // an empty list
    &.{ 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x01, 0xaa, 0x00, 0x00 }, // one certificate of one byte
    &.{ 0x01, 0x00, 0x00, 0x00 }, // a context that is not empty
    // server_name extension bodies (RFC 6066 §3)
    &.{},
    &.{ 0x00, 0x00 },
    &.{ 0x00, 0x05, 0x00, 0x00, 0x03, 'o', 's', 'a' },
    &.{ 0x00, 0x05, 0x00, 0x00, 0x00 }, // a zero-length host name
    &.{ 0x00, 0x08, 0x00, 0x00, 0x03, 'o', 's', 'a', 0x00, 0x00, 0x03, 'n', 'o', 'd' }, // two host names
    &.{ 0x00, 0x04, 0x00, 0x09, 0x01, 0x00 }, // a list that does not close the extension
    // ClientHello and ServerHello messages
    &.{},
    &([_]u8{ 0x01, 0x00, 0x00, 0x05, 0x03, 0x03 } ++ ([_]u8{0x00} ** 5)), // a ClientHello short of its random
    &([_]u8{ 0x01, 0x00, 0x00, 0x39, 0x03, 0x03 } ++ ([_]u8{0x07} ** 32) ++
        [_]u8{ 0x00, 0x00, 0x02, 0x13, 0x01, 0x00, 0x00, 0x00 }), // a ClientHello with one suite and no extensions
    &([_]u8{ 0x02, 0x00, 0x00, 0x39, 0x03, 0x03 } ++ ([_]u8{0x07} ** 32) ++
        [_]u8{ 0x00, 0x00, 0x02, 0x13, 0x01, 0x00, 0x00, 0x00 }), // a ServerHello with one suite and no extensions
    &([_]u8{ 0x01, 0x00, 0x00, 0x3a, 0x03, 0x03 } ++ ([_]u8{0x07} ** 32) ++
        [_]u8{0x21} ++ ([_]u8{0x08} ** 33) ++
        [_]u8{ 0x00, 0x02, 0x13, 0x01, 0x00, 0x00 }), // a legacy session id over 32 bytes
    &([_]u8{ 0x01, 0x00, 0x00, 0x39, 0x03, 0x03 } ++ ([_]u8{0x07} ** 32) ++
        [_]u8{ 0x00, 0x00, 0x03, 0x13, 0x01, 0x99, 0x00, 0x00 }), // an odd cipher-suite list length
    &([_]u8{ 0x01, 0x00, 0x00, 0x39, 0x03, 0x03 } ++ ([_]u8{0x07} ** 32) ++
        [_]u8{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 }), // a cipher suite this stack does not implement
    &([_]u8{ 0x01, 0x00, 0x00, 0x39, 0x03, 0x03 } ++ ([_]u8{0x07} ** 32) ++
        [_]u8{ 0x00, 0x00, 0x02, 0x13, 0x01, 0x00, 0xff, 0xff }), // an extension length past the message
    &([_]u8{ 0x01, 0x00, 0x00, 0x39, 0x03, 0x03 } ++ ([_]u8{0x07} ** 32) ++
        [_]u8{ 0x00, 0x00, 0x02, 0x13, 0x01, 0x00, 0x08, 0x00 }), // an extension block of four bytes
};

/// The window the fuzzer fills. A seed longer than this would be cut short on
/// its way to an oracle, and the length checks would never see the rest of it.
///
/// A handshake decodes out of a copy the caller hands it, so this is also the
/// ceiling on one peer's flight a fuzz input can be. A leaf that re-encodes
/// what it decoded sizes that buffer from this one, with the argument written
/// at its own use.
const input_buffer_len = 256;

comptime {
    // A seed longer than the window the fuzzer reads into would be cut short,
    // and the length checks would never see the rest of it.
    for (corpus) |seed| std.debug.assert(seed.len <= input_buffer_len);
}

/// The fuzzer keeps one of these by pointer for the whole run, so it is empty
/// by design: everything the driver needs is comptime.
const Context = struct {};

test "vendored TLS decode" {
    // A fuzz test is a plain test to a plain build. Without `-ffuzz` the runner
    // walks the corpus instead of handing it to the fuzzer, which is what makes
    // a bare `zig build fuzz` a bounded gate rather than an empty step.
    try t.fuzz(Context{}, testOne, .{ .corpus = &corpus });
}

fn testOne(_: Context, smith: *t.Smith) anyerror!void {
    var buffer: [input_buffer_len]u8 = undefined;
    // `in` is the corpus entry verbatim while the corpus is replayed, and null
    // when the fuzzer drives, in which case `slice` consumes its input.
    const bytes = if (smith.in) |replay| replay else buffer[0..smith.slice(&buffer)];
    // The same bytes to all three, in the order they are met: a certificate is
    // DER, the handshake messages that frame extensions come next, and the two
    // hellos carry the whole flight.
    try der.check(bytes);
    try messages.check(bytes);
    // Only the hello leaf is handed an allocator, and only because it is the
    // one that reaches a real allocation: a server that accepts a client
    // certificate copies the DER through the allocator the handshake was given
    // and `deinit` releases it. The other two leaves borrow every slice they
    // parse and would have nothing to do with one, so passing it would be an
    // unused parameter — the fiction AGENTS.md §1 rules out. A uniform
    // signature across three leaves is worth less than one honest parameter.
    try hello.check(t.allocator, bytes);
}
