//! The wire contract this peer speaks, and where each item was read from.
//!
//! Constants here pin ALPN spellings and the raw-key SPKI shape. RFC 7250
//! certificate-type negotiation is documented below and exercised by the
//! vendored core and live stock iroh interop, not by copied expected bytes.
//!
//! # 1. The ALPNs
//!
//! A node speaks **one** protocol at a time. `src/node/node_config.zig:36` and
//! `:41` name the two a node can be configured with:
//!
//! | Name | Read from |
//! |---|---|
//! | `/iroh-gossip/1` | `src/node/node_config.zig:36`, re-exported as `node.gossip_alpn` at `src/node/node.zig:247` |
//! | `/iroh-relay/1` | `src/node/node_config.zig:41`, re-exported as `node.relay_alpn` at `src/node/node.zig:248` |
//!
//! Two more names the Zig tree uses as wire protocols, offered here so that a
//! peer built for any of them finds the same string:
//!
//! | Name | Read from |
//! |---|---|
//! | `/iroh-bytes/4` | `src/blobs/protocol.zig:66` |
//! | `ozai` | `test/loopback_side.zig:36`, the transport-level protocol the two in-tree loopback drivers speak |
//!
//! **`/iroh-qad/0` is deliberately absent.** `src/router/alpn_table.zig:173`
//! reserves it for iroh's own QUIC address discovery and `Builder.accept`
//! refuses it with `error.reserved_alpn` (`:208`); `src/node/node_accept.zig:45`
//! caps a node at one ALPN and `src/node/node_build.zig:224-230` registers the
//! application one alone, so a table built in this tree never offers it. That
//! is a decision rather than an oversight: `src/router/qad_route.zig` holds the
//! route that would serve it and records why nothing calls it — the vendored
//! QUIC core carries neither the OBSERVED_ADDRESS frame nor the
//! `address_discovery` transport parameter, so a node here could negotiate
//! QAD and report nothing. A peer that offered it would be offering something
//! no node here can answer.
//!
//! Order matters and is the preference order: `src/router/alpn_table.zig:228-231`
//! records that the offer list goes out in registration order and the first
//! ALPN a peer offers that the server also offers is the one negotiated
//! (`iroh/src/endpoint.rs:973-977` upstream). rustls picks the first entry of
//! the *server's* list the client also offered, so the list below is a
//! preference order and nothing else.
//!
//! # 2. The identity model
//!
//! A node id **is** the certificate. There is no chain, no issuer, no host
//! name and no validity period:
//!
//! - The certificate is a bare 44-byte DER `SubjectPublicKeyInfo` wrapping the
//!   32 raw bytes of an Ed25519 public key — `vendor/quic/src/quic/tls13.zig:182`
//!   (`ed25519_spki_len = 44`), built by `ed25519Spki` (`:210-215`) over the
//!   fixed 12-byte prefix at `:200-207` and the node id, which is why the last
//!   32 of the 44 bytes are the id and the pin is a byte comparison
//!   (`bridge_manager.zig:186-197`, `dial_client.zig:152-183`).
//! - Presented in **both** directions. `src/transport/bridge_manager.zig:187-196`
//!   is the server half and `src/transport/dial_client.zig:167-171` is the
//!   client half, so a node's id is proved to its peer rather than claimed.
//! - Verification is `expect_peer_node_id` (client, `tls13.zig:1309`, read at
//!   `:2578-2580`) and `ClientAuth.expect_node_id` (server, `:335`, read at
//!   `:3243-3245`), both `crypto.timing_safe.eql` over 32 bytes.
//! - The CertificateVerify scheme is Ed25519 and only Ed25519 in practice:
//!   `tls13.zig:262` supplies the `.curveEd25519` algorithm tag by construction,
//!   which is what makes the `.ed25519` arm of
//!   `verifyCertificateVerifySignature` reachable for a raw SPKI at all.
//!
//! RFC 8446 §4.4.2 makes the wire bytes for all of this identical to an X.509
//! Certificate message carrying a 44-byte DER blob — which is why the bytes
//! below are the whole of it and no DER builder is needed.
//!
//! # 3. RFC 7250 raw-public-key negotiation
//!
//! Raw public keys use the 44-byte Ed25519 SPKI above. The TLS certificate-type
//! values are `X.509 = 0` and `RawPublicKey = 2` (RFC 7250 §3). The ClientHello
//! offer for each of `client_certificate_type` (19) and
//! `server_certificate_type` (20) is the one-element vector `[2]`, encoded as
//! the two bytes `[1, 2]`; EncryptedExtensions selects the offered type with the
//! one-byte value `[2]`. TLS 1.3 places this selection in EncryptedExtensions,
//! not in CertificateRequest.
//!
//! Rustls 0.23.45 exposes these requirements through
//! `ServerCertVerifier::requires_raw_public_keys`,
//! `ResolvesClientCert::only_raw_public_keys`, and
//! `ResolvesServerCert::only_raw_public_keys`. This peer returns `true` from
//! each applicable trait method; no verifier or resolver silently accepts an
//! X.509 certificate or bypasses certificate-type negotiation. The Zig TLS
//! implementation is raw-SPKI-only, so absent extensions, X.509 selection, and
//! malformed or duplicate extension encodings are not alternate success paths.
//! CertificateVerify remains mandatory and is checked as Ed25519 over the
//! presented key; both sides compare the raw 32-byte node id against the
//! configured pin.
//!
//! The negotiated contract is exercised by the stock live interop in
//! `test/rust_interop_test.zig` and by the core's RFC 7250 regressions. These
//! notes record the expected wire behavior rather than copy bytes into a
//! second, tautological test.

/// `/iroh-gossip/1`. Read from `src/node/node_config.zig:36`.
pub const ALPN_GOSSIP: &[u8] = b"/iroh-gossip/1";

/// `/iroh-relay/1`. Read from `src/node/node_config.zig:41`.
pub const ALPN_RELAY: &[u8] = b"/iroh-relay/1";

/// `/iroh-bytes/4`. Read from `src/blobs/protocol.zig:66`.
pub const ALPN_BLOBS: &[u8] = b"/iroh-bytes/4";

/// `ozai`. Read from `test/loopback_side.zig:36`, and the protocol the
/// in-process interop driver in `test/rust_interop_test.zig` speaks.
pub const ALPN_TRANSPORT: &[u8] = b"ozai";

/// `/iroh-qad/0`, reserved by `src/router/alpn_table.zig:173` and never offered.
/// Named here so the reason it is missing is written down rather than guessed.
pub const ALPN_QAD: &[u8] = b"/iroh-qad/0";

/// Everything this peer offers, in preference order. See the module doc.
pub const ALPN_OFFERED: &[&[u8]] = &[ALPN_GOSSIP, ALPN_RELAY, ALPN_BLOBS, ALPN_TRANSPORT];

/// The DER prefix of an Ed25519 `SubjectPublicKeyInfo`.
/// Read from `vendor/quic/src/quic/tls13.zig:200-207`.
pub const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2A, // SEQUENCE, 42 bytes
    0x30, 0x05, // SEQUENCE, 5 bytes: AlgorithmIdentifier
    0x06, 0x03, 0x2B, 0x65, 0x70, // OBJECT IDENTIFIER 1.3.101.112 (Ed25519)
    0x03, 0x21, 0x00, // BIT STRING, 33 bytes, 0 unused bits
];

/// A peer certificate. `tls13.zig:182` names the same 44.
pub const SPKI_LEN: usize = 44;

/// A node id, in bytes. `tls13.zig:181` and `bridge_config.zig:32`.
pub const NODE_ID_LEN: usize = 32;

/// A seed, in bytes. `base/key.zig`, `SecretKey.seed_length`.
pub const SEED_LEN: usize = 32;

/// The prefix of a PKCS#8 v2 `OneAsymmetricKey` wrapping an Ed25519 seed, so
/// that rustls' `CryptoProvider::key_provider` can load the key this peer
/// signs with. Not a Zig-side value: the Zig core takes the 32 raw seed bytes
/// (`bridge_manager.zig:114`, `dial_client.zig:107`).
pub const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2E, // SEQUENCE, 46 bytes
    0x02, 0x01, 0x00, // INTEGER 0: version 1 (v2)
    0x30, 0x05, // SEQUENCE, 5 bytes
    0x06, 0x03, 0x2B, 0x65, 0x70, // OBJECT IDENTIFIER 1.3.101.112
    0x04, 0x22, // OCTET STRING, 34 bytes
    0x04, 0x20, // OCTET STRING, 32 bytes: the seed
];

/// The 44-byte certificate a node id is presented as.
pub fn spki(node_id: &[u8; NODE_ID_LEN]) -> [u8; SPKI_LEN] {
    let mut der = [0u8; SPKI_LEN];
    der[..SPKI_PREFIX.len()].copy_from_slice(&SPKI_PREFIX);
    der[SPKI_PREFIX.len()..].copy_from_slice(node_id);
    der
}

/// The 48-byte PKCS#8 v2 key a 32-byte seed signs with.
pub fn pkcs8(seed: &[u8; SEED_LEN]) -> [u8; PKCS8_PREFIX.len() + SEED_LEN] {
    let mut der = [0u8; PKCS8_PREFIX.len() + SEED_LEN];
    der[..PKCS8_PREFIX.len()].copy_from_slice(&PKCS8_PREFIX);
    der[PKCS8_PREFIX.len()..].copy_from_slice(seed);
    der
}

/// The 32 bytes an SPKI carries, or `None` when the bytes are not one.
///
/// The same refusal `liftEd25519Spki` makes (`tls13.zig:224-245`): a length that
/// is not 44 is `MalformedSubjectPublicKeyInfo`, and so is a wrong tag or a
/// wrong prefix. This is the peer half of the pin, so it must refuse exactly
/// what the other half refuses.
pub fn lift_node_id(der: &[u8]) -> Option<[u8; NODE_ID_LEN]> {
    if der.len() != SPKI_LEN || der[..SPKI_PREFIX.len()] != SPKI_PREFIX {
        return None;
    }
    let mut node_id = [0u8; NODE_ID_LEN];
    node_id.copy_from_slice(&der[SPKI_PREFIX.len()..]);
    Some(node_id)
}

/// `true` when two node ids are the same, in time that does not depend on how
/// many leading bytes agree. The Zig side compares with `crypto.timing_safe.eql`
/// (`tls13.zig:2579`, `:3244`); this is the same property on this side.
pub fn same_node_id(left: &[u8; NODE_ID_LEN], right: &[u8; NODE_ID_LEN]) -> bool {
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

/// 32 bytes of hex into 32 bytes. `None` for anything else.
///
/// Hand-rolled rather than pulled in as a dependency: it is twelve lines and it
/// is on the path that decides whether a peer is even started.
pub fn parse_node_id_hex(text: &str) -> Option<[u8; NODE_ID_LEN]> {
    if text.len() != NODE_ID_LEN * 2 {
        return None;
    }
    let mut bytes = [0u8; NODE_ID_LEN];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        bytes[index] = ((hi << 4) | lo) as u8;
    }
    Some(bytes)
}

/// 32 bytes as 64 lower-case hex characters.
pub fn node_id_hex(node_id: &[u8; NODE_ID_LEN]) -> String {
    let mut text = String::with_capacity(NODE_ID_LEN * 2);
    for byte in node_id {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

/// 32 bytes of hex into a seed, under the same rules as [`parse_node_id_hex`].
pub fn parse_seed_hex(text: &str) -> Option<[u8; SEED_LEN]> {
    parse_node_id_hex(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two spellings the whole peer hangs on, pinned against the Zig tree.
    #[test]
    fn the_alpn_spellings_are_the_zig_tree_spellings() {
        assert_eq!(ALPN_GOSSIP, b"/iroh-gossip/1");
        assert_eq!(ALPN_RELAY, b"/iroh-relay/1");
        assert_eq!(ALPN_BLOBS, b"/iroh-bytes/4");
        assert_eq!(ALPN_TRANSPORT, b"ozai");
        // Reserved by `src/router/alpn_table.zig:173` and refused by
        // `Builder.accept`, so it is never in the offer list.
        assert_eq!(ALPN_QAD, b"/iroh-qad/0");
        assert!(!ALPN_OFFERED.contains(&ALPN_QAD));
        for offered in ALPN_OFFERED {
            assert!(!offered.is_empty(), "an empty ALPN is a protocol nobody speaks");
        }
    }

    #[test]
    fn an_spki_is_forty_four_bytes_and_the_last_thirty_two_are_the_node_id() {
        let node_id = [0x5Au8; NODE_ID_LEN];
        let der = spki(&node_id);
        assert_eq!(der.len(), 44);
        assert_eq!(der.len(), SPKI_LEN);
        assert_eq!(&der[12..], &node_id[..]);
        assert_eq!(lift_node_id(&der), Some(node_id));
    }

    #[test]
    fn a_certificate_that_is_not_an_spki_is_refused_the_way_the_core_refuses_it() {
        let node_id = [0x11u8; NODE_ID_LEN];
        let good = spki(&node_id);

        // One byte short, one byte long, and a flipped bit in the prefix: the
        // three refusals `liftEd25519Spki` names.
        assert_eq!(lift_node_id(&good[..SPKI_LEN - 1]), None);
        let mut longer = good.to_vec();
        longer.push(0);
        assert_eq!(lift_node_id(&longer), None);
        let mut wrong_tag = good;
        wrong_tag[0] = 0x31;
        assert_eq!(lift_node_id(&wrong_tag), None);
        assert_eq!(lift_node_id(&[]), None);
    }

    #[test]
    fn hex_round_trips_and_refuses_what_is_not_hex() {
        let node_id = [0xC3u8; NODE_ID_LEN];
        let text = node_id_hex(&node_id);
        assert_eq!(text.len(), 64);
        assert_eq!(parse_node_id_hex(&text), Some(node_id));
        assert_eq!(parse_node_id_hex(""), None);
        assert_eq!(parse_node_id_hex(&text[..62]), None);
        assert_eq!(parse_node_id_hex(&"z".repeat(64)), None);
        assert_eq!(parse_seed_hex(&text), Some(node_id));
    }

    #[test]
    fn the_node_id_comparison_reads_every_byte() {
        let mut node_id = [0u8; NODE_ID_LEN];
        assert!(same_node_id(&node_id, &node_id));
        // The last byte, not the first: a comparison that stopped early would
        // call this equal.
        node_id[NODE_ID_LEN - 1] = 1;
        assert!(!same_node_id(&[0u8; NODE_ID_LEN], &node_id));
    }

    #[test]
    fn the_pkcs8_key_carries_the_seed_whole() {
        let seed = [0x7Eu8; SEED_LEN];
        let der = pkcs8(&seed);
        assert_eq!(der.len(), 48);
        assert_eq!(&der[16..], &seed[..]);
    }
}