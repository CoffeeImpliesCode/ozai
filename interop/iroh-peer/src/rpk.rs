//! TLS 1.3 over strict RFC 7250 raw Ed25519 public keys.
//!
//! The direct `noq` adapter uses rustls' raw-public-key verifier and resolver
//! contracts, requiring certificate types 19 and 20 to negotiate
//! `RawPublicKey`. It presents the same 44-byte SPKI and pins the same 32-byte
//! node id as the Zig core:
//!
//! - each peer presents one bare Ed25519 SPKI, with no certificate chain;
//! - client and server verifiers compare its 32-byte key against the configured
//!   node-id pin;
//! - CertificateVerify remains mandatory and is checked as Ed25519 against the
//!   presented key.
//!
//! TLS 1.3 selects the offered certificate type in EncryptedExtensions. There
//! is no X.509 fallback and no extension bypass in this adapter.
//!
//! The verifiers are `Debug + Send + Sync` value types holding one
//! `[u8; 32]`, so there is nothing to share and nothing to free.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::ResolvesClientCert;
use rustls::crypto::{
    CryptoProvider, WebPkiSupportedAlgorithms, verify_tls13_signature_with_raw_key,
};
use rustls::pki_types::{
    CertificateDer, InvalidSignature, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
    SignatureVerificationAlgorithm, SubjectPublicKeyInfoDer, UnixTime, alg_id,
};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::CertifiedKey;
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error as TlsError,
    SignatureScheme, SupportedProtocolVersion, server,
};

use crate::contract;

/// TLS 1.3 and only TLS 1.3. RFC 9001 §4.2 makes TLS 1.2 unavailable over QUIC
/// anyway; iroh says the same at `iroh-1.3.0/src/tls/verifier.rs:18`.
const PROTOCOL_VERSIONS: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// Ed25519 and nothing else, which is what an iroh node ever signs with. The
/// Zig core offers five schemes on the wire (`tls13.zig:3895-3907`) and its
/// `.ed25519` arm is the only one this identity can use.
static ED25519: Ed25519Ring = Ed25519Ring;

/// The supported-scheme table both verifiers answer with. `all` is what
/// `verify_tls13_signature_with_raw_key` looks a scheme up in, and `mapping` is
/// what turns `SignatureScheme::ED25519` into the algorithm above.
static SUPPORTED: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[&ED25519],
    mapping: &[(SignatureScheme::ED25519, &[&ED25519])],
};

/// Ed25519 signature verification, over ring.
///
/// `rustls::crypto::ring::sign::Ed25519SigningKey` is private, so the
/// verification side is spelled out here. iroh builds the same value over
/// ed25519-dalek (`iroh-1.3.0/src/tls/verifier.rs:181-211`); ring is already in
/// this graph through noq's `ring` feature, so this costs no new dependency.
#[derive(Debug)]
struct Ed25519Ring;

impl SignatureVerificationAlgorithm for Ed25519Ring {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
            .verify(message, signature)
            .map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> alg_id::AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn signature_alg_id(&self) -> alg_id::AlgorithmIdentifier {
        alg_id::ED25519
    }
}

/// The public key of `seed`, computed with ring's Ed25519.
///
/// `ring` is already in the graph through noq's `ring` feature and rustls'
/// provider, so this costs no new dependency for the one value the peer needs
/// before rustls is configured: the node id it has to print and pin.
pub fn node_id_of(seed: &[u8; contract::SEED_LEN]) -> [u8; contract::NODE_ID_LEN] {
    use ring::signature::KeyPair;
    let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(seed)
        .expect("a 32-byte seed is a valid Ed25519 seed");
    let mut node_id = [0u8; contract::NODE_ID_LEN];
    node_id.copy_from_slice(pair.public_key().as_ref());
    node_id
}

/// The key and the 44-byte certificate this node presents.
///
/// rustls puts `cert.cert` into the Certificate message verbatim and never
/// parses it, so a bare SPKI is a legal value for it; the SPKI is read back by
/// `verify_tls13_signature_with_raw_key` on the peer's side, which is the same
/// read the Zig core makes with `liftEd25519Spki`.
fn certified_key(
    provider: &CryptoProvider,
    seed: &[u8; contract::SEED_LEN],
) -> Result<Arc<CertifiedKey>, TlsError> {
    let der = contract::pkcs8(seed);
    let key = provider
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.to_vec())))?;
    // rustls 0.23.45's `CertifiedKey.cert` is a chain, and a raw key is the
    // one-certificate case of it: the Certificate message carries these bytes
    // verbatim and nothing parses them.
    Ok(Arc::new(CertifiedKey {
        cert: vec![CertificateDer::from(contract::spki(&node_id_of(seed)).to_vec())],
        key,
        ocsp: None,
    }))
}

/// Presents this peer's SPKI as a server certificate and declares that raw
/// public keys are the only certificate type it supports.

#[derive(Debug)]
struct SpkiResolver {
    key: Arc<CertifiedKey>,
}

impl server::ResolvesServerCert for SpkiResolver {
    fn resolve(&self, _client_hello: server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.key))
    }

    fn only_raw_public_keys(&self) -> bool {
        true
    }
}

/// Presents this peer's SPKI when a server requests client authentication.
#[derive(Debug)]
struct SpkiClientResolver {
    key: Arc<CertifiedKey>,
}

impl ResolvesClientCert for SpkiClientResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        sigschemes
            .contains(&SignatureScheme::ED25519)
            .then(|| Arc::clone(&self.key))
    }

    fn only_raw_public_keys(&self) -> bool {
        true
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// The peer pin on the server side: the client's certificate must carry
/// `expected`.
///
/// The Zig mirror is `ClientAuth.expect_node_id`, read at `tls13.zig:3243-3245`,
/// with `mode = .required` (`bridge_config.zig:183-185`, which turns the pin
/// into a demanded certificate whether or not `require_peer_certificate` says
/// so). `client_auth_mandatory` is that `.required`: a client that answers with
/// no certificate at all fails here rather than passing unproved.
#[derive(Debug)]
struct PinnedClient {
    expected: [u8; contract::NODE_ID_LEN],
}

impl ClientCertVerifier for PinnedClient {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // No `certificate_authorities`: an identity here is a raw key, so there
        // is no issuer to point at. `buildCertificateRequest` says the same
        // (`tls13.zig:375-380`).
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        if !intermediates.is_empty() {
            return Err(TlsError::InvalidCertificate(CertificateError::UnknownIssuer));
        }
        let Some(presented) = contract::lift_node_id(end_entity.as_ref()) else {
            return Err(TlsError::InvalidCertificate(CertificateError::BadEncoding));
        };
        if !contract::same_node_id(&presented, &self.expected) {
            return Err(TlsError::InvalidCertificate(CertificateError::UnknownIssuer));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &SUPPORTED,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SUPPORTED.supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// The peer pin on the client side: the server's certificate must carry
/// `expected`.
#[derive(Debug)]
struct PinnedServer {
    expected: [u8; contract::NODE_ID_LEN],
}

impl ServerCertVerifier for PinnedServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if !intermediates.is_empty() {
            return Err(TlsError::InvalidCertificate(CertificateError::UnknownIssuer));
        }
        let Some(presented) = contract::lift_node_id(end_entity.as_ref()) else {
            return Err(TlsError::InvalidCertificate(CertificateError::BadEncoding));
        };
        if !contract::same_node_id(&presented, &self.expected) {
            return Err(TlsError::InvalidCertificate(CertificateError::UnknownIssuer));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &SUPPORTED,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SUPPORTED.supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// The one crypto provider both configurations are built with.
///
/// `ring` rather than `aws-lc-rs`, and said out loud rather than left to
/// `CryptoProvider::install_default`: a peer that silently picked a provider
/// would make a signature a function of a process-wide global, which is the
/// hidden input `docs/ARCHITECTURE.md:37` and `AGENTS.md` §2 forbid. It also
/// keeps one provider in the graph, so noq-proto's and rustls' agree.
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A client configuration that presents this peer's SPKI and pins `peer`.
pub fn client_config(
    provider: &Arc<CryptoProvider>,
    seed: &[u8; contract::SEED_LEN],
    peer: [u8; contract::NODE_ID_LEN],
) -> Result<rustls::ClientConfig, TlsError> {
    let resolver = SpkiClientResolver {
        key: certified_key(provider, seed)?,
    };
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::clone(provider))
        .with_protocol_versions(PROTOCOL_VERSIONS)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServer { expected: peer }))
        .with_client_cert_resolver(Arc::new(resolver));
    config.alpn_protocols = contract::ALPN_OFFERED
        .iter()
        .map(|alpn| alpn.to_vec())
        .collect();
    Ok(config)
}

/// A server configuration that presents this peer's SPKI and pins `peer`.
///
/// `max_early_data_size` is `0`, so this server offers no 0-RTT. The Zig side
/// offers it (`tls13.zig:3383-3390` puts `max_early_data_size` at `0xffffffff`
/// in a NewSessionTicket) but nothing here asks for it, and a server that
/// refuses 0-RTT is not a server that fails a full handshake.
pub fn server_config(
    provider: &Arc<CryptoProvider>,
    seed: &[u8; contract::SEED_LEN],
    peer: [u8; contract::NODE_ID_LEN],
) -> Result<rustls::ServerConfig, TlsError> {
    let resolver = SpkiResolver {
        key: certified_key(provider, seed)?,
    };
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::clone(provider))
        .with_protocol_versions(PROTOCOL_VERSIONS)?
        .with_client_cert_verifier(Arc::new(PinnedClient { expected: peer }))
        .with_cert_resolver(Arc::new(resolver));
    // RFC 9001 §4.6.1: this must be `u32::MAX` or `0`.
    config.max_early_data_size = 0;
    // The protocols this peer answers, in preference order. Without this rustls
    // offers none and answers every ClientHello with `no_application_protocol`
    // (alert 120), which is a refusal that looks like a missing ALPN on the
    // other side rather than a missing list here.
    config.alpn_protocols = contract::ALPN_OFFERED
        .iter()
        .map(|alpn| alpn.to_vec())
        .collect();
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The node id is the last 32 bytes of the certificate, and it is the
    /// Ed25519 public key of the seed — the whole identity model in one check.
    #[test]
    fn the_certificate_carries_the_node_id() {
        let seed = [0x2Au8; contract::SEED_LEN];
        let node_id = node_id_of(&seed);
        let der = contract::spki(&node_id);
        assert_eq!(contract::lift_node_id(&der), Some(node_id));
    }

    /// The key that signs the CertificateVerify is the key the certificate
    /// carries. Checked through rustls itself: the resolver's key is loaded from
    /// the PKCS#8 wrapper this module builds, and a wrapper that were wrong
    /// would fail to load.
    #[test]
    fn the_key_loads_from_the_pkcs8_wrapper() {
        let provider = provider();
        let seed = [0x37u8; contract::SEED_LEN];
        let key = certified_key(&provider, &seed).expect("the PKCS#8 wrapper loads");
        assert_eq!(key.cert.len(), 1);
        assert_eq!(key.cert[0].as_ref().len(), contract::SPKI_LEN);
    }

    /// The server pin is the same comparison the other way.
    #[test]
    fn the_server_pin_refuses_another_node() {
        let pinned = PinnedClient {
            expected: [0x01u8; contract::NODE_ID_LEN],
        };
        let stranger = contract::spki(&[0x02u8; contract::NODE_ID_LEN]);
        let certificate = CertificateDer::from(stranger.to_vec());
        assert!(
            pinned
                .verify_client_cert(&certificate, &[], UnixTime::now())
                .is_err(),
            "a client certificate carrying another key must be refused"
        );
        let mine = contract::spki(&[0x01u8; contract::NODE_ID_LEN]);
        let certificate = CertificateDer::from(mine.to_vec());
        assert!(
            pinned
                .verify_client_cert(&certificate, &[], UnixTime::now())
                .is_ok(),
            "the pinned node's own certificate must be accepted"
        );
    }

    /// The client pin refuses another server and permits only the pinned SPKI.
    #[test]
    fn the_client_pin_refuses_another_node() {
        let pinned = PinnedServer {
            expected: [0x31u8; contract::NODE_ID_LEN],
        };
        let name = ServerName::try_from("ozai").expect("test server name");
        let stranger = CertificateDer::from(
            contract::spki(&[0x32u8; contract::NODE_ID_LEN]).to_vec(),
        );
        assert!(
            pinned
                .verify_server_cert(&stranger, &[], &name, &[], UnixTime::now())
                .is_err(),
            "a server certificate carrying another key must be refused"
        );
        let mine = CertificateDer::from(
            contract::spki(&[0x31u8; contract::NODE_ID_LEN]).to_vec(),
        );
        assert!(
            pinned
                .verify_server_cert(&mine, &[], &name, &[], UnixTime::now())
                .is_ok(),
            "the pinned server's own certificate must be accepted"
        );
    }
}