//! A minimal iroh peer, and the partner for `test/rust_interop_test.zig`.
//!
//! It is a test peer and not a product: an ephemeral UDP socket, one Ed25519
//! identity, the ALPNs the Zig tree speaks, one handshake, and application
//! bytes in both directions. Everything else iroh 1.3.0 has — relays, tickets,
//! discovery, 0-RTT, metrics, a node store — is a subsystem this peer would
//! have to be wrong about rather than right about.
//!
//! # Two TLS modes, and why both exist
//!
//! - `--tls rpk` (the default) drives **noq 1.3.0** directly with the strict
//!   configuration in [`rpk`]: certificate types 19 and 20 negotiate raw keys,
//!   the 44-byte Ed25519 SPKI is presented in both directions, each side checks
//!   the peer's node-id pin, and CertificateVerify proves possession. With
//!   `--connect`, this same configuration also exercises the client role.
//! - `--tls iroh` drives **stock `iroh::Endpoint` 1.3.0** in either role. It
//!   keeps iroh's verifier and resolver unchanged, checks the observed peer
//!   SPKI against the configured pin after the handshake, then exchanges real
//!   bidirectional-stream bytes with the Zig peer.
//!
//! [`contract`] holds the negotiated wire contract both modes are written
//! against.
//!
//! # What it prints, and who reads it
//!
//! The Zig side reads this process the way `test/two_process_child.zig` reads
//! `ozai-node`: two pipes and a `poll`, a banner, a live `progress:` line after
//! every state change, and a final report. The `progress:` line is the exact
//! 15-field shape `test/two_process_progress.zig` parses, in order, so that
//! harness's own `Want` gates read this peer without a second parser.
//!
//! ```text
//! node  <64 hex characters>
//! listening  <ip>:<port>    (server) or bound  <ip>:<port>    (client)
//! progress: dials … (the field list `two_process_progress.zig` requires)
//! stopped:  …
//! ```
//!
//! A peer cannot wait for a state, so it reports one and the Zig side decides
//! what to do about a deadline. Every wait there is therefore on an observed
//! counter and not on a duration.

mod contract;
mod rpk;

use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rustls::pki_types::CertificateDer;

use contract::{NODE_ID_LEN, SEED_LEN};

/// The exact payload this peer sends first.
const QUESTION: &[u8] = b"ozai-to-iroh-peer";

/// The exact payload this peer returns after validating the request.
const ANSWER: &[u8] = b"iroh-peer-to-ozai";

/// Which TLS configuration to run.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tls {
    /// The strict direct noq peer.
    Rpk,
    /// Stock iroh 1.3.0, with the upstream verifier unchanged.
    Iroh,
}

/// Everything the command line can say.
struct Options {
    tls: Tls,
    bind: SocketAddr,
    seed: [u8; SEED_LEN],
    /// The node id this peer must compare with the actual peer certificate.
    expect_peer: [u8; NODE_ID_LEN],
    /// If present, use a direct client route to connect to this address.
    connect: Option<SocketAddr>,
    /// How long this peer waits for the things it waits for.
    deadline: Duration,
}

/// The counters the `progress:` line carries, in the order
/// `test/two_process_progress.zig` requires.
///
/// Every field is published whether or not this peer has a use for it: a gate
/// that named a field the program does not publish panics in that harness, and
/// a peer that invented its own order would be a second parser's worth of
/// drift.
#[derive(Default)]
struct Counters {
    dials: u64,
    refused: u64,
    accepted: u64,
    finished: u64,
    up: u64,
    admitted: u64,
    established: u64,
    registered: u64,
    sent: u64,
    received: u64,
    forwarded: u64,
    attempts: u64,
    spawned: u64,
    disconnected: u64,
    closed: u64,
}

impl Counters {
    /// The one line the Zig side gates on.
    fn line(&self) -> String {
        format!(
            "progress: dials {}, refused {}, accepted {}, finished {}, up {}, \
admitted {}, established {}, registered {}, sent {}, received {}, \
forwarded {}, attempts {}, spawned {}, disconnected {}, closed {}",
            self.dials,
            self.refused,
            self.accepted,
            self.finished,
            self.up,
            self.admitted,
            self.established,
            self.registered,
            self.sent,
            self.received,
            self.forwarded,
            self.attempts,
            self.spawned,
            self.disconnected,
            self.closed,
        )
    }

    /// Print the live snapshot, and flush it: a snapshot sitting in a buffer is
    /// a snapshot the Zig side cannot gate on.
    fn print(&self) {
        println!("{}", self.line());
        let _ = std::io::stdout().flush();
    }

    /// The final report, printed once after the peer has wound down.
    fn report(&self, node_id: &str, negotiated: &str, peer_node_id: &str) -> String {
        format!(
            "stopped: node {node_id}, alpn {negotiated}, peer {peer_node_id}, \
accepted {}, up {}, sent {}, received {}",
            self.accepted, self.up, self.sent, self.received
        )
    }
}

fn main() -> Result<()> {
    let options = match parse_args() {
        Ok(Some(options)) => options,
        // `--help` is an answer, not a failure: the Zig side prints a failing
        // run with the command line it used, and a peer that exits 1 on `--help`
        // reads like a peer that could not start.
        Ok(None) => return Ok(()),
        Err(err) => {
            eprintln!("ozai-iroh-peer: {err:#}");
            return Err(err);
        }
    };
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("the tokio runtime")?
        .block_on(run(options))
}

/// Read the command line. `Ok(None)` is `--help`.
fn parse_args() -> Result<Option<Options>> {
    let mut tls = Tls::Rpk;
    let mut bind: SocketAddr = "127.0.0.1:0".parse().expect("a literal address");
    let mut seed = [0x6Cu8; SEED_LEN];
    let mut expect_peer: Option<[u8; NODE_ID_LEN]> = None;
    let mut connect: Option<SocketAddr> = None;
    let mut deadline_ms: u64 = 30_000;

    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = || args.next().with_context(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--tls" => {
                tls = match value()?.as_str() {
                    "rpk" => Tls::Rpk,
                    "iroh" => Tls::Iroh,
                    other => bail!("--tls takes rpk or iroh, not {other:?}"),
                };
            }
            "--bind" => bind = value()?.parse().context("--bind is not an address")?,
            "--seed-hex" => {
                seed = contract::parse_seed_hex(&value()?)
                    .context("--seed-hex is not 32 bytes of hex")?
            }
            "--expect-peer" => {
                expect_peer = Some(
                    contract::parse_node_id_hex(&value()?)
                        .context("--expect-peer is not 32 bytes of hex")?,
                )
            }
            "--connect" => connect = Some(value()?.parse().context("--connect is not an address")?),
            "--for" => {
                deadline_ms = value()?
                    .parse()
                    .context("--for is a number of milliseconds")?
            }
            "--help" | "-h" => {
                println!(
                    "ozai-iroh-peer --bind <ip:port> --tls rpk|iroh --seed-hex <64 hex> \
--expect-peer <64 hex> [--connect <ip:port>] --for <ms>"
                );
                return Ok(None);
            }
            other => bail!("unknown flag {other:?}; try --help"),
        }
    }
    Ok(Some(Options {
        tls,
        bind,
        seed,
        expect_peer: expect_peer.context("--expect-peer is required")?,
        connect,
        deadline: Duration::from_millis(deadline_ms),
    }))
}

async fn run(options: Options) -> Result<()> {
    // A peer that offered the reserved protocol would be offering something no
    // node in this tree can register (`src/router/alpn_table.zig:173`), so the
    // offer list is checked against it here rather than only in `contract`'s
    // tests: this is the list that goes on the wire.
    assert!(
        !contract::ALPN_OFFERED.contains(&contract::ALPN_QAD),
        "the reserved QAD protocol must never be offered"
    );
    let node_id = rpk::node_id_of(&options.seed);
    let node_id_hex = contract::node_id_hex(&node_id);
    match (options.tls, options.connect) {
        (Tls::Rpk, None) => run_noq_server(&options, &node_id_hex).await,
        (Tls::Rpk, Some(address)) => run_noq_client(&options, &node_id_hex, address).await,
        (Tls::Iroh, address) => run_iroh(&options, &node_id_hex, address).await,
    }
}

/// The server banner, with the address that the peer can dial.
fn announce(node_id_hex: &str, bound: SocketAddr, tls: Tls) {
    announce_with_address(node_id_hex, "listening", bound, tls);
}

/// The client banner; its socket is bound but is not listening for connections.
fn announce_client(node_id_hex: &str, bound: SocketAddr, tls: Tls) {
    announce_with_address(node_id_hex, "bound", bound, tls);
}

fn announce_with_address(node_id_hex: &str, address_label: &str, bound: SocketAddr, tls: Tls) {
    println!("node  {node_id_hex}");
    println!("{address_label}  {bound}");
    println!("tls  {tls:?}");
    // One line per protocol, so the Zig side compares this peer's offer against
    // its own constants rather than against a Rust source file it cannot read.
    // `/iroh-qad/0` is deliberately absent; `contract` says why.
    for alpn in contract::ALPN_OFFERED {
        println!("offer  {}", String::from_utf8_lossy(alpn));
    }
    let _ = std::io::stdout().flush();
}

/// One server handshake and byte exchange, on `noq` 1.3.0.
async fn run_noq_server(options: &Options, node_id_hex: &str) -> Result<()> {
    let provider = rpk::provider();
    let quic = noq::crypto::rustls::QuicServerConfig::try_from(
        rpk::server_config(&provider, &options.seed, options.expect_peer)
            .context("the server TLS configuration")?,
    )
    .context("the QUIC server configuration")?;

    let mut config = noq::ServerConfig::with_crypto(Arc::new(quic));
    // One bidirectional stream carries this peer's request and response.
    if let Some(transport) = Arc::get_mut(&mut config.transport) {
        transport.max_concurrent_bidi_streams(1_u8.into());
    }

    let endpoint = noq::Endpoint::server(config, options.bind).context("the server socket")?;
    let bound = endpoint.local_addr().context("the bound address")?;
    announce(node_id_hex, bound, options.tls);

    let mut counters = Counters::default();
    counters.attempts += 1;
    counters.print();
    let outcome = tokio::time::timeout(
        options.deadline,
        exchange_noq(&endpoint, options.expect_peer, &mut counters),
    )
    .await;

    match outcome {
        Ok(Ok((negotiated, peer_node_id))) => {
            println!("{}", counters.report(node_id_hex, &negotiated, &peer_node_id));
            if counters.received != QUESTION.len() as u64 || counters.sent != ANSWER.len() as u64 {
                bail!(
                    "the bidirectional payload exchange was incomplete: {}",
                    counters.line()
                );
            }
            Ok(())
        }
        Ok(Err(err)) => {
            println!("{}", counters.report(node_id_hex, "-", "-"));
            Err(err)
        }
        Err(_elapsed) => {
            println!("{}", counters.report(node_id_hex, "-", "-"));
            bail!("no connection within --for; last progress line was {}", counters.line())
        }
    }
}

/// One client handshake and byte exchange, on strict `noq` 1.3.0.
async fn run_noq_client(
    options: &Options,
    node_id_hex: &str,
    address: SocketAddr,
) -> Result<()> {
    let provider = rpk::provider();
    let quic = noq::crypto::rustls::QuicClientConfig::try_from(
        rpk::client_config(&provider, &options.seed, options.expect_peer)
            .context("the client TLS configuration")?,
    )
    .context("the QUIC client configuration")?;
    let endpoint = noq::Endpoint::client(options.bind).context("the client socket")?;
    endpoint.set_default_client_config(noq::ClientConfig::new(Arc::new(quic)));
    let bound = endpoint.local_addr().context("the bound client address")?;
    announce_client(node_id_hex, bound, options.tls);

    let mut counters = Counters::default();
    counters.dials += 1;
    counters.attempts += 1;
    counters.print();
    let outcome = tokio::time::timeout(
        options.deadline,
        exchange_noq_client(&endpoint, address, options.expect_peer, &mut counters),
    )
    .await;

    match outcome {
        Ok(Ok((negotiated, peer_node_id))) => {
            println!("{}", counters.report(node_id_hex, &negotiated, &peer_node_id));
            if counters.sent != QUESTION.len() as u64 || counters.received != ANSWER.len() as u64 {
                bail!(
                    "the bidirectional payload exchange was incomplete: {}",
                    counters.line()
                );
            }
            Ok(())
        }
        Ok(Err(err)) => {
            println!("{}", counters.report(node_id_hex, "-", "-"));
            Err(err)
        }
        Err(_elapsed) => {
            println!("{}", counters.report(node_id_hex, "-", "-"));
            bail!("no connection within --for; last progress line was {}", counters.line())
        }
    }
}

/// Accept one connection and exchange the exact request and answer on one
/// bidirectional stream.
async fn exchange_noq(
    endpoint: &noq::Endpoint,
    expect_peer: [u8; NODE_ID_LEN],
    counters: &mut Counters,
) -> Result<(String, String)> {
    let incoming = endpoint.accept().await.context("accepting a connection")?;
    let connection = incoming.await.context("the handshake")?;
    counters.accepted += 1;
    counters.established += 1;
    counters.up += 1;
    counters.print();

    let peer_node_id = observed_peer_node_id(connection.peer_identity(), &expect_peer)?;
    let negotiated = noq_alpn(&connection)?;
    let (mut writer, mut reader) = connection.accept_bi().await.context("accepting a stream")?;
    let received = reader.read_to_end(4096).await.context("reading the request")?;
    counters.received = received.len() as u64;
    counters.print();
    if received.as_slice() != QUESTION {
        bail!("the client sent unexpected request bytes: {received:?}");
    }

    writer.write_all(ANSWER).await.context("writing the answer")?;
    writer.finish().context("finishing the stream")?;
    if let Some(code) = writer.stopped().await.context("waiting for answer delivery")? {
        bail!("the peer stopped the answer stream with code {code}");
    }
    counters.sent = ANSWER.len() as u64;
    counters.print();
    Ok((negotiated, peer_node_id))
}

/// Connect to a Zig endpoint and exchange the exact request and answer on one
/// bidirectional stream.
async fn exchange_noq_client(
    endpoint: &noq::Endpoint,
    address: SocketAddr,
    expect_peer: [u8; NODE_ID_LEN],
    counters: &mut Counters,
) -> Result<(String, String)> {
    let connecting = endpoint.connect(address, "ozai").context("starting the connection")?;
    let connection = connecting.await.context("the handshake")?;
    counters.established += 1;
    counters.up += 1;
    counters.print();

    let peer_node_id = observed_peer_node_id(connection.peer_identity(), &expect_peer)?;
    let negotiated = noq_alpn(&connection)?;
    let (mut writer, mut reader) = connection.open_bi().await.context("opening a stream")?;
    writer.write_all(QUESTION).await.context("writing the request")?;
    writer.finish().context("finishing the request")?;
    counters.sent = QUESTION.len() as u64;
    counters.print();

    let received = reader.read_to_end(4096).await.context("reading the answer")?;
    counters.received = received.len() as u64;
    counters.print();
    if received.as_slice() != ANSWER {
        bail!("the server sent unexpected answer bytes: {received:?}");
    }
    Ok((negotiated, peer_node_id))
}

/// Read the actual certificate carried by a Rustls-backed connection, then
/// compare the observed SPKI node id with the configured pin.
fn observed_peer_node_id(
    identity: Option<Box<dyn std::any::Any>>,
    expected: &[u8; NODE_ID_LEN],
) -> Result<String> {
    let identity = identity.context("the TLS connection exposed no peer identity")?;
    let certificates = identity
        .downcast_ref::<Vec<CertificateDer<'static>>>()
        .context("the TLS connection exposed an unexpected peer identity type")?;
    if certificates.len() != 1 {
        bail!(
            "the peer identity must contain exactly one raw SPKI, got {} certificates",
            certificates.len()
        );
    }
    let presented = contract::lift_node_id(certificates[0].as_ref())
        .context("the peer identity is not the supported 44-byte Ed25519 SPKI")?;
    if !contract::same_node_id(&presented, expected) {
        bail!(
            "the observed peer node id {} did not match the configured pin {}",
            contract::node_id_hex(&presented),
            contract::node_id_hex(expected)
        );
    }
    Ok(contract::node_id_hex(&presented))
}

/// Read the negotiated ALPN from noq's Rustls handshake data.
fn noq_alpn(connection: &noq::Connection) -> Result<String> {
    let handshake = connection
        .handshake_data()
        .context("the handshake exposed no negotiated data")?;
    let data = handshake
        .downcast::<noq::crypto::rustls::HandshakeData>()
        .map_err(|_| anyhow::anyhow!("the handshake exposed an unexpected data type"))?;
    let protocol = data.protocol.context("the handshake selected no ALPN")?;
    String::from_utf8(protocol).context("the negotiated ALPN is not UTF-8")
}

// ─── stock iroh 1.3.0 ─────────────────────────────────────────────────────

/// The same exchange on stock `iroh::Endpoint`, with iroh's own TLS.
///
/// The upstream certificate verifier is left unchanged. This stock mode checks
/// the actual peer certificate exposed by the completed connection against the
/// configured pin before reading application bytes; the direct `noq` mode
/// additionally enforces that pin inside its TLS verifier.
async fn run_iroh(
    options: &Options,
    node_id_hex: &str,
    connect: Option<SocketAddr>,
) -> Result<()> {
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(iroh::SecretKey::from_bytes(&options.seed))
        .alpns(contract::ALPN_OFFERED.iter().map(|alpn| alpn.to_vec()).collect())
        .bind_addr((options.bind.ip(), 0))
        .context("the bind address")?
        .bind()
        .await
        .context("binding an iroh endpoint")?;

    let bound = endpoint
        .addr()
        .ip_addrs()
        .next()
        .copied()
        .context("the address iroh bound")?;
    if connect.is_some() {
        announce_client(node_id_hex, bound, options.tls);
    } else {
        announce(node_id_hex, bound, options.tls);
    }

    let mut counters = Counters::default();
    if connect.is_some() {
        counters.dials += 1;
    }
    counters.attempts += 1;
    counters.print();
    let outcome = tokio::time::timeout(options.deadline, async {
        match connect {
            Some(address) => {
                exchange_iroh_client(&endpoint, address, options.expect_peer, &mut counters).await
            }
            None => exchange_iroh_server(&endpoint, options.expect_peer, &mut counters).await,
        }
    })
    .await;
    match outcome {
        Ok(Ok((negotiated, peer_node_id))) => {
            println!("{}", counters.report(node_id_hex, &negotiated, &peer_node_id));
            if counters.received != QUESTION.len() as u64 || counters.sent != ANSWER.len() as u64 {
                bail!(
                    "the bidirectional payload exchange was incomplete: {}",
                    counters.line()
                );
            }
            Ok(())
        }
        Ok(Err(err)) => {
            println!("{}", counters.report(node_id_hex, "-", "-"));
            Err(err).context("the iroh handshake or exchange")
        }
        Err(_elapsed) => {
            println!("{}", counters.report(node_id_hex, "-", "-"));
            bail!("no iroh connection within --for")
        }
    }
}

async fn exchange_iroh_server(
    endpoint: &iroh::Endpoint,
    expect_peer: [u8; NODE_ID_LEN],
    counters: &mut Counters,
) -> Result<(String, String)> {
    let incoming = endpoint.accept().await.context("accepting a connection")?;
    let connection = incoming.await.context("the handshake")?;
    counters.accepted += 1;
    counters.established += 1;
    counters.up += 1;
    counters.print();

    let peer_node_id = observed_peer_node_id(connection.peer_identity(), &expect_peer)?;
    let negotiated = String::from_utf8(connection.alpn().to_vec())
        .context("the negotiated ALPN is not UTF-8")?;
    let (mut writer, mut reader) = connection.accept_bi().await.context("accepting a stream")?;
    let received = reader.read_to_end(4096).await.context("reading the request")?;
    counters.received = received.len() as u64;
    counters.print();
    if received.as_slice() != QUESTION {
        bail!("the client sent unexpected request bytes: {received:?}");
    }

    writer.write_all(ANSWER).await.context("writing the answer")?;
    writer.finish().context("finishing the stream")?;
    if let Some(code) = writer.stopped().await.context("waiting for answer delivery")? {
        bail!("the peer stopped the answer stream with code {code}");
    }
    counters.sent = ANSWER.len() as u64;
    counters.print();
    Ok((negotiated, peer_node_id))
}

/// Dial one explicit direct address with stock iroh and exchange both payloads.
async fn exchange_iroh_client(
    endpoint: &iroh::Endpoint,
    address: SocketAddr,
    expect_peer: [u8; NODE_ID_LEN],
    counters: &mut Counters,
) -> Result<(String, String)> {
    let peer_id = iroh::EndpointId::from_bytes(&expect_peer).context("the expected peer id")?;
    let peer_addr = iroh::EndpointAddr::new(peer_id).with_ip_addr(address);
    let connection = endpoint
        .connect(peer_addr, contract::ALPN_GOSSIP)
        .await
        .context("the handshake")?;
    counters.established += 1;
    counters.up += 1;
    counters.print();

    let peer_node_id = observed_peer_node_id(connection.peer_identity(), &expect_peer)?;
    let negotiated = String::from_utf8(connection.alpn().to_vec())
        .context("the negotiated ALPN is not UTF-8")?;
    let (mut writer, mut reader) = connection.open_bi().await.context("opening a stream")?;
    writer.write_all(QUESTION).await.context("writing the request")?;
    writer.finish().context("finishing the request")?;
    counters.sent = QUESTION.len() as u64;
    counters.print();

    // Reading the answer to FIN proves that the peer received and checked the
    // finished request before the endpoint is dropped.
    let received = reader.read_to_end(4096).await.context("reading the answer")?;
    counters.received = received.len() as u64;
    counters.print();
    if received.as_slice() != ANSWER {
        bail!("the server sent unexpected answer bytes: {received:?}");
    }
    Ok((negotiated, peer_node_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact field list `test/two_process_progress.zig:25-29` parses, in
    /// that order. A gate naming a field this line does not publish panics in
    /// that harness, and a field in the wrong place reads as a wrong count.
    #[test]
    fn the_progress_line_carries_every_field_in_order() {
        let line = Counters::default().line();
        assert!(line.starts_with("progress: "));
        let fields = [
            "dials",
            "refused",
            "accepted",
            "finished",
            "up",
            "admitted",
            "established",
            "registered",
            "sent",
            "received",
            "forwarded",
            "attempts",
            "spawned",
            "disconnected",
            "closed",
        ];
        // Walked field by field rather than searched for: `parseProgress` reads
        // this line positionally, so a field that moved is a field the Zig
        // harness would read the wrong value for.
        let mut at = "progress: ".len();
        for (index, name) in fields.iter().enumerate() {
            assert!(
                line[at..].starts_with(name),
                "the progress line wants {name} at {at}: {line}"
            );
            at += name.len();
            assert_eq!(line[at..].as_bytes()[0], b' ', "no space before a count: {line}");
            at += 1;
            // Every default counter is zero, so every count is one digit. A
            // wider one would mean a default that is not zero, and this line is
            // the shape the harness parses.
            assert_eq!(line[at..].as_bytes()[0], b'0', "a default counter is not 0: {line}");
            at += 1;
            if index + 1 < fields.len() {
                assert!(line[at..].starts_with(", "), "no separator at {at}: {line}");
                at += 2;
            }
        }
        assert_eq!(at, line.len(), "the line has fields past the list: {line}");
    }

    /// The banner spelling `test/two_process_child.zig` and
    /// `test/two_process_launch.zig` read. This peer prints the node id as hex
    /// rather than the `z-base-32` an `ozai-node` prints, and the Zig side
    /// reads it with `NodeId.parseHex`; the length is what both agree on.
    #[test]
    fn the_banner_carries_a_hex_node_id_of_the_right_length() {
        assert_eq!(contract::node_id_hex(&[0x0Fu8; NODE_ID_LEN]).len(), 64);
    }
}