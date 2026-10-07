//! The pinned Rust interoperability partner for `test/rust_interop_test.zig`.
//!
//! Transport mode exchanges a fixed request and response over a real QUIC
//! stream. Common endpoint setup keeps upstream TLS verification unchanged and
//! checks the observed peer SPKI against the configured pin before any protocol
//! handler can access application bytes.
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
//! 12-field shape `test/two_process_progress.zig` parses, in order, so that
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

mod blobs;
mod contract;
mod gossip;
mod relay;
mod rpk;

use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rustls::pki_types::CertificateDer;

use contract::{NODE_ID_LEN, SEED_LEN};
use iroh_blobs::protocol::{ChunkRanges, ChunkRangesExt};

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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Protocol {
    Transport,
    Gossip,
    Blobs,
    Relay,
    RelayEndpoint,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Role {
    Server,
    Client,
}

/// Everything the command line can say.
struct Options {
    tls: Tls,
    bind: SocketAddr,
    seed: [u8; SEED_LEN],
    /// The node id this peer must compare with the actual peer certificate.
    expect_peer: Option<[u8; NODE_ID_LEN]>,
    /// If present, use a direct client route to connect to this address.
    connect: Option<SocketAddr>,
    /// How long this peer waits for the things it waits for.
    deadline: Duration,
    protocol: Protocol,
    role: Role,
    topic: Option<iroh_gossip::TopicId>,
    message: Option<Vec<u8>>,
    blob_hash: Option<iroh_blobs::Hash>,
    blob_range: ChunkRanges,
    blob_size: Option<u64>,
    relay_url: Option<iroh::RelayUrl>,
    relay_only: bool,
    relay_qad_bind: Option<SocketAddr>,
    relay_qad_cert: Option<PathBuf>,
    relay_qad_key: Option<PathBuf>,
}

impl Options {
    fn peer_pin(&self) -> Result<[u8; NODE_ID_LEN]> {
        self.expect_peer.context("--expect-peer is required for this mode")
    }
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
    sent: u64,
    received: u64,
    attempts: u64,
    spawned: u64,
    neighbour_up: u64,
    broadcasts_received: u64,
    blob_transfers_completed: u64,
    blob_sent_bytes: u64,
    blob_received_bytes: u64,
}

impl Counters {
    /// The one line the Zig side gates on.
    fn line(&self) -> String {
        format!(
            "progress: dials {}, refused {}, accepted {}, finished {}, up {}, \
attempts {}, spawned {}, neighbour up {}, broadcasts received {}, \
blob transfers completed {}, blob sent bytes {}, blob received bytes {}",
            self.dials,
            self.refused,
            self.accepted,
            self.finished,
            self.up,
            self.attempts,
            self.spawned,
            self.neighbour_up,
            self.broadcasts_received,
            self.blob_transfers_completed,
            self.blob_sent_bytes,
            self.blob_received_bytes,
        )
    }

    /// Print the live snapshot, and flush it: a snapshot sitting in a buffer is
    /// a snapshot the Zig side cannot gate on.
    fn print(&self) -> Result<()> {
        println!("{}", self.line());
        std::io::stdout().flush().context("flushing progress")
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
    parse_options(std::env::args().skip(1))
}

fn parse_options(args: impl IntoIterator<Item = String>) -> Result<Option<Options>> {
    let mut protocol = Protocol::Transport;
    let mut role = None;
    let mut topic = None;
    let mut message = None;
    let mut blob_hash = None;
    let mut blob_range = ChunkRanges::all();
    let mut blob_size = None;
    let mut relay_url = None;
    let mut relay_only = false;
    let mut relay_qad_bind = None;
    let mut relay_qad_cert = None;
    let mut relay_qad_key = None;
    let mut tls = Tls::Rpk;
    let mut explicit_tls = false;
    let mut bind: SocketAddr = "127.0.0.1:0".parse().expect("a literal address");
    let mut seed = [0x6Cu8; SEED_LEN];
    let mut expect_peer: Option<[u8; NODE_ID_LEN]> = None;
    let mut connect: Option<SocketAddr> = None;
    let mut deadline_ms: u64 = 30_000;

    let mut args = args.into_iter();
    while let Some(flag) = args.next() {
        let mut value = || args.next().with_context(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--protocol" => protocol = match value()?.as_str() {
                "transport" => Protocol::Transport,
                "gossip" => Protocol::Gossip,
                "blobs" => Protocol::Blobs,
                "relay" => Protocol::Relay,
                "relay-endpoint" => Protocol::RelayEndpoint,
                other => bail!("unknown protocol {other:?}"),
            },
            "--role" => role = Some(match value()?.as_str() {
                "server" => Role::Server,
                "client" => Role::Client,
                other => bail!("--role takes server or client, not {other:?}"),
            }),
            "--topic-hex" => topic = Some(iroh_gossip::TopicId::from(
                contract::parse_node_id_hex(&value()?).context("--topic-hex is not 32 bytes of hex")?
            )),
            "--message" => message = Some(value()?.into_bytes()),
            "--blob-hash" => blob_hash = Some(value()?.parse().context("--blob-hash is not a hash")?),
            "--blob-size" => blob_size = Some(value()?.parse::<u64>().context("--blob-size is not u64")?),
            "--blob-range" => {
                let text = value()?;
                blob_range = if text == "all" {
                    ChunkRanges::all()
                } else {
                    let (start, end) = text.split_once(':').context("--blob-range takes all or start:end chunks")?;
                    let start = start.parse::<u64>().context("invalid range start")?;
                    let end = end.parse::<u64>().context("invalid range end")?;
                    if start >= end { bail!("blob chunk range must be nonempty"); }
                    ChunkRanges::chunks(start..end)
                };
            }
            "--relay-url" => relay_url = Some(value()?.parse().context("--relay-url is not a relay URL")?),
            "--relay-only" => relay_only = true,
            "--relay-qad-bind" => relay_qad_bind = Some(value()?.parse().context("--relay-qad-bind is not an address")?),
            "--relay-qad-cert" => relay_qad_cert = Some(PathBuf::from(value()?)),
            "--relay-qad-key" => relay_qad_key = Some(PathBuf::from(value()?)),
            "--tls" => {
                explicit_tls = true;
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
                    "ozai-iroh-peer --protocol transport|gossip|blobs|relay|relay-endpoint \
--role server|client --bind <ip:port> --tls rpk|iroh --seed-hex <64 hex> \
--expect-peer <64 hex> [--connect <ip:port>] --for <ms> \
[--topic-hex <64 hex> --message <text>] [--blob-hash <hash> \
--blob-range all|start:end --blob-size <bytes>] [--relay-url <url> --relay-only] \
[--relay-qad-bind <ip:port> --relay-qad-cert <DER path> --relay-qad-key <PKCS8 DER path>]"
                );
                return Ok(None);
            }
            other => bail!("unknown flag {other:?}; try --help"),
        }
    }
    let role = role.unwrap_or(if connect.is_some() { Role::Client } else { Role::Server });
    if role == Role::Server && connect.is_some() {
        bail!("--connect conflicts with --role server");
    }
    if !(protocol == Protocol::Relay && role == Role::Server) && expect_peer.is_none() {
        bail!("--expect-peer is required");
    }
    if role == Role::Client && connect.is_none() && relay_url.is_none() {
        bail!("client mode requires --connect or --relay-url");
    }
    if protocol != Protocol::Transport {
        if explicit_tls && tls == Tls::Rpk {
            bail!("protocol modes use stock iroh; --tls rpk is transport-only");
        }
        tls = Tls::Iroh;
    }
    if relay_only && relay_url.is_none() {
        bail!("--relay-only requires --relay-url");
    }
    if protocol == Protocol::Transport && tls == Tls::Rpk
        && role == Role::Client && connect.is_none()
    {
        bail!("strict RPK client mode requires --connect");
    }
    Ok(Some(Options {
        tls,
        bind,
        seed,
        expect_peer,
        connect,
        deadline: Duration::from_millis(deadline_ms),
        protocol,
        role,
        topic,
        message,
        blob_hash,
        blob_range,
        blob_size,
        relay_url,
        relay_only,
        relay_qad_bind,
        relay_qad_cert,
        relay_qad_key,
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
    match options.protocol {
        Protocol::Gossip => gossip::run(&options, &node_id_hex).await,
        Protocol::Blobs => blobs::run(&options, &node_id_hex).await,
        Protocol::Relay | Protocol::RelayEndpoint => relay::run(&options, &node_id_hex).await,
        Protocol::Transport => match (options.tls, options.connect) {
            (Tls::Rpk, None) => run_noq_server(&options, &node_id_hex).await,
            (Tls::Rpk, Some(address)) => run_noq_client(&options, &node_id_hex, address).await,
            (Tls::Iroh, address) => run_iroh(&options, &node_id_hex, address).await,
        },
    }
}

/// The server banner, with the address that the peer can dial.
fn announce(node_id_hex: &str, bound: SocketAddr, tls: Tls) -> Result<()> {
    announce_with_address(node_id_hex, "listening", bound, tls, contract::ALPN_OFFERED)
}

/// The client banner; its socket is bound but is not listening for connections.
fn announce_client(node_id_hex: &str, bound: SocketAddr, tls: Tls) -> Result<()> {
    announce_with_address(node_id_hex, "bound", bound, tls, contract::ALPN_OFFERED)
}

fn announce_with_address(node_id_hex: &str, address_label: &str, bound: SocketAddr, tls: Tls, alpns: &[&[u8]]) -> Result<()> {
    println!("node  {node_id_hex}");
    println!("{address_label}  {bound}");
    println!("tls  {tls:?}");
    // One line per protocol, so the Zig side compares this peer's offer against
    // its own constants rather than against a Rust source file it cannot read.
    // `/iroh-qad/0` is deliberately absent; `contract` says why.
    for alpn in alpns {
        println!("offer  {}", String::from_utf8_lossy(alpn));
    }
    std::io::stdout().flush().context("flushing banner")
}

/// One server handshake and byte exchange, on `noq` 1.3.0.
async fn run_noq_server(options: &Options, node_id_hex: &str) -> Result<()> {
    let provider = rpk::provider();
    let quic = noq::crypto::rustls::QuicServerConfig::try_from(
        rpk::server_config(&provider, &options.seed, options.peer_pin()?)
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
    announce(node_id_hex, bound, options.tls)?;

    let mut counters = Counters::default();
    counters.attempts += 1;
    counters.print()?;
    let outcome = tokio::time::timeout(
        options.deadline,
        exchange_noq(&endpoint, options.peer_pin()?, &mut counters),
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
        rpk::client_config(&provider, &options.seed, options.peer_pin()?)
            .context("the client TLS configuration")?,
    )
    .context("the QUIC client configuration")?;
    let endpoint = noq::Endpoint::client(options.bind).context("the client socket")?;
    endpoint.set_default_client_config(noq::ClientConfig::new(Arc::new(quic)));
    let bound = endpoint.local_addr().context("the bound client address")?;
    announce_client(node_id_hex, bound, options.tls)?;

    let mut counters = Counters::default();
    counters.dials += 1;
    counters.attempts += 1;
    counters.print()?;
    let outcome = tokio::time::timeout(
        options.deadline,
        exchange_noq_client(&endpoint, address, options.peer_pin()?, &mut counters),
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
    counters.up += 1;
    counters.print()?;

    let peer_node_id = observed_peer_node_id(connection.peer_identity(), &expect_peer)?;
    let negotiated = noq_alpn(&connection)?;
    let (mut writer, mut reader) = connection.accept_bi().await.context("accepting a stream")?;
    let received = reader.read_to_end(4096).await.context("reading the request")?;
    counters.received = received.len() as u64;
    counters.print()?;
    if received.as_slice() != QUESTION {
        bail!("the client sent unexpected request bytes: {received:?}");
    }

    writer.write_all(ANSWER).await.context("writing the answer")?;
    writer.finish().context("finishing the stream")?;
    if let Some(code) = writer.stopped().await.context("waiting for answer delivery")? {
        bail!("the peer stopped the answer stream with code {code}");
    }
    counters.sent = ANSWER.len() as u64;
    counters.print()?;
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
    counters.up += 1;
    counters.print()?;

    let peer_node_id = observed_peer_node_id(connection.peer_identity(), &expect_peer)?;
    let negotiated = noq_alpn(&connection)?;
    let (mut writer, mut reader) = connection.open_bi().await.context("opening a stream")?;
    writer.write_all(QUESTION).await.context("writing the request")?;
    writer.finish().context("finishing the request")?;
    counters.sent = QUESTION.len() as u64;
    counters.print()?;

    let received = reader.read_to_end(4096).await.context("reading the answer")?;
    counters.received = received.len() as u64;
    counters.print()?;
    if received.as_slice() != ANSWER {
        bail!("the server sent unexpected answer bytes: {received:?}");
    }
    if let Some(code) = writer.stopped().await.context("waiting for request delivery")? {
        bail!("the peer stopped the request stream with code {code}");
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

async fn bind_iroh(options: &Options, alpn: &[u8]) -> Result<iroh::Endpoint> {
    let relay_mode = match &options.relay_url {
        Some(url) => {
            let quic = options.relay_qad_bind.map(|bind| iroh_relay::RelayQuicConfig::new(bind.port()));
            let config = iroh::RelayConfig::new(url.clone(), quic);
            iroh::RelayMode::Custom(iroh::RelayMap::from_iter([config]))
        }
        None => iroh::RelayMode::Disabled,
    };
    let mut builder = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(iroh::SecretKey::from_bytes(&options.seed))
        .alpns(vec![alpn.to_vec()])
        .relay_mode(relay_mode)
        .bind_addr(options.bind)
        .context("the bind address")?;
    if let Some(path) = &options.relay_qad_cert {
        let certificate = std::fs::read(path).context("reading the relay QAD certificate")?;
        builder = builder.ca_tls_config(iroh_relay::tls::CaTlsConfig::default()
            .with_extra_roots(vec![CertificateDer::from(certificate)]));
    }
    if options.relay_only {
        builder = builder.clear_ip_transports();
    }
    builder.bind().await.context("binding an iroh endpoint")
}

/// The caller owns the Endpoint until the application stream FIN is acknowledged.
/// This function authenticates the observed SPKI before returning application access.
async fn connect_iroh(
    options: &Options,
    endpoint: &iroh::Endpoint,
    alpn: &[u8],
    counters: &mut Counters,
) -> Result<iroh::endpoint::Connection> {
    let pin = options.peer_pin()?;
    counters.attempts += 1;
    let connection = match options.role {
        Role::Client => {
            counters.dials += 1;
            counters.print()?;
            let id = iroh::EndpointId::from_bytes(&pin).context("the expected peer id")?;
            let mut address = iroh::EndpointAddr::new(id);
            if let Some(ip) = options.connect {
                address = address.with_ip_addr(ip);
            }
            if let Some(url) = &options.relay_url {
                address = address.with_relay_url(url.clone());
            }
            endpoint.connect(address, alpn).await.context("the handshake")?
        }
        Role::Server => {
            counters.print()?;
            let incoming = endpoint.accept().await.context("accepting a connection")?;
            let connection = incoming.await.context("the handshake")?;
            counters.accepted += 1;
            connection
        }
    };
    observed_peer_node_id(connection.peer_identity(), &pin)?;
    if connection.alpn() != alpn {
        bail!("the handshake selected a different application ALPN");
    }
    counters.up += 1;
    counters.print()?;
    Ok(connection)
}

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
    let endpoint = bind_iroh(options, contract::ALPN_TRANSPORT).await?;

    let bound = endpoint
        .addr()
        .ip_addrs()
        .next()
        .copied()
        .context("the address iroh bound")?;
    let label = if connect.is_some() { "bound" } else { "listening" };
    announce_with_address(node_id_hex, label, bound, options.tls, &[contract::ALPN_TRANSPORT])?;

    let mut counters = Counters::default();
    let outcome = tokio::time::timeout(options.deadline, async {
        let connection = connect_iroh(options, &endpoint, contract::ALPN_TRANSPORT, &mut counters).await?;
        match options.role {
            Role::Client => exchange_iroh_client(&connection, options.peer_pin()?, &mut counters).await,
            Role::Server => exchange_iroh_server(&connection, options.peer_pin()?, &mut counters).await,
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
    connection: &iroh::endpoint::Connection,
    expect_peer: [u8; NODE_ID_LEN],
    counters: &mut Counters,
) -> Result<(String, String)> {
    let peer_node_id = observed_peer_node_id(connection.peer_identity(), &expect_peer)?;
    let negotiated = String::from_utf8(connection.alpn().to_vec())
        .context("the negotiated ALPN is not UTF-8")?;
    let (mut writer, mut reader) = connection.accept_bi().await.context("accepting a stream")?;
    let received = reader.read_to_end(4096).await.context("reading the request")?;
    counters.received = received.len() as u64;
    counters.print()?;
    if received.as_slice() != QUESTION {
        bail!("the client sent unexpected request bytes: {received:?}");
    }

    writer.write_all(ANSWER).await.context("writing the answer")?;
    writer.finish().context("finishing the stream")?;
    if let Some(code) = writer.stopped().await.context("waiting for answer delivery")? {
        bail!("the peer stopped the answer stream with code {code}");
    }
    counters.sent = ANSWER.len() as u64;
    counters.print()?;
    Ok((negotiated, peer_node_id))
}

/// Dial one explicit direct address with stock iroh and exchange both payloads.
async fn exchange_iroh_client(
    connection: &iroh::endpoint::Connection,
    expect_peer: [u8; NODE_ID_LEN],
    counters: &mut Counters,
) -> Result<(String, String)> {
    let peer_node_id = observed_peer_node_id(connection.peer_identity(), &expect_peer)?;
    let negotiated = String::from_utf8(connection.alpn().to_vec())
        .context("the negotiated ALPN is not UTF-8")?;
    let (mut writer, mut reader) = connection.open_bi().await.context("opening a stream")?;
    writer.write_all(QUESTION).await.context("writing the request")?;
    writer.finish().context("finishing the request")?;
    counters.sent = QUESTION.len() as u64;
    counters.print()?;

    // Reading the answer to FIN proves that the peer received and checked the
    // finished request before the endpoint is dropped.
    let received = reader.read_to_end(4096).await.context("reading the answer")?;
    counters.received = received.len() as u64;
    counters.print()?;
    if received.as_slice() != ANSWER {
        bail!("the server sent unexpected answer bytes: {received:?}");
    }
    if let Some(code) = writer.stopped().await.context("waiting for request delivery")? {
        bail!("the peer stopped the request stream with code {code}");
    }
    Ok((negotiated, peer_node_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(flags: &[&str]) -> Result<Option<Options>> {
        parse_options(flags.iter().map(|flag| (*flag).to_owned()))
    }

    #[test]
    fn only_relay_server_can_omit_the_peer_pin() {
        assert!(options(&[]).is_err());
        assert!(options(&["--protocol", "relay"]).unwrap().unwrap().expect_peer.is_none());
        assert!(options(&["--protocol", "relay", "--role", "client",
            "--relay-url", "http://127.0.0.1:1234"]).is_err());
        assert!(options(&["--protocol", "relay-endpoint"]).is_err());
    }

    #[test]
    fn conflicting_role_and_connection_is_rejected() {
        assert!(options(&["--role", "server", "--connect", "127.0.0.1:1",
            "--expect-peer", &"11".repeat(32)]).is_err());
    }

    #[test]
    fn malformed_blob_ranges_are_rejected() {
        for range in ["1:1", "2:1", "-1:2", "1", "all:2"] {
            assert!(options(&["--blob-range", range]).is_err());
        }
    }

    #[test]
    fn observed_identity_requires_the_actual_pinned_spki() {
        let pin = [0x11; NODE_ID_LEN];
        let identity = || Some(Box::new(vec![CertificateDer::from(
            contract::spki(&pin).to_vec()
        )]) as Box<dyn std::any::Any>);
        assert_eq!(observed_peer_node_id(identity(), &pin).unwrap(), contract::node_id_hex(&pin));
        assert!(observed_peer_node_id(identity(), &[0x22; NODE_ID_LEN]).is_err());
        assert!(observed_peer_node_id(None, &pin).is_err());
        assert!(observed_peer_node_id(Some(Box::new(vec![
            CertificateDer::from(vec![0; 44])
        ])), &pin).is_err());
        assert!(observed_peer_node_id(Some(Box::new(Vec::<CertificateDer<'static>>::new())), &pin).is_err());
    }
}