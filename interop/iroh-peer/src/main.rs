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
//! - `--tls rpk` (the default) drives **noq 1.3.0** directly with the TLS
//!   configuration in [`rpk`]: the 44-byte Ed25519 SPKI presented in both
//!   directions, a byte-for-byte node-id pin on each side, an Ed25519
//!   CertificateVerify, and RFC 7250 switched off. noq 1.3.0 is the exact
//!   version `iroh 1.3.0` pins (`iroh-1.3.0/Cargo.toml:289-292`).
//! - `--tls iroh` drives **stock `iroh::Endpoint` 1.3.0**, whose rustls
//!   verifiers require RFC 7250 certificate-type negotiation that the vendored
//!   Zig core does not implement. It is here so that the refusal is something
//!   the test observes rather than something this crate asserts.
//!
//! [`contract`] holds the wire contract both modes are written against, and the
//! record of what does not interoperate.
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
//! listening  <ip>:<port>
//! progress: dails … (the field list `two_process_progress.zig` requires)
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

use contract::{NODE_ID_LEN, SEED_LEN};

/// The bytes this peer answers with. A constant rather than a flag's value, so
/// the Zig side has one string to expect and there is no second place to change
/// it.
const ANSWER: &[u8] = b"iroh-peer-to-ozai";

/// Which TLS configuration to run.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tls {
    /// The deviation-free peer: noq 1.3.0 with this crate's `rpk` module.
    Rpk,
    /// Stock iroh 1.3.0, RFC 7250 and all.
    Iroh,
}

/// Everything the command line can say.
struct Options {
    tls: Tls,
    bind: SocketAddr,
    seed: [u8; SEED_LEN],
    /// The node id this peer pins its peer to. There is no "any peer" mode:
    /// a pinless peer proves nothing about who it is talking to, and the Zig
    /// side always pins.
    expect_peer: [u8; NODE_ID_LEN],
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
            "--for" => {
                deadline_ms = value()?
                    .parse()
                    .context("--for is a number of milliseconds")?
            }
            "--help" | "-h" => {
                println!(
                    "ozai-iroh-peer --bind <ip:port> --tls rpk|iroh --seed-hex <64 hex> \
--expect-peer <64 hex> --for <ms>"
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
    match options.tls {
        Tls::Rpk => run_noq(&options, &node_id_hex).await,
        Tls::Iroh => run_iroh(&options, &node_id_hex).await,
    }
}

/// The two banner lines, in the spelling `test/two_process_child.zig` reads:
/// `value("listening")` for the address and `value("node")` for the identity.
fn announce(node_id_hex: &str, bound: SocketAddr, tls: Tls) {
    println!("node  {node_id_hex}");
    println!("listening  {bound}");
    println!("tls  {tls:?}");
    // One line per protocol, so the Zig side compares this peer's offer against
    // its own constants rather than against a Rust source file it cannot read.
    // `/iroh-qad/0` is deliberately absent; `contract` says why.
    for alpn in contract::ALPN_OFFERED {
        println!("offer  {}", String::from_utf8_lossy(alpn));
    }
    let _ = std::io::stdout().flush();
}

// ─── noq 1.3.0, RFC 7250 off ──────────────────────────────────────────────

/// One handshake and one byte exchange, on `noq` 1.3.0.
async fn run_noq(options: &Options, node_id_hex: &str) -> Result<()> {
    let provider = rpk::provider();
    let quic = noq::crypto::rustls::QuicServerConfig::try_from(
        rpk::server_config(&provider, &options.seed, options.expect_peer)
            .context("the server TLS configuration")?,
    )
    .context("the QUIC server configuration")?;

    let mut config = noq::ServerConfig::with_crypto(Arc::new(quic));
    // Two streams is what this peer uses: one the peer opens and one it opens.
    // The transport's defaults are far larger and a second peer is not
    // something this peer has anything to say about.
    if let Some(transport) = Arc::get_mut(&mut config.transport) {
        transport.max_concurrent_uni_streams(2_u8.into());
        transport.max_concurrent_bidi_streams(2_u8.into());
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
            if counters.received == 0 || counters.sent == 0 {
                bail!(
                    "a handshake completed but bytes did not cross both ways: {}",
                    counters.line()
                );
            }
            Ok(())
        }
        // The reason goes on the pipe as well as to stderr: the Zig side reads
        // stdout, and a run that failed with the reason only on stderr is a run
        // whose failure this peer did not report.
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

/// Accept one connection, read one stream, answer on a stream of this peer's own.
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

    // The peer proved its id inside `verify_client_cert`, which is the mirror of
    // the Zig server's `ClientAuth.expect_node_id`. noq exposes no accessor for
    // a peer's key — the Zig core has `peerNodeId()` and noq does not — so the
    // id this reports is the pin that comparison was made against. Asserting
    // that it equals what the Zig side saw on its own is the test's job.
    let peer_node_id = contract::node_id_hex(&expect_peer);

    let mut reader = connection.accept_uni().await.context("accepting a stream")?;
    // noq's `read_to_end` takes a limit and answers with the bytes, so there is
    // no buffer here to size wrong.
    let received = reader.read_to_end(4096).await.context("reading")?;
    counters.received = received.len() as u64;
    counters.print();

    let mut writer = connection.open_uni().await.context("opening a stream")?;
    writer.write_all(ANSWER).await.context("writing")?;
    writer.finish().context("finishing the stream")?;
    counters.sent = ANSWER.len() as u64;
    counters.print();

    // The exchange is over. The connection is dropped here rather than awaited:
    // noq's `closed()` answers with the peer's close *reason* rather than with a
    // `Result`, and a peer that read a reason as a failure would report a clean
    // shutdown as an error. What the Zig side compares is the bytes, so nothing
    // here waits for a close in order to report it.

    Ok((
        String::from_utf8_lossy(&received).into_owned(),
        peer_node_id,
    ))
}

// ─── stock iroh 1.3.0 ─────────────────────────────────────────────────────

/// The same exchange on `iroh::Endpoint`, with iroh's own TLS.
///
/// This mode is here to be observed failing. Its rustls verifiers require RFC
/// 7250 certificate-type negotiation (`iroh-1.3.0/src/tls/verifier.rs:106`,
/// `:176`; `resolver.rs:35`, `:52`), which the vendored Zig core neither offers
/// nor answers, so a run in this mode ends at EncryptedExtensions with rustls'
/// `PeerIncompatible::IncorrectCertificateTypeExtension`. A run in which it
/// succeeds is a change in iroh's TLS and would make `contract`'s record wrong.
///
/// iroh 1.3.0 also exposes no accessor for an accepted connection's peer node
/// id — `remote_node_id` appears only in commented-out lines of its own tests
/// (`iroh-1.3.0/src/endpoint.rs:2570`, `:2671`) — and its
/// `ClientCertificateVerifier::verify_client_cert` accepts any key it is given
/// (`verifier.rs:137-140`), so the client identity is proved but never named.
/// Both facts are why the report below says `-` for the peer.
async fn run_iroh(options: &Options, node_id_hex: &str) -> Result<()> {
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
    announce(node_id_hex, bound, options.tls);

    let mut counters = Counters::default();
    counters.attempts += 1;
    counters.print();

    let outcome =
        tokio::time::timeout(options.deadline, exchange_iroh(&endpoint, &mut counters)).await;
    match outcome {
        Ok(Ok(negotiated)) => {
            println!("{}", counters.report(node_id_hex, &negotiated, "-"));
            Ok(())
        }
        Ok(Err(err)) => {
            println!("{}", counters.report(node_id_hex, "-", "-"));
            Err(err).context("the iroh handshake")
        }
        Err(_elapsed) => {
            println!("{}", counters.report(node_id_hex, "-", "-"));
            bail!("no iroh connection within --for")
        }
    }
}

async fn exchange_iroh(
    endpoint: &iroh::Endpoint,
    counters: &mut Counters,
) -> Result<String> {
    let incoming = endpoint.accept().await.context("accepting a connection")?;
    let connection = incoming.await.context("the handshake")?;
    counters.accepted += 1;
    counters.established += 1;
    counters.up += 1;
    counters.print();

    let mut reader = connection.accept_uni().await.context("accepting a stream")?;
    let received = reader.read_to_end(4096).await.context("reading")?;
    counters.received = received.len() as u64;
    counters.print();

    let mut writer = connection.open_uni().await.context("opening a stream")?;
    writer.write_all(ANSWER).await.context("writing")?;
    writer.finish().context("finishing the stream")?;
    counters.sent = ANSWER.len() as u64;
    counters.print();

    // The same reasoning as `exchange_noq`: the exchange is over and the
    // connection is dropped rather than awaited.
    Ok(String::from_utf8_lossy(connection.alpn()).into_owned())
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