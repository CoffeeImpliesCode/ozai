//! Deterministic iroh 1.3.0 partner for the native (Zig) QUIC interop fixture.
//!
//! One process plays exactly one role (`--mode listen` or `--mode dial`) and runs
//! exactly one bounded transfer scenario per connection. Every byte that crosses
//! the connection is declared on the command line: nothing is inferred, nothing is
//! swallowed, and there is no flush sleep. The process exits `0` only after every
//! declared payload was sent and every declared expectation matched byte for byte.

use std::future::Future;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use iroh::endpoint::presets;
use iroh::endpoint::{Connection, ConnectionError};
use iroh::{Endpoint, EndpointAddr, PublicKey, RelayMode, SecretKey, TransportAddr};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

const DEFAULT_ALPN: &str = "/ozai/1";
const MAX_PAYLOAD: usize = 64 * 1024;
const PIN_REJECT_REASON: &[u8] = b"peer pin mismatch";

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let config = match parse_args()? {
        Parsed::Help => {
            print_help();
            return Ok(());
        }
        Parsed::Run(config) => config,
    };
    let deadline = config.timeout;
    let secret_key = config.secret_key.clone().unwrap_or_else(SecretKey::generate);

    // Relays and address lookup are switched off on purpose: the fixture only ever
    // talks to the peer it was pointed at, over the socket it was bound to.
    let mut builder = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .secret_key(secret_key)
        .alpns(config.alpns.clone());
    if let Some(addr) = config.bind {
        builder = builder
            .bind_addr(addr)
            .with_context(|| format!("invalid bind address {addr}"))?;
    }
    let endpoint = within(deadline, "bind endpoint", async { builder.bind().await }).await?;
    println!("node {}", hex::encode(endpoint.id().as_bytes()));
    for addr in endpoint.bound_sockets() {
        println!("listening {addr}");
    }

    // The scenario and the endpoint shutdown are both bounded, and the shutdown is
    // always awaited, so a failure can never leave the endpoint half torn down.
    let scenario = tokio::time::timeout(deadline, drive(&endpoint, &config)).await;
    let cleanup = tokio::time::timeout(deadline, async { endpoint.close().await }).await;
    match scenario {
        Ok(Ok(())) => {
            cleanup.map_err(|_| anyhow!("endpoint shutdown timed out"))?;
            Ok(())
        }
        Ok(Err(err)) => {
            let _ = cleanup;
            Err(err)
        }
        Err(_) => {
            let _ = cleanup;
            bail!("scenario did not finish within {}", secs(deadline));
        }
    }
}

async fn drive(endpoint: &Endpoint, config: &Config) -> Result<()> {
    match config.mode {
        Mode::Listen => listen(endpoint, config).await,
        Mode::Dial => dial(endpoint, config).await,
    }
}

async fn listen(endpoint: &Endpoint, config: &Config) -> Result<()> {
    println!("ready");
    for index in 0..config.max_conns {
        let accepted = tokio::time::timeout(config.timeout, async { endpoint.accept().await })
            .await
            .map_err(|_| anyhow!("accept timed out after {}", secs(config.timeout)))?
            .context("accept failed")?;
        let conn = within(config.timeout, "incoming handshake", async { accepted.await }).await?;
        serve_one(conn, config)
            .await
            .with_context(|| format!("connection {} of {} failed", index + 1, config.max_conns))?;
    }
    println!("done");
    Ok(())
}

async fn dial(endpoint: &Endpoint, config: &Config) -> Result<()> {
    let (target_id, target_addr) = config
        .dial
        .context("--mode dial requires --dial <node_id_hex>@<ip>:<port>")?;
    println!(
        "dialling {}@{}",
        hex::encode(target_id.as_bytes()),
        target_addr
    );

    let peer = EndpointAddr::from_parts(target_id, [TransportAddr::Ip(target_addr)]);
    let alpn = config
        .alpns
        .first()
        .expect("validated: at least one ALPN is always configured");
    // `connect` verifies the peer certificate against `target_id`, so a wrong pin
    // fails here instead of producing a connection.
    let conn = within(config.timeout, "connect", async {
        endpoint.connect(peer, alpn).await
    })
    .await?;
    log_peer(conn.remote_id(), conn.alpn());
    if let Err(err) = check_pin(conn.remote_id(), config) {
        conn.close(0u8.into(), PIN_REJECT_REASON);
        return Err(err);
    }

    exchange(&conn, config).await?;
    println!("success");
    Ok(())
}

/// Runs the declared scenario for one authenticated connection.
async fn serve_one(conn: Connection, config: &Config) -> Result<()> {
    log_peer(conn.remote_id(), conn.alpn());
    if let Err(err) = check_pin(conn.remote_id(), config) {
        conn.close(0u8.into(), PIN_REJECT_REASON);
        return Err(err);
    }

    exchange(&conn, config).await?;

    // The peer closes the connection once it holds every byte it declared, so this
    // is the shutdown barrier. Its absence is reported, but it does not invalidate
    // the bytes this role already verified. `closed` resolves to the reason itself
    // rather than to a result, and an application close is the only reason this
    // fixture ever declared, so every other variant is a transport failure the
    // declared bytes do not excuse.
    match tokio::time::timeout(config.timeout, conn.closed()).await {
        Ok(ConnectionError::ApplicationClosed(reason)) => println!("peer closed {reason:?}"),
        Ok(reason) => return Err(anyhow!("peer connection failed: {reason}")),
        Err(_) => eprintln!("warning: peer did not close within {}", secs(config.timeout)),
    }
    Ok(())
}

/// Runs exactly one bounded transfer scenario over an established connection.
///
/// Phase one sends everything this role declared, in a fixed order. Phase two
/// verifies everything this role expects, with every receive bounded by the
/// scenario deadline. The listener replies on the bi stream only after its own
/// expectations hold, which makes that reply the peer's proof that every byte it
/// sent was received.
async fn exchange(conn: &Connection, config: &Config) -> Result<()> {
    let deadline = config.timeout;
    let (gate_tx, gate_rx) = oneshot::channel::<()>();
    let mut tasks: Vec<(&'static str, JoinHandle<Result<Channel>>)> = Vec::new();
    let mut gated: Option<(&'static str, JoinHandle<Result<Channel>>)> = None;

    if config.mode == Mode::Dial {
        if let Some(payload) = config.send_bi.as_deref() {
            let (mut send, mut recv) =
                within(deadline, "open_bi", async { conn.open_bi().await }).await?;
            within(deadline, "write bi stream", async {
                send.write_all(payload).await
            })
            .await?;
            // `finish` is synchronous in noq 1.3.0: it marks the send side finished
            // and returns. It stays inside `within` so the step keeps the scenario
            // deadline and its own name.
            within(deadline, "finish bi stream", async { send.finish() }).await?;
            println!("sent_bi {}", payload.len());
            if config.expect_bi.is_some() {
                tasks.push((
                    "bi",
                    tokio::spawn(async move {
                        let reply = within(deadline, "read bi reply", async {
                            recv.read_to_end(MAX_PAYLOAD).await
                        })
                        .await?;
                        println!("received_bi {}", hex::encode(&reply));
                        Ok(Channel::Bi(reply))
                    }),
                ));
            }
        }
    } else if config.expect_bi.is_some() || config.response_bi.is_some() {
        let conn = conn.clone();
        let response = config.response_bi.clone();
        let echo = config.echo;
        gated = Some((
            "bi",
            tokio::spawn(async move {
                let (mut send, mut recv) =
                    within(deadline, "accept_bi", async { conn.accept_bi().await }).await?;
                let payload = within(deadline, "read bi stream", async {
                    recv.read_to_end(MAX_PAYLOAD).await
                })
                .await?;
                println!("received_bi {}", hex::encode(&payload));
                // The gate opens only once every other channel of this role has
                // been verified, so the reply is the peer's completion barrier.
                if gate_rx.await.is_ok() {
                    let reply = response
                        .as_deref()
                        .or(if echo { Some(payload.as_slice()) } else { None });
                    if let Some(reply) = reply {
                        within(deadline, "write bi reply", async {
                            send.write_all(reply).await
                        })
                        .await?;
                        within(deadline, "finish bi reply", async { send.finish() }).await?;
                    }
                }
                Ok(Channel::Bi(payload))
            }),
        ));
    }

    if let Some(payload) = config.send_uni.as_deref() {
        let mut send = within(deadline, "open_uni", async { conn.open_uni().await }).await?;
        within(deadline, "write uni stream", async {
            send.write_all(payload).await
        })
        .await?;
        within(deadline, "finish uni stream", async { send.finish() }).await?;
        println!("sent_uni {}", payload.len());
    }
    if let Some(payload) = config.send_datagram.as_deref() {
        conn.send_datagram(payload.to_vec().into())
            .context("send datagram")?;
        println!("sent_datagram {}", payload.len());
    }

    if config.expect_uni.is_some() {
        let conn = conn.clone();
        tasks.push((
            "uni",
            tokio::spawn(async move {
                let mut recv =
                    within(deadline, "accept_uni", async { conn.accept_uni().await }).await?;
                let payload = within(deadline, "read uni stream", async {
                    recv.read_to_end(MAX_PAYLOAD).await
                })
                .await?;
                println!("received_uni {}", hex::encode(&payload));
                Ok(Channel::Uni(payload))
            }),
        ));
    }
    if config.expect_datagram.is_some() {
        let conn = conn.clone();
        tasks.push((
            "datagram",
            tokio::spawn(async move {
                let payload = within(deadline, "read datagram", async {
                    conn.read_datagram().await
                })
                .await?
                .to_vec();
                println!("received_datagram {}", hex::encode(&payload));
                Ok(Channel::Datagram(payload))
            }),
        ));
    }

    // Every receive task is joined, so none is ever dropped unfinished. The gated
    // bi task is released only after all other expectations have been checked, and
    // the gate sender is dropped first on the failure path so it cannot hang.
    let mut failures: Vec<String> = Vec::new();
    for (name, task) in tasks {
        match join_within(deadline, name, task).await {
            Ok(channel) => record(channel, &mut failures, config),
            Err(err) => failures.push(format!("{name}: {err:#}")),
        }
    }
    if failures.is_empty() {
        let _ = gate_tx.send(());
    } else {
        drop(gate_tx);
    }
    if let Some((name, task)) = gated {
        match join_within(deadline, name, task).await {
            Ok(channel) => record(channel, &mut failures, config),
            Err(err) => failures.push(format!("{name}: {err:#}")),
        }
    }
    if !failures.is_empty() {
        bail!("{}", failures.join("; "));
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Listen,
    Dial,
}

enum Channel {
    Bi(Vec<u8>),
    Uni(Vec<u8>),
    Datagram(Vec<u8>),
}

impl Channel {
    fn name(&self) -> &'static str {
        match self {
            Channel::Bi(_) => "bi",
            Channel::Uni(_) => "uni",
            Channel::Datagram(_) => "datagram",
        }
    }

    fn payload(&self) -> &[u8] {
        match self {
            Channel::Bi(payload) | Channel::Uni(payload) | Channel::Datagram(payload) => payload,
        }
    }

    fn expected<'a>(&self, config: &'a Config) -> Option<&'a [u8]> {
        match self {
            Channel::Bi(_) => config.expect_bi.as_deref(),
            Channel::Uni(_) => config.expect_uni.as_deref(),
            Channel::Datagram(_) => config.expect_datagram.as_deref(),
        }
    }
}

/// Checks one received channel against its declared expectation and records the
/// mismatch, if any, without stopping the other channels from being checked.
fn record(channel: Channel, failures: &mut Vec<String>, config: &Config) {
    match verify(channel.payload(), channel.expected(config)) {
        Ok(()) => {
            if let Some(expected) = channel.expected(config) {
                println!("verified_{} {}", channel.name(), hex::encode(expected));
            }
        }
        Err(err) => failures.push(format!("{}: {err:#}", channel.name())),
    }
}

struct Config {
    mode: Mode,
    bind: Option<SocketAddr>,
    dial: Option<(PublicKey, SocketAddr)>,
    expect_remote: Option<PublicKey>,
    secret_key: Option<SecretKey>,
    alpns: Vec<Vec<u8>>,
    send_bi: Option<Vec<u8>>,
    send_uni: Option<Vec<u8>>,
    send_datagram: Option<Vec<u8>>,
    expect_bi: Option<Vec<u8>>,
    expect_uni: Option<Vec<u8>>,
    expect_datagram: Option<Vec<u8>>,
    response_bi: Option<Vec<u8>>,
    echo: bool,
    max_conns: usize,
    timeout: Duration,
}

impl Config {
    /// The single validation pass: everything the rest of the program assumes is
    /// checked here, once, before an endpoint is bound.
    fn validate(&self) -> Result<()> {
        if self.max_conns == 0 {
            bail!("--max-conns must be at least 1");
        }
        if self.timeout.is_zero() {
            bail!("--timeout-secs must be greater than zero");
        }
        match self.mode {
            Mode::Listen => {
                if self.bind.is_none() {
                    bail!("--mode listen requires --listen <ip>:<port>");
                }
                if self.send_bi.is_some() {
                    bail!("--send-bi is dial initiated: a listener uses --response-bi instead");
                }
                if self.dial.is_some() {
                    bail!("--dial is only valid with --mode dial");
                }
            }
            Mode::Dial => {
                if self.dial.is_none() {
                    bail!("--mode dial requires --dial <node_id_hex>@<ip>:<port>");
                }
                if self.response_bi.is_some() {
                    bail!("--response-bi is only valid with --mode listen");
                }
                if self.expect_bi.is_some() && self.send_bi.is_none() {
                    bail!("--expect-bi is the bi reply, which requires --send-bi");
                }
            }
        }
        if !self.echo && self.response_bi.is_some() {
            bail!("--no-echo conflicts with --response-bi: that reply is already fixed");
        }
        if let (Some((dial_id, _)), Some(pin)) = (&self.dial, &self.expect_remote) {
            if dial_id != pin {
                bail!(
                    "--expect-remote {} contradicts the --dial pin {}",
                    hex::encode(pin.as_bytes()),
                    hex::encode(dial_id.as_bytes())
                );
            }
        }
        Ok(())
    }
}

enum Parsed {
    Run(Config),
    Help,
}

fn parse_args() -> Result<Parsed> {
    let mut args = std::env::args().skip(1);
    let mut mode = Mode::Listen;
    let mut bind = None;
    let mut dial = None;
    let mut expect_remote = None;
    let mut secret_key = None;
    let mut alpns: Vec<Vec<u8>> = Vec::new();
    let mut send_bi = None;
    let mut send_uni = None;
    let mut send_datagram = None;
    let mut expect_bi = None;
    let mut expect_uni = None;
    let mut expect_datagram = None;
    let mut response_bi = None;
    let mut echo = true;
    let mut max_conns = 1usize;
    let mut timeout_secs = 30u64;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(Parsed::Help),
            "--mode" => {
                mode = match value(&mut args, "--mode")?.as_str() {
                    "listen" => Mode::Listen,
                    "dial" => Mode::Dial,
                    other => bail!("invalid --mode {other:?}: expected \"listen\" or \"dial\""),
                };
            }
            "--listen" => {
                bind = Some(value(&mut args, "--listen")?.parse().with_context(|| {
                    format!("invalid --listen value, expected <ip>:<port>")
                })?);
            }
            "--dial" => {
                let raw = value(&mut args, "--dial")?;
                let (id, addr) = raw
                    .split_once('@')
                    .context("invalid --dial value, expected <node_id_hex>@<ip>:<port>")?;
                let key = hex32(id, "--dial node id")?;
                let addr = addr.parse().with_context(|| {
                    format!("invalid --dial address {addr}, expected <ip>:<port>")
                })?;
                dial = Some((key, addr));
            }
            "--secret-key" => {
                let key = hex32(&value(&mut args, "--secret-key")?, "--secret-key")?;
                secret_key = Some(SecretKey::from_bytes(key.as_bytes()));
            }
            "--expect-remote" => {
                expect_remote =
                    Some(hex32(&value(&mut args, "--expect-remote")?, "--expect-remote")?);
            }
            "--alpn" => alpns.push(value(&mut args, "--alpn")?.into_bytes()),
            "--send-bi" => send_bi = Some(hex_payload(&value(&mut args, "--send-bi")?, "--send-bi")?),
            "--send-uni" => {
                send_uni = Some(hex_payload(&value(&mut args, "--send-uni")?, "--send-uni")?)
            }
            "--send-datagram" => {
                send_datagram = Some(hex_payload(
                    &value(&mut args, "--send-datagram")?,
                    "--send-datagram",
                )?);
            }
            "--expect-bi" => {
                expect_bi = Some(hex_payload(&value(&mut args, "--expect-bi")?, "--expect-bi")?)
            }
            "--expect-uni" => {
                expect_uni = Some(hex_payload(&value(&mut args, "--expect-uni")?, "--expect-uni")?)
            }
            "--expect-datagram" => {
                expect_datagram = Some(hex_payload(
                    &value(&mut args, "--expect-datagram")?,
                    "--expect-datagram",
                )?);
            }
            "--response-bi" => {
                response_bi = Some(hex_payload(
                    &value(&mut args, "--response-bi")?,
                    "--response-bi",
                )?)
            }
            "--no-echo" => echo = false,
            "--max-conns" => {
                max_conns = value(&mut args, "--max-conns")?
                    .parse()
                    .context("invalid --max-conns value, expected an integer")?;
            }
            "--timeout" | "--timeout-secs" => {
                timeout_secs = value(&mut args, &arg)?
                    .parse()
                    .context("invalid --timeout-secs value, expected an integer")?;
            }
            other => bail!("unknown option: {other} (see --help)"),
        }
    }

    if alpns.is_empty() {
        alpns.push(DEFAULT_ALPN.as_bytes().to_vec());
    }
    let config = Config {
        mode,
        bind,
        dial,
        expect_remote,
        secret_key,
        alpns,
        send_bi,
        send_uni,
        send_datagram,
        expect_bi,
        expect_uni,
        expect_datagram,
        response_bi,
        echo,
        max_conns,
        timeout: Duration::from_secs(timeout_secs),
    };
    config.validate()?;
    Ok(Parsed::Run(config))
}

fn value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    args.next().ok_or_else(|| anyhow!("missing value for {flag}"))
}

fn hex_payload(raw: &str, flag: &str) -> Result<Vec<u8>> {
    hex::decode(raw).with_context(|| format!("invalid hex for {flag}"))
}

fn hex32(raw: &str, flag: &str) -> Result<PublicKey> {
    let bytes = hex_payload(raw, flag)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow!("{flag} must be 32 bytes, got {}", bytes.len()))?;
    PublicKey::from_bytes(&bytes).with_context(|| format!("invalid key for {flag}"))
}

fn log_peer(remote_id: PublicKey, alpn: &[u8]) {
    println!("connected {}", hex::encode(remote_id.as_bytes()));
    // The negotiated protocol is borrowed from the connection, so nothing is copied
    // here, and an empty slice is the stack reporting that none was selected.
    if alpn.is_empty() {
        println!("negotiated_alpn none");
    } else {
        println!("negotiated_alpn {}", hex::encode(alpn));
    }
}

fn check_pin(remote_id: PublicKey, config: &Config) -> Result<()> {
    match &config.expect_remote {
        Some(expected) if *expected != remote_id => bail!(
            "remote identity mismatch: pinned {} but the peer authenticated as {}",
            hex::encode(expected.as_bytes()),
            hex::encode(remote_id.as_bytes())
        ),
        _ => Ok(()),
    }
}

fn verify(got: &[u8], expected: Option<&[u8]>) -> Result<()> {
    match expected {
        Some(expected) if expected != got => bail!(
            "payload mismatch: expected {} ({} bytes), got {} ({} bytes)",
            hex::encode(expected),
            expected.len(),
            hex::encode(got),
            got.len()
        ),
        _ => Ok(()),
    }
}

/// Awaits `fut` under the scenario deadline and names the failure it produced.
///
/// `E` is whatever iroh or noq named for the operation being bounded — a bind, a
/// connect, a handshake, a stream, a datagram — and it is converted once, here.
/// Each call site keeps its own concrete error instead of erasing it into
/// `anyhow::Error` before the deadline is applied, and the conversion is a move:
/// it adds no per-call allocation and no clone.
async fn within<T, E, F>(deadline: Duration, what: &str, fut: F) -> Result<T>
where
    E: Into<anyhow::Error>,
    F: Future<Output = std::result::Result<T, E>>,
{
    match tokio::time::timeout(deadline, fut).await {
        Ok(result) => {
            let result: Result<T> = result.map_err(|err| err.into());
            result.with_context(|| format!("{what} failed"))
        }
        Err(_) => bail!("{what} timed out after {}", secs(deadline)),
    }
}

/// Awaits an owned transfer task under the scenario deadline.
async fn join_within<T>(deadline: Duration, what: &str, task: JoinHandle<Result<T>>) -> Result<T> {
    match tokio::time::timeout(deadline, task).await {
        Ok(Ok(result)) => result.with_context(|| format!("{what} failed")),
        Ok(Err(join)) => bail!("{what} task failed: {join}"),
        Err(_) => bail!("{what} timed out after {}", secs(deadline)),
    }
}

fn secs(duration: Duration) -> String {
    format!("{}s", duration.as_secs())
}

fn print_help() {
    println!(
        "\
iroh-partner - deterministic iroh 1.3.0 partner for the native interop fixture

Role (one process plays exactly one role):
  --mode listen                 accept connections, one scenario per connection
  --mode dial                   connect to one peer, one scenario

Endpoint:
  --listen <ip:port>            required with --mode listen; optional with --mode
                                dial, to pin the local UDP port
  --dial <node_id_hex>@<ip:port>  required with --mode dial; pins the peer
  --secret-key <hex32>          endpoint identity, generated when omitted
  --expect-remote <hex32>       require this authenticated remote id, fail closed
  --alpn <name>                 repeatable; the listener accepts all of them, the
                                dialer requests the first
  --timeout-secs <n>            deadline for every operation and for the whole
                                scenario (default 30)
  --max-conns <n>               connections handled in listen mode (default 1)

Scenario (each flag declares one obligation; nothing is inferred):
  --send-bi <hex>               open the bi stream (dial only), send these bytes
  --expect-bi <hex>             require these bytes on the bi stream: the reply for
                                a dialer, the peer's request for a listener
  --response-bi <hex>           listen only: reply with these bytes
  --send-uni <hex>              open a uni stream and send these bytes
  --expect-uni <hex>            require these bytes on the peer's uni stream
  --send-datagram <hex>         send one unreliable datagram
  --expect-datagram <hex>       require exactly this datagram
  --no-echo                     listen only: do not reply with the received bytes
                                when --response-bi is absent

A role sends everything it declared first, then verifies everything it expects. The
listener sends its bi reply only once its own expectations hold, so a dialer that
passes --expect-bi proves that every byte it sent was received.

stdout, one flushed line per event:
  node <hex>                    local endpoint id
  listening <ip:port>           bound socket
  ready                         the listener is accepting
  dialling <hex>@<ip:port>
  connected <hex>               authenticated remote id from the peer certificate
  negotiated_alpn <hex>|none
  sent_bi|sent_uni|sent_datagram <len>
  received_bi|received_uni|received_datagram <hex>
  verified_bi|verified_uni|verified_datagram <hex>
  peer closed ...               the listener observed the peer shutdown
  done | success

Exit status is 0 only when every declared payload matched, and non-zero on a
mismatch, a pin or ALPN failure, a deadline, or any I/O error."
    );
}