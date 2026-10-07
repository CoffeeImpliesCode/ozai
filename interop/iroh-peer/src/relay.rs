//! Stock relay carrier and same-connection relay-to-direct application probe.
use std::io::Write;
use anyhow::{Context, Result, ensure};
use iroh_relay::{
    client::{Client, ClientBuilder},
    protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg},
    server::{QuicConfig, RelayConfig, Server, ServerConfig},
};
use n0_future::{SinkExt, StreamExt};

const ALPN: &[u8] = b"ozai-relay-endpoint/1";

pub async fn run(options: &crate::Options, node_id_hex: &str) -> Result<()> {
    println!("node  {node_id_hex}");
    std::io::stdout().flush()?;
    if options.protocol == crate::Protocol::Relay && options.role == crate::Role::Server
        && options.expect_peer.is_none() {
        return run_carrier(options).await;
    }
    tokio::time::timeout(options.deadline, async {
        match options.protocol {
            crate::Protocol::Relay => run_carrier(options).await,
            crate::Protocol::RelayEndpoint => run_endpoint(options).await,
            _ => anyhow::bail!("relay module received another protocol"),
        }
    }).await.context("relay deadline elapsed")?
}

async fn carrier_client(url: iroh::RelayUrl, key: iroh::SecretKey) -> Result<Client> {
    let tls = iroh_relay::tls::CaTlsConfig::embedded()
        .client_config(std::sync::Arc::new(rustls::crypto::ring::default_provider()))?;
    Ok(ClientBuilder::new(url, key, iroh_dns::dns::DnsResolver::new())
        .tls_client_config(tls).connect().await?)
}

async fn run_carrier(options: &crate::Options) -> Result<()> {
    let server = if options.role == crate::Role::Server {
        let mut config = ServerConfig::default();
        config.relay = Some(RelayConfig::new(options.bind));
        if let Some(bind) = options.relay_qad_bind {
            let cert = std::fs::read(options.relay_qad_cert.as_ref()
                .context("--relay-qad-cert is required with --relay-qad-bind")?)?;
            let key = std::fs::read(options.relay_qad_key.as_ref()
                .context("--relay-qad-key is required with --relay-qad-bind")?)?;
            let tls = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
                rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_no_client_auth()
                .with_single_cert(vec![rustls::pki_types::CertificateDer::from(cert)],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(key).into())?;
            let mut quic = QuicConfig::new(bind);
            quic.server_config = Some(tls);
            config.quic = Some(quic);
        }
        Some(Server::spawn(config).await?)
    } else {
        None
    };
    let url = match &server {
        Some(server) => {
            let addr = server.http_addr().context("relay has no HTTP listener")?;
            let qad = server.quic_addr().map(|a| a.to_string())
                .unwrap_or_else(|| "disabled".into());
            println!("relay-ready: url http://{addr}/ qad {qad}");
            std::io::stdout().flush()?;
            format!("http://{addr}/").parse()?
        }
        None => options.relay_url.clone().context("--relay-url is required")?,
    };
    if server.is_some() && options.expect_peer.is_none() {
        // A fixture's standalone carrier is a service, not an application peer.
        tokio::time::sleep(options.deadline).await;
    } else {
        let peer = iroh::EndpointId::from_bytes(&options.peer_pin()?)?;
        let payload = options.message.as_deref().context("--message is required")?;
        let mut client = carrier_client(url, iroh::SecretKey::from_bytes(&options.seed)).await?;
        println!("relay-client-ready: registered");
        std::io::stdout().flush()?;
        carrier_exchange(&mut client, options.role, peer, payload).await?;
        println!("relay-carrier: remote_id {} payload_hex {}", hex::encode(peer.as_bytes()),
            hex::encode(payload));
        std::io::stdout().flush()?;
        client.close().await?;
    }
    if let Some(server) = server {
        server.shutdown().await?;
    }
    Ok(())
}

async fn carrier_exchange(
    client: &mut Client, role: crate::Role, peer: iroh::EndpointId, payload: &[u8],
) -> Result<()> {
    if role == crate::Role::Client {
        client.send(ClientToRelayMsg::Datagrams {
            dst_endpoint_id: peer, datagrams: Datagrams::from(payload),
        }).await?;
    }
    loop {
        match client.next().await.context("relay carrier closed")?? {
            RelayToClientMsg::Datagrams { remote_endpoint_id, datagrams } => {
                ensure!(remote_endpoint_id == peer, "relay datagram sender differs from pin");
                ensure!(datagrams.segment_size.is_none(), "expected one datagram, not a GRO batch");
                ensure!(datagrams.contents.as_ref() == payload, "relay datagram bytes differ");
                if role == crate::Role::Server {
                    client.send(ClientToRelayMsg::Datagrams {
                        dst_endpoint_id: peer, datagrams,
                    }).await?;
                }
                return Ok(());
            }
            RelayToClientMsg::Ping(data) => client.send(ClientToRelayMsg::Pong(data)).await?,
            RelayToClientMsg::EndpointGone(id) if id == peer =>
                anyhow::bail!("pinned relay peer disconnected"),
            _ => {}
        }
    }
}

async fn run_endpoint(options: &crate::Options) -> Result<()> {
    ensure!(options.relay_url.is_some(), "--relay-url is required");
    let payload = options.message.as_deref().context("--message is required")?;
    let endpoint = crate::bind_iroh(options, ALPN).await?;
    println!("relay-endpoint-ready: remote_id {}", hex::encode(options.peer_pin()?));
    std::io::stdout().flush()?;
    let mut counters = crate::Counters::default();
    let connection = crate::connect_iroh(options, &endpoint, ALPN, &mut counters).await?;
    let stable_id = connection.stable_id();
    let remote_id = connection.remote_id();
    wait_selected(&connection, false).await?;
    exchange(&connection, options.role, payload).await?;
    report_phase(&connection, stable_id, remote_id, 1, false, payload)?;
    if !options.relay_only {
        // The fixture opens peer UDP after observing phase 1. Iroh's native
        // traversal adds/selects a path on this connection, never a second dial.
        wait_selected(&connection, true).await?;
        exchange(&connection, options.role, payload).await?;
        report_phase(&connection, stable_id, remote_id, 2, true, payload)?;
    }
    let expected_counts = match options.role {
        crate::Role::Client => (1, 0),
        crate::Role::Server => (0, 1),
    };
    ensure!((counters.dials, counters.accepted) == expected_counts,
        "relay probe must use exactly one dial or accept");
    println!("relay-counts: dials {} accepts {}", counters.dials, counters.accepted);
    std::io::stdout().flush()?;
    finish_connection(&connection, options.role).await?;
    endpoint.close().await;
    Ok(())
}

async fn finish_connection(connection: &iroh::endpoint::Connection, role: crate::Role) -> Result<()> {
    if role == crate::Role::Client {
        // Receiving the echo FIN does not mean the responder has received our
        // ACK of it. Only the responder knows its reply FIN is acknowledged.
        // Keep the carrier and QUIC endpoint alive until it completes that proof
        // and closes; run()'s deadline bounds an uncooperative responder.
        let reason = connection.closed().await;
        verify_responder_close(&reason)?;
        println!("relay-peer-closed: {reason}");
    } else {
        connection.close(0u32.into(), b"relay probe complete");
    }
    Ok(())
}

fn verify_responder_close(reason: &iroh::endpoint::ConnectionError) -> Result<()> {
    use iroh::endpoint::{ConnectionError, TransportErrorCode};
    match reason {
        ConnectionError::ApplicationClosed(close) if close.error_code == 0u32.into() => Ok(()),
        ConnectionError::ConnectionClosed(close)
            if close.error_code == TransportErrorCode::NO_ERROR => Ok(()),
        _ => anyhow::bail!("responder did not close gracefully: {reason}"),
    }
}

async fn wait_selected(connection: &iroh::endpoint::Connection, direct: bool) -> Result<()> {
    let mut snapshots = connection.paths_stream();
    loop {
        if connection.paths().iter().any(|p| p.is_selected()
            && if direct { p.is_ip() } else { p.is_relay() }) {
            return Ok(());
        }
        snapshots.next().await.context("connection closed before requested path selected")?;
    }
}

async fn exchange(
    connection: &iroh::endpoint::Connection, role: crate::Role, payload: &[u8],
) -> Result<()> {
    let (mut send, mut recv) = match role {
        crate::Role::Client => connection.open_bi().await?,
        crate::Role::Server => connection.accept_bi().await?,
    };
    if role == crate::Role::Client {
        send.write_all(payload).await?;
        send.finish()?;
        ensure!(recv.read_to_end(payload.len() + 1).await? == payload, "inner reply differs");
    } else {
        ensure!(recv.read_to_end(payload.len() + 1).await? == payload, "inner request differs");
        send.write_all(payload).await?;
        send.finish()?;
    }
    ensure!(send.stopped().await?.is_none(), "inner stream stopped before FIN acknowledgement");
    Ok(())
}

fn report_phase(
    connection: &iroh::endpoint::Connection, stable_id: usize, remote_id: iroh::EndpointId,
    phase: u8, direct: bool, payload: &[u8],
) -> Result<()> {
    ensure!(connection.stable_id() == stable_id, "connection changed");
    ensure!(connection.remote_id() == remote_id, "authenticated peer changed");
    ensure!(connection.paths().iter().any(|p| p.is_selected()
        && if direct { p.is_ip() } else { p.is_relay() }), "application path changed during phase");
    println!("relay-phase{phase}: stable_id {stable_id} remote_id {} selected {} bytes {} payload_hex {}",
        hex::encode(remote_id.as_bytes()), if direct { "direct" } else { "relay" },
        payload.len(), hex::encode(payload));
    std::io::stdout().flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn endpoint_completion_rejects_timeout_reset_and_nonzero_peer_close() {
        use iroh::endpoint::{
            ApplicationClose, ConnectionError, TransportError, TransportErrorCode,
        };
        for reason in [
            ConnectionError::TimedOut,
            ConnectionError::Reset,
            ConnectionError::LocallyClosed,
            ConnectionError::VersionMismatch,
            ConnectionError::CidsExhausted,
            ConnectionError::ApplicationClosed(ApplicationClose {
                error_code: 1u32.into(),
                reason: bytes::Bytes::from_static(b"failed"),
            }),
            ConnectionError::ConnectionClosed(
                TransportError::new(TransportErrorCode::INTERNAL_ERROR, String::new()).into(),
            ),
            ConnectionError::TransportError(
                TransportError::new(TransportErrorCode::INTERNAL_ERROR, String::new()),
            ),
        ] {
            assert!(verify_responder_close(&reason).is_err(), "accepted {reason}");
        }
        let normal = ConnectionError::ApplicationClosed(ApplicationClose {
            error_code: 0u32.into(),
            reason: bytes::Bytes::from_static(b"relay probe complete"),
        });
        assert!(verify_responder_close(&normal).is_ok());
        let normal_transport = ConnectionError::ConnectionClosed(
            TransportError::new(TransportErrorCode::NO_ERROR, String::new()).into(),
        );
        assert!(verify_responder_close(&normal_transport).is_ok());
    }

    #[tokio::test]
    async fn real_carrier_preserves_exact_datagram_bytes_and_sender() -> Result<()> {
        let mut config = ServerConfig::default();
        config.relay = Some(RelayConfig::new("127.0.0.1:0".parse::<std::net::SocketAddr>()?));
        let server = Server::spawn(config).await?;
        let url: iroh::RelayUrl = format!("http://{}/", server.http_addr().unwrap()).parse()?;
        let alice = iroh::SecretKey::from_bytes(&[11; 32]);
        let bob = iroh::SecretKey::from_bytes(&[12; 32]);
        let mut a = carrier_client(url.clone(), alice.clone()).await?;
        let mut b = carrier_client(url, bob.clone()).await?;
        let bytes = b"\0actual relay bytes\xff";
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::try_join!(
                carrier_exchange(&mut a, crate::Role::Client, bob.public(), bytes),
                carrier_exchange(&mut b, crate::Role::Server, alice.public(), bytes)
            )?;
            Result::<()>::Ok(())
        }).await??;
        server.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn endpoint_initiator_keeps_connection_live_until_responder_finishes() -> Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let client = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .secret_key(iroh::SecretKey::from_bytes(&[15; 32]))
                .alpns(vec![ALPN.to_vec()])
                .relay_mode(iroh::RelayMode::Disabled)
                .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>()?)?
                .bind().await?;
            let server = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .secret_key(iroh::SecretKey::from_bytes(&[16; 32]))
                .alpns(vec![ALPN.to_vec()])
                .relay_mode(iroh::RelayMode::Disabled)
                .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>()?)?
                .bind().await?;
            let (caller, responder) = tokio::try_join!(
                async { Ok::<_, anyhow::Error>(client.connect(server.addr(), ALPN).await?) },
                async {
                    Ok::<_, anyhow::Error>(server.accept().await
                        .context("missing incoming endpoint connection")?.await?)
                },
            )?;
            let payload = b"\0exact endpoint completion bytes\xff";
            tokio::try_join!(
                exchange(&caller, crate::Role::Client, payload),
                exchange(&responder, crate::Role::Server, payload),
            )?;
            let mut completion = std::pin::pin!(
                finish_connection(&caller, crate::Role::Client)
            );
            // Poll without elapsed time: finishing the caller must neither return nor
            // emit CONNECTION_CLOSE while the responder still owns its completion.
            std::future::poll_fn(|cx| {
                assert!(Future::poll(completion.as_mut(), cx).is_pending());
                std::task::Poll::Ready(())
            }).await;
            ensure!(caller.close_reason().is_none(), "caller closed before responder completion");
            ensure!(responder.close_reason().is_none(), "responder observed premature close");
            finish_connection(&responder, crate::Role::Server).await?;
            completion.await?;
            client.close().await;
            server.close().await;
            Result::<()>::Ok(())
        }).await.context("endpoint completion regression deadline elapsed")?
    }

    #[tokio::test]
    async fn carrier_rejects_inexact_payload_instead_of_echoing_it() -> Result<()> {
        let mut config = ServerConfig::default();
        config.relay = Some(RelayConfig::new("127.0.0.1:0".parse::<std::net::SocketAddr>()?));
        let server = Server::spawn(config).await?;
        let url: iroh::RelayUrl = format!("http://{}/", server.http_addr().unwrap()).parse()?;
        let alice = iroh::SecretKey::from_bytes(&[13; 32]);
        let bob = iroh::SecretKey::from_bytes(&[14; 32]);
        let mut a = carrier_client(url.clone(), alice.clone()).await?;
        let mut b = carrier_client(url, bob.clone()).await?;
        a.send(ClientToRelayMsg::Datagrams { dst_endpoint_id: bob.public(), datagrams: Datagrams::from(b"wrong") }).await?;
        let result = tokio::time::timeout(std::time::Duration::from_secs(5),
            carrier_exchange(&mut b, crate::Role::Server, alice.public(), b"expected")).await?;
        assert!(result.is_err());
        server.shutdown().await?;
        Ok(())
    }
}
