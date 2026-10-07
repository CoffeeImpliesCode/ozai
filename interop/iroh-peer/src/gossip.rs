//! Real upstream Gossip actor: only authenticated connections enter the actor.
use std::fmt::Write;
use anyhow::{Context, Result, bail, ensure};
use iroh::{EndpointAddr, EndpointId, address_lookup::memory::MemoryLookup};
use iroh_gossip::{ALPN, api::Event, net::Gossip};
use n0_future::StreamExt;

use crate::{Counters, Options, Role};

const ACK_PREFIX: &[u8] = b"ozai-gossip-ack:";

fn validate_received(
    expected_peer: EndpointId,
    expected_payload: &[u8],
    sender: EndpointId,
    payload: &[u8],
) -> Result<()> {
    if sender != expected_peer {
        bail!("gossip message was delivered by an unpinned peer");
    }
    if payload != expected_payload {
        bail!("gossip message payload did not match --message");
    }
    Ok(())
}

pub(crate) async fn run(options: &Options, node_id_hex: &str) -> Result<()> {
    ensure!(!options.topics.is_empty(), "--topic-hex is required");
    let payload = options.message.as_deref().context("--message is required")?;
    let mut ack = Vec::with_capacity(ACK_PREFIX.len() + payload.len());
    ack.extend_from_slice(ACK_PREFIX);
    ack.extend_from_slice(payload);
    let pin = options.peer_pin()?;
    let peer = EndpointId::from_bytes(&pin).context("the peer id")?;
    let endpoint = crate::bind_iroh(options, ALPN).await?;
    let lookup = MemoryLookup::new();
    let mut address = EndpointAddr::new(peer);
    if let Some(ip) = options.connect {
        address = address.with_ip_addr(ip);
    }
    if let Some(url) = &options.relay_url {
        address = address.with_relay_url(url.clone());
    }
    lookup.add_endpoint_info(address);
    endpoint.address_lookup().context("endpoint lookup")?.add(lookup);
    let bound = endpoint.addr().ip_addrs().next().copied().context("bound IP address")?;
    match options.role {
        Role::Server => crate::announce(node_id_hex, bound, options.tls)?,
        Role::Client => crate::announce_client(node_id_hex, bound, options.tls)?,
    }
    let gossip = Gossip::builder().spawn(endpoint.clone());
    let mut counters = Counters::default();
    let outcome = tokio::time::timeout(options.deadline, async {
        // The actor must not dial before the observed certificate pin barrier.
        let mut topics = Vec::with_capacity(options.topics.len());
        for id in &options.topics {
            topics.push(gossip.subscribe(*id, vec![]).await?);
        }
        let connection = crate::connect_iroh(options, &endpoint, ALPN, &mut counters).await?;
        let peer_hex = crate::observed_peer_node_id(connection.peer_identity(), &pin)?;
        gossip.handle_connection(connection.clone()).await?;
        if options.role == Role::Client {
            for (topic, id) in topics.iter_mut().zip(&options.topics) {
                *topic = gossip.subscribe(*id, vec![peer]).await?;
            }
        }
        for topic in &mut topics {
            exchange_topic(topic, options.role, peer, payload, &ack, &mut counters).await?;
        }
        // broadcast_neighbors only enqueues commands. The consumer closes only
        // after receiving our final ACK on every topic; keep the actor alive
        // until that receipt, not a scheduler yield or a guessed drain delay.
        verify_consumer_close(&connection.closed().await)?;
        let mut payload_hex = String::with_capacity(payload.len() * 2);
        for byte in payload {
            write!(&mut payload_hex, "{byte:02x}")?;
        }
        let mut ack_hex = String::with_capacity(ack.len() * 2);
        for byte in &ack {
            write!(&mut ack_hex, "{byte:02x}")?;
        }
        for id in &options.topics {
            let topic_hex = crate::contract::node_id_hex(id.as_bytes());
            println!(
                "gossip-proof: scope neighbors, topic {}, sender {}, payload {}, received {}, broadcast {}",
                topic_hex, peer_hex, payload_hex, payload.len(), payload.len(),
            );
            println!(
                "gossip-ack-proof: scope neighbors, topic {}, sender {}, payload {}, received {}, broadcast {}",
                topic_hex, peer_hex, ack_hex, ack.len(), ack.len(),
            );
        }
        println!("{}", counters.report(node_id_hex, std::str::from_utf8(ALPN)?, &peer_hex));
        Ok::<(), anyhow::Error>(())
    }).await;
    let shutdown = gossip.shutdown().await;
    endpoint.close().await;
    outcome.context("gossip --for deadline elapsed")??;
    shutdown.context("shutting down gossip")?;
    Ok(())
}

fn verify_consumer_close(reason: &iroh::endpoint::ConnectionError) -> Result<()> {
    use iroh::endpoint::{ConnectionError, TransportErrorCode};
    match reason {
        ConnectionError::ApplicationClosed(close) if close.error_code == 0u32.into() => Ok(()),
        ConnectionError::ConnectionClosed(close)
            if close.error_code == TransportErrorCode::NO_ERROR => Ok(()),
        _ => bail!("gossip consumer did not confirm completion: {reason}"),
    }
}

async fn exchange_topic(
    topic: &mut iroh_gossip::api::GossipTopic, role: Role, peer: EndpointId,
    payload: &[u8], ack: &[u8], counters: &mut Counters,
) -> Result<()> {
    topic.joined().await?;
    counters.neighbour_up += 1;
    counters.print()?;
    let mut broadcast = false;
    let mut received_payload = false;
    let mut received_ack = false;
    if role == Role::Client {
        topic.broadcast_neighbors(payload.to_vec().into()).await?;
        broadcast = true;
    }
    while !received_payload || !received_ack {
        match topic.next().await.context("gossip subscription ended before APP ACK")?? {
            Event::Received(message) => {
                if message.content.as_ref() == payload {
                    validate_received(peer, payload, message.delivered_from, &message.content)?;
                    if !received_payload {
                        received_payload = true;
                        counters.broadcasts_received += 1;
                        counters.print()?;
                        if !broadcast {
                            topic.broadcast_neighbors(payload.to_vec().into()).await?;
                            broadcast = true;
                        }
                        topic.broadcast_neighbors(ack.to_vec().into()).await?;
                    }
                } else {
                    validate_received(peer, ack, message.delivered_from, &message.content)?;
                    if !broadcast {
                        bail!("peer sent APP ACK before our payload broadcast");
                    }
                    if !received_ack {
                        received_ack = true;
                        counters.broadcasts_received += 1;
                        counters.print()?;
                    }
                }
            }
            Event::Lagged => bail!("gossip subscriber lost events"),
            Event::NeighborDown(id) if id == peer => bail!("pinned gossip neighbor left before APP ACK"),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn received_proof_requires_exact_payload_and_authenticated_sender() {
        let peer = iroh::SecretKey::from_bytes(&[7; 32]).public();
        let other = iroh::SecretKey::from_bytes(&[8; 32]).public();
        assert!(validate_received(peer, b"expected", peer, b"expected").is_ok());
        assert!(validate_received(peer, b"expected", other, b"expected").is_err());
        assert!(validate_received(peer, b"expected", peer, b"unexpected").is_err());
    }

    #[test]
    fn received_ack_is_distinct_from_initial_payload_and_is_pinned() {
        let peer = iroh::SecretKey::from_bytes(&[7; 32]).public();
        let other = iroh::SecretKey::from_bytes(&[8; 32]).public();
        let ack = b"ozai-gossip-ack:expected";
        assert!(validate_received(peer, ack, peer, ack).is_ok());
        assert!(validate_received(peer, ack, peer, b"expected").is_err());
        assert!(validate_received(peer, ack, other, ack).is_err());
        assert!(validate_received(peer, ack, peer, b"ozai-gossip-ack:other").is_err());
    }

    async fn run_against_consumer(close_code: Option<u32>) -> Result<Result<()>> {
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(iroh::SecretKey::from_bytes(&[0x72; 32]))
            .relay_mode(iroh::RelayMode::Disabled)
            .alpns(vec![ALPN.to_vec()])
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>()?)?
            .bind().await?;
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let first = "73".repeat(32);
        let second = "74".repeat(32);
        let options = crate::parse_options([
            "--protocol".to_owned(), "gossip".to_owned(),
            "--role".to_owned(), "client".to_owned(),
            "--expect-peer".to_owned(), crate::contract::node_id_hex(endpoint.id().as_bytes()),
            "--connect".to_owned(), endpoint.bound_sockets()[0].to_string(),
            "--topic-hex".to_owned(), first,
            "--topic-hex".to_owned(), second,
            "--message".to_owned(), "queued payload".to_owned(),
            "--for".to_owned(), "1000".to_owned(),
        ])?.context("gossip options")?;
        let mut topics = Vec::new();
        for id in &options.topics {
            topics.push(gossip.subscribe(*id, vec![]).await?);
        }
        let node = crate::contract::node_id_hex(
            iroh::SecretKey::from_bytes(&options.seed).public().as_bytes(),
        );
        let mut client = tokio::spawn(async move { run(&options, &node).await });
        let exchange = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let connection = endpoint.accept().await.context("consumer accept")?.await?;
            gossip.handle_connection(connection.clone()).await?;
            let payload = b"queued payload";
            let ack = b"ozai-gossip-ack:queued payload";
            for topic in &mut topics {
                topic.joined().await?;
                loop {
                    if let Event::Received(message) = topic.next().await.context("consumer ended before payload")?? {
                        ensure!(message.content.as_ref() == payload, "unexpected initial message");
                        break;
                    }
                }
                // Both sends enqueue without giving a delivery receipt. This is
                // the adversarial payload+ACK ordering from the rooted defect.
                topic.broadcast_neighbors(payload.to_vec().into()).await?;
                topic.broadcast_neighbors(ack.to_vec().into()).await?;
                loop {
                    match topic.next().await.context("consumer ended before final ACK")?? {
                        Event::Received(message) => {
                            ensure!(message.content.as_ref() == ack, "unexpected final ACK");
                            break;
                        }
                        Event::NeighborDown(_) => bail!("producer left before final ACK receipt"),
                        _ => {}
                    }
                }
            }
            assert!(!client.is_finished(), "run reported success without the consumer's receipt");
            if let Some(code) = close_code {
                connection.close(code.into(), b"gossip consumer complete");
            }
            (&mut client).await.context("gossip run task")
        }).await;
        if exchange.is_err() {
            client.abort();
            let _cancelled = client.await;
        }
        let shutdown = gossip.shutdown().await;
        endpoint.close().await;
        shutdown?;
        exchange.context("gossip consumer harness deadline")?
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_delivers_final_ack_on_every_topic_before_consumer_completion() -> Result<()> {
        run_against_consumer(Some(0)).await??;
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_rejects_missing_consumer_completion_receipt() -> Result<()> {
        assert!(run_against_consumer(None).await?.is_err());
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_rejects_failed_consumer_close() -> Result<()> {
        assert!(run_against_consumer(Some(1)).await?.is_err());
        Ok(())
    }
}
