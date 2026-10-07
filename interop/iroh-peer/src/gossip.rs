//! Real upstream Gossip actor: only authenticated connections enter the actor.
use std::fmt::Write;
use anyhow::{Context, Result, bail};
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
    let topic_id = options.topic.context("--topic-hex is required")?;
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
    endpoint.address_lookup().as_ref().context("endpoint lookup")?.add(lookup);
    let bound = endpoint.addr().ip_addrs().next().copied().context("bound IP address")?;
    match options.role {
        Role::Server => crate::announce(node_id_hex, bound, options.tls)?,
        Role::Client => crate::announce_client(node_id_hex, bound, options.tls)?,
    }
    let gossip = Gossip::builder().spawn(endpoint.clone());
    let mut counters = Counters::default();
    let outcome = tokio::time::timeout(options.deadline, async {
        // Subscribe without bootstrap first: no actor dial before the observed
        // certificate pin barrier. The helper accepts in server role.
        let mut topic = gossip.subscribe(topic_id, vec![]).await?;
        let connection = crate::connect_iroh(options, &endpoint, ALPN, &mut counters).await?;
        let peer_hex = crate::observed_peer_node_id(connection.peer_identity(), &pin)?;
        gossip.handle_connection(connection.clone()).await?;
        if options.role == Role::Client {
            topic = gossip.subscribe(topic_id, vec![peer]).await?;
        }
        topic.joined().await?;
        counters.neighbour_up += 1;
        counters.print()?;
        let mut broadcast = false;
        let mut received_payload = false;
        let mut received_ack = false;
        if options.role == Role::Client {
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
                            // APP ACK is real Gossip, sent only after exact pinned payload receipt.
                            topic.broadcast_neighbors(ack.clone().into()).await?;
                        }
                    } else {
                        validate_received(peer, &ack, message.delivered_from, &message.content)?;
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
        let mut payload_hex = String::with_capacity(payload.len() * 2);
        for byte in payload {
            write!(&mut payload_hex, "{byte:02x}")?;
        }
        println!(
            "gossip-proof: scope neighbors, topic {}, sender {}, payload {}, received {}, broadcast {}",
            crate::contract::node_id_hex(topic_id.as_bytes()),
            peer_hex,
            payload_hex,
            payload.len(),
            payload.len(),
        );
        let mut ack_hex = String::with_capacity(ack.len() * 2);
        for byte in &ack {
            write!(&mut ack_hex, "{byte:02x}")?;
        }
        println!(
            "gossip-ack-proof: scope neighbors, topic {}, sender {}, payload {}, received {}, broadcast {}",
            crate::contract::node_id_hex(topic_id.as_bytes()),
            peer_hex,
            ack_hex,
            ack.len(),
            ack.len(),
        );
        println!("{}", counters.report(node_id_hex, std::str::from_utf8(ALPN)?, &peer_hex));
        Ok::<(), anyhow::Error>(())
    }).await;
    let shutdown = gossip.shutdown().await;
    endpoint.close().await;
    outcome.context("gossip --for deadline elapsed")??;
    shutdown.context("shutting down gossip")?;
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
}
