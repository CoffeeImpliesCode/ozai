use std::ops::{Bound, Range, RangeBounds};

use anyhow::{bail, ensure, Context, Result};
use iroh_blobs::{
    api::blobs::EncodedItem,
    protocol::{ChunkRanges, GetRequest},
    provider::{self, events::{EventMask, EventSender, ProviderMessage, RequestMode, RequestUpdate}},
    store::mem::MemStore,
    Hash, ALPN,
};
use n0_future::StreamExt;

fn default_payload() -> Vec<u8> {
    (0..49_189).map(|i| ((i * 31 + i / 1024) % 251) as u8).collect()
}

fn byte_ranges(ranges: &ChunkRanges, size: u64) -> Result<Vec<Range<u64>>> {
    let mut result = Vec::new();
    for range in ranges.iter() {
        let start = match range.start_bound() {
            Bound::Included(chunk) => chunk.0.checked_mul(1024).context("range overflow")?,
            _ => bail!("unsupported chunk start"),
        };
        let end = match range.end_bound() {
            Bound::Excluded(chunk) => chunk.0.checked_mul(1024).context("range overflow")?.min(size),
            Bound::Unbounded => size,
            _ => bail!("unsupported chunk end"),
        };
        ensure!(start < end, "requested chunks are outside the blob");
        result.push(start..end);
    }
    ensure!(!result.is_empty(), "empty blob range");
    Ok(result)
}

pub async fn run(options: &crate::Options, node_id_hex: &str) -> Result<()> {
    let endpoint = crate::bind_iroh(options, ALPN).await?;
    let label = if matches!(options.role, crate::Role::Server) { "listening" } else { "bound" };
    crate::announce_with_address(node_id_hex, label, endpoint.bound_sockets()[0], options.tls, &[ALPN])?;
    let mut counters = crate::Counters::default();
    let data: std::borrow::Cow<'_, [u8]> = match options.message.as_deref() {
        Some(data) => std::borrow::Cow::Borrowed(data),
        None => std::borrow::Cow::Owned(default_payload()),
    };
    let result = tokio::time::timeout(options.deadline, async {
        let expected_hash = Hash::new(&data);
        let hash = options.blob_hash.unwrap_or(expected_hash);
        let size = data.len() as u64;
        println!("blob hash {expected_hash} size {size}");
        let connection = crate::connect_iroh(options, &endpoint, ALPN, &mut counters).await?;
        match options.role {
            crate::Role::Server => {
                let store = MemStore::new();
                let tag = store.add_slice(&data).await.context("adding provider blob")?;
                if let Some(expected_size) = options.blob_size {
                    ensure!(size == expected_size, "provider size {size} != --blob-size {expected_size}");
                }
                provide(&store, connection, tag.hash, size, &mut counters).await?;
            }
            crate::Role::Client => {
                let getter = MemStore::new();
                let ranges = options.blob_range.clone();
                let stats = getter.remote().execute_get(connection.clone(), GetRequest::blob_ranges(hash, ranges.clone()))
                    .await.context("Bao-verified get")?;
                ensure!(hash == expected_hash, "requested hash does not identify the expected payload");
                let mut exported = getter.export_bao(hash, ranges.clone()).stream();
                let observed_size = match exported.next().await {
                    Some(EncodedItem::Size(size)) => size,
                    Some(EncodedItem::Error(error)) => bail!("reading downloaded size: {error}"),
                    _ => bail!("download supplied no Bao size"),
                };
                ensure!(observed_size == size, "download size {observed_size} != expected {size}");
                if let Some(expected) = options.blob_size {
                    ensure!(observed_size == expected, "download size {observed_size} != --blob-size {expected}");
                }
                let mut verified = 0;
                for range in byte_ranges(&ranges, observed_size)? {
                    let got = getter.export_ranges(hash, range.clone()).concatenate().await
                        .context("exporting verified requested bytes")?;
                    ensure!(got.as_slice() == &data[range.start as usize..range.end as usize], "download payload mismatch");
                    verified += got.len();
                }
                counters.sent += stats.payload_bytes_written + stats.other_bytes_written;
                counters.received += stats.total_bytes_read();
                counters.finished += 1;
                println!("blob verified hash {hash} size {observed_size} bytes {verified} payload_read {} proof_read {} request_written {}",
                    stats.payload_bytes_read, stats.other_bytes_read, stats.other_bytes_written);
                counters.print()?;
                connection.close(0u32.into(), b"verified blob");
                connection.closed().await;
                counters.closed += 1;
            }
        }
        counters.print()
    }).await.context("blob exchange deadline").and_then(|result| result);
    endpoint.close().await;
    result
}

async fn provide(
    store: &MemStore, connection: iroh::endpoint::Connection, hash: Hash,
    size: u64, counters: &mut crate::Counters,
) -> Result<()> {
    let mask = EventMask { get: RequestMode::NotifyLog, ..EventMask::DEFAULT };
    let (events, mut receiver) = EventSender::channel(8, mask);
    let provider = provider::handle_connection(connection.clone(), (**store).clone(), events);
    let observe = async {
        let message = receiver.recv().await.context("provider supplied no request event")?;
        let ProviderMessage::GetRequestReceivedNotify(mut message) = message else {
            bail!("provider received a non-get request");
        };
        ensure!(message.inner.request.hash == hash, "requested unknown blob hash");
        let mut started = false;
        while let Some(update) = message.rx.recv().await.context("provider event channel")? {
            match update {
                RequestUpdate::Started(event) => {
                    ensure!(event.hash == hash && event.size == size && event.index == 0, "provider transfer metadata mismatch");
                    started = true;
                }
                RequestUpdate::Completed(event) => {
                    ensure!(started, "provider completed without a transfer start");
                    counters.sent += event.stats.payload_bytes_sent + event.stats.other_bytes_sent;
                    counters.received += event.stats.other_bytes_read;
                    counters.finished += 1;
                    println!("blob provided hash {hash} size {size} payload_sent {} proof_sent {} request_read {}",
                        event.stats.payload_bytes_sent, event.stats.other_bytes_sent, event.stats.other_bytes_read);
                    counters.print()?;
                    connection.closed().await;
                    counters.closed += 1;
                    return Ok(());
                }
                RequestUpdate::Aborted(event) => bail!("provider transfer aborted: {:?}", event.stats),
                RequestUpdate::Progress(_) => {}
            }
        }
        bail!("provider transfer ended without completion")
    };
    let (_, result) = tokio::join!(provider, async {
        let result = observe.await;
        if result.is_err() {
            connection.close(1u32.into(), b"blob provider failed");
        }
        result
    });
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_blobs::protocol::ChunkRangesExt;

    #[test]
    fn deterministic_payload_crosses_three_groups_and_has_partial_tail() {
        let data = default_payload();
        assert_eq!(data.len(), 49_189);
        assert_eq!(data[16_384], ((16_384 * 31 + 16) % 251) as u8);
        assert_eq!(data[49_188], ((49_188 * 31 + 48) % 251) as u8);
    }

    #[test]
    fn requested_bytes_clip_only_the_partial_last_chunk() {
        assert_eq!(byte_ranges(&ChunkRanges::bytes(15 * 1024..18 * 1024), 49_189).unwrap(), vec![15_360..18_432]);
        assert_eq!(byte_ranges(&ChunkRanges::bytes(47 * 1024..49 * 1024), 49_189).unwrap(), vec![48_128..49_189]);
        assert!(byte_ranges(&ChunkRanges::bytes(49 * 1024..50 * 1024), 49_189).is_err());
        assert!(byte_ranges(&ChunkRanges::empty(), 49_189).is_err());
    }
}
