use std::{
    io,
    num::NonZeroU64,
    ops::{Bound, Range, RangeBounds},
    sync::atomic::{AtomicBool, Ordering},
};

use anyhow::{bail, ensure, Context, Result};
use iroh_blobs::{
    api::blobs::EncodedItem,
    get::{
        fsm::{AtBlobHeader, AtConnected, AtEndBlob, BlobContentNext, ConnectedNext, EndBlobNext},
        Stats,
    },
    protocol::{ChunkRanges, GetRequest},
    provider::{self, events::{EventMask, EventSender, ProviderMessage, RequestMode, RequestUpdate}},
    store::mem::MemStore,
    util::RecvStream,
    Hash, ALPN,
};
use n0_future::{time::Instant, StreamExt};

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

struct StrictRecvStream<'a> {
    inner: iroh::endpoint::RecvStream,
    closing: &'a AtomicBool,
}

impl RecvStream for StrictRecvStream<'_> {
    async fn recv_bytes(&mut self, len: usize) -> io::Result<bytes::Bytes> {
        if !self.closing.load(Ordering::Relaxed) {
            return RecvStream::recv_bytes(&mut self.inner, len).await;
        }
        // The pinned closing state only logs extra bytes. Turn its final read
        // into an error, and certify completion only on the real stream FIN.
        let mut byte = [0u8; 1];
        match self.inner.read(&mut byte).await? {
            None => Ok(bytes::Bytes::new()),
            Some(_) => Err(io::Error::new(io::ErrorKind::InvalidData, "extra bytes after Bao response")),
        }
    }

    async fn recv_bytes_exact(&mut self, len: usize) -> io::Result<bytes::Bytes> {
        RecvStream::recv_bytes_exact(&mut self.inner, len).await
    }

    async fn recv_exact(&mut self, target: &mut [u8]) -> io::Result<()> {
        RecvStream::recv_exact(&mut self.inner, target).await
    }

    fn stop(&mut self, code: iroh::endpoint::VarInt) -> io::Result<()> {
        RecvStream::stop(&mut self.inner, code)
    }

    fn id(&self) -> u64 {
        RecvStream::id(&self.inner)
    }
}

async fn import_verified_blob<R: RecvStream>(
    store: &MemStore, hash: Hash, header: AtBlobHeader<R>,
) -> Result<AtEndBlob<R>> {
    let (mut content, size) = header.next().await.context("reading Bao header")?;
    let Some(size) = NonZeroU64::new(size) else {
        ensure!(hash == Hash::EMPTY, "zero-size response for nonempty blob hash");
        let end = content.drain().await.context("verifying empty Bao response")?;
        store.add_slice(&[]).await.context("importing verified empty blob")?;
        return Ok(end);
    };
    let buffer_size = (size.get() / iroh_blobs::store::IROH_BLOCK_SIZE.bytes() as u64 + 2).min(64) as usize;
    let handle = store.import_bao(hash, size, buffer_size).await.context("opening verified Bao import")?;
    let write = async move {
        loop {
            match content.next().await {
                BlobContentNext::More((next, item)) => {
                    handle.tx.send(item.context("verifying Bao content")?).await
                        .context("importing verified Bao content")?;
                    content = next;
                }
                BlobContentNext::Done(end) => {
                    drop(handle.tx);
                    return Ok::<_, anyhow::Error>(end);
                }
            }
        }
    };
    let complete = async move {
        handle.rx.await.context("completing verified Bao import")?
            .context("committing verified Bao import")
    };
    let (_, end) = tokio::try_join!(complete, write)?;
    Ok(end)
}

async fn strict_get(
    store: &MemStore, connection: &iroh::endpoint::Connection, request: GetRequest,
) -> Result<Stats> {
    let start = Instant::now();
    let (send, recv) = connection.open_bi().await.context("opening blob GET stream")?;
    let closing = AtomicBool::new(false);
    let reader = StrictRecvStream { inner: recv, closing: &closing };
    let hash = request.hash;
    let connected = AtConnected::new(start, reader, send, request, Default::default());
    let root = match connected.next().await.context("sending blob GET")? {
        ConnectedNext::StartRoot(root) => root,
        ConnectedNext::StartChild(_) => bail!("blob GET unexpectedly requested a child"),
        ConnectedNext::Closing(_) => bail!("blob GET requested no root ranges"),
    };
    let end = import_verified_blob(store, hash, root.next()).await?;
    let at_closing = match end.next() {
        EndBlobNext::Closing(at_closing) => at_closing,
        EndBlobNext::MoreChildren(_) => bail!("blob GET unexpectedly requested children"),
    };
    closing.store(true, Ordering::Relaxed);
    at_closing.next().await.context("requiring exact Bao response and stream FIN")
}

pub async fn run(options: &crate::Options, node_id_hex: &str) -> Result<()> {
    let endpoint = crate::bind_iroh(options, ALPN).await?;
    let label = if matches!(options.role, crate::Role::Server) { "listening" } else { "bound" };
    crate::announce_with_optional_address(
        node_id_hex, label, endpoint.bound_sockets().first().copied(), options.tls, &[ALPN],
    )?;
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
                let stats = strict_get(&getter, &connection, GetRequest::blob_ranges(hash, ranges.clone()))
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
                counters.blob_sent_bytes += stats.payload_bytes_written + stats.other_bytes_written;
                counters.blob_received_bytes += stats.total_bytes_read();
                counters.blob_transfers_completed += 1;
                println!("blob verified hash {hash} size {observed_size} bytes {verified} payload_read {} proof_read {} request_written {}",
                    stats.payload_bytes_read, stats.other_bytes_read, stats.other_bytes_written);
                counters.print()?;
                connection.close(0u32.into(), b"verified blob");
                connection.closed().await;
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
                    counters.blob_sent_bytes += event.stats.payload_bytes_sent + event.stats.other_bytes_sent;
                    // Pinned Request::read_async consumes one read_u8 discriminant before
                    // returning the GET body length counted by StreamPair::read_request.
                    let request_wire_bytes = event.stats.other_bytes_read + 1;
                    counters.blob_received_bytes += request_wire_bytes;
                    println!("blob provided hash {hash} size {size} payload_sent {} proof_sent {} request_read {}",
                        event.stats.payload_bytes_sent, event.stats.other_bytes_sent, request_wire_bytes);
                    counters.print()?;
                    connection.closed().await;
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

    async fn raw_provider_exchange(extra_byte: bool, finish: bool) -> Result<Result<()>> {
        let seed = [0x91; 32];
        let provider = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(iroh::SecretKey::from_bytes(&seed))
            .relay_mode(iroh::RelayMode::Disabled)
            .alpns(vec![ALPN.to_vec()])
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>()?)?
            .bind().await?;
        let address = provider.bound_sockets()[0];
        let pin = crate::contract::node_id_hex(provider.id().as_bytes());
        let options = crate::parse_options([
            "--protocol".to_owned(), "blobs".to_owned(),
            "--role".to_owned(), "client".to_owned(),
            "--connect".to_owned(), address.to_string(),
            "--expect-peer".to_owned(), pin,
            "--message".to_owned(), "strict Bao EOF".to_owned(),
            "--for".to_owned(), "1000".to_owned(),
        ])?.context("blob options")?;
        let node = crate::contract::node_id_hex(
            iroh::SecretKey::from_bytes(&options.seed).public().as_bytes(),
        );
        let store = MemStore::new();
        let tag = store.add_slice(b"strict Bao EOF").await?;
        let mut response = store.export_bao(tag.hash, ChunkRanges::all()).bao_to_vec().await?;
        if extra_byte {
            response.push(0xA5);
        }
        let serve = async {
            let connection = provider.accept().await.context("provider accept")?.await?;
            let (mut send, mut recv) = connection.accept_bi().await?;
            let request = recv.read_to_end(4096).await?;
            let request: iroh_blobs::protocol::Request = postcard::from_bytes(&request)?;
            let iroh_blobs::protocol::Request::Get(request) = request else {
                bail!("getter sent a non-GET request");
            };
            ensure!(request.hash == tag.hash, "getter requested the wrong root");
            send.write_all(&response).await?;
            if finish {
                send.finish()?;
            }
            // Retain the real send stream: dropping it would inject a reset,
            // obscuring the distinct valid-Bao-but-missing-FIN case.
            connection.closed().await;
            drop(send);
            Ok::<(), anyhow::Error>(())
        };
        let exchange = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            async { tokio::join!(serve, run(&options, &node)) },
        ).await;
        provider.close().await;
        let (served, result) = exchange.context("raw provider harness deadline")?;
        served?;
        Ok(result)
    }

    #[tokio::test]
    async fn getter_accepts_verified_bao_with_actual_fin() -> Result<()> {
        raw_provider_exchange(false, true).await??;
        Ok(())
    }

    #[tokio::test]
    async fn getter_rejects_trailing_byte_even_with_fin() -> Result<()> {
        let result = raw_provider_exchange(true, true).await?;
        assert!(result.is_err(), "getter certified Bao with an extra response byte");
        Ok(())
    }

    #[tokio::test]
    async fn getter_rejects_trailing_byte_without_fin() -> Result<()> {
        let result = raw_provider_exchange(true, false).await?;
        assert!(result.is_err(), "getter certified trailing garbage without actual EOF");
        Ok(())
    }

    #[tokio::test]
    async fn getter_requires_fin_after_valid_bao() -> Result<()> {
        let result = raw_provider_exchange(false, false).await?;
        assert!(result.is_err(), "getter certified a response whose stream never finished");
        Ok(())
    }
}
