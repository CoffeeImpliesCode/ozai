use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use iroh_blobs::{
    api::blobs::EncodedItem,
    protocol::{ChunkRanges, ChunkRangesExt, GetRequest, Request},
    store::mem::MemStore,
};
use n0_future::StreamExt;

const COMMIT: &str = "e82cbdcbdac9a78033174aad55e3199b2cf4c0dc";

fn payload() -> Vec<u8> {
    (0..49_189).map(|i| ((i * 31 + i / 1024) % 251) as u8).collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let directory = args.next().context("usage: blobs-vectors <fixture-directory>")?;
    ensure!(args.next().is_none(), "usage: blobs-vectors <fixture-directory>");
    capture(Path::new(&directory)).await
}

async fn capture(directory: &Path) -> Result<()> {
    std::fs::create_dir_all(directory).context("creating fixture directory")?;
    let data = payload();
    let store = MemStore::new();
    let tag = store.add_slice(&data).await.context("adding fixture payload")?;
    std::fs::write(directory.join("data49189.bin"), &data)?;
    std::fs::write(directory.join("root32.bin"), tag.hash.as_bytes())?;
    let mut outboard = Vec::new();
    let mut stream = store.export_bao(tag.hash, ChunkRanges::all()).stream();
    while let Some(item) = stream.next().await {
        match item {
            EncodedItem::Parent(parent) => {
                outboard.extend_from_slice(parent.pair.0.as_bytes());
                outboard.extend_from_slice(parent.pair.1.as_bytes());
            }
            EncodedItem::Error(error) => bail!("exporting outboard: {error}"),
            EncodedItem::Done => break,
            EncodedItem::Size(_) | EncodedItem::Leaf(_) => {}
        }
    }
    std::fs::write(directory.join("outboard.bin"), &outboard)?;
    for (name, ranges) in [
        ("all", ChunkRanges::all()),
        ("15-18", ChunkRanges::bytes(15 * 1024..18 * 1024)),
        ("47-49", ChunkRanges::bytes(47 * 1024..49 * 1024)),
    ] {
        let request = postcard::to_stdvec(&Request::Get(GetRequest::blob_ranges(tag.hash, ranges.clone())))?;
        let response = store.export_bao(tag.hash, ranges).bao_to_vec().await
            .with_context(|| format!("exporting Bao {name}"))?;
        std::fs::write(directory.join(format!("request-{name}.bin")), &request)?;
        std::fs::write(directory.join(format!("response-{name}.bin")), &response)?;
        println!("capture {name} request_bytes {} response_bytes {}", request.len(), response.len());
    }
    println!("iroh-blobs 0.103.0 commit {COMMIT} hash {} size {} outboard_bytes {}",
        tag.hash, data.len(), outboard.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn captured_bao_contains_real_size_and_clipped_tail() {
        let data = payload();
        let store = MemStore::new();
        let tag = store.add_slice(&data).await.unwrap();
        let all = store.export_bao(tag.hash, ChunkRanges::all()).bao_to_vec().await.unwrap();
        assert_eq!(&all[..8], &(data.len() as u64).to_le_bytes());
        assert_eq!(all.len(), 8 + 3 * 64 + data.len());
        let tail = store.export_bao(tag.hash, ChunkRanges::bytes(47 * 1024..49 * 1024)).bao_to_vec().await.unwrap();
        assert_eq!(&tail[..8], &(data.len() as u64).to_le_bytes());
        assert!(tail.ends_with(&data[48 * 1024..]));
        let request = postcard::to_stdvec(&Request::Get(GetRequest::blob_ranges(tag.hash, ChunkRanges::all()))).unwrap();
        let decoded: Request = postcard::from_bytes(&request).unwrap();
        let Request::Get(decoded) = decoded else { panic!("wrong request variant") };
        assert_eq!(decoded.hash, tag.hash);
        assert!(postcard::from_bytes::<Request>(&request[..request.len() - 1]).is_err());
    }

    #[tokio::test]
    async fn upstream_import_rejects_wrong_root_corruption_and_truncation() {
        let store = MemStore::new();
        let tag = store.add_slice(payload()).await.unwrap();
        let wire = store.export_bao(tag.hash, ChunkRanges::all()).bao_to_vec().await.unwrap();
        let mut corrupted = wire.clone();
        corrupted[8] ^= 1;
        let target = MemStore::new();
        assert!(target.import_bao_bytes(tag.hash, ChunkRanges::all(), corrupted).await.is_err());
        let target = MemStore::new();
        assert!(target.import_bao_bytes(tag.hash, ChunkRanges::all(), wire[..wire.len() - 1].to_vec()).await.is_err());
        let target = MemStore::new();
        assert!(target.import_bao_bytes(iroh_blobs::Hash::new(b"wrong root"), ChunkRanges::all(), wire).await.is_err());
    }

    #[tokio::test]
    async fn upstream_import_exports_exact_cross_group_and_tail_ranges() {
        let data = payload();
        let store = MemStore::new();
        let tag = store.add_slice(&data).await.unwrap();
        for range in [15 * 1024..18 * 1024, 47 * 1024..49 * 1024] {
            let ranges = ChunkRanges::bytes(range.clone());
            let wire = store.export_bao(tag.hash, ranges.clone()).bao_to_vec().await.unwrap();
            let target = MemStore::new();
            target.import_bao_bytes(tag.hash, ranges, wire).await.unwrap();
            let clipped = range.start..range.end.min(data.len() as u64);
            let got = target.export_ranges(tag.hash, clipped.clone()).concatenate().await.unwrap();
            assert_eq!(got, data[clipped.start as usize..clipped.end as usize]);
        }
    }
}
