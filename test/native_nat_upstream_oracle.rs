// Include this fixture in Main's OWNED GENERATED Noq test-crate root.
// That root uses absolute #[path] modules referencing unchanged pinned cached source.
// Never modify/cache-copy/append to upstream lib.rs or any foreign source.
// The real private Encodable implementations below are the oracle, not copied codecs.
// Pinned VCS: c1f411562e6078852749b8bcf1190523096a107f.
use std::{net::{IpAddr, Ipv4Addr, Ipv6Addr}, num::NonZeroU8};
use crate::{coding::{BufExt, Encodable}, frame::{AddAddress, ReachOut, RemoveAddress},
    transport_parameters::TransportParameters, Side, VarInt};

fn emit(name: &str, bytes: &[u8]) {
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    println!("NATIVE_NAT_ORACLE {name} {hex}");
    let output = std::path::PathBuf::from(std::env::var_os("OZAI_NATIVE_NAT_FIXTURE_DIR")
        .expect("set OZAI_NATIVE_NAT_FIXTURE_DIR to the fixture output directory"));
    std::fs::create_dir_all(&output).unwrap();
    std::fs::write(output.join(format!("{name}.bin")), bytes).unwrap();
}

#[test]
fn native_nat_private_codec_oracle() {
    let addresses = [
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
    ];
    let sequences = [0, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, (1 << 62) - 1];
    for (family, ip) in addresses.into_iter().enumerate() {
        for sequence in sequences {
            let sequence = VarInt::from_u64(sequence).unwrap();
            let add = AddAddress::new((ip, 0x1234), sequence);
            let mut bytes = Vec::new();
            add.encode(&mut bytes);
            emit(&format!("add_v{}_{}", if family == 0 {4} else {6}, sequence), &bytes);
            let mut body = &bytes[4..];
            assert_eq!(AddAddress::read(&mut body, family == 1).unwrap(), add);
            assert!(body.is_empty());
            let reach = ReachOut { round: sequence, ip, port: 0x1234 };
            bytes.clear();
            reach.encode(&mut bytes);
            emit(&format!("reach_v{}_{}", if family == 0 {4} else {6}, sequence), &bytes);
            let mut body = &bytes[4..];
            assert_eq!(ReachOut::read(&mut body, family == 1).unwrap(), reach);
            assert!(body.is_empty());
        }
    }
    for sequence in sequences {
        let remove = RemoveAddress::new(VarInt::from_u64(sequence).unwrap());
        let mut bytes = Vec::new();
        remove.encode(&mut bytes);
        emit(&format!("remove_{sequence}"), &bytes);
        let mut body = &bytes[4..];
        assert_eq!(RemoveAddress::read(&mut body).unwrap(), remove);
        assert!(body.is_empty());
    }
    for limit in [1, 32, 255] {
        let mut params = TransportParameters::default();
        params.max_remote_nat_traversal_addresses = NonZeroU8::new(limit);
        let mut bytes = Vec::new();
        params.write(&mut bytes);
        let decoded = TransportParameters::read(Side::Client, &mut &bytes[..]).unwrap();
        assert_eq!(decoded.max_remote_nat_traversal_addresses, NonZeroU8::new(limit));
        let mut rest = &bytes[..];
        while !rest.is_empty() {
            let id: VarInt = BufExt::get(&mut rest).unwrap();
            let len: VarInt = BufExt::get(&mut rest).unwrap();
            let length = usize::try_from(len.into_inner()).unwrap();
            let value = &rest[..length];
            if id.into_inner() == 0x3d7f91120401 {
                emit(&format!("parameter_{limit}"), value);
            }
            rest = &rest[length..];
        }
    }
}
