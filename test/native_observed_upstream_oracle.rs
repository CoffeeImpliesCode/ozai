// Include this unit-test module inside an owned generated Noq test crate root.
// The root loads unchanged noq-proto 1.3.0 source modules via absolute #[path].
// Exact upstream VCS: c1f411562e6078852749b8bcf1190523096a107f.
// It cannot be a Cargo integration test: the actual codecs are pub(crate).
// Add only to the generated root, never to cached or reference source:
// #[cfg(test)] mod ozai_observed_oracle { include!("/absolute/path/to/this/file"); }
// Set OZAI_OBSERVED_FIXTURE_DIR, then run the generated crate's library test:
// cargo test --lib ozai_generate_observed_fixtures -- --nocapture
// No bytes below are hand-captured or a replacement implementation of Noq.

use crate::{
    address_discovery::Role,
    coding::{BufExt, BufMutExt, Encodable},
    frame::ObservedAddr,
    VarInt,
};
use std::{fs, net::SocketAddr, path::PathBuf};

#[test]
fn ozai_generate_observed_fixtures() {
    let output = PathBuf::from(std::env::var_os("OZAI_OBSERVED_FIXTURE_DIR")
        .expect("set OZAI_OBSERVED_FIXTURE_DIR to the fixture output directory"));
    fs::create_dir_all(&output).unwrap();
    let addresses: [(&str, SocketAddr); 2] = [
        ("ipv4", "203.0.113.9:443".parse().unwrap()),
        ("ipv6", "[2001:db8::1]:65535".parse().unwrap()),
    ];
    let sequences = [0, 63, 64, 16383, 16384, 1073741823, 1073741824, (1u64 << 62) - 1];
    for (family, address) in addresses {
        for sequence in sequences {
            let report = ObservedAddr::new(address, VarInt::from_u64(sequence).unwrap());
            let mut bytes = Vec::new();
            report.encode(&mut bytes);
            assert_eq!(report.size(), bytes.len());
            let mut input = bytes.as_slice();
            let _: VarInt = input.get().unwrap();
            let decoded = ObservedAddr::read(&mut input, address.is_ipv6()).unwrap();
            assert_eq!(decoded, report);
            assert!(input.is_empty());
            fs::write(output.join(format!("observed_{family}_{sequence}.bin")), bytes).unwrap();
        }
    }
    for (name, role) in [
        ("send_only", Role::send_only()),
        ("receive_only", Role::receive_only()),
        ("both", Role::both()),
    ] {
        let value = role.as_transport_parameter().unwrap();
        let mut bytes = Vec::new();
        bytes.write(value);
        let mut input = bytes.as_slice();
        assert_eq!(Role::try_from(input.get::<VarInt>().unwrap()).unwrap(), role);
        assert!(input.is_empty());
        fs::write(output.join(format!("observed_role_{name}.bin")), bytes).unwrap();
    }
    assert!(Role::default().as_transport_parameter().is_none());
    fs::write(output.join("observed_provenance.txt"),
        "noq-proto=1.3.0\nvcs=c1f411562e6078852749b8bcf1190523096a107f\ncodec=frame::ObservedAddr::encode/read,address_discovery::Role\n").unwrap();
}
