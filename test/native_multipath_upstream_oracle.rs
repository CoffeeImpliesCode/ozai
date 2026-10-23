// Include from an owned generated test-crate root that imports unchanged Noq1.3
// cached modules using absolute #[path] declarations. Never modify cache,
// reference trees, or copies of foreign lib.rs.
// #[cfg(test)] mod ozai_multipath_oracle { include!("/absolute/path/to/this/file"); }
// OZAI_MULTIPATH_FIXTURE_DIR=... cargo test --lib ozai_generate_multipath_fixtures
// All wire bytes are produced by actual private upstream codecs.
use crate::{
    coding::{BufExt, Encodable},
    connection::PathId,
    frame::{self, EcnCounts, MaxPathId, NewConnectionId, PathAbandon, PathAckEncoder,
        PathCidsBlocked, PathsBlocked, PathStatusAvailable, PathStatusBackup, RetireConnectionId},
    range_set::ArrayRangeSet,
    transport_parameters::TransportParameters,
    ConnectionId, ResetToken, TransportErrorCode, VarInt,
};
use std::{fs, path::{Path, PathBuf}};

fn emit<T: Encodable>(output: &Path, name: &str, value: &T) {
    let mut bytes = Vec::new();
    value.encode(&mut bytes);
    let decoded: Vec<_> = frame::Iter::new(bytes.clone().into()).unwrap().collect();
    assert_eq!(decoded.len(), 1);
    assert!(decoded[0].is_ok());
    fs::write(output.join(format!("{name}.bin")), bytes).unwrap();
}

#[test]
fn ozai_generate_multipath_fixtures() {
    let output = PathBuf::from(std::env::var_os("OZAI_MULTIPATH_FIXTURE_DIR")
        .expect("set OZAI_MULTIPATH_FIXTURE_DIR"));
    fs::create_dir_all(&output).unwrap();
    let mut ranges = ArrayRangeSet::new();
    ranges.insert(7..11);
    let ecn = EcnCounts { ect0: 1, ect1: 2, ce: 3 };
    for id in [0, 1] {
        let path_id = PathId(id);
        let suffix = format!("_{id}");
        emit(&output, &format!("path_ack{suffix}"), &PathAckEncoder {
            path_id, delay: 0, ranges: &ranges, ecn: None,
        });
        emit(&output, &format!("path_ack_ecn{suffix}"), &PathAckEncoder {
            path_id, delay: 0, ranges: &ranges, ecn: Some(&ecn),
        });
        emit(&output, &format!("path_abandon{suffix}"), &PathAbandon {
            path_id, error_code: TransportErrorCode::from(VarInt::from_u32(0)),
        });
        emit(&output, &format!("path_status_backup{suffix}"), &PathStatusBackup {
            path_id, status_seq_no: VarInt::from_u32(2),
        });
        emit(&output, &format!("path_status_available{suffix}"), &PathStatusAvailable {
            path_id, status_seq_no: VarInt::from_u32(2),
        });
        emit(&output, &format!("path_new_connection_id{suffix}"), &NewConnectionId {
            path_id: Some(path_id), sequence: 0, retire_prior_to: 0,
            id: ConnectionId::new(&[0xab]), reset_token: ResetToken::from([0xcd; 16]),
        });
        emit(&output, &format!("path_retire_connection_id{suffix}"), &RetireConnectionId {
            path_id: Some(path_id), sequence: 0,
        });
        emit(&output, &format!("max_path_id{suffix}"), &MaxPathId(path_id));
        emit(&output, &format!("paths_blocked{suffix}"), &PathsBlocked(path_id));
        emit(&output, &format!("path_cids_blocked{suffix}"), &PathCidsBlocked {
            path_id, next_seq: VarInt::from_u32(2),
        });
        let mut params = TransportParameters::default();
        params.initial_max_path_id = Some(path_id);
        let mut full = Vec::new();
        params.write(&mut full);
        fs::write(output.join(format!("multipath_params{suffix}.bin")), &full).unwrap();
        let mut input = full.as_slice();
        while !input.is_empty() {
            let start = input;
            let parameter: VarInt = BufExt::get(&mut input).unwrap();
            let length: VarInt = BufExt::get(&mut input).unwrap();
            let length = length.into_inner() as usize;
            assert!(length <= input.len());
            input = &input[length..];
            if parameter.into_inner() == 0x3e {
                let consumed = start.len() - input.len();
                fs::write(output.join(format!("initial_max_path_id{suffix}.bin")),
                    &start[..consumed]).unwrap();
            }
        }
    }
    fs::write(output.join("multipath_provenance.txt"),
        "noq-proto=1.3.0\nvcs=c1f411562e6078852749b8bcf1190523096a107f\ncodec=frame::{PathAckEncoder,PathAbandon,PathStatusBackup,PathStatusAvailable,NewConnectionId,RetireConnectionId,MaxPathId,PathsBlocked,PathCidsBlocked}::encode;transport_parameters::TransportParameters::write\n").unwrap();
}
