#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Write;
use hiveguard_core::persistence::snapshot::load_snapshot_v2;

/// Fuzz the snapshot loader with arbitrary binary data.
/// Tests resilience against corrupted/crafted snapshot files:
/// - Invalid magic headers, truncated data, malformed bincode
fuzz_target!(|data: &[u8]| {
    let dir = tempfile::TempDir::new().unwrap();
    let snap_path = dir.path().join("snapshot.bin");
    {
        let mut f = std::fs::File::create(&snap_path).unwrap();
        f.write_all(data).unwrap();
    }
    // Must not panic — all errors should be returned as Err
    let _result = load_snapshot_v2(&snap_path);
});
