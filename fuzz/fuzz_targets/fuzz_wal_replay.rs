#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Write;
use hiveguard_core::persistence::wal::WalReader;

/// Fuzz the WAL reader with arbitrary binary data.
/// This tests resilience against corrupted/malicious WAL files:
/// - Invalid length fields, truncated records, CRC mismatches
/// - Crafted payloads causing deserialization issues
fuzz_target!(|data: &[u8]| {
    let dir = tempfile::TempDir::new().unwrap();
    let wal_path = dir.path().join("wal.bin");
    {
        let mut f = std::fs::File::create(&wal_path).unwrap();
        f.write_all(data).unwrap();
    }
    // Must not panic — errors and corrupt records should be handled gracefully
    let _entries = WalReader::replay(&wal_path);
});
