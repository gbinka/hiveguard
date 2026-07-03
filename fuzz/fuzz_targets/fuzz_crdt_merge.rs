#![no_main]
use libfuzzer_sys::fuzz_target;
use hiveguard_core::crdt::{CrdtBanRecord, TOMBSTONE_QUORUM};
use hiveguard_core::hlc::HlcTimestamp;
use std::collections::HashSet;

/// Fuzz the CRDT merge operation with arbitrary binary inputs.
/// Exercises merge with crafted HLC timestamps, reporters sets,
/// severity values, and tombstone flags.
fuzz_target!(|data: &[u8]| {
    if data.len() < 20 {
        return;
    }

    let ip: ipnet::IpNet = "10.0.0.1/32".parse().unwrap();

    // Build record A from first half of data
    let mid = data.len() / 2;
    let a_data = &data[..mid];
    let b_data = &data[mid..];

    let a = make_record(ip, a_data);
    let b = make_record(ip, b_data);

    // merge must not panic, and must be commutative
    let ab = a.merge(&b);
    let ba = b.merge(&a);

    if let (Some(ref ab), Some(ref ba)) = (&ab, &ba) {
        assert_eq!(ab.severity, ba.severity);
        assert_eq!(ab.tombstone, ba.tombstone);
        assert_eq!(ab.reporters, ba.reporters);
    }

    // Also test merge with different subjects — must return None
    let other_ip: ipnet::IpNet = "10.0.0.2/32".parse().unwrap();
    let c = make_record(other_ip, a_data);
    assert!(a.merge(&c).is_none());
});

fn make_record(subject: ipnet::IpNet, data: &[u8]) -> CrdtBanRecord {
    let wall_time = if data.len() >= 8 {
        u64::from_le_bytes(data[..8].try_into().unwrap_or([0; 8]))
    } else {
        1000
    };
    let counter = if data.len() >= 12 {
        u32::from_le_bytes(data[8..12].try_into().unwrap_or([0; 4]))
    } else {
        0
    };
    let severity = if data.len() >= 13 { data[12] } else { 100 };
    let tombstone = data.last().map(|b| b % 2 == 0).unwrap_or(false);

    let mut tombstone_reporters = HashSet::new();
    if tombstone {
        // Add enough reporters to meet quorum
        for i in 0..TOMBSTONE_QUORUM {
            tombstone_reporters.insert(format!("tomb-{i}"));
        }
    }

    let mut reporters = HashSet::new();
    reporters.insert(format!("node-{}", severity));

    CrdtBanRecord {
        subject,
        first_seen: HlcTimestamp::new(wall_time, counter, 1),
        ban_until: HlcTimestamp::new(wall_time.saturating_add(86400000), 0, 1),
        severity,
        reporters,
        evidence_hash: [0u8; 32],
        reason: "fuzz".to_string(),
        tombstone_reporters,
        tombstone,
        last_modified: HlcTimestamp::new(wall_time, counter, 1),
    }
}
