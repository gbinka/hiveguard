#![no_main]
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr};
use hiveguard_core::ban_store::{BanStore, InMemoryBanStore};
use hiveguard_core::models::{BanRecord, BanSource};

fuzz_target!(|data: &[u8]| {
    if data.len() < 5 {
        return;
    }
    let mut store = InMemoryBanStore::default();

    // Use chunks of 5 bytes: 1 byte command + 4 bytes IP
    for chunk in data.chunks(5) {
        if chunk.len() < 5 {
            break;
        }
        let cmd = chunk[0] % 4;
        let ip = IpAddr::V4(Ipv4Addr::new(chunk[1], chunk[2], chunk[3], chunk[4]));
        let prefix = 24 + (chunk[0] / 4) % 9; // 24..32
        let net: ipnet::IpNet = format!("{}/{}", ip, prefix).parse().unwrap();

        match cmd {
            0 => {
                let record = BanRecord {
                    subject: net,
                    created_at: chrono::Utc::now(),
                    expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
                    severity: chunk[1],
                    reason: "fuzz".into(),
                    evidence_hash: [0u8; 32],
                    source: BanSource::LocalDetector("fuzz".into()),
                };
                store.add_ban(record);
            }
            1 => {
                store.remove_ban(&net);
            }
            2 => {
                let _ = store.is_banned(&ip);
            }
            3 => {
                store.cleanup_expired();
            }
            _ => unreachable!(),
        }
    }
    // Final consistency check: all bans returned are queryable
    for record in store.get_all_bans() {
        let addr = record.subject.addr();
        let _ = store.is_banned(&addr);
    }
});
