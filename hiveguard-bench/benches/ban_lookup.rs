use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hiveguard_core::ban_store::{BanStore, InMemoryBanStore};
use hiveguard_core::models::{BanRecord, BanSource};
use chrono::Utc;
use ipnet::IpNet;
use rand::Rng;
use std::net::IpAddr;

fn make_random_ban(rng: &mut impl Rng) -> BanRecord {
    let ip = IpAddr::V4(std::net::Ipv4Addr::new(
        rng.gen(),
        rng.gen(),
        rng.gen(),
        rng.gen(),
    ));
    let prefix_len = if rng.gen_bool(0.8) { 32 } else { 24 };
    let net: IpNet = format!("{}/{}", ip, prefix_len).parse().unwrap_or_else(|_| {
        IpNet::from(ip)
    });

    BanRecord {
        subject: net.trunc(),
        created_at: Utc::now(),
        expires_at: Some(Utc::now() + chrono::Duration::hours(24)),
        severity: rng.gen_range(50..=255),
        reason: "benchmark ban".into(),
        evidence_hash: [0u8; 32],
        source: BanSource::LocalDetector("bench".into()),
        geo_info: None,
    }
}

fn create_store(count: usize) -> (InMemoryBanStore, Vec<IpAddr>) {
    let mut rng = rand::thread_rng();
    let mut store = InMemoryBanStore::new();
    let mut lookup_ips = Vec::with_capacity(1000);

    for _ in 0..count {
        let ban = make_random_ban(&mut rng);
        // Save some IPs for lookup
        if lookup_ips.len() < 1000 {
            lookup_ips.push(ban.subject.addr());
        }
        let _ = store.add_ban(ban);
    }

    // Also add some random IPs that are NOT banned for miss testing
    for _ in 0..500 {
        lookup_ips.push(IpAddr::V4(std::net::Ipv4Addr::new(
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
        )));
    }

    (store, lookup_ips)
}

fn bench_is_banned_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("ban_lookup");

    for &size in &[1_000, 10_000, 100_000, 500_000] {
        let (store, lookup_ips) = create_store(size);

        group.bench_with_input(
            BenchmarkId::new("is_banned", size),
            &size,
            |b, _| {
                let mut idx = 0;
                b.iter(|| {
                    let ip = &lookup_ips[idx % lookup_ips.len()];
                    idx += 1;
                    black_box(store.is_banned(ip))
                })
            },
        );
    }

    group.finish();
}

fn bench_add_ban(c: &mut Criterion) {
    let mut group = c.benchmark_group("ban_add");

    group.bench_function("add_10k_bans", |b| {
        b.iter(|| {
            let mut store = InMemoryBanStore::new();
            let mut rng = rand::thread_rng();
            for _ in 0..10_000 {
                let ban = make_random_ban(&mut rng);
                let _ = store.add_ban(ban);
            }
            black_box(store.get_all_bans().len())
        })
    });

    group.finish();
}

fn bench_cleanup_expired(c: &mut Criterion) {
    let mut group = c.benchmark_group("ban_cleanup");

    group.bench_function("cleanup_100k_mixed", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _ in 0..iters {
                let mut rng = rand::thread_rng();
                let mut store = InMemoryBanStore::new();
                let past = Utc::now() - chrono::Duration::hours(1);
                let future = Utc::now() + chrono::Duration::hours(1);
                for i in 0..100_000u32 {
                    let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                        (i >> 24) as u8,
                        (i >> 16) as u8,
                        (i >> 8) as u8,
                        i as u8,
                    ));
                    let expires = if rng.gen_bool(0.5) { Some(past) } else { Some(future) };
                    let ban = BanRecord {
                        subject: IpNet::from(ip),
                        created_at: Utc::now(),
                        expires_at: expires,
                        severity: 100,
                        reason: "bench".into(),
                        evidence_hash: [0u8; 32],
                        source: BanSource::LocalDetector("bench".into()),
                        geo_info: None,
                    };
                    let _ = store.add_ban(ban);
                }
                let start = std::time::Instant::now();
                store.cleanup_expired();
                total += start.elapsed();
            }
            total
        })
    });

    group.finish();
}

criterion_group!(benches, bench_is_banned_lookup, bench_add_ban, bench_cleanup_expired);
criterion_main!(benches);
