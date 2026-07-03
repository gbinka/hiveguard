use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use hiveguard_enforce::ObserveOnlyEnforcer;
use hiveguard_enforce::Enforcer;
use ipnet::IpNet;
use rand::Rng;
use std::net::IpAddr;

fn generate_random_ips(count: usize) -> Vec<IpNet> {
    let mut rng = rand::thread_rng();
    let mut ips = Vec::with_capacity(count);
    for _ in 0..count {
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
        ));
        ips.push(IpNet::from(ip));
    }
    ips
}

fn bench_enforcement_batch(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("enforcement_batch");

    // Benchmark: apply_ban 10k IPs one by one
    let ips_10k = generate_random_ips(10_000);
    group.throughput(Throughput::Elements(10_000));

    group.bench_function("apply_ban_10k_sequential", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut enforcer = ObserveOnlyEnforcer::new();
                for ip in &ips_10k {
                    enforcer.apply_ban(ip).await.unwrap();
                }
                black_box(enforcer.get_current_bans().await.unwrap().len())
            })
        })
    });

    // Benchmark: sync_full with 10k IPs
    group.bench_function("sync_full_10k", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut enforcer = ObserveOnlyEnforcer::new();
                enforcer.sync_full(&ips_10k).await.unwrap();
                black_box(enforcer.get_current_bans().await.unwrap().len())
            })
        })
    });

    // Benchmark: remove_ban 10k IPs
    group.bench_function("remove_ban_10k", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut enforcer = ObserveOnlyEnforcer::new();
                enforcer.sync_full(&ips_10k).await.unwrap();
                for ip in &ips_10k {
                    enforcer.remove_ban(ip).await.unwrap();
                }
                black_box(enforcer.get_current_bans().await.unwrap().len())
            })
        })
    });

    // Benchmark: mixed apply/remove churn
    group.bench_function("churn_10k_apply_remove", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut enforcer = ObserveOnlyEnforcer::new();
                for (i, ip) in ips_10k.iter().enumerate() {
                    enforcer.apply_ban(ip).await.unwrap();
                    if i >= 100 && i % 2 == 0 {
                        enforcer.remove_ban(&ips_10k[i - 100]).await.unwrap();
                    }
                }
                black_box(enforcer.get_current_bans().await.unwrap().len())
            })
        })
    });

    group.finish();
}

criterion_group!(benches, bench_enforcement_batch);
criterion_main!(benches);
