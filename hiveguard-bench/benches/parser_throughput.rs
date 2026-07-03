use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use hiveguard_ingest::ssh_parser::{parse_ssh_line, ssh_event_to_normalized, SshPatterns};
use hiveguard_ingest::nginx_parser::{parse_nginx_line, nginx_event_to_normalized, NginxPattern};

fn generate_ssh_lines(count: usize) -> Vec<String> {
    let mut lines = Vec::with_capacity(count);
    for i in 0..count {
        let oct3 = (i / 256) % 256;
        let oct4 = i % 256;
        let variant = i % 5;
        let line = match variant {
            0 => format!(
                "Apr  8 14:30:{:02} server sshd[{}]: Failed password for root from 10.{}.{}.{} port {} ssh2",
                i % 60, 1000 + i, (i / 65536) % 256, oct3, oct4, 40000 + (i % 20000)
            ),
            1 => format!(
                "Apr  8 14:30:{:02} server sshd[{}]: Failed password for invalid user admin from 10.{}.{}.{} port {} ssh2",
                i % 60, 2000 + i, (i / 65536) % 256, oct3, oct4, 40000 + (i % 20000)
            ),
            2 => format!(
                "Apr  8 14:30:{:02} server sshd[{}]: Invalid user test from 10.{}.{}.{}",
                i % 60, 3000 + i, (i / 65536) % 256, oct3, oct4
            ),
            3 => format!(
                "Apr  8 14:30:{:02} server sshd[{}]: Accepted password for deploy from 10.{}.{}.{} port {} ssh2",
                i % 60, 4000 + i, (i / 65536) % 256, oct3, oct4, 40000 + (i % 20000)
            ),
            _ => format!(
                "Apr  8 14:30:{:02} server sshd[{}]: Accepted publickey for admin from 10.{}.{}.{} port {} ssh2",
                i % 60, 5000 + i, (i / 65536) % 256, oct3, oct4, 40000 + (i % 20000)
            ),
        };
        lines.push(line);
    }
    lines
}

fn generate_nginx_lines(count: usize) -> Vec<String> {
    let paths = ["/index.html", "/api/v1/users", "/wp-login.php", "/.env", "/about"];
    let user_agents = [
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "curl/7.68.0",
        "Nikto/2.1.5",
        "python-requests/2.25.1",
        "Mozilla/5.0 (compatible; Googlebot/2.1)",
    ];
    let statuses = [200, 301, 403, 404, 500];

    let mut lines = Vec::with_capacity(count);
    for i in 0..count {
        let oct3 = (i / 256) % 256;
        let oct4 = i % 256;
        let path = paths[i % paths.len()];
        let ua = user_agents[i % user_agents.len()];
        let status = statuses[i % statuses.len()];
        let line = format!(
            "10.{}.{}.{} - - [08/Apr/2026:14:30:{:02} +0000] \"GET {} HTTP/1.1\" {} 1234 \"-\" \"{}\"",
            (i / 65536) % 256, oct3, oct4, i % 60, path, status, ua
        );
        lines.push(line);
    }
    lines
}

fn bench_ssh_parser_throughput(c: &mut Criterion) {
    let lines = generate_ssh_lines(100_000);
    let patterns = SshPatterns::new();

    let mut group = c.benchmark_group("ssh_parser");
    group.throughput(Throughput::Elements(100_000));

    group.bench_function("parse_100k_lines", |b| {
        b.iter(|| {
            let mut count = 0usize;
            for line in &lines {
                if parse_ssh_line(black_box(line), &patterns).is_some() {
                    count += 1;
                }
            }
            black_box(count)
        })
    });

    group.bench_function("parse_and_normalize_100k_lines", |b| {
        b.iter(|| {
            let mut count = 0usize;
            for line in &lines {
                if let Some(event) = parse_ssh_line(black_box(line), &patterns) {
                    let _ = black_box(ssh_event_to_normalized(event));
                    count += 1;
                }
            }
            black_box(count)
        })
    });

    group.finish();
}

fn bench_nginx_parser_throughput(c: &mut Criterion) {
    let lines = generate_nginx_lines(100_000);
    let pattern = NginxPattern::new();

    let mut group = c.benchmark_group("nginx_parser");
    group.throughput(Throughput::Elements(100_000));

    group.bench_function("parse_100k_lines", |b| {
        b.iter(|| {
            let mut count = 0usize;
            for line in &lines {
                if parse_nginx_line(black_box(line), &pattern).is_some() {
                    count += 1;
                }
            }
            black_box(count)
        })
    });

    group.bench_function("parse_and_normalize_100k_lines", |b| {
        b.iter(|| {
            let mut count = 0usize;
            for line in &lines {
                if let Some(event) = parse_nginx_line(black_box(line), &pattern) {
                    let _ = black_box(nginx_event_to_normalized(event));
                    count += 1;
                }
            }
            black_box(count)
        })
    });

    group.finish();
}

criterion_group!(benches, bench_ssh_parser_throughput, bench_nginx_parser_throughput);
criterion_main!(benches);
