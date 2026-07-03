//! Test harness: run multi-feature entropy detector against real nginx logs
//! and report all detections for false-positive analysis.
//!
//! Usage:
//!   cargo run --release --example test_entropy_on_logs -- test_data/nginx_logs/

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, BufRead};
use std::path::Path;

use hiveguard_core::detectors::entropy_analysis::{
    compute_anomaly_score, extract_features, ScoringWeights,
};

use regex::Regex;

fn main() {
    let args: Vec<String> = env::args().collect();
    let log_dir = if args.len() > 1 {
        &args[1]
    } else {
        "test_data/nginx_logs"
    };

    let pattern = Regex::new(
        r#"^([0-9a-fA-F.:]+) - [^\s]+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\d+) "[^"]*" "([^"]*)""#,
    )
    .unwrap();

    let weights = ScoringWeights::default();
    let score_threshold = 25.0;

    let mut total_lines = 0u64;
    let mut parsed_lines = 0u64;
    let mut detected = 0u64;
    let mut detections: Vec<Detection> = Vec::new();
    let mut ip_hit_count: HashMap<String, u64> = HashMap::new();
    let mut benign_suppressed = 0u64;

    // Collect and sort log files
    let mut files: Vec<_> = fs::read_dir(log_dir)
        .expect("Cannot read log directory")
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .map(|n| n.starts_with("access.log"))
                .unwrap_or(false)
        })
        .collect();
    files.sort_by_key(|e| e.file_name());

    for entry in &files {
        let path = entry.path();
        eprintln!("Processing: {}", path.display());
        let file = fs::File::open(&path).expect("Cannot open log file");
        let reader = io::BufReader::new(file);

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            total_lines += 1;

            let caps = match pattern.captures(&line) {
                Some(c) => c,
                None => continue,
            };
            parsed_lines += 1;

            let ip = caps[1].to_string();
            let request_str = &caps[3];
            let status_code: u16 = caps[4].parse().unwrap_or(0);

            // Parse request line: METHOD path HTTP/ver
            let parts: Vec<&str> = request_str.splitn(3, ' ').collect();
            if parts.len() < 2 {
                continue;
            }
            let full_path = parts[1];

            // Split path and query
            let (path_part, query_part) = match full_path.find('?') {
                Some(pos) => (&full_path[..pos], &full_path[pos + 1..]),
                None => (full_path, ""),
            };

            // Run multi-feature analysis
            let features = extract_features(path_part, query_part, status_code);
            let anomaly = match compute_anomaly_score(&features, &weights) {
                Some(a) => a,
                None => continue,
            };

            // Track benign suppression
            if features.known_benign_pattern && anomaly.score < score_threshold {
                benign_suppressed += 1;
            }

            if anomaly.score >= score_threshold {
                detected += 1;
                *ip_hit_count.entry(ip.clone()).or_insert(0) += 1;

                detections.push(Detection {
                    ip,
                    status_code,
                    score: anomaly.score,
                    shannon: features.shannon,
                    bigram: features.bigram_entropy,
                    compression: features.compression_ratio,
                    high_bytes_pct: features.high_byte_fraction * 100.0,
                    ctrl_chars_pct: features.control_char_fraction * 100.0,
                    benign: features.known_benign_pattern,
                    explanation: anomaly.explanation,
                    url: full_path.to_string(),
                    data_len: features.data_len,
                });
            }
        }
    }

    // --- Report ---
    println!("\n========== ENTROPY DETECTOR TEST RESULTS ==========");
    println!("Total lines:          {}", total_lines);
    println!("Parsed lines:         {}", parsed_lines);
    println!("Detections (>=25.0):  {}", detected);
    println!("Benign suppressed:    {}", benign_suppressed);
    println!(
        "Detection rate:       {:.4}%",
        if parsed_lines > 0 {
            detected as f64 / parsed_lines as f64 * 100.0
        } else {
            0.0
        }
    );
    println!("Unique IPs flagged:   {}", ip_hit_count.len());

    // Sort detections by score descending
    detections.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());

    // Show top 100 detections
    println!("\n--- Top detections (by score) ---");
    println!(
        "{:<16} {:>6} {:>6} {:>6} {:>6} {:>6} {:>5} {:>5} {:<6} {:<40} {}",
        "IP", "Status", "Score", "H", "Bi", "Comp", "HB%", "CC%", "Benign", "Explanation", "URL"
    );
    for d in detections.iter().take(100) {
        let url_trunc = if d.url.len() > 120 {
            format!("{}...", &d.url[..117])
        } else {
            d.url.clone()
        };
        println!(
            "{:<16} {:>6} {:>6.1} {:>6.2} {:>6.2} {:>6.2} {:>5.1} {:>5.1} {:<6} {:<40} {}",
            d.ip,
            d.status_code,
            d.score,
            d.shannon,
            d.bigram,
            d.compression,
            d.high_bytes_pct,
            d.ctrl_chars_pct,
            if d.benign { "YES" } else { "no" },
            d.explanation,
            url_trunc,
        );
    }

    // Show score distribution
    println!("\n--- Score distribution ---");
    let buckets: &[(f64, f64)] = &[
        (25.0, 30.0),
        (30.0, 40.0),
        (40.0, 50.0),
        (50.0, 60.0),
        (60.0, 70.0),
        (70.0, 80.0),
        (80.0, 90.0),
        (90.0, 100.1),
    ];
    for (lo, hi) in buckets {
        let count = detections.iter().filter(|d| d.score >= *lo && d.score < *hi).count();
        if count > 0 {
            println!("  [{:>5.1}, {:>5.1}): {}", lo, hi, count);
        }
    }

    // Show top IPs
    println!("\n--- Top flagged IPs ---");
    let mut ips: Vec<_> = ip_hit_count.into_iter().collect();
    ips.sort_by(|a, b| b.1.cmp(&a.1));
    for (ip, count) in ips.iter().take(30) {
        println!("  {:<40} {}", ip, count);
    }

    // Show detections flagged as benign (potential FPs)
    let benign_detections: Vec<_> = detections.iter().filter(|d| d.benign).collect();
    if !benign_detections.is_empty() {
        println!("\n--- POTENTIAL FALSE POSITIVES (benign pattern but still detected) ---");
        for d in benign_detections.iter().take(50) {
            println!(
                "  score={:.1} ip={} status={} url={}",
                d.score, d.ip, d.status_code, d.url
            );
            println!("    explanation: {}", d.explanation);
        }
    } else {
        println!("\n--- No benign-pattern URLs detected (good!) ---");
    }

    // Show unique URLs with 200 status that were detected (most likely FPs)
    let ok_detections: Vec<_> = detections.iter().filter(|d| d.status_code == 200).collect();
    if !ok_detections.is_empty() {
        println!("\n--- Detections with HTTP 200 (review for FP) ---");
        for d in ok_detections.iter().take(50) {
            println!(
                "  score={:.1} ip={} url={}",
                d.score, d.ip, d.url
            );
            println!("    explanation: {}", d.explanation);
        }
    }
}

struct Detection {
    ip: String,
    status_code: u16,
    score: f64,
    shannon: f64,
    bigram: f64,
    compression: f64,
    high_bytes_pct: f64,
    ctrl_chars_pct: f64,
    benign: bool,
    explanation: String,
    url: String,
    data_len: usize,
}
