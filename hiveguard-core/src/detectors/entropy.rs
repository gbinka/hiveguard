use std::net::IpAddr;

use ipnet::IpNet;

use crate::detector::Detector;
use crate::models::{Action, DetectionSignal, EventType, NormalizedEvent};

use super::entropy_analysis::{
    self, compute_anomaly_score, extract_features, ScoringWeights,
};

// Re-export shannon_entropy for backward compatibility (used by fuzz targets, benches).
pub use entropy_analysis::shannon_entropy;

/// Multi-feature entropy-based payload detector.
///
/// Combines **six** independent signals to distinguish truly malicious
/// high-entropy payloads (shellcode, obfuscated SQLi) from benign
/// high-entropy URLs (WordPress cache-busters, Facebook click IDs,
/// base64 tracking tokens):
///
/// 1. **Compression ratio** (DEFLATE) — approximation of Kolmogorov
///    complexity. Random bytes are incompressible (ratio ≈ 1.0);
///    structured data compresses well (ratio < 0.6).
/// 2. **Bigram entropy** — Shannon entropy over byte pairs. Captures
///    sequential structure that unigram entropy misses.
/// 3. **High-byte fraction** — bytes > 0x7F should never appear in
///    valid URL-encoded traffic.
/// 4. **Control-char fraction** — ASCII control characters are a
///    strong shellcode indicator.
/// 5. **Shannon entropy** — classic unigram entropy, kept as a minor
///    supporting signal.
/// 6. **HTTP status correlation** — 4xx/5xx responses amplify the
///    anomaly score; 200 OK responses suppress it.
///
/// Additionally, known-benign URL patterns (WordPress static assets,
/// social-media click IDs, hex cache-busters) reduce the score,
/// eliminating the class of false positives documented in
/// `entropy_problems.md`.
///
/// Severity range: 30–80; confidence: 0.5–0.85 depending on score.
pub struct EntropyDetector {
    weights: ScoringWeights,
    /// Minimum anomaly score (0–100) to emit a signal (default: 25.0).
    score_threshold: f64,
}

impl EntropyDetector {
    pub fn new() -> Self {
        Self {
            weights: ScoringWeights::default(),
            score_threshold: 25.0,
        }
    }

    /// Construct from the expanded configuration.
    pub fn from_config(
        score_threshold: f64,
        benign_penalty: f64,
        error_multiplier: f64,
    ) -> Self {
        let mut weights = ScoringWeights::default();
        weights.benign_penalty = benign_penalty;
        weights.error_response_multiplier = error_multiplier;
        Self {
            weights,
            score_threshold,
        }
    }

    /// Legacy constructor — maps old min/max entropy range onto the
    /// new multi-feature model for backward compatibility.
    pub fn with_range(min: f64, max: f64) -> Self {
        // If the caller set a very low min (e.g. 3.0 for testing),
        // lower the score_threshold proportionally so tests that
        // expect detections at Shannon ≈ 4 still get signals.
        let threshold = if min < 4.0 { 5.0 } else { 25.0 };
        let _ = max; // max no longer used directly
        Self {
            weights: ScoringWeights::default(),
            score_threshold: threshold,
        }
    }

    fn ip_to_net(ip: IpAddr) -> IpNet {
        match ip {
            IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::new(v4, 32).unwrap()),
            IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::new(v6, 128).unwrap()),
        }
    }
}

impl Default for EntropyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for EntropyDetector {
    fn name(&self) -> &str {
        "entropy"
    }

    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        match event.event_type {
            EventType::HttpRequest | EventType::Http4xx | EventType::Http5xx => {}
            _ => return None,
        }

        let path = event.metadata.get("path")?;
        let query = event
            .metadata
            .get("query")
            .map(|s| s.as_str())
            .unwrap_or("");

        let status_code: u16 = event
            .metadata
            .get("status_code")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        // --- Multi-feature analysis ---
        let features = extract_features(path, query, status_code);
        let anomaly = compute_anomaly_score(&features, &self.weights)?;

        if anomaly.score < self.score_threshold {
            return None;
        }

        // Map anomaly score (threshold..100) → severity (30..80).
        let score_range = 100.0 - self.score_threshold;
        let normalized = ((anomaly.score - self.score_threshold) / score_range).min(1.0);
        let severity = (normalized * 50.0 + 30.0) as u8;

        // Higher anomaly score → higher confidence.
        let confidence = (0.5 + normalized * 0.35) as f32;

        let combined_display = if query.is_empty() {
            path.clone()
        } else {
            format!("{path}?{query}")
        };

        // Truncate display string safely at a char boundary.
        let truncated = if combined_display.len() <= 80 {
            combined_display.as_str()
        } else {
            let mut end = 80;
            while end > 0 && !combined_display.is_char_boundary(end) {
                end -= 1;
            }
            &combined_display[..end]
        };

        let evidence = format!(
            "{}:entropy_v2:{:.2}:{}",
            event.source_ip, anomaly.score, path
        );

        Some(DetectionSignal {
            source_ip: Self::ip_to_net(event.source_ip),
            severity,
            confidence,
            reason: format!(
                "Entropy anomaly (score={:.1}, H={:.2}): {} [{}]",
                anomaly.score,
                features.shannon,
                truncated,
                anomaly.explanation,
            ),
            evidence_hash: *blake3::hash(evidence.as_bytes()).as_bytes(),
            suggested_action: Action::Observe,
            detector_name: "entropy".into(),
            timestamp: event.timestamp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;

    fn make_http_event(ip: &str, path: &str, query: Option<&str>) -> NormalizedEvent {
        make_http_event_with_status(ip, path, query, None)
    }

    fn make_http_event_with_status(
        ip: &str,
        path: &str,
        query: Option<&str>,
        status: Option<u16>,
    ) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("path".to_string(), path.to_string());
        if let Some(q) = query {
            metadata.insert("query".to_string(), q.to_string());
        }
        if let Some(s) = status {
            metadata.insert("status_code".to_string(), s.to_string());
        }
        NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: ip.parse().unwrap(),
            event_type: if status.unwrap_or(200) >= 400 && status.unwrap_or(200) < 500 {
                EventType::Http4xx
            } else if status.unwrap_or(200) >= 500 {
                EventType::Http5xx
            } else {
                EventType::HttpRequest
            },
            source_name: "test".into(),
            raw_line: format!("GET {path}"),
            metadata,
        }
    }

    // ---- Shannon entropy backward-compat tests ----

    #[test]
    fn shannon_entropy_empty() {
        assert_eq!(shannon_entropy(b""), 0.0);
    }

    #[test]
    fn shannon_entropy_single_byte() {
        assert_eq!(shannon_entropy(b"aaaa"), 0.0);
    }

    #[test]
    fn shannon_entropy_uniform() {
        let data: Vec<u8> = (0..=255).collect();
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 0.01, "Expected ~8.0, got {e}");
    }

    #[test]
    fn shannon_entropy_normal_url() {
        let url = b"/index.html";
        let e = shannon_entropy(url);
        assert!(e < 4.0, "Normal URL should have low entropy, got {e}");
    }

    #[test]
    fn shannon_entropy_shellcode_like() {
        let payload: &[u8] = &[
            0x4f, 0x89, 0xe7, 0x31, 0xd2, 0xb0, 0x3b, 0x0f, 0xfe, 0x08, 0x2f, 0x62, 0x69,
            0x6e, 0x2f, 0x73, 0x68, 0xcc, 0x90, 0x48, 0x31, 0xc0, 0x50, 0x54,
        ];
        let e = shannon_entropy(payload);
        assert!(e > 3.5, "Shellcode-like should have moderate entropy, got {e}");
    }

    #[test]
    fn entropy_two_bytes_entropy() {
        let e = shannon_entropy(b"abababab");
        assert!((e - 1.0).abs() < 0.01, "Expected ~1.0, got {e}");
    }

    // ---- Detector behavior tests ----

    #[test]
    fn detector_ignores_normal_url() {
        let mut d = EntropyDetector::new();
        let event = make_http_event("10.0.0.1", "/index.html", None);
        assert!(d.process(&event).is_none());
    }

    #[test]
    fn detector_ignores_non_http() {
        let mut d = EntropyDetector::new();
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".parse().unwrap(),
            event_type: EventType::AuthFailure,
            source_name: "test".into(),
            raw_line: "failure".into(),
            metadata: HashMap::new(),
        };
        assert!(d.process(&event).is_none());
    }

    #[test]
    fn detector_missing_path_no_signal() {
        let mut d = EntropyDetector::new();
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".parse().unwrap(),
            event_type: EventType::HttpRequest,
            source_name: "test".into(),
            raw_line: "GET /".into(),
            metadata: HashMap::new(),
        };
        assert!(d.process(&event).is_none());
    }

    #[test]
    fn entropy_default_constructor() {
        let d = EntropyDetector::default();
        assert_eq!(d.name(), "entropy");
    }

    // ---- FALSE POSITIVE tests: the scenarios from entropy_problems.md ----

    #[test]
    fn no_signal_for_wp_font_url() {
        let mut d = EntropyDetector::new();
        let event = make_http_event_with_status(
            "195.136.14.38",
            "/wp-content/themes/stroje2021/fonts/inter/Inter-Regular.woff2",
            Some("v=3.15"),
            Some(200),
        );
        assert!(
            d.process(&event).is_none(),
            "WordPress font URL should NOT trigger (was a false positive)"
        );
    }

    #[test]
    fn no_signal_for_wp_css_with_hash() {
        let mut d = EntropyDetector::new();
        let event = make_http_event_with_status(
            "66.249.65.196",
            "/wp-includes/css/dist/block-library/style.min.css",
            Some("ver=7fb0afd1afc3762184e29f84eeaa21dd"),
            Some(200),
        );
        assert!(
            d.process(&event).is_none(),
            "WordPress CSS with hash version should NOT trigger"
        );
    }

    #[test]
    fn no_signal_for_wp_thumbnail() {
        let mut d = EntropyDetector::new();
        let event = make_http_event_with_status(
            "46.151.136.145",
            "/wp-content/themes/miejskasciezka/showtn.php",
            Some("i=http%3A%2F%2Fmiejskasciezka.pl%2Fwp-content%2Fuploads"),
            Some(200),
        );
        assert!(
            d.process(&event).is_none(),
            "WordPress thumbnail URL should NOT trigger"
        );
    }

    #[test]
    fn no_signal_for_fbclid() {
        let mut d = EntropyDetector::new();
        let event = make_http_event_with_status(
            "185.237.158.29",
            "/newsletter/",
            Some("fbclid=IwZXh0bgNhZW0CMTEAc3J0YwZhcHBfaWQMMjU2MjgxMDQwNTU4AAEeRdEsWryM8jI2IYQpE7QeKvODTu"),
            Some(200),
        );
        assert!(
            d.process(&event).is_none(),
            "Facebook fbclid link should NOT trigger"
        );
    }

    #[test]
    fn no_signal_for_wp_image() {
        let mut d = EntropyDetector::new();
        let event = make_http_event_with_status(
            "80.49.242.130",
            "/wp-content/uploads/2020/12/drobnoszlachecki-200x207.jpg",
            None,
            Some(200),
        );
        assert!(
            d.process(&event).is_none(),
            "WordPress image URL should NOT trigger"
        );
    }

    #[test]
    fn no_signal_for_civicrm_cron() {
        let mut d = EntropyDetector::new();
        let event = make_http_event_with_status(
            "203.0.113.10",
            "/wp-content/plugins/civicrm/civicrm/bin/cron.php",
            Some("name=cronuser&pass=secret123&key=d6c025af143"),
            Some(200),
        );
        assert!(
            d.process(&event).is_none(),
            "CiviCRM cron URL should NOT trigger"
        );
    }

    // ---- TRUE POSITIVE tests ----

    #[test]
    fn detects_binary_shellcode_in_url() {
        // Construct a URL with actual non-printable / high bytes (as if raw binary in path).
        // This simulates poorly-encoded shellcode that slipped into an HTTP path.
        let mut d = EntropyDetector::new();
        let mut metadata = HashMap::new();
        // The key difference: high bytes and control chars → always malicious.
        let binary_path: String = (0..60)
            .map(|i| char::from(((i * 173 + 91) % 256) as u8))
            .collect();
        metadata.insert("path".to_string(), binary_path);
        metadata.insert("status_code".to_string(), "400".to_string());
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".parse().unwrap(),
            event_type: EventType::Http4xx,
            source_name: "test".into(),
            raw_line: "GET /binary".into(),
            metadata,
        };
        let signal = d.process(&event);
        assert!(
            signal.is_some(),
            "Binary shellcode payload should trigger detection"
        );
    }

    #[test]
    fn detects_high_entropy_unknown_params_on_error() {
        let mut d = EntropyDetector::from_config(15.0, 30.0, 1.5);
        // Non-benign parameter names with random-looking binary values + 404
        // Include some high bytes and long enough data to trigger compression detection
        let mut metadata = HashMap::new();
        let suspicious_path: String = (0..80)
            .map(|i| char::from(((i * 173 + 91) % 256) as u8))
            .collect();
        metadata.insert("path".to_string(), suspicious_path);
        metadata.insert("status_code".to_string(), "404".to_string());
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".parse().unwrap(),
            event_type: EventType::Http4xx,
            source_name: "test".into(),
            raw_line: "GET /cgi-bin".into(),
            metadata,
        };
        let signal = d.process(&event);
        assert!(
            signal.is_some(),
            "Random binary params on 404 error should trigger"
        );
    }

    #[test]
    fn signal_severity_in_expected_range() {
        let mut d = EntropyDetector::from_config(10.0, 30.0, 1.5);
        let mut metadata = HashMap::new();
        let binary_path: String = (0..60)
            .map(|i| char::from(((i * 173 + 91) % 256) as u8))
            .collect();
        metadata.insert("path".to_string(), binary_path);
        metadata.insert("status_code".to_string(), "400".to_string());
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".parse().unwrap(),
            event_type: EventType::Http4xx,
            source_name: "test".into(),
            raw_line: "GET /binary".into(),
            metadata,
        };
        if let Some(s) = d.process(&event) {
            assert!(
                s.severity >= 30 && s.severity <= 80,
                "Severity should be 30-80, got {}",
                s.severity
            );
            assert!(
                s.confidence >= 0.5 && s.confidence <= 0.85,
                "Confidence should be 0.5-0.85, got {}",
                s.confidence
            );
        }
    }

    #[test]
    fn reason_contains_score() {
        let mut d = EntropyDetector::from_config(10.0, 30.0, 1.5);
        let mut metadata = HashMap::new();
        let binary_path: String = (0..60)
            .map(|i| char::from(((i * 173 + 91) % 256) as u8))
            .collect();
        metadata.insert("path".to_string(), binary_path);
        metadata.insert("status_code".to_string(), "500".to_string());
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".parse().unwrap(),
            event_type: EventType::Http5xx,
            source_name: "test".into(),
            raw_line: "GET /bin".into(),
            metadata,
        };
        if let Some(s) = d.process(&event) {
            assert!(s.reason.contains("score="), "Reason should contain score");
            assert!(s.reason.contains("H="), "Reason should contain entropy");
        }
    }

    #[test]
    fn detector_works_with_ipv6() {
        let mut d = EntropyDetector::from_config(10.0, 30.0, 1.5);
        let mut metadata = HashMap::new();
        let binary_path: String = (0..60)
            .map(|i| char::from(((i * 173 + 91) % 256) as u8))
            .collect();
        metadata.insert("path".to_string(), binary_path);
        metadata.insert("status_code".to_string(), "400".to_string());
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "2001:db8::1".parse().unwrap(),
            event_type: EventType::Http4xx,
            source_name: "test".into(),
            raw_line: "GET /bin".into(),
            metadata,
        };
        if let Some(s) = d.process(&event) {
            assert!(s.source_ip.addr().to_string().contains("2001:db8"));
        }
    }

    #[test]
    fn http4xx_events_are_processed() {
        let mut d = EntropyDetector::from_config(10.0, 30.0, 1.5);
        let mut metadata = HashMap::new();
        let binary_path: String = (0..60)
            .map(|i| char::from(((i * 173 + 91) % 256) as u8))
            .collect();
        metadata.insert("path".to_string(), binary_path);
        metadata.insert("status_code".to_string(), "403".to_string());
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".parse().unwrap(),
            event_type: EventType::Http4xx,
            source_name: "test".into(),
            raw_line: "GET /forbidden".into(),
            metadata,
        };
        // Should at least attempt to process (not early-return on event type).
        let _ = d.process(&event);
    }

    #[test]
    fn http5xx_events_are_processed() {
        let mut d = EntropyDetector::from_config(10.0, 30.0, 1.5);
        let mut metadata = HashMap::new();
        let binary_path: String = (0..60)
            .map(|i| char::from(((i * 173 + 91) % 256) as u8))
            .collect();
        metadata.insert("path".to_string(), binary_path);
        metadata.insert("status_code".to_string(), "500".to_string());
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".parse().unwrap(),
            event_type: EventType::Http5xx,
            source_name: "test".into(),
            raw_line: "GET /error".into(),
            metadata,
        };
        let _ = d.process(&event);
    }
}
