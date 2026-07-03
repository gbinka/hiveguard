//! Standalone analyzer - not wrapped as a plugin (use detector.entropy).

use std::collections::HashMap;
use std::io::Write;

use flate2::write::DeflateEncoder;
use flate2::Compression;

// ---------------------------------------------------------------------------
// Feature vector produced by the multi-feature entropy analysis.
// ---------------------------------------------------------------------------

/// Full feature vector extracted from a URL for entropy-based anomaly scoring.
#[derive(Debug, Clone)]
pub struct EntropyFeatures {
    /// Classic Shannon entropy of the analysed segment (0.0–8.0).
    pub shannon: f64,
    /// Bigram (order-2) Shannon entropy — captures local structure (0.0–16.0).
    pub bigram_entropy: f64,
    /// Compression ratio via DEFLATE: compressed_len / raw_len.
    /// Random data ≈ 0.95–1.0, structured data < 0.6.
    pub compression_ratio: f64,
    /// Fraction of bytes > 0x7F (should be 0 for valid URLs).
    pub high_byte_fraction: f64,
    /// Fraction of ASCII control chars (0x00–0x1F excl. TAB/CR/LF).
    pub control_char_fraction: f64,
    /// True if the URL matched a known benign pattern.
    pub known_benign_pattern: bool,
    /// True if the HTTP response indicated an error (4xx/5xx).
    pub is_error_response: bool,
    /// Length of the analysed segment.
    pub data_len: usize,
}

// ---------------------------------------------------------------------------
// Shannon entropy (unigram, kept for backward compat & as one feature).
// ---------------------------------------------------------------------------

/// Compute Shannon entropy of a byte sequence.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

// ---------------------------------------------------------------------------
// Bigram entropy — captures sequential (order-2) structure.
// ---------------------------------------------------------------------------

/// Compute Shannon entropy over byte bigrams.
///
/// Structured data (natural language, URL paths) has predictable bigram
/// transitions → lower bigram entropy. Random / shellcode bytes
/// produce more uniform bigram distribution → higher bigram entropy.
pub fn bigram_entropy(data: &[u8]) -> f64 {
    if data.len() < 2 {
        return 0.0;
    }

    let mut freq: HashMap<(u8, u8), u32> = HashMap::with_capacity(256);
    for window in data.windows(2) {
        *freq.entry((window[0], window[1])).or_insert(0) += 1;
    }

    let total = (data.len() - 1) as f64;
    let mut entropy = 0.0;

    for &count in freq.values() {
        let p = count as f64 / total;
        entropy -= p * p.log2();
    }

    entropy
}

// ---------------------------------------------------------------------------
// Compression ratio — practical approximation of Kolmogorov complexity.
// ---------------------------------------------------------------------------

/// Compress `data` with DEFLATE and return compressed_len / raw_len.
///
/// For short inputs (< 100 bytes) returns 0.5 (neutral) since DEFLATE
/// framing overhead (~11 bytes) dominates and the metric is meaningless.
/// At 50 bytes, the overhead alone produces ratio > 1.0 which would
/// trigger false positives on every short URL.
///
/// Structured/repetitive data compresses well (ratio ~0.3–0.6).
/// Random data barely compresses (ratio ~0.95–1.05, can exceed 1.0
/// due to DEFLATE framing overhead on truly random input).
pub fn compression_ratio(data: &[u8]) -> f64 {
    if data.len() < 100 {
        return 0.5;
    }

    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
    // Write cannot fail on a Vec sink.
    let _ = encoder.write_all(data);
    let compressed = match encoder.finish() {
        Ok(v) => v,
        Err(_) => return 1.0,
    };

    compressed.len() as f64 / data.len() as f64
}

// ---------------------------------------------------------------------------
// Character class profiling.
// ---------------------------------------------------------------------------

/// Profile of byte-class distribution in a data segment.
#[derive(Debug, Clone)]
pub struct CharClassProfile {
    pub printable_ascii: usize,
    pub high_bytes: usize,
    pub control_chars: usize,
    pub total: usize,
}

impl CharClassProfile {
    pub fn high_byte_fraction(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        self.high_bytes as f64 / self.total as f64
    }

    pub fn control_char_fraction(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        self.control_chars as f64 / self.total as f64
    }
}

/// Classify each byte in `data` into printable-ASCII, high-byte, or control-char.
pub fn char_class_profile(data: &[u8]) -> CharClassProfile {
    let mut printable_ascii = 0usize;
    let mut high_bytes = 0usize;
    let mut control_chars = 0usize;

    for &b in data {
        match b {
            0x20..=0x7E => printable_ascii += 1,
            b'\t' | b'\n' | b'\r' => printable_ascii += 1,
            0x80..=0xFF => high_bytes += 1,
            _ => control_chars += 1,
        }
    }

    CharClassProfile {
        printable_ascii,
        high_bytes,
        control_chars,
        total: data.len(),
    }
}

// ---------------------------------------------------------------------------
// URL structural decomposition & known-benign pattern matching.
// ---------------------------------------------------------------------------

/// Segments of a decomposed URL.
#[derive(Debug)]
pub struct UrlParts<'a> {
    pub path: &'a str,
    pub query_params: Vec<(&'a str, &'a str)>,
}

/// Decompose a combined `path?query` string into structural parts.
pub fn decompose_url(combined: &str) -> UrlParts<'_> {
    let (path, query) = match combined.find('?') {
        Some(pos) => (&combined[..pos], &combined[pos + 1..]),
        None => (combined, ""),
    };

    let query_params: Vec<(&str, &str)> = if query.is_empty() {
        Vec::new()
    } else {
        query
            .split('&')
            .filter_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                let key = parts.next()?;
                let val = parts.next().unwrap_or("");
                Some((key, val))
            })
            .collect()
    };

    UrlParts { path, query_params }
}

/// Well-known benign path prefixes in WordPress and common web stacks.
const BENIGN_PATH_PREFIXES: &[&str] = &[
    "/wp-content/",
    "/wp-includes/",
    "/wp-admin/",
    "/wp-json/",
    "/wp-cron.php",
    "/static/",
    "/assets/",
    "/media/",
    "/favicon",
    "/robots.txt",
    "/sitemap",
    "/.well-known/",
    "/cdn-cgi/",
    "/node_modules/",
    "/dist/",
    "/build/",
    "/bundles/",
];

/// Well-known benign query parameter names that carry high-entropy tokens.
const BENIGN_PARAM_NAMES: &[&str] = &[
    "ver",
    "v",
    "hash",
    "etag",
    "fbclid",
    "gclid",
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_content",
    "utm_term",
    "mc_cid",
    "mc_eid",
    "msclkid",
    "_ga",
    "ref",
    "token",           // high-entropy but standard
    "nonce",
    "signature",
    "sig",
    // WordPress-specific params seen in production traffic
    "rest_route",
    "doing_wp_cron",
    "wordfence_syncAttackData",
    "wordfence_lh",
    "timestamp",
    "ical",
    "outlook-ical",
    "post_type",
    "action",
    "orderby",
    "order",
    "per_page",
    "_fields",
    "_embed",
    "include",
    "tags",
    "tag",
    "p",
    "page_id",
    "s",
    "cat",
    "paged",
    // Common redirect/auth/sharing params
    "redirect_to",
    "reauth",
    "share",
    "lang",
    "pid",
];

/// Well-known benign static file extensions.
const BENIGN_EXTENSIONS: &[&str] = &[
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".webp", ".avif", ".mp4", ".webm",
    ".map", ".json", ".xml", ".txt",
    ".pdf", ".zip", ".gz",
];

/// Check if the URL matches known benign patterns.
pub fn is_known_benign_url(path: &str, params: &[(&str, &str)]) -> bool {
    let path_lower = path.to_ascii_lowercase();

    // Benign path prefix
    for prefix in BENIGN_PATH_PREFIXES {
        if path_lower.starts_with(prefix) {
            return true;
        }
    }

    // Benign static file extension
    for ext in BENIGN_EXTENSIONS {
        if path_lower.ends_with(ext) {
            return true;
        }
    }

    // All query params are from the benign set
    if !params.is_empty()
        && params
            .iter()
            .all(|(key, _)| BENIGN_PARAM_NAMES.iter().any(|b| key.eq_ignore_ascii_case(b)))
    {
        return true;
    }

    false
}

/// Check if a string looks like a hex hash (e.g. cache-buster version string).
pub fn looks_like_hex_hash(s: &str) -> bool {
    s.len() >= 16 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Check if a string looks like base64-encoded data.
pub fn looks_like_base64(s: &str) -> bool {
    s.len() >= 20
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_')
}

// ---------------------------------------------------------------------------
// Orchestrator: extract full feature vector from a URL + metadata.
// ---------------------------------------------------------------------------

/// Extract the full entropy feature vector for a given URL.
///
/// `path` and `query` correspond to the HTTP request path and query string.
/// `status_code` is the HTTP response status (0 if unavailable).
pub fn extract_features(path: &str, query: &str, status_code: u16) -> EntropyFeatures {
    // For entropy analysis we focus on the query string when present,
    // as that's where injectable payloads typically reside. When the query
    // is empty or very short we fall back to the full combined string.
    let combined = if query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{query}")
    };

    let data = combined.as_bytes();
    let url_parts = decompose_url(&combined);
    let profile = char_class_profile(data);

    // Determine the segment to measure entropy on.
    // If there are query parameters with non-trivial values, measure entropy
    // on the concatenation of param values (where payloads hide).
    // Otherwise, measure on the full combined string.
    let analysis_target: Vec<u8> = {
        let param_values: String = url_parts
            .query_params
            .iter()
            .filter(|(key, _)| {
                !BENIGN_PARAM_NAMES
                    .iter()
                    .any(|b| key.eq_ignore_ascii_case(b))
            })
            .map(|(_, val)| *val)
            .collect::<Vec<&str>>()
            .join("");
        if param_values.len() >= 10 {
            param_values.into_bytes()
        } else {
            data.to_vec()
        }
    };

    let shannon = shannon_entropy(&analysis_target);
    let bigram = bigram_entropy(&analysis_target);
    let comp_ratio = compression_ratio(&analysis_target);

    let known_benign =
        is_known_benign_url(url_parts.path, &url_parts.query_params);

    let is_error = matches!(status_code, 400..=599);

    EntropyFeatures {
        shannon,
        bigram_entropy: bigram,
        compression_ratio: comp_ratio,
        high_byte_fraction: profile.high_byte_fraction(),
        control_char_fraction: profile.control_char_fraction(),
        known_benign_pattern: known_benign,
        is_error_response: is_error,
        data_len: data.len(),
    }
}

// ---------------------------------------------------------------------------
// Multi-feature anomaly score.
// ---------------------------------------------------------------------------

/// Weights for the multi-feature scoring model.
#[derive(Debug, Clone)]
pub struct ScoringWeights {
    /// Weight for (compression_ratio − threshold).
    pub w_compression: f64,
    /// Weight for bigram entropy above threshold.
    pub w_bigram: f64,
    /// Weight for high-byte fraction (strong binary indicator).
    pub w_high_bytes: f64,
    /// Weight for control-char fraction.
    pub w_control_chars: f64,
    /// Weight for Shannon entropy above threshold.
    pub w_shannon: f64,
    /// Bonus multiplier when response is 4xx/5xx.
    pub error_response_multiplier: f64,
    /// Score reduction when a known-benign pattern is matched.
    pub benign_penalty: f64,
    /// Minimum data length to even consider analysis.
    pub min_data_len: usize,
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            // Compression ratio is the strongest single feature.
            // Random/shellcode data: ratio ~0.95, structured: ~0.4
            w_compression: 35.0,
            // Bigram entropy: random ~13–15, structured ~7–10. Threshold at ~11.
            w_bigram: 20.0,
            // High bytes should be 0% in any valid URL.
            // Even 1% is extremely suspicious. Weight scales to 100.
            w_high_bytes: 100.0,
            // Control chars also very suspicious in URLs.
            w_control_chars: 80.0,
            // Shannon entropy is the weakest feature (many FPs), kept as minor signal.
            w_shannon: 10.0,
            // 4xx/5xx responses make the signal 50% stronger.
            error_response_multiplier: 1.5,
            // Known benign patterns reduce score by this amount.
            benign_penalty: 30.0,
            // Don't analyse URLs shorter than 15 chars (too little data).
            min_data_len: 15,
        }
    }
}

/// Result of multi-feature anomaly scoring.
#[derive(Debug, Clone)]
pub struct AnomalyScore {
    /// Composite anomaly score (0–100 range, can slightly exceed).
    pub score: f64,
    /// Human-readable breakdown of which features triggered.
    pub explanation: String,
    /// The full feature vector for logging/debugging.
    pub features: EntropyFeatures,
}

/// Compute the multi-feature anomaly score for the given feature vector.
///
/// Returns `None` if the data is too short to analyse meaningfully.
pub fn compute_anomaly_score(features: &EntropyFeatures, weights: &ScoringWeights) -> Option<AnomalyScore> {
    if features.data_len < weights.min_data_len {
        return None;
    }

    let mut score = 0.0_f64;
    let mut parts: Vec<String> = Vec::new();

    // 1. Compression ratio contribution.
    //    Threshold 0.75: above this the data is hard to compress → suspicious.
    let comp_contrib = (features.compression_ratio - 0.75).max(0.0) * weights.w_compression / 0.25;
    if comp_contrib > 0.5 {
        score += comp_contrib;
        parts.push(format!("compress={:.2}", features.compression_ratio));
    }

    // 2. Bigram entropy contribution.
    //    Threshold 11.0: above this the bigram transitions are unusually uniform.
    let bigram_contrib = (features.bigram_entropy - 11.0).max(0.0) * weights.w_bigram / 4.0;
    if bigram_contrib > 0.5 {
        score += bigram_contrib;
        parts.push(format!("bigram={:.2}", features.bigram_entropy));
    }

    // 3. High bytes — very strong binary indicator.
    if features.high_byte_fraction > 0.0 {
        let hb_contrib = features.high_byte_fraction * weights.w_high_bytes;
        score += hb_contrib;
        parts.push(format!("highbytes={:.1}%", features.high_byte_fraction * 100.0));
    }

    // 4. Control chars.
    if features.control_char_fraction > 0.0 {
        let cc_contrib = features.control_char_fraction * weights.w_control_chars;
        score += cc_contrib;
        parts.push(format!("ctrlchars={:.1}%", features.control_char_fraction * 100.0));
    }

    // 5. Shannon entropy — minor signal.
    //    Threshold 5.5: high Shannon alone is not conclusive.
    let shannon_contrib = (features.shannon - 5.5).max(0.0) * weights.w_shannon / 2.5;
    if shannon_contrib > 0.5 {
        score += shannon_contrib;
        parts.push(format!("shannon={:.2}", features.shannon));
    }

    // 6. Error response multiplier — if the server rejected it, it's more suspicious.
    if features.is_error_response && score > 0.0 {
        score *= weights.error_response_multiplier;
        parts.push("4xx/5xx".into());
    }

    // 7. Known benign pattern penalty — reduce score.
    if features.known_benign_pattern {
        score = (score - weights.benign_penalty).max(0.0);
        if score <= 0.0 {
            parts.clear();
        }
        parts.push("benign-pattern".into());
    }

    // Cap at 100.
    score = score.min(100.0);

    let explanation = if parts.is_empty() {
        "no anomaly".into()
    } else {
        parts.join(", ")
    };

    Some(AnomalyScore {
        score,
        explanation,
        features: features.clone(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_basic() {
        assert_eq!(shannon_entropy(b""), 0.0);
        assert_eq!(shannon_entropy(b"aaaa"), 0.0);
        let uniform: Vec<u8> = (0..=255).collect();
        assert!((shannon_entropy(&uniform) - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_bigram_entropy_structured_vs_random() {
        let structured = b"/wp-content/themes/flavor/style.css?ver=1.2.3";
        let random_like: Vec<u8> = (0..45).map(|i| ((i * 137 + 43) % 256) as u8).collect();

        let be_struct = bigram_entropy(structured);
        let be_random = bigram_entropy(&random_like);
        assert!(
            be_random > be_struct,
            "Random bigram entropy ({be_random}) should exceed structured ({be_struct})"
        );
    }

    #[test]
    fn test_compression_ratio_structured_vs_random() {
        // Use longer inputs so DEFLATE overhead doesn't dominate.
        let structured = b"/wp-content/themes/flavor/fonts/Inter-Regular.woff2?v=3.15\
            /wp-content/themes/flavor/fonts/Inter-Bold.woff2?v=3.15\
            /wp-content/themes/flavor/style.css?ver=1.2.3";
        let random_like: Vec<u8> = (0..structured.len())
            .map(|i| ((i * 173 + 91) % 256) as u8)
            .collect();

        let cr_struct = compression_ratio(structured);
        let cr_random = compression_ratio(&random_like);
        assert!(
            cr_struct < cr_random,
            "Structured compression ratio ({cr_struct}) should be lower than random ({cr_random})"
        );
    }

    #[test]
    fn test_compression_short_input() {
        // Short inputs return neutral 0.5 (DEFLATE overhead makes ratio meaningless)
        assert_eq!(compression_ratio(b"short"), 0.5);
        assert_eq!(compression_ratio(b"a medium-length string that is under one hundred bytes of data"), 0.5);
        // 99 bytes: still below threshold
        assert_eq!(compression_ratio(b"this string is exactly 99 chars long and should return neutral point five because threshold xxxxx"), 0.5);
    }

    #[test]
    fn test_char_class_profile_url() {
        let url = b"/index.html?foo=bar";
        let profile = char_class_profile(url);
        assert_eq!(profile.high_bytes, 0);
        assert_eq!(profile.control_chars, 0);
        assert_eq!(profile.printable_ascii, url.len());
    }

    #[test]
    fn test_char_class_profile_binary() {
        let data = &[0x00, 0x01, 0xFF, 0xFE, 0x41, 0x42]; // 2 ctrl, 2 high, 2 printable
        let profile = char_class_profile(data);
        assert_eq!(profile.control_chars, 2);
        assert_eq!(profile.high_bytes, 2);
        assert_eq!(profile.printable_ascii, 2);
    }

    #[test]
    fn test_benign_url_detection() {
        assert!(is_known_benign_url("/wp-content/themes/flavor/style.css", &[]));
        assert!(is_known_benign_url("/wp-includes/js/jquery.min.js", &[]));
        assert!(is_known_benign_url("/images/logo.png", &[]));
        assert!(is_known_benign_url("/page", &[("fbclid", "abc123xyz")]));
        assert!(!is_known_benign_url("/api/v1/exec", &[("cmd", "whoami")]));
    }

    #[test]
    fn test_hex_hash_detection() {
        assert!(looks_like_hex_hash("7fb0afd1afc3762184e29f84eeaa21dd"));
        assert!(looks_like_hex_hash("d6c025af143abcdef0"));
        assert!(!looks_like_hex_hash("short"));
        assert!(!looks_like_hex_hash("not-a-hex-hash-value!"));
    }

    #[test]
    fn test_base64_detection() {
        assert!(looks_like_base64("IwZXh0bgNhZW0CMTEAc3J0YwZhcHBfaWQM"));
        assert!(!looks_like_base64("short"));
    }

    #[test]
    fn test_extract_features_benign_wordpress() {
        let features = extract_features(
            "/wp-content/themes/flavor/fonts/Inter-Regular.woff2",
            "v=3.15",
            200,
        );
        assert!(features.known_benign_pattern);
        assert!(!features.is_error_response);
        assert_eq!(features.high_byte_fraction, 0.0);
    }

    #[test]
    fn test_extract_features_shellcode() {
        // Simulate URL-encoded shellcode-like payload
        let path = "/cgi-bin/test";
        let query = "payload=%00%01%FF%FE%80%90%CC%48%31%C0";
        let features = extract_features(path, query, 500);
        assert!(features.is_error_response);
        assert!(!features.known_benign_pattern);
    }

    #[test]
    fn test_anomaly_score_benign_wordpress_url() {
        let features = extract_features(
            "/wp-content/themes/flavor/fonts/Inter-Regular.woff2",
            "v=3.15",
            200,
        );
        let weights = ScoringWeights::default();
        let result = compute_anomaly_score(&features, &weights);
        match result {
            Some(score) => assert!(
                score.score < 20.0,
                "Benign WP URL should have low score, got {}: {}",
                score.score,
                score.explanation
            ),
            None => {} // Too short, also fine
        }
    }

    #[test]
    fn test_anomaly_score_fbclid() {
        let features = extract_features(
            "/newsletter/",
            "fbclid=IwZXh0bgNhZW0CMTEAc3J0YwZhcHBfaWQMMjU2MjgxMDQwNTU4AAEeRdEs",
            200,
        );
        let weights = ScoringWeights::default();
        let result = compute_anomaly_score(&features, &weights).unwrap();
        assert!(
            result.score < 20.0,
            "Facebook link should have low score, got {}: {}",
            result.score,
            result.explanation
        );
    }

    #[test]
    fn test_anomaly_score_random_payload_high() {
        // Simulate truly random bytes in URL (via extract_features).
        // We'll test directly with crafted features to ensure the scoring model works.
        let features = EntropyFeatures {
            shannon: 6.5,
            bigram_entropy: 13.5,
            compression_ratio: 0.97,
            high_byte_fraction: 0.15,
            control_char_fraction: 0.05,
            known_benign_pattern: false,
            is_error_response: true,
            data_len: 100,
        };
        let weights = ScoringWeights::default();
        let result = compute_anomaly_score(&features, &weights).unwrap();
        assert!(
            result.score > 50.0,
            "Random binary payload should score high, got {}: {}",
            result.score,
            result.explanation
        );
    }

    #[test]
    fn test_anomaly_score_too_short() {
        let features = extract_features("/a", "", 200);
        let weights = ScoringWeights::default();
        assert!(compute_anomaly_score(&features, &weights).is_none());
    }

    #[test]
    fn test_decompose_url_with_query() {
        let parts = decompose_url("/path/to/page?foo=bar&baz=qux");
        assert_eq!(parts.path, "/path/to/page");
        assert_eq!(parts.query_params.len(), 2);
        assert_eq!(parts.query_params[0], ("foo", "bar"));
        assert_eq!(parts.query_params[1], ("baz", "qux"));
    }

    #[test]
    fn test_decompose_url_without_query() {
        let parts = decompose_url("/path/to/page");
        assert_eq!(parts.path, "/path/to/page");
        assert!(parts.query_params.is_empty());
    }

    #[test]
    fn test_wp_hash_version_url_low_score() {
        // Actual WordPress URL with cache-buster hash that was causing false positives
        let features = extract_features(
            "/wp-includes/css/dist/block-library/style.min.css",
            "ver=7fb0afd1afc3762184e29f84eeaa21dd",
            200,
        );
        let weights = ScoringWeights::default();
        let result = compute_anomaly_score(&features, &weights);
        match result {
            Some(score) => assert!(
                score.score < 15.0,
                "WP URL with ver hash should score low, got {}: {}",
                score.score,
                score.explanation
            ),
            None => {} // acceptable
        }
    }

    #[test]
    fn test_google_crawler_css_url_low_score() {
        let features = extract_features(
            "/wp-includes/css/dist/block-library/style.min.css",
            "ver=7fb0afd1afc3762184e29f84eeaa21dd",
            200,
        );
        let weights = ScoringWeights::default();
        let result = compute_anomaly_score(&features, &weights);
        match result {
            Some(score) => assert!(
                score.score < 15.0,
                "Crawler CSS request should score low, got {}",
                score.score
            ),
            None => {}
        }
    }
}
