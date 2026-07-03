use std::time::Duration;

use crate::config::DetectorsConfig;
use crate::detector::Detector;
use crate::detectors::{
    DistributedSlowDetector, EntropyDetector, HoneypotDetector,
    Http4xxFloodDetector, HttpLoginBruteforceDetector, PathProbeDetector,
    PortScanDetector, ScannerFingerprintDetector, SmtpBruteforceDetector,
    SshBruteforceDetector, TimingDetector,
};

/// Create a list of active detectors based on configuration.
pub fn create_detectors(config: &DetectorsConfig) -> Vec<Box<dyn Detector>> {
    let mut detectors: Vec<Box<dyn Detector>> = Vec::new();

    // SSH brute-force + user enumeration
    if config.ssh_bruteforce.enabled {
        let bf = &config.ssh_bruteforce;
        let ue = &config.ssh_user_enum;

        let bf_window = bf.window.as_duration().unwrap_or(Duration::from_secs(300));
        let bf_ban = bf
            .ban_duration
            .as_duration()
            .unwrap_or(Duration::from_secs(86400));
        let ue_window = ue.window.as_duration().unwrap_or(Duration::from_secs(120));
        let ue_ban = ue
            .ban_duration
            .as_duration()
            .unwrap_or(Duration::from_secs(172800));

        detectors.push(Box::new(SshBruteforceDetector::with_config(
            bf.threshold,
            bf_window,
            bf_ban,
            ue.threshold,
            ue_window,
            ue_ban,
        )));
    }

    // Path probe
    if config.path_probe.enabled {
        let pp = &config.path_probe;
        let ban_dur = pp
            .ban_duration
            .as_duration()
            .unwrap_or(Duration::from_secs(259200));
        detectors.push(Box::new(PathProbeDetector::with_config(
            pp.paths.clone(),
            ban_dur,
        )));
    }

    // HTTP 4xx flood
    if config.http_4xx_flood.enabled {
        let hf = &config.http_4xx_flood;
        let window = hf.window.as_duration().unwrap_or(Duration::from_secs(60));
        let ban_dur = hf
            .ban_duration
            .as_duration()
            .unwrap_or(Duration::from_secs(3600));
        detectors.push(Box::new(Http4xxFloodDetector::with_config(
            hf.threshold,
            window,
            ban_dur,
        )));
    }

    // HTTP login brute-force (wp-login.php, xmlrpc.php)
    if config.http_login_bruteforce.enabled {
        let lb = &config.http_login_bruteforce;
        let window = lb.window.as_duration().unwrap_or(Duration::from_secs(600));
        let ban_dur = lb
            .ban_duration
            .as_duration()
            .unwrap_or(Duration::from_secs(86400));
        detectors.push(Box::new(HttpLoginBruteforceDetector::with_config(
            lb.paths.clone(),
            lb.threshold,
            window,
            ban_dur,
        )));
    }

    // Scanner fingerprint
    if config.scanner_fingerprint.enabled {
        let sf = &config.scanner_fingerprint;
        let ban_dur = sf
            .ban_duration
            .as_duration()
            .unwrap_or(Duration::from_secs(259200));
        // Use default scanner signatures (configurable list could be added to config later)
        detectors.push(Box::new(ScannerFingerprintDetector::with_config(
            default_scanner_signatures(),
            ban_dur,
        )));
    }

    // SMTP brute-force
    if config.smtp_bruteforce.enabled {
        let sb = &config.smtp_bruteforce;
        let window = sb.window.as_duration().unwrap_or(Duration::from_secs(300));
        let ban_dur = sb
            .ban_duration
            .as_duration()
            .unwrap_or(Duration::from_secs(86400));
        detectors.push(Box::new(SmtpBruteforceDetector::with_config(
            sb.threshold,
            window,
            ban_dur,
        )));
    }

    // Honeypot
    if config.honeypot.enabled {
        let hp = &config.honeypot;
        let ban_dur = hp.ban_duration.as_duration(); // None = permanent
        detectors.push(Box::new(HoneypotDetector::with_config(
            hp.paths.clone(),
            ban_dur,
            hp.severity,
        )));
    }

    // Entropy (multi-feature: compression ratio + bigram entropy + char-class + URL structure)
    if config.entropy.enabled {
        let ec = &config.entropy;
        detectors.push(Box::new(EntropyDetector::from_config(
            ec.score_threshold,
            ec.benign_penalty,
            ec.error_response_multiplier,
        )));
    }

    // Timing
    if config.timing.enabled {
        let tc = &config.timing;
        let window = tc.window.as_duration().unwrap_or(Duration::from_secs(60));
        detectors.push(Box::new(TimingDetector::with_config(
            window,
            tc.min_samples as usize,
            tc.stddev_threshold_ms,
        )));
    }

    // Port scan
    if config.port_scan.enabled {
        let ps = &config.port_scan;
        let window = ps.window.as_duration().unwrap_or(Duration::from_secs(30));
        let ban_dur = ps
            .ban_duration
            .as_duration()
            .unwrap_or(Duration::from_secs(172800));
        detectors.push(Box::new(PortScanDetector::with_config(
            window,
            ps.threshold as usize,
            ban_dur,
        )));
    }

    // Distributed slow
    if config.distributed_slow.enabled {
        let ds = &config.distributed_slow;
        let window = ds.window.as_duration().unwrap_or(Duration::from_secs(600));
        let ban_dur = ds
            .ban_duration
            .as_duration()
            .unwrap_or(Duration::from_secs(43200));
        detectors.push(Box::new(DistributedSlowDetector::with_config(
            window,
            ds.subnet_threshold as usize,
            ban_dur,
        )));
    }

    detectors
}

fn default_scanner_signatures() -> Vec<String> {
    vec![
        "nikto".into(),
        "sqlmap".into(),
        "nuclei".into(),
        "nessus".into(),
        "openvas".into(),
        "w3af".into(),
        "skipfish".into(),
        "wpscan".into(),
        "dirbuster".into(),
        "gobuster".into(),
        "masscan".into(),
        "zgrab".into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    #[test]
    fn default_config_creates_all_detectors() {
        let config = DetectorsConfig::default();
        let detectors = create_detectors(&config);
        // 5 basic + 1 login bruteforce + 5 advanced = 11
        assert_eq!(detectors.len(), 11);

        let names: Vec<&str> = detectors.iter().map(|d| d.name()).collect();
        assert!(names.contains(&"ssh_bruteforce"));
        assert!(names.contains(&"path_probe"));
        assert!(names.contains(&"http_4xx_flood"));
        assert!(names.contains(&"http_login_bruteforce"));
        assert!(names.contains(&"scanner_fingerprint"));
        assert!(names.contains(&"smtp_bruteforce"));
        assert!(names.contains(&"honeypot"));
        assert!(names.contains(&"entropy"));
        assert!(names.contains(&"timing"));
        assert!(names.contains(&"port_scan"));
        assert!(names.contains(&"distributed_slow"));
    }

    #[test]
    fn disabled_ssh_bruteforce_not_created() {
        let mut config = DetectorsConfig::default();
        config.ssh_bruteforce.enabled = false;
        let detectors = create_detectors(&config);

        let names: Vec<&str> = detectors.iter().map(|d| d.name()).collect();
        assert!(!names.contains(&"ssh_bruteforce"));
        assert_eq!(detectors.len(), 10);
    }

    #[test]
    fn disabled_path_probe_not_created() {
        let mut config = DetectorsConfig::default();
        config.path_probe.enabled = false;
        let detectors = create_detectors(&config);

        let names: Vec<&str> = detectors.iter().map(|d| d.name()).collect();
        assert!(!names.contains(&"path_probe"));
        assert_eq!(detectors.len(), 10);
    }

    #[test]
    fn disabled_http_4xx_flood_not_created() {
        let mut config = DetectorsConfig::default();
        config.http_4xx_flood.enabled = false;
        let detectors = create_detectors(&config);

        let names: Vec<&str> = detectors.iter().map(|d| d.name()).collect();
        assert!(!names.contains(&"http_4xx_flood"));
        assert_eq!(detectors.len(), 10);
    }

    #[test]
    fn disabled_scanner_fingerprint_not_created() {
        let mut config = DetectorsConfig::default();
        config.scanner_fingerprint.enabled = false;
        let detectors = create_detectors(&config);

        let names: Vec<&str> = detectors.iter().map(|d| d.name()).collect();
        assert!(!names.contains(&"scanner_fingerprint"));
        assert_eq!(detectors.len(), 10);
    }

    #[test]
    fn disabled_smtp_bruteforce_not_created() {
        let mut config = DetectorsConfig::default();
        config.smtp_bruteforce.enabled = false;
        let detectors = create_detectors(&config);

        let names: Vec<&str> = detectors.iter().map(|d| d.name()).collect();
        assert!(!names.contains(&"smtp_bruteforce"));
        assert_eq!(detectors.len(), 10);
    }

    #[test]
    fn all_basic_disabled_creates_only_advanced() {
        let mut config = DetectorsConfig::default();
        config.ssh_bruteforce.enabled = false;
        config.path_probe.enabled = false;
        config.http_4xx_flood.enabled = false;
        config.scanner_fingerprint.enabled = false;
        config.smtp_bruteforce.enabled = false;
        let detectors = create_detectors(&config);
        assert_eq!(detectors.len(), 6); // 1 login bruteforce + 5 advanced detectors
    }

    #[test]
    fn all_disabled_creates_none() {
        let mut config = DetectorsConfig::default();
        config.ssh_bruteforce.enabled = false;
        config.path_probe.enabled = false;
        config.http_4xx_flood.enabled = false;
        config.scanner_fingerprint.enabled = false;
        config.smtp_bruteforce.enabled = false;
        config.honeypot.enabled = false;
        config.entropy.enabled = false;
        config.timing.enabled = false;
        config.port_scan.enabled = false;
        config.distributed_slow.enabled = false;
        config.http_login_bruteforce.enabled = false;
        let detectors = create_detectors(&config);
        assert_eq!(detectors.len(), 0);
    }

    #[test]
    fn custom_http_4xx_config_applied() {
        let mut config = DetectorsConfig::default();
        config.ssh_bruteforce.enabled = false;
        config.path_probe.enabled = false;
        config.scanner_fingerprint.enabled = false;
        config.smtp_bruteforce.enabled = false;
        config.http_4xx_flood.threshold = 10;
        config.http_4xx_flood.window = HumanDuration::from_secs(120);
        config.http_4xx_flood.ban_duration = HumanDuration::from_secs(7200);

        let detectors = create_detectors(&config);
        let names: Vec<&str> = detectors.iter().map(|d| d.name()).collect();
        assert!(names.contains(&"http_4xx_flood"));
    }

    #[test]
    fn custom_smtp_config_applied() {
        let mut config = DetectorsConfig::default();
        config.ssh_bruteforce.enabled = false;
        config.path_probe.enabled = false;
        config.scanner_fingerprint.enabled = false;
        config.http_4xx_flood.enabled = false;
        config.smtp_bruteforce.threshold = 3;
        config.smtp_bruteforce.window = HumanDuration::from_secs(120);
        config.smtp_bruteforce.ban_duration = HumanDuration::from_secs(7200);

        let detectors = create_detectors(&config);
        let names: Vec<&str> = detectors.iter().map(|d| d.name()).collect();
        assert!(names.contains(&"smtp_bruteforce"));
    }

    // --- Phase 20: advanced detector config tests ---

    #[test]
    fn disabled_honeypot_not_created() {
        let mut config = DetectorsConfig::default();
        config.honeypot.enabled = false;
        let detectors = create_detectors(&config);
        let names: Vec<&str> = detectors.iter().map(|d| d.name()).collect();
        assert!(!names.contains(&"honeypot"));
    }

    #[test]
    fn disabled_entropy_not_created() {
        let mut config = DetectorsConfig::default();
        config.entropy.enabled = false;
        let detectors = create_detectors(&config);
        let names: Vec<&str> = detectors.iter().map(|d| d.name()).collect();
        assert!(!names.contains(&"entropy"));
    }

    #[test]
    fn disabled_timing_not_created() {
        let mut config = DetectorsConfig::default();
        config.timing.enabled = false;
        let detectors = create_detectors(&config);
        let names: Vec<&str> = detectors.iter().map(|d| d.name()).collect();
        assert!(!names.contains(&"timing"));
    }

    #[test]
    fn disabled_port_scan_not_created() {
        let mut config = DetectorsConfig::default();
        config.port_scan.enabled = false;
        let detectors = create_detectors(&config);
        let names: Vec<&str> = detectors.iter().map(|d| d.name()).collect();
        assert!(!names.contains(&"port_scan"));
    }

    #[test]
    fn disabled_distributed_slow_not_created() {
        let mut config = DetectorsConfig::default();
        config.distributed_slow.enabled = false;
        let detectors = create_detectors(&config);
        let names: Vec<&str> = detectors.iter().map(|d| d.name()).collect();
        assert!(!names.contains(&"distributed_slow"));
    }
}
