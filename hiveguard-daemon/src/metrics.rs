use std::sync::Arc;
use std::sync::atomic::AtomicI64;

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;
use tracing::error;

// ---------------------------------------------------------------------------
// Label types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct SourceLabels {
    pub source: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct DetectorLabels {
    pub detector: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct OperationLabels {
    pub operation: String,
}

/// Labels for alert delivery metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct AlertLabels {
    pub destination: String,
    pub alert_type: String,
}

/// Labels for SIEM exporter metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct SiemLabels {
    pub exporter: String,
}

/// Labels for CTI enricher metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct CtiLabels {
    pub provider: String,
}

/// Labels for Elasticsearch exporter metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ElasticLabels {
    pub index: String,
}

/// Labels for Splunk HEC exporter metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct SplunkLabels {
    pub target: String,
}

/// Labels for Datadog Logs API exporter metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct DatadogLabels {
    pub target: String,
}

// ---------------------------------------------------------------------------
// Histogram constructors (for Family::new_with_constructor)
// ---------------------------------------------------------------------------

fn event_processing_histogram() -> Histogram {
    Histogram::new(
        [0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
            .into_iter(),
    )
}

fn enforcement_histogram() -> Histogram {
    Histogram::new(
        [0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0]
            .into_iter(),
    )
}

fn elastic_flush_histogram() -> Histogram {
    Histogram::new(
        [0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0]
            .into_iter(),
    )
}

fn http_siem_flush_histogram() -> Histogram {
    Histogram::new(
        [0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0]
            .into_iter(),
    )
}

/// Central metrics registry for HiveGuard OpenMetrics exposition.
pub struct Metrics {
    registry: Registry,

    // Gauges
    pub active_bans: Gauge<i64, AtomicI64>,
    pub whitelisted_count: Gauge<i64, AtomicI64>,
    /// Set by cluster module when peer manager is wired.
    #[allow(dead_code)]
    pub peer_count: Gauge<i64, AtomicI64>,
    pub memory_usage_bytes: Gauge<i64, AtomicI64>,

    // Counters
    pub events_processed_total: Family<SourceLabels, Counter>,
    pub bans_created_total: Family<DetectorLabels, Counter>,
    pub bans_expired_total: Counter,
    pub detection_signals_total: Family<DetectorLabels, Counter>,

    // Histograms
    pub event_processing_duration_seconds: Family<SourceLabels, Histogram, fn() -> Histogram>,
    pub enforcement_duration_seconds: Family<OperationLabels, Histogram, fn() -> Histogram>,

    // Alert counters / gauges
    pub alerts_sent_total: Family<AlertLabels, Counter>,
    pub alerts_failed_total: Family<AlertLabels, Counter>,
    pub alert_queue_depth: Gauge<i64, AtomicI64>,

    // SIEM export counters / gauges
    pub siem_exported_total: Family<SiemLabels, Counter>,
    pub siem_export_errors_total: Family<SiemLabels, Counter>,
    pub siem_buffer_size_bytes: Gauge<i64, AtomicI64>,

    // CTI enrichment counters
    pub cti_cache_hits_total: Family<CtiLabels, Counter>,
    pub cti_api_calls_total: Family<CtiLabels, Counter>,
    pub cti_api_errors_total: Family<CtiLabels, Counter>,

    // Elasticsearch bulk exporter metrics
    pub elastic_exported_total: Family<ElasticLabels, Counter>,
    pub elastic_export_errors_total: Family<ElasticLabels, Counter>,
    pub elastic_flush_duration_seconds: Family<ElasticLabels, Histogram, fn() -> Histogram>,

    // Splunk HEC exporter metrics (Phase 3.3.1)
    pub splunk_exported_total: Family<SplunkLabels, Counter>,
    pub splunk_export_errors_total: Family<SplunkLabels, Counter>,
    pub splunk_flush_duration_seconds: Family<SplunkLabels, Histogram, fn() -> Histogram>,

    // Datadog Logs API exporter metrics (Phase 3.3.2)
    pub datadog_exported_total: Family<DatadogLabels, Counter>,
    pub datadog_export_errors_total: Family<DatadogLabels, Counter>,
    pub datadog_flush_duration_seconds: Family<DatadogLabels, Histogram, fn() -> Histogram>,
}

impl Metrics {
    /// Create a new Metrics instance with all metrics registered.
    pub fn new() -> Self {
        let mut registry = Registry::default();

        // --- Gauges ---
        let active_bans = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "hiveguard_active_bans",
            "Number of currently active bans",
            active_bans.clone(),
        );

        let whitelisted_count = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "hiveguard_whitelisted_count",
            "Number of whitelisted entries",
            whitelisted_count.clone(),
        );

        let peer_count = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "hiveguard_peer_count",
            "Number of known cluster peers",
            peer_count.clone(),
        );

        let memory_usage_bytes = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "hiveguard_memory_usage_bytes",
            "Approximate memory usage in bytes",
            memory_usage_bytes.clone(),
        );

        // --- Counters ---
        let events_processed_total = Family::<SourceLabels, Counter>::default();
        registry.register(
            "hiveguard_events_processed",
            "Total number of events processed",
            events_processed_total.clone(),
        );

        let bans_created_total = Family::<DetectorLabels, Counter>::default();
        registry.register(
            "hiveguard_bans_created",
            "Total number of bans created",
            bans_created_total.clone(),
        );

        let bans_expired_total = Counter::default();
        registry.register(
            "hiveguard_bans_expired",
            "Total number of bans that have expired",
            bans_expired_total.clone(),
        );

        let detection_signals_total = Family::<DetectorLabels, Counter>::default();
        registry.register(
            "hiveguard_detection_signals",
            "Total number of detection signals generated",
            detection_signals_total.clone(),
        );

        // --- Histograms ---
        let event_processing_duration_seconds =
            Family::<SourceLabels, Histogram, fn() -> Histogram>::new_with_constructor(
                event_processing_histogram as fn() -> Histogram,
            );
        registry.register(
            "hiveguard_event_processing_duration_seconds",
            "Time spent processing a single event (detect + score + enforce)",
            event_processing_duration_seconds.clone(),
        );

        let enforcement_duration_seconds =
            Family::<OperationLabels, Histogram, fn() -> Histogram>::new_with_constructor(
                enforcement_histogram as fn() -> Histogram,
            );
        registry.register(
            "hiveguard_enforcement_duration_seconds",
            "Time spent applying or removing a ban via the enforcer",
            enforcement_duration_seconds.clone(),
        );

        // --- Alert metrics ---
        let alerts_sent_total = Family::<AlertLabels, Counter>::default();
        registry.register(
            "hiveguard_alerts_sent",
            "Total number of alerts successfully delivered",
            alerts_sent_total.clone(),
        );

        let alerts_failed_total = Family::<AlertLabels, Counter>::default();
        registry.register(
            "hiveguard_alerts_failed",
            "Total number of alert delivery failures",
            alerts_failed_total.clone(),
        );

        let alert_queue_depth = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "hiveguard_alert_queue_depth",
            "Number of alerts currently waiting in the retry queue",
            alert_queue_depth.clone(),
        );

        // --- SIEM metrics ---
        let siem_exported_total = Family::<SiemLabels, Counter>::default();
        registry.register(
            "hiveguard_siem_exported",
            "Total number of events successfully exported to SIEM",
            siem_exported_total.clone(),
        );

        let siem_export_errors_total = Family::<SiemLabels, Counter>::default();
        registry.register(
            "hiveguard_siem_export_errors",
            "Total number of SIEM export errors",
            siem_export_errors_total.clone(),
        );

        let siem_buffer_size_bytes = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "hiveguard_siem_buffer_size_bytes",
            "Approximate size in bytes of the SIEM retry buffer",
            siem_buffer_size_bytes.clone(),
        );

        // --- CTI enrichment metrics ---
        let cti_cache_hits_total = Family::<CtiLabels, Counter>::default();
        registry.register(
            "hiveguard_cti_cache_hits",
            "Total number of CTI enrichment results served from cache",
            cti_cache_hits_total.clone(),
        );

        let cti_api_calls_total = Family::<CtiLabels, Counter>::default();
        registry.register(
            "hiveguard_cti_api_calls",
            "Total number of live CTI API calls made",
            cti_api_calls_total.clone(),
        );

        let cti_api_errors_total = Family::<CtiLabels, Counter>::default();
        registry.register(
            "hiveguard_cti_api_errors",
            "Total number of CTI API call errors",
            cti_api_errors_total.clone(),
        );

        // --- Elasticsearch bulk exporter metrics ---
        let elastic_exported_total = Family::<ElasticLabels, Counter>::default();
        registry.register(
            "hiveguard_elastic_exported",
            "Total number of events successfully bulk-indexed into Elasticsearch",
            elastic_exported_total.clone(),
        );

        let elastic_export_errors_total = Family::<ElasticLabels, Counter>::default();
        registry.register(
            "hiveguard_elastic_export_errors",
            "Total number of Elasticsearch bulk flush errors",
            elastic_export_errors_total.clone(),
        );

        let elastic_flush_duration_seconds =
            Family::<ElasticLabels, Histogram, fn() -> Histogram>::new_with_constructor(
                elastic_flush_histogram as fn() -> Histogram,
            );
        registry.register(
            "hiveguard_elastic_flush_duration_seconds",
            "Time spent on each Elasticsearch _bulk request",
            elastic_flush_duration_seconds.clone(),
        );

        // --- Splunk HEC exporter metrics ---
        let splunk_exported_total = Family::<SplunkLabels, Counter>::default();
        registry.register(
            "hiveguard_splunk_exported",
            "Total number of events successfully delivered to Splunk HEC",
            splunk_exported_total.clone(),
        );

        let splunk_export_errors_total = Family::<SplunkLabels, Counter>::default();
        registry.register(
            "hiveguard_splunk_export_errors",
            "Total number of Splunk HEC flush errors",
            splunk_export_errors_total.clone(),
        );

        let splunk_flush_duration_seconds =
            Family::<SplunkLabels, Histogram, fn() -> Histogram>::new_with_constructor(
                http_siem_flush_histogram as fn() -> Histogram,
            );
        registry.register(
            "hiveguard_splunk_flush_duration_seconds",
            "Time spent on each Splunk HEC POST request",
            splunk_flush_duration_seconds.clone(),
        );

        // --- Datadog Logs API exporter metrics ---
        let datadog_exported_total = Family::<DatadogLabels, Counter>::default();
        registry.register(
            "hiveguard_datadog_exported",
            "Total number of events successfully delivered to Datadog Logs API",
            datadog_exported_total.clone(),
        );

        let datadog_export_errors_total = Family::<DatadogLabels, Counter>::default();
        registry.register(
            "hiveguard_datadog_export_errors",
            "Total number of Datadog Logs API flush errors",
            datadog_export_errors_total.clone(),
        );

        let datadog_flush_duration_seconds =
            Family::<DatadogLabels, Histogram, fn() -> Histogram>::new_with_constructor(
                http_siem_flush_histogram as fn() -> Histogram,
            );
        registry.register(
            "hiveguard_datadog_flush_duration_seconds",
            "Time spent on each Datadog Logs API POST request",
            datadog_flush_duration_seconds.clone(),
        );

        Self {
            registry,
            active_bans,
            whitelisted_count,
            peer_count,
            memory_usage_bytes,
            events_processed_total,
            bans_created_total,
            bans_expired_total,
            detection_signals_total,
            event_processing_duration_seconds,
            enforcement_duration_seconds,
            alerts_sent_total,
            alerts_failed_total,
            alert_queue_depth,
            siem_exported_total,
            siem_export_errors_total,
            siem_buffer_size_bytes,
            cti_cache_hits_total,
            cti_api_calls_total,
            cti_api_errors_total,
            elastic_exported_total,
            elastic_export_errors_total,
            elastic_flush_duration_seconds,
            splunk_exported_total,
            splunk_export_errors_total,
            splunk_flush_duration_seconds,
            datadog_exported_total,
            datadog_export_errors_total,
            datadog_flush_duration_seconds,
        }
    }

    /// Render all metrics in OpenMetrics text exposition format.
    pub fn render(&self) -> String {
        let mut buffer = String::new();
        if let Err(e) = encode(&mut buffer, &self.registry) {
            error!("Failed to encode metrics: {e}");
            return String::from("# error encoding metrics\n");
        }
        buffer
    }

    /// Update memory usage gauge by reading /proc/self/statm (Linux-specific).
    pub fn update_memory_usage(&self) {
        if let Ok(contents) = std::fs::read_to_string("/proc/self/statm") {
            // statm: size resident shared text lib data dt (in pages)
            if let Some(resident_pages) = contents.split_whitespace().nth(1) {
                if let Ok(pages) = resident_pages.parse::<i64>() {
                    let page_size = 4096i64; // typical page size
                    self.memory_usage_bytes.set(pages * page_size);
                }
            }
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared handle used throughout the application.
pub type SharedMetrics = Arc<Metrics>;

/// Create a new shared metrics instance.
pub fn create_metrics() -> SharedMetrics {
    Arc::new(Metrics::new())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_creation_succeeds() {
        let m = Metrics::new();
        let output = m.render();
        assert!(output.contains("hiveguard_active_bans"));
        assert!(output.contains("hiveguard_whitelisted_count"));
        assert!(output.contains("hiveguard_peer_count"));
        assert!(output.contains("hiveguard_bans_expired"));

        m.events_processed_total
            .get_or_create(&SourceLabels { source: "test".into() })
            .inc();
        m.bans_created_total
            .get_or_create(&DetectorLabels { detector: "test".into() })
            .inc();
        m.detection_signals_total
            .get_or_create(&DetectorLabels { detector: "test".into() })
            .inc();
        m.event_processing_duration_seconds
            .get_or_create(&SourceLabels { source: "test".into() })
            .observe(0.001);
        m.enforcement_duration_seconds
            .get_or_create(&OperationLabels { operation: "test".into() })
            .observe(0.001);

        let output = m.render();
        assert!(output.contains("hiveguard_events_processed"));
        assert!(output.contains("hiveguard_bans_created"));
        assert!(output.contains("hiveguard_detection_signals"));
        assert!(output.contains("hiveguard_event_processing_duration_seconds"));
        assert!(output.contains("hiveguard_enforcement_duration_seconds"));
    }

    #[test]
    fn gauge_set_and_render() {
        let m = Metrics::new();
        m.active_bans.set(42);
        m.whitelisted_count.set(5);
        m.peer_count.set(3);

        let output = m.render();
        assert!(output.contains("hiveguard_active_bans 42"));
        assert!(output.contains("hiveguard_whitelisted_count 5"));
        assert!(output.contains("hiveguard_peer_count 3"));
    }

    #[test]
    fn counter_increment_and_render() {
        let m = Metrics::new();
        m.events_processed_total
            .get_or_create(&SourceLabels { source: "ssh".into() })
            .inc_by(100);
        m.events_processed_total
            .get_or_create(&SourceLabels { source: "nginx".into() })
            .inc_by(50);
        m.bans_created_total
            .get_or_create(&DetectorLabels { detector: "ssh_bruteforce".into() })
            .inc_by(3);
        m.bans_expired_total.inc_by(2);
        m.detection_signals_total
            .get_or_create(&DetectorLabels { detector: "path_probe".into() })
            .inc_by(10);

        let output = m.render();
        assert!(output.contains(r#"source="ssh"}"#));
        assert!(output.contains(r#"source="nginx"}"#));
        assert!(output.contains(r#"detector="ssh_bruteforce"}"#));
        assert!(output.contains("hiveguard_bans_expired"));
        assert!(output.contains(r#"detector="path_probe"}"#));
    }

    #[test]
    fn histogram_observe_and_render() {
        let m = Metrics::new();
        m.event_processing_duration_seconds
            .get_or_create(&SourceLabels { source: "ssh".into() })
            .observe(0.001);
        m.event_processing_duration_seconds
            .get_or_create(&SourceLabels { source: "ssh".into() })
            .observe(0.002);
        m.enforcement_duration_seconds
            .get_or_create(&OperationLabels { operation: "apply".into() })
            .observe(0.01);

        let output = m.render();
        assert!(output.contains("hiveguard_event_processing_duration_seconds_count"));
        assert!(output.contains("hiveguard_event_processing_duration_seconds_sum"));
        assert!(output.contains("hiveguard_enforcement_duration_seconds_count"));
        assert!(output.contains("hiveguard_enforcement_duration_seconds_sum"));
    }

    #[test]
    fn default_metrics_identical_to_new() {
        let m = Metrics::default();
        let output = m.render();
        assert!(output.contains("hiveguard_active_bans"));
    }

    #[test]
    fn shared_metrics_clone() {
        let m = create_metrics();
        let m2 = m.clone();
        m.active_bans.set(10);
        assert_eq!(m2.active_bans.get(), 10);
    }

    #[test]
    fn render_openmetrics_text_format() {
        let m = Metrics::new();
        m.active_bans.set(1);
        let output = m.render();
        assert!(output.contains("# HELP hiveguard_active_bans"));
        assert!(output.contains("# TYPE hiveguard_active_bans gauge"));
        assert!(output.contains("hiveguard_active_bans 1"));
    }

    #[test]
    fn memory_usage_bytes_defaults_to_zero() {
        let m = Metrics::new();
        assert_eq!(m.memory_usage_bytes.get(), 0);
    }

    #[test]
    fn multiple_label_values_independent() {
        let m = Metrics::new();
        m.events_processed_total
            .get_or_create(&SourceLabels { source: "ssh".into() })
            .inc_by(10);
        m.events_processed_total
            .get_or_create(&SourceLabels { source: "nginx".into() })
            .inc_by(20);
        m.events_processed_total
            .get_or_create(&SourceLabels { source: "postfix".into() })
            .inc_by(5);

        let output = m.render();
        assert!(output.contains(r#"source="ssh"}"#));
        assert!(output.contains(r#"source="nginx"}"#));
        assert!(output.contains(r#"source="postfix"}"#));
    }
}
