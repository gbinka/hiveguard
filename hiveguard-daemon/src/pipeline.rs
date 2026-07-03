use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

use hiveguard_core::ban_store::BanStore;
use hiveguard_core::bot_registry::{BotPolicy, BotRegistry};
use hiveguard_core::detector::Detector;
use hiveguard_core::models::{GeoIpInfo, NormalizedEvent};
use hiveguard_core::persistence::StateManager;
use hiveguard_enforce::Enforcer;
use hiveguard_plugin_api::traits::Plugin;
use hiveguard_plugin_api::{AlertEvent, ScoringEnginePlugin, SiemSinkPlugin};
use hiveguard_host::AlertDispatcherHandle;

use crate::plugin_bridge::decision_to_record;
use hiveguard_cti::SharedGeoIpDb;
use hiveguard_cti::enricher::CtiEnricher;

use crate::metrics::{CtiLabels, DetectorLabels, OperationLabels, SharedMetrics, SourceLabels};
use crate::siem_exporter::{SiemEvent, SiemSyslogExporter};

/// Event processing pipeline: ingest → detect → score → enforce.
pub struct Pipeline {
    receiver: mpsc::Receiver<NormalizedEvent>,
    detectors: Vec<Box<dyn Detector>>,
    scoring: Box<dyn ScoringEnginePlugin>,
    state: Arc<Mutex<StateManager>>,
    enforcer: Arc<Mutex<Box<dyn Enforcer>>>,
    bot_registry: Option<Arc<Mutex<BotRegistry>>>,
    metrics: Option<SharedMetrics>,
    /// Shared hot-reloadable GeoIP database (None = enrichment disabled).
    geoip_db: Option<SharedGeoIpDb>,
    /// ASNs whose traffic is never banned (trusted-ASN whitelist).
    trusted_asns: HashSet<u32>,
    /// Severity multiplier applied to datacenter-sourced signals.
    datacenter_multiplier: f32,
    /// Handle to the host-side alert dispatcher (fan-out + dedup + retry).
    /// `None` when no notifier plugins are configured.
    alert_dispatcher: Option<AlertDispatcherHandle>,
    /// Optional SIEM syslog exporter (legacy, kept for generic syslog CEF/LEEF).
    siem_exporter: Option<SiemSyslogExporter>,
    /// SIEM sink plugins (sink-elastic, sink-splunk, sink-datadog, sink-syslog).
    /// Each batch produced by the pipeline is fanned out to every sink.
    siem_sinks: Vec<Arc<dyn SiemSinkPlugin>>,
    /// Optional CTI enricher (AbuseIPDB, …) for IP reputation checks.
    cti_enricher: Option<Arc<CtiEnricher>>,
    /// Optional sniffer that feeds detection signals + ban changes into the
    /// daemon's UI API for live updates to connected UI clients.
    ui_sniffer: Option<crate::ui_api::UiSniffer>,
    /// Optional cluster handle — locally-issued bans are announced here for
    /// gossip replication to peer nodes. `None` when clustering is disabled.
    #[cfg(feature = "cluster")]
    cluster: Option<crate::cluster::ClusterHandle>,
}

impl Pipeline {
    pub fn new(
        receiver: mpsc::Receiver<NormalizedEvent>,
        detectors: Vec<Box<dyn Detector>>,
        scoring: Box<dyn ScoringEnginePlugin>,
        state: Arc<Mutex<StateManager>>,
        enforcer: Arc<Mutex<Box<dyn Enforcer>>>,
    ) -> Self {
        Self {
            receiver,
            detectors,
            scoring,
            state,
            enforcer,
            bot_registry: None,
            metrics: None,
            geoip_db: None,
            trusted_asns: HashSet::new(),
            datacenter_multiplier: 1.5,
            alert_dispatcher: None,
            siem_exporter: None,
            siem_sinks: Vec::new(),
            cti_enricher: None,
            ui_sniffer: None,
            #[cfg(feature = "cluster")]
            cluster: None,
        }
    }

    /// Attach a UI sniffer for live push updates to connected UI clients.
    pub fn with_ui_sniffer(mut self, sniffer: crate::ui_api::UiSniffer) -> Self {
        self.ui_sniffer = Some(sniffer);
        self
    }

    /// Attach the cluster handle so locally-issued bans replicate to peers.
    #[cfg(feature = "cluster")]
    pub fn with_cluster(mut self, handle: crate::cluster::ClusterHandle) -> Self {
        self.cluster = Some(handle);
        self
    }

    /// Set bot registry for bot classification.
    pub fn with_bot_registry(mut self, bot_registry: Arc<Mutex<BotRegistry>>) -> Self {
        self.bot_registry = Some(bot_registry);
        self
    }

    /// Set metrics handle for pipeline instrumentation.
    pub fn with_metrics(mut self, metrics: SharedMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Enable GeoIP enrichment with a shared hot-reloadable database.
    pub fn with_geoip(
        mut self,
        geoip_db: SharedGeoIpDb,
        trusted_asns: Vec<u32>,
        datacenter_multiplier: f32,
    ) -> Self {
        self.geoip_db = Some(geoip_db);
        self.trusted_asns = trusted_asns.into_iter().collect();
        self.datacenter_multiplier = datacenter_multiplier;
        self
    }

    /// Attach an alert dispatcher handle for push notifications on bans and detections.
    pub fn with_alert_dispatcher(mut self, handle: AlertDispatcherHandle) -> Self {
        self.alert_dispatcher = Some(handle);
        self
    }

    /// Attach a CTI enricher (AbuseIPDB, …) for IP reputation checks.
    pub fn with_cti_enricher(mut self, enricher: Arc<CtiEnricher>) -> Self {
        self.cti_enricher = Some(enricher);
        self
    }

    /// Attach a SIEM syslog exporter for structured CEF/LEEF export (Phase 3.1).
    pub fn with_siem_exporter(mut self, exporter: SiemSyslogExporter) -> Self {
        self.siem_exporter = Some(exporter);
        self
    }

    /// Attach SIEM sink plugins (sink-elastic / sink-splunk / sink-datadog /
    /// sink-syslog). Each ban event is fanned out to every configured sink.
    pub fn with_siem_sinks(mut self, sinks: Vec<Arc<dyn SiemSinkPlugin>>) -> Self {
        self.siem_sinks = sinks;
        self
    }

    /// Run the event processing loop until the channel is closed.
    pub async fn run(&mut self) {
        info!("Pipeline started, waiting for events");
        let mut events_processed: u64 = 0;
        let mut signals_generated: u64 = 0;
        let mut bans_issued: u64 = 0;

        while let Some(mut event) = self.receiver.recv().await {
            let event_start = std::time::Instant::now();
            events_processed += 1;
            let source_name = event.source_name.clone();

            debug!(
                source = %event.source_name,
                ip = %event.source_ip,
                event_type = ?event.event_type,
                "Processing event #{}", events_processed
            );

            // Increment event counter
            if let Some(ref m) = self.metrics {
                m.events_processed_total
                    .get_or_create(&SourceLabels { source: source_name.clone() })
                    .inc();
            }

            // --- GeoIP enrichment: enrich event.metadata and check trusted ASNs ---
            let geo_info: Option<GeoIpInfo> = if let Some(ref geoip) = self.geoip_db {
                let guard = geoip.load();
                if let Some(ref db) = **guard {
                    let info = db.lookup(event.source_ip);

                    // Populate event metadata keys
                    if let Some(ref iso) = info.country_iso {
                        event.metadata.insert("geo_country".to_string(), iso.clone());
                    }
                    if let Some(asn) = info.asn {
                        event.metadata.insert("geo_asn".to_string(), asn.to_string());
                    }
                    if let Some(ref org) = info.asn_org {
                        event.metadata.insert("geo_org".to_string(), org.clone());
                    }
                    event.metadata.insert(
                        "geo_datacenter".to_string(),
                        info.is_datacenter.to_string(),
                    );

                    // Trusted-ASN whitelist: skip all detectors for trusted AS numbers
                    if let Some(asn) = info.asn {
                        if self.trusted_asns.contains(&asn) {
                            debug!(
                                ip = %event.source_ip,
                                asn = asn,
                                "Trusted ASN — skipping detectors"
                            );
                            if let Some(ref m) = self.metrics {
                                m.event_processing_duration_seconds
                                    .get_or_create(&SourceLabels {
                                        source: source_name.clone(),
                                    })
                                    .observe(event_start.elapsed().as_secs_f64());
                            }
                            continue;
                        }
                    }

                    Some(info)
                } else {
                    None
                }
            } else {
                None
            };

            // --- Bot classification: check User-Agent before running detectors ---
            if let Some(ref bot_reg) = self.bot_registry {
                let ua = event.metadata.get("user_agent").map(|s| s.as_str()).unwrap_or("");
                if !ua.is_empty() {
                    let ip_str = event.source_ip.to_string();
                    let mut reg = bot_reg.lock().await;
                    if let Some(policy) = reg.classify(ua, &ip_str) {
                        match policy {
                            BotPolicy::Allow => {
                                debug!(
                                    ip = %event.source_ip,
                                    ua = ua,
                                    "Bot allowed — skipping detectors"
                                );
                                continue; // skip all detectors for this event
                            }
                            BotPolicy::Block => {
                                info!(
                                    ip = %event.source_ip,
                                    ua = ua,
                                    "Bot blocked — generating ban signal"
                                );
                                // Block policy events still go through detectors
                                // (they'll likely trigger scanner_fingerprint anyway)
                            }
                            BotPolicy::Monitor => {
                                // Monitor: just track, run detectors normally
                            }
                        }
                    }
                }
            }

            // --- CTI enrichment: check all enabled reputation feeds (Phase 1.3) ---
            if let Some(ref cti) = self.cti_enricher {
                let ip = event.source_ip;
                let (cti_signal, cti_stats) = cti.enrich(ip).await;

                // Update Prometheus counters
                if let Some(ref m) = self.metrics {
                    // Use the winning signal's provider name; fall back to "cti" aggregate.
                    let provider_name = cti_signal.as_ref().map(|s| s.provider).unwrap_or("cti");
                    let label = CtiLabels { provider: provider_name.to_string() };
                    if cti_stats.cache_hit {
                        m.cti_cache_hits_total.get_or_create(&label).inc();
                    }
                    if cti_stats.api_called {
                        m.cti_api_calls_total.get_or_create(&label).inc();
                    }
                    if cti_stats.api_error {
                        m.cti_api_errors_total.get_or_create(&label).inc();
                    }
                }

                // Inject a synthetic DetectionSignal if threshold exceeded
                if let Some(sig) = cti_signal {
                    use hiveguard_core::models::{Action, DetectionSignal};
                    use ipnet::IpNet;

                    let synthetic = DetectionSignal {
                        source_ip: IpNet::from(ip),
                        severity: sig.severity,
                        confidence: sig.confidence_score as f32 / 100.0,
                        reason: sig.description.clone(),
                        evidence_hash: [0u8; 32],
                        suggested_action: Action::Ban(std::time::Duration::from_secs(86400)),
                        detector_name: sig.provider.to_string(),
                        timestamp: chrono::Utc::now(),
                    };

                    info!(
                        provider = sig.provider,
                        ip = %ip,
                        severity = sig.severity,
                        score = sig.confidence_score,
                        "CTI signal: {}",
                        sig.description
                    );

                    if let Some(ref m) = self.metrics {
                        m.detection_signals_total
                            .get_or_create(&DetectorLabels {
                                detector: sig.provider.to_string(),
                            })
                            .inc();
                    }

                    // Run through scoring engine now (before the detector loop).
                    // Whitelist check moved to pipeline — plugin's ScoringEnginePlugin
                    // doesn't take a whitelist argument by design.
                    let signal_ip = synthetic.source_ip.addr();
                    let whitelisted = {
                        let st = self.state.lock().await;
                        st.whitelist().is_whitelisted(&signal_ip)
                    };
                    let cti_decision = if whitelisted {
                        debug!(
                            ip = %signal_ip,
                            "Suppressed CTI scoring for whitelisted IP"
                        );
                        None
                    } else {
                        if let Some(ref sniffer) = self.ui_sniffer {
                            sniffer.observe(synthetic.clone());
                        }
                        self.scoring.record(synthetic);
                        self.scoring.evaluate(signal_ip)
                    };
                    if let Some(decision) = cti_decision {
                        let mut ban_record = decision_to_record(decision);
                        ban_record.geo_info = geo_info.clone();
                        bans_issued += 1;
                        info!(
                            subject = %ban_record.subject,
                            severity = ban_record.severity,
                            reason = %ban_record.reason,
                            "CTI-triggered ban (total: {})", bans_issued
                        );
                        let subject = ban_record.subject;
                        let ban_severity = ban_record.severity;
                        let ban_reason = ban_record.reason.clone();
                        let ban_geo = ban_record.geo_info.clone();
                        // Replicate to cluster peers before `ban_record` is moved.
                        #[cfg(feature = "cluster")]
                        if let Some(ref c) = self.cluster {
                            c.announce_local_ban(&ban_record);
                        }
                        {
                            let mut st = self.state.lock().await;
                            if let Err(e) = st.add_ban(ban_record) {
                                error!(subject = %subject, "Failed to persist CTI ban: {}", e);
                            }
                        }
                        if let Some(ref sniffer) = self.ui_sniffer {
                            sniffer.notify_bans_changed();
                        }
                        {
                            let enforce_start = std::time::Instant::now();
                            let mut enf = self.enforcer.lock().await;
                            if let Err(e) = enf.apply_ban(&subject).await {
                                error!(subject = %subject, "Failed to apply CTI ban: {}", e);
                            }
                            if let Some(ref m) = self.metrics {
                                m.enforcement_duration_seconds
                                    .get_or_create(&OperationLabels {
                                        operation: "apply".to_string(),
                                    })
                                    .observe(enforce_start.elapsed().as_secs_f64());
                            }
                        }
                        if let Some(ref am) = self.alert_dispatcher {
                            am.send(AlertEvent::IpBanned {
                                ip: subject,
                                severity: ban_severity,
                                reason: ban_reason.clone(),
                                geo: ban_geo.clone(),
                            });
                        }
                        // Fan-out CTI ban to all SIEM sink plugins.
                        if !self.siem_sinks.is_empty() {
                            let ban_ev = build_ban_normalized_event(
                                subject.addr(),
                                &ban_reason,
                                ban_severity,
                                "abuseipdb",
                                "86400s",
                                "CtiBan",
                                ban_geo.as_ref(),
                            );
                            fan_out_sinks(&self.siem_sinks, ban_ev).await;
                        }
                        if let Some(ref m) = self.metrics {
                            m.bans_created_total
                                .get_or_create(&DetectorLabels {
                                    detector: "abuseipdb".to_string(),
                                })
                                .inc();
                            let st = self.state.lock().await;
                            m.active_bans.set(st.ban_store().get_all_bans().len() as i64);
                        }
                    }
                }
            }

            // Pass event through each detector
            let mut detection_signals = Vec::new();
            for detector in &mut self.detectors {
                if let Some(mut signal) = detector.process(&event) {
                    // Apply datacenter severity multiplier if applicable
                    if let Some(ref gi) = geo_info {
                        if gi.is_datacenter && self.datacenter_multiplier != 1.0 {
                            let boosted = (signal.severity as f32 * self.datacenter_multiplier)
                                .min(255.0) as u8;
                            signal.severity = boosted;
                        }
                    }

                    info!(
                        detector = detector.name(),
                        ip = %signal.source_ip,
                        severity = signal.severity,
                        reason = %signal.reason,
                        "Detection signal generated"
                    );

                    // Emit HoneypotHit alert
                    if detector.name() == "honeypot" {
                        if let Some(ref am) = self.alert_dispatcher {
                            let path = event
                                .metadata
                                .get("path")
                                .cloned()
                                .unwrap_or_else(|| event.raw_line.clone());
                            am.send(AlertEvent::HoneypotHit {
                                ip: event.source_ip.to_string(),
                                path,
                            });
                        }
                    }

                    // Increment signal counter
                    if let Some(ref m) = self.metrics {
                        m.detection_signals_total
                            .get_or_create(&DetectorLabels { detector: detector.name().to_string() })
                            .inc();
                    }

                    detection_signals.push(signal);
                }
            }

            signals_generated += detection_signals.len() as u64;

            // Pass signals through scoring engine
            for signal in detection_signals {
                let detector_name = signal.detector_name.clone();
                let signal_ip = signal.source_ip.addr();
                let whitelisted = {
                    let st = self.state.lock().await;
                    st.whitelist().is_whitelisted(&signal_ip)
                };
                if whitelisted {
                    debug!(
                        ip = %signal_ip,
                        detector = %detector_name,
                        "Suppressed ban for whitelisted IP"
                    );
                    continue;
                }
                if let Some(ref sniffer) = self.ui_sniffer {
                    sniffer.observe(signal.clone());
                }
                self.scoring.record(signal);
                let decision = self.scoring.evaluate(signal_ip);

                if let Some(decision) = decision {
                    let mut ban_record = decision_to_record(decision);
                    // Attach GeoIP enrichment to the ban record
                    ban_record.geo_info = geo_info.clone();

                    bans_issued += 1;
                    info!(
                        subject = %ban_record.subject,
                        severity = ban_record.severity,
                        reason = %ban_record.reason,
                        expires_at = ?ban_record.expires_at,
                        country = ?ban_record.geo_info.as_ref().and_then(|g| g.country_iso.as_deref()),
                        asn = ?ban_record.geo_info.as_ref().and_then(|g| g.asn),
                        "Ban issued (total: {})", bans_issued
                    );

                    let subject = ban_record.subject;
                    let ban_severity = ban_record.severity;
                    let ban_reason = ban_record.reason.clone();
                    let ban_geo = ban_record.geo_info.clone();
                    // Compute ban_duration for SIEM export before ban_record is moved
                    let ban_duration_str = match ban_record.expires_at {
                        None => "permanent".to_string(),
                        Some(expires) => {
                            let secs = (expires - ban_record.created_at)
                                .num_seconds()
                                .max(0) as u64;
                            if secs % 86_400 == 0 && secs > 0 {
                                format!("{}d", secs / 86_400)
                            } else if secs % 3_600 == 0 && secs > 0 {
                                format!("{}h", secs / 3_600)
                            } else if secs % 60 == 0 && secs > 0 {
                                format!("{}m", secs / 60)
                            } else {
                                format!("{secs}s")
                            }
                        }
                    };

                    // Replicate to cluster peers before `ban_record` is moved.
                    #[cfg(feature = "cluster")]
                    if let Some(ref c) = self.cluster {
                        c.announce_local_ban(&ban_record);
                    }
                    // Persist ban in StateManager
                    {
                        let mut st = self.state.lock().await;
                        if let Err(e) = st.add_ban(ban_record) {
                            error!(subject = %subject, "Failed to persist ban: {}", e);
                            continue;
                        }
                    }
                    if let Some(ref sniffer) = self.ui_sniffer {
                        sniffer.notify_bans_changed();
                    }

                    // Apply ban via enforcer (with timing)
                    {
                        let enforce_start = std::time::Instant::now();
                        let mut enf = self.enforcer.lock().await;
                        if let Err(e) = enf.apply_ban(&subject).await {
                            error!(subject = %subject, "Failed to apply ban: {}", e);
                        }
                        if let Some(ref m) = self.metrics {
                            m.enforcement_duration_seconds
                                .get_or_create(&OperationLabels { operation: "apply".to_string() })
                                .observe(enforce_start.elapsed().as_secs_f64());
                        }
                    }

                    // Export to SIEM (Phase 3.1)
                    if let Some(ref mut siem) = self.siem_exporter {
                        let siem_event = SiemEvent {
                            src_ip: subject.addr().to_string(),
                            reason: ban_reason.clone(),
                            severity: ban_severity,
                            detector: detector_name.clone(),
                            ban_duration: ban_duration_str.clone(),
                            country: ban_geo
                                .as_ref()
                                .and_then(|g| g.country_iso.clone()),
                            asn: ban_geo.as_ref().and_then(|g| g.asn),
                            event_class: "BanTriggered".to_string(),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                        };
                        siem.export(&siem_event);
                    }

                    // Fan-out ban to all SIEM sink plugins.
                    if !self.siem_sinks.is_empty() {
                        let ban_ev = build_ban_normalized_event(
                            subject.addr(),
                            &ban_reason,
                            ban_severity,
                            &detector_name,
                            &ban_duration_str,
                            "BanTriggered",
                            ban_geo.as_ref(),
                        );
                        fan_out_sinks(&self.siem_sinks, ban_ev).await;
                    }

                    // Emit ban alert
                    if let Some(ref am) = self.alert_dispatcher {
                        let prefix_len = subject.prefix_len();
                        let is_subnet = match subject.addr() {
                            std::net::IpAddr::V4(_) => prefix_len < 32,
                            std::net::IpAddr::V6(_) => prefix_len < 128,
                        };
                        if is_subnet {
                            am.send(AlertEvent::SubnetBanned {
                                subnet: subject,
                                ip_count: 0, // exact count not tracked at this layer
                                reason: ban_reason,
                            });
                        } else {
                            am.send(AlertEvent::IpBanned {
                                ip: subject,
                                severity: ban_severity,
                                reason: ban_reason,
                                geo: ban_geo,
                            });
                        }
                    }

                    // Increment ban counter and update gauge
                    if let Some(ref m) = self.metrics {
                        m.bans_created_total
                            .get_or_create(&DetectorLabels { detector: detector_name.clone() })
                            .inc();
                        let st = self.state.lock().await;
                        m.active_bans.set(st.ban_store().get_all_bans().len() as i64);
                        m.whitelisted_count
                            .set(st.whitelist().entries().len() as i64);
                    }
                }
            }

            // Record event processing duration
            if let Some(ref m) = self.metrics {
                m.event_processing_duration_seconds
                    .get_or_create(&SourceLabels { source: source_name.clone() })
                    .observe(event_start.elapsed().as_secs_f64());
            }
        }

        info!(
            events_processed = events_processed,
            signals_generated = signals_generated,
            bans_issued = bans_issued,
            "Pipeline stopped"
        );
    }
}

/// Build a `NormalizedEvent` representing a ban for fan-out to SIEM sink plugins.
///
/// SIEM sinks consume `Vec<NormalizedEvent>` (see `SiemBatch`). We construct one
/// here that carries the ban metadata in `event.metadata` keys so downstream
/// receivers can index / search on it consistently.
fn build_ban_normalized_event(
    src_ip: std::net::IpAddr,
    reason: &str,
    severity: u8,
    detector: &str,
    ban_duration: &str,
    event_class: &str,
    geo: Option<&GeoIpInfo>,
) -> NormalizedEvent {
    use std::collections::HashMap;
    use hiveguard_core::models::EventType;

    let mut metadata: HashMap<String, String> = HashMap::new();
    metadata.insert("reason".into(), reason.to_string());
    metadata.insert("severity".into(), severity.to_string());
    metadata.insert("detector".into(), detector.to_string());
    metadata.insert("ban_duration".into(), ban_duration.to_string());
    metadata.insert("event_class".into(), event_class.to_string());
    if let Some(g) = geo {
        if let Some(c) = &g.country_iso {
            metadata.insert("country".into(), c.clone());
        }
        if let Some(a) = g.asn {
            metadata.insert("asn".into(), a.to_string());
        }
        if let Some(o) = &g.asn_org {
            metadata.insert("asn_org".into(), o.clone());
        }
        metadata.insert("is_datacenter".into(), g.is_datacenter.to_string());
    }
    NormalizedEvent {
        timestamp: chrono::Utc::now(),
        source_ip: src_ip,
        event_type: EventType::Custom(event_class.to_string()),
        source_name: "hiveguard-daemon".into(),
        raw_line: format!(
            "ban {src_ip} reason={reason} severity={severity} detector={detector} duration={ban_duration}"
        ),
        metadata,
    }
}

/// Fan-out a single ban event to every configured SIEM sink. Failures are
/// logged but do not abort the pipeline — sinks are best-effort.
async fn fan_out_sinks(
    sinks: &[Arc<dyn SiemSinkPlugin>],
    event: NormalizedEvent,
) {
    for sink in sinks {
        let batch = vec![event.clone()];
        if let Err(e) = sink.send(batch).await {
            warn!(
                plugin = sink.manifest().id,
                error = %e,
                "SIEM sink failed to ship batch"
            );
        }
    }
}

/// Background task: periodically clean up expired bans and remove them from enforcer.
pub async fn ban_expiry_task(
    state: Arc<Mutex<StateManager>>,
    enforcer: Arc<Mutex<Box<dyn Enforcer>>>,
    interval: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    metrics: Option<SharedMetrics>,
) {
    info!(interval_secs = interval.as_secs(), "Ban expiry task started");
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // first tick is immediate, skip it

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                // Collect expired bans
                let expired_subjects: Vec<ipnet::IpNet>;
                {
                    let st = state.lock().await;
                    let now = chrono::Utc::now();
                    expired_subjects = st
                        .ban_store()
                        .get_all_bans()
                        .iter()
                        .filter(|b| b.expires_at.map(|exp| exp <= now).unwrap_or(false))
                        .map(|b| b.subject)
                        .collect();
                }

                if expired_subjects.is_empty() {
                    continue;
                }

                let expired_count = expired_subjects.len();
                info!(count = expired_count, "Cleaning up expired bans");

                // Remove from state
                {
                    let mut st = state.lock().await;
                    st.ban_store_mut().cleanup_expired();
                }

                // Remove from enforcer
                {
                    let mut enf = enforcer.lock().await;
                    for subject in &expired_subjects {
                        let enforce_start = std::time::Instant::now();
                        if let Err(e) = enf.remove_ban(subject).await {
                            warn!(subject = %subject, "Failed to remove expired ban from enforcer: {}", e);
                        }
                        if let Some(ref m) = metrics {
                            m.enforcement_duration_seconds
                                .get_or_create(&OperationLabels { operation: "remove".to_string() })
                                .observe(enforce_start.elapsed().as_secs_f64());
                        }
                    }
                }

                // Update metrics
                if let Some(ref m) = metrics {
                    m.bans_expired_total.inc_by(expired_count as u64);
                    let st = state.lock().await;
                    m.active_bans.set(st.ban_store().get_all_bans().len() as i64);
                }
            }
            _ = shutdown.changed() => {
                info!("Ban expiry task stopping");
                break;
            }
        }
    }
}

/// Background task: sd-notify watchdog heartbeat every 15 seconds.
pub async fn watchdog_task(mut shutdown: tokio::sync::watch::Receiver<bool>) {
    info!("Watchdog task started (interval: 15s)");
    let mut ticker = tokio::time::interval(Duration::from_secs(15));
    ticker.tick().await; // skip first immediate tick

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let _ = sd_notify::notify(&[sd_notify::NotifyState::Watchdog]);
            }
            _ = shutdown.changed() => {
                info!("Watchdog task stopping");
                break;
            }
        }
    }
}

/// Background task: periodically take a snapshot of the state.
pub async fn snapshot_task(
    state: Arc<Mutex<StateManager>>,
    interval: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    info!(interval_secs = interval.as_secs(), "Snapshot task started");
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // skip immediate first tick

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let mut st = state.lock().await;
                if let Err(e) = st.take_snapshot() {
                    error!("Failed to take snapshot: {}", e);
                }
            }
            _ = shutdown.changed() => {
                info!("Snapshot task stopping, taking final snapshot");
                let mut st = state.lock().await;
                if let Err(e) = st.take_snapshot() {
                    error!("Failed to take final snapshot: {}", e);
                }
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use hiveguard_core::ban_store::BanStore;
    use hiveguard_core::detectors::SshBruteforceDetector;
    use hiveguard_core::models::{EventType, NormalizedEvent};
    use hiveguard_core::persistence::wal::WalSyncMode;
    use hiveguard_enforce::ObserveOnlyEnforcer;
    use hiveguard_plugin_api::context::parking_lot_compat::RegistryHandle;
    use hiveguard_plugin_api::secrets::SecretResolver;
    use hiveguard_plugin_api::{CancellationToken, PluginContext, PluginMetrics};
    use std::collections::HashMap;
    use std::net::IpAddr;

    async fn default_scoring() -> Box<dyn ScoringEnginePlugin> {
        let ctx = PluginContext::new(
            "scoring.default".to_string(),
            std::env::temp_dir(),
            Arc::new(SecretResolver::new()),
            PluginMetrics {
                registry: Arc::new(RegistryHandle::default()),
                plugin_id: "scoring.default".to_string(),
            },
            CancellationToken::new(),
        );
        hiveguard_plugin_scoring_default::DefaultScoringPlugin::create(
            ctx,
            serde_json::json!({}),
        )
        .await
        .expect("default scoring plugin must construct")
    }

    #[tokio::test]
    async fn pipeline_processes_events_and_bans() {
        let dir = tempfile::TempDir::new().unwrap();
        let state = Arc::new(Mutex::new(
            StateManager::new(dir.path(), WalSyncMode::None).unwrap(),
        ));
        let enforcer: Arc<Mutex<Box<dyn Enforcer>>> =
            Arc::new(Mutex::new(Box::new(ObserveOnlyEnforcer::new())));

        let (tx, rx) = mpsc::channel(100);

        let detectors: Vec<Box<dyn Detector>> = vec![Box::new(SshBruteforceDetector::new())];
        let scoring = default_scoring().await;

        let mut pipeline = Pipeline::new(rx, detectors, scoring, state.clone(), enforcer.clone());

        let pipeline_handle = tokio::spawn(async move {
            pipeline.run().await;
        });

        // Send 5 auth failures from the same IP (threshold = 5)
        let ip: IpAddr = "1.99.99.99".parse().unwrap();
        for i in 0..5 {
            let event = NormalizedEvent {
                timestamp: Utc::now(),
                source_ip: ip,
                event_type: EventType::AuthFailure,
                source_name: "ssh".to_string(),
                raw_line: format!("test line {i}"),
                metadata: HashMap::new(),
            };
            tx.send(event).await.unwrap();
        }

        // Give pipeline time to process
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check state — should have a ban
        {
            let st = state.lock().await;
            assert!(
                st.ban_store().is_banned(&ip).is_some(),
                "IP should be banned after 5 auth failures"
            );
        }

        // Check enforcer — should have applied the ban
        {
            let enf = enforcer.lock().await;
            let bans = enf.get_current_bans().await.unwrap();
            assert!(
                !bans.is_empty(),
                "Enforcer should have at least one ban"
            );
        }

        // Drop sender to close channel and stop pipeline
        drop(tx);
        pipeline_handle.await.unwrap();
    }

    #[tokio::test]
    async fn pipeline_below_threshold_no_ban() {
        let dir = tempfile::TempDir::new().unwrap();
        let state = Arc::new(Mutex::new(
            StateManager::new(dir.path(), WalSyncMode::None).unwrap(),
        ));
        let enforcer: Arc<Mutex<Box<dyn Enforcer>>> =
            Arc::new(Mutex::new(Box::new(ObserveOnlyEnforcer::new())));

        let (tx, rx) = mpsc::channel(100);

        let detectors: Vec<Box<dyn Detector>> = vec![Box::new(SshBruteforceDetector::new())];
        let scoring = default_scoring().await;

        let mut pipeline = Pipeline::new(rx, detectors, scoring, state.clone(), enforcer.clone());

        let pipeline_handle = tokio::spawn(async move {
            pipeline.run().await;
        });

        // Send only 3 auth failures (threshold = 5)
        let ip: IpAddr = "1.88.88.88".parse().unwrap();
        for i in 0..3 {
            let event = NormalizedEvent {
                timestamp: Utc::now(),
                source_ip: ip,
                event_type: EventType::AuthFailure,
                source_name: "ssh".to_string(),
                raw_line: format!("test line {i}"),
                metadata: HashMap::new(),
            };
            tx.send(event).await.unwrap();
        }

        tokio::time::sleep(Duration::from_millis(100)).await;

        {
            let st = state.lock().await;
            assert!(
                st.ban_store().is_banned(&ip).is_none(),
                "IP should NOT be banned with only 3 failures"
            );
        }

        drop(tx);
        pipeline_handle.await.unwrap();
    }

    #[tokio::test]
    async fn pipeline_ignores_non_matching_events() {
        let dir = tempfile::TempDir::new().unwrap();
        let state = Arc::new(Mutex::new(
            StateManager::new(dir.path(), WalSyncMode::None).unwrap(),
        ));
        let enforcer: Arc<Mutex<Box<dyn Enforcer>>> =
            Arc::new(Mutex::new(Box::new(ObserveOnlyEnforcer::new())));

        let (tx, rx) = mpsc::channel(100);

        let detectors: Vec<Box<dyn Detector>> = vec![Box::new(SshBruteforceDetector::new())];
        let scoring = default_scoring().await;

        let mut pipeline = Pipeline::new(rx, detectors, scoring, state.clone(), enforcer.clone());

        let pipeline_handle = tokio::spawn(async move {
            pipeline.run().await;
        });

        // Send 10 AuthSuccess events — SSH detector ignores these
        let ip: IpAddr = "1.77.77.77".parse().unwrap();
        for i in 0..10 {
            let event = NormalizedEvent {
                timestamp: Utc::now(),
                source_ip: ip,
                event_type: EventType::AuthSuccess,
                source_name: "ssh".to_string(),
                raw_line: format!("accepted line {i}"),
                metadata: HashMap::new(),
            };
            tx.send(event).await.unwrap();
        }

        tokio::time::sleep(Duration::from_millis(100)).await;

        {
            let st = state.lock().await;
            assert!(st.ban_store().is_banned(&ip).is_none());
        }

        drop(tx);
        pipeline_handle.await.unwrap();
    }

    #[tokio::test]
    async fn pipeline_multiple_detectors() {
        use hiveguard_core::detectors::PathProbeDetector;

        let dir = tempfile::TempDir::new().unwrap();
        let state = Arc::new(Mutex::new(
            StateManager::new(dir.path(), WalSyncMode::None).unwrap(),
        ));
        let enforcer: Arc<Mutex<Box<dyn Enforcer>>> =
            Arc::new(Mutex::new(Box::new(ObserveOnlyEnforcer::new())));

        let (tx, rx) = mpsc::channel(100);

        let detectors: Vec<Box<dyn Detector>> = vec![
            Box::new(SshBruteforceDetector::new()),
            Box::new(PathProbeDetector::new()),
        ];
        let scoring = default_scoring().await;

        let mut pipeline = Pipeline::new(rx, detectors, scoring, state.clone(), enforcer.clone());

        let pipeline_handle = tokio::spawn(async move {
            pipeline.run().await;
        });

        // Send a path probe event — severity 200 > threshold 100 → immediate ban
        let ip: IpAddr = "1.66.66.66".parse().unwrap();
        let mut metadata = HashMap::new();
        metadata.insert("path".to_string(), "/wp-login.php".to_string());
        metadata.insert("method".to_string(), "GET".to_string());
        metadata.insert("user_agent".to_string(), "scanner/1.0".to_string());
        metadata.insert("status_code".to_string(), "404".to_string());

        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: ip,
            event_type: EventType::Http4xx,
            source_name: "nginx".to_string(),
            raw_line: "GET /wp-login.php HTTP/1.1".to_string(),
            metadata,
        };
        tx.send(event).await.unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;

        {
            let st = state.lock().await;
            assert!(
                st.ban_store().is_banned(&ip).is_some(),
                "Path probe should trigger immediate ban"
            );
        }

        drop(tx);
        pipeline_handle.await.unwrap();
    }
}
