use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

use hiveguard_core::ban_store::BanStore;
use hiveguard_core::bot_registry::{BotPolicy, BotRegistry};
use hiveguard_core::detector::Detector;
use hiveguard_core::models::{BanRecord, GeoIpInfo, NormalizedEvent};
use hiveguard_core::persistence::{BanAdmission, StateManager};
use hiveguard_enforce::Enforcer;
use hiveguard_plugin_api::traits::Plugin;
use hiveguard_plugin_api::{AlertEvent, ScoringEnginePlugin, SiemSinkPlugin};
use hiveguard_host::AlertDispatcherHandle;

use crate::plugin_bridge::decision_to_record;
use hiveguard_cti::SharedGeoIpDb;
use hiveguard_cti::enricher::CtiEnricher;

use crate::metrics::{CtiLabels, DetectorLabels, OperationLabels, SharedMetrics, SourceLabels};
use crate::siem_exporter::{SiemEvent, SiemSyslogExporter};

use hiveguard_core::bot_registry::BOT_POLICY_DETECTOR;
/// Minimum interval between two bot-policy signals for one source.
const BOT_SIGNAL_INTERVAL: Duration = Duration::from_secs(60);
/// Bound of the bot-policy rate-limit map.
const BOT_SIGNAL_TRACKED_MAX: usize = 10_000;

/// Event processing pipeline: ingest → detect → score → enforce.
pub struct Pipeline {
    receiver: mpsc::Receiver<NormalizedEvent>,
    detectors: Vec<Box<dyn Detector>>,
    scoring: Box<dyn ScoringEnginePlugin>,
    state: Arc<Mutex<StateManager>>,
    enforcer: Arc<Mutex<Box<dyn Enforcer>>>,
    bot_registry: Option<Arc<Mutex<BotRegistry>>>,
    /// Last bot-policy signal per source (rate limit, bounded).
    bot_signal_last: std::collections::HashMap<std::net::IpAddr, std::time::Instant>,
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
            bot_signal_last: std::collections::HashMap::new(),
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

    pub fn close_input(&mut self) {
        self.receiver.close();
    }

    /// Ban signal for a User-Agent matching a `policy: block` bot rule.
    /// Rate-limited to one signal per source per [`BOT_SIGNAL_INTERVAL`] so a
    /// burst from one client does not flood scoring and the log while the
    /// ban is being applied.
    fn bot_block_signal(
        &mut self,
        event: &NormalizedEvent,
        m: &hiveguard_core::bot_registry::BotMatch,
    ) -> Option<hiveguard_core::models::DetectionSignal> {
        let now = std::time::Instant::now();
        if let Some(last) = self.bot_signal_last.get(&event.source_ip) {
            if now.duration_since(*last) < BOT_SIGNAL_INTERVAL {
                return None;
            }
        }
        if self.bot_signal_last.len() >= BOT_SIGNAL_TRACKED_MAX {
            self.bot_signal_last
                .retain(|_, t| now.duration_since(*t) < BOT_SIGNAL_INTERVAL);
            if self.bot_signal_last.len() >= BOT_SIGNAL_TRACKED_MAX {
                self.bot_signal_last.clear();
            }
        }
        self.bot_signal_last.insert(event.source_ip, now);
        Some(m.block_signal(event))
    }

    /// Persist a ban decision unless an active ban already covers it, then
    /// replicate it. Returns `true` only for a brand-new ban — the caller then
    /// logs it, counts it and pushes it to the enforcer. An extension updates
    /// the store (and peers) but the firewall already holds the subject.
    async fn admit(&self, ban_record: &BanRecord) -> bool {
        let subject = ban_record.subject;
        let admission = {
            let mut st = self.state.lock().await;
            st.admit_ban(ban_record.clone(), chrono::Utc::now())
        };
        let added = match admission {
            Err(e) => {
                error!(subject = %subject, "Failed to persist ban: {}", e);
                return false;
            }
            Ok(BanAdmission::AlreadyCovered { by, expires_at }) => {
                debug!(
                    subject = %subject,
                    covered_by = %by,
                    expires_at = ?expires_at,
                    "Ban skipped: subject already has an active ban"
                );
                return false;
            }
            Ok(BanAdmission::Extended { previous_expiry }) => {
                info!(
                    subject = %subject,
                    previous_expiry = ?previous_expiry,
                    expires_at = ?ban_record.expires_at,
                    "Ban extended"
                );
                false
            }
            Ok(BanAdmission::Added) => true,
        };
        #[cfg(feature = "cluster")]
        if let Some(ref c) = self.cluster {
            c.announce_local_ban(ban_record);
        }
        if let Some(ref sniffer) = self.ui_sniffer {
            sniffer.notify_bans_changed();
        }
        added
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

            // Signals for this event (bot policy first, then detectors).
            let mut detection_signals = Vec::new();

            // --- Bot classification: check User-Agent before running detectors ---
            if let Some(bot_reg) = self.bot_registry.clone() {
                let ua = event.metadata.get("user_agent").map(|s| s.as_str()).unwrap_or("");
                if !ua.is_empty() {
                    let ip_str = event.source_ip.to_string();
                    let matched = bot_reg.lock().await.classify_rule(ua, &ip_str);
                    if let Some(m) = matched {
                        match m.policy {
                            BotPolicy::Allow => {
                                debug!(
                                    ip = %event.source_ip,
                                    ua = ua,
                                    "Unverified bot User-Agent — running detectors"
                                );
                            }
                            BotPolicy::Block => {
                                // `policy: block` bans (short, per rule
                                // `ban_duration_secs`, default 1 h) through the
                                // normal signal path: whitelisted / trusted-ASN
                                // sources (verified crawlers) are never banned,
                                // and detectors still run for this event.
                                if let Some(signal) = self.bot_block_signal(&event, &m) {
                                    if let Some(ref met) = self.metrics {
                                        met.detection_signals_total
                                            .get_or_create(&DetectorLabels {
                                                detector: BOT_POLICY_DETECTOR.to_string(),
                                            })
                                            .inc();
                                    }
                                    info!(
                                        detector = BOT_POLICY_DETECTOR,
                                        ip = %signal.source_ip,
                                        severity = signal.severity,
                                        reason = %signal.reason,
                                        "Detection signal generated"
                                    );
                                    detection_signals.push(signal);
                                }
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
                    // Overlap, not containment: the subject may be a /24 while
                    // the whitelist entry protecting it is a /32.
                    let whitelisted = {
                        let st = self.state.lock().await;
                        st.whitelist().overlaps(&synthetic.source_ip)
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
                    let cti_decision = match cti_decision {
                        Some(decision) => {
                            let mut ban_record = decision_to_record(decision);
                            ban_record.geo_info = geo_info.clone();
                            self.admit(&ban_record).await.then_some(ban_record)
                        }
                        None => None,
                    };
                    if let Some(ban_record) = cti_decision {
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
            for detector in &mut self.detectors {
                for mut signal in detector.process_multi(&event) {
                    // Signals about other IPs (cross-IP campaign detectors)
                    // must not inherit this event's GeoIP facts.
                    let about_event_ip = signal.source_ip.contains(&event.source_ip);
                    // Apply datacenter severity multiplier if applicable
                    if let Some(gi) = geo_info.as_ref().filter(|_| about_event_ip) {
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
                    st.whitelist().overlaps(&signal.source_ip)
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
                    // Attach GeoIP enrichment to the ban record — only when the
                    // ban is about this event's source (campaign detectors can
                    // emit signals for other participants).
                    if ban_record.subject.contains(&event.source_ip) {
                        ban_record.geo_info = geo_info.clone();
                    }

                    // Check-and-persist under one state lock: a subject that
                    // already has an active ban must not get a second one.
                    if !self.admit(&ban_record).await {
                        continue;
                    }

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
                // Serialize desired-state changes and enforcement. Holding state
                // through sync prevents an older snapshot overwriting a new ban.
                let mut st = state.lock().await;
                let now = chrono::Utc::now();
                let expired: Vec<_> = st.ban_store().get_all_bans().into_iter()
                    .filter(|b| b.expires_at.is_some_and(|exp| exp <= now))
                    .map(|b| b.subject).collect();
                let mut removed = 0;
                for subject in expired {
                    match st.remove_ban(&subject) {
                        Ok(true) => removed += 1,
                        Ok(false) => {},
                        Err(e) => error!(%subject, "Failed to persist ban expiry: {e}"),
                    }
                }
                let desired: Vec<_> = st.ban_store().get_all_bans().into_iter()
                    .filter(|b| !st.whitelist().overlaps(&b.subject))
                    .filter(|b| b.expires_at.is_none_or(|exp| exp > now))
                    .map(|b| b.subject).collect();
                let enforce_start = std::time::Instant::now();
                // Always sync, including no expiry and an empty desired set:
                // this repairs failed apply/remove and external firewall drift.
                if let Err(e) = enforcer.lock().await.sync_full(&desired).await {
                    error!("Firewall reconciliation failed; retrying on next tick: {e}");
                }
                if let Some(ref m) = metrics {
                    m.bans_expired_total.inc_by(removed);
                    m.active_bans.set(desired.len() as i64);
                    m.enforcement_duration_seconds
                        .get_or_create(&OperationLabels { operation: "sync".to_string() })
                        .observe(enforce_start.elapsed().as_secs_f64());
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
    async fn spoofed_allowed_bot_still_triggers_http_flood() {
        use hiveguard_core::bot_registry::BotRule;
        use hiveguard_core::detectors::HttpFloodDetector;
        let dir = tempfile::TempDir::new().unwrap();
        let state = Arc::new(Mutex::new(StateManager::new(dir.path(), WalSyncMode::None).unwrap()));
        let enforcer: Arc<Mutex<Box<dyn Enforcer>>> = Arc::new(Mutex::new(Box::new(ObserveOnlyEnforcer::new())));
        let (tx, rx) = mpsc::channel(10);
        let registry = BotRegistry::new(vec![BotRule {
            name: "Googlebot".into(), ua_contains: "Googlebot".into(), org: "test".into(), policy: BotPolicy::Allow,
        }]);
        let detector = HttpFloodDetector::with_config(Duration::from_secs(60), 3, 0, Duration::from_secs(60), vec![]);
        let mut pipeline = Pipeline::new(rx, vec![Box::new(detector)], default_scoring().await, state.clone(), enforcer)
            .with_bot_registry(Arc::new(Mutex::new(registry)));
        let ip = "11.22.33.44".parse().unwrap();
        for _ in 0..3 {
            tx.send(NormalizedEvent { timestamp: Utc::now(), source_ip: ip,
                event_type: EventType::HttpRequest, source_name: "nginx".into(), raw_line: "GET /".into(),
                metadata: HashMap::from([("user_agent".into(), "attacker Googlebot".into()), ("path".into(), "/".into())]),
            }).await.unwrap();
        }
        drop(tx);
        pipeline.run().await;
        assert!(state.lock().await.ban_store().is_banned(&ip).is_some());
    }

    fn ua_event(ip: IpAddr, ua: &str) -> NormalizedEvent {
        NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: ip,
            event_type: EventType::HttpRequest,
            source_name: "nginx".into(),
            raw_line: "GET /".into(),
            metadata: HashMap::from([
                ("user_agent".into(), ua.into()),
                ("path".into(), "/".into()),
                ("method".into(), "GET".into()),
            ]),
        }
    }

    /// `bots: [{policy: block}]` used to only log; it now bans (short) via
    /// the normal signal path. Whitelisted sources and `allow` rules never
    /// ban, and a burst from one client yields a single signal.
    #[tokio::test]
    async fn bot_policy_block_bans_except_whitelisted_and_allow() {
        use hiveguard_core::bot_registry::BotRule;
        let dir = tempfile::TempDir::new().unwrap();
        let state = Arc::new(Mutex::new(StateManager::new(dir.path(), WalSyncMode::None).unwrap()));
        let whitelisted: IpAddr = "100.64.10.2".parse().unwrap();
        state.lock().await.add_whitelist(ipnet::IpNet::from(whitelisted)).unwrap();
        let enforcer: Arc<Mutex<Box<dyn Enforcer>>> = Arc::new(Mutex::new(Box::new(ObserveOnlyEnforcer::new())));
        let (tx, rx) = mpsc::channel(32);
        let registry = BotRegistry::new(vec![
            BotRule { name: "BadScraper".into(), ua_contains: "badscraper".into(), org: String::new(), policy: BotPolicy::Block },
            BotRule { name: "Googlebot".into(), ua_contains: "Googlebot".into(), org: String::new(), policy: BotPolicy::Allow },
        ])
        .with_block_ban_durations([("BadScraper".to_string(), Duration::from_secs(1800))]);
        let mut pipeline = Pipeline::new(rx, vec![], default_scoring().await, state.clone(), enforcer)
            .with_bot_registry(Arc::new(Mutex::new(registry)));

        let blocked: IpAddr = "100.64.10.1".parse().unwrap();
        let google: IpAddr = "100.64.10.3".parse().unwrap();
        for _ in 0..5 {
            tx.send(ua_event(blocked, "BadScraper/3.0")).await.unwrap();
        }
        tx.send(ua_event(whitelisted, "BadScraper/3.0")).await.unwrap();
        tx.send(ua_event(google, "Mozilla/5.0 (compatible; Googlebot/2.1)")).await.unwrap();
        drop(tx);
        pipeline.run().await;

        let st = state.lock().await;
        let ban = st.ban_store().is_banned(&blocked).expect("block policy bans");
        assert_eq!(ban.source, hiveguard_core::models::BanSource::LocalDetector("bot_policy".into()));
        let ttl = ban.expires_at.expect("temporary") - ban.created_at;
        assert!(ttl.num_seconds() > 1700 && ttl.num_seconds() <= 1800, "rule duration used: {ttl}");
        assert!(st.ban_store().is_banned(&whitelisted).is_none(), "whitelist protects");
        assert!(st.ban_store().is_banned(&google).is_none(), "allow never bans");
        assert_eq!(pipeline.bot_signal_last.len(), 2, "rate-limited per source");
    }

    /// Subnet signals (login brute force from a UA-rotating /24) must ban the
    /// whole /24 end to end — regression guard for the July /24 → /32 bug.
    #[tokio::test]
    async fn login_bruteforce_subnet_signal_bans_whole_subnet() {
        use hiveguard_core::detectors::HttpLoginBruteforceDetector;
        let dir = tempfile::TempDir::new().unwrap();
        let state = Arc::new(Mutex::new(StateManager::new(dir.path(), WalSyncMode::None).unwrap()));
        let enforcer: Arc<Mutex<Box<dyn Enforcer>>> = Arc::new(Mutex::new(Box::new(ObserveOnlyEnforcer::new())));
        let (tx, rx) = mpsc::channel(64);
        let detector = HttpLoginBruteforceDetector::with_config(
            vec!["/wp-login.php".into()],
            5,
            Duration::from_secs(600),
            Duration::from_secs(3600),
        )
        .with_subnet_aggregation(24, 0, 10, 5);
        let mut pipeline = Pipeline::new(rx, vec![Box::new(detector)], default_scoring().await, state.clone(), enforcer);
        for i in 1..=10u8 {
            let mut ev = ua_event(format!("100.64.53.{i}").parse().unwrap(), &format!("UA-{i}"));
            ev.metadata.insert("method".into(), "POST".into());
            ev.metadata.insert("path".into(), "/wp-login.php".into());
            tx.send(ev).await.unwrap();
        }
        drop(tx);
        pipeline.run().await;
        let st = state.lock().await;
        let other_member: IpAddr = "100.64.53.200".parse().unwrap();
        let ban = st.ban_store().is_banned(&other_member).expect("whole /24 banned");
        assert_eq!(ban.subject.to_string(), "100.64.53.0/24");
    }

    /// Multi-signal detectors (detector.campaign): one event can ban other
    /// IPs (retro bans of earlier participants); whitelisted participants are
    /// still protected and bans stay host-scoped (/32).
    #[tokio::test]
    async fn campaign_retro_signals_ban_other_participants_except_whitelisted() {
        use hiveguard_core::detectors::{CampaignConfig, CampaignDetector};
        let dir = tempfile::TempDir::new().unwrap();
        let state = Arc::new(Mutex::new(StateManager::new(dir.path(), WalSyncMode::None).unwrap()));
        let whitelisted: IpAddr = "209.50.164.3".parse().unwrap();
        state.lock().await.add_whitelist(ipnet::IpNet::from(whitelisted)).unwrap();
        let enforcer: Arc<Mutex<Box<dyn Enforcer>>> = Arc::new(Mutex::new(Box::new(ObserveOnlyEnforcer::new())));
        let (tx, rx) = mpsc::channel(100);
        let detector = CampaignDetector::with_config(CampaignConfig {
            min_distinct_ips: 10,
            min_requests: 10,
            ..Default::default()
        });
        let mut pipeline = Pipeline::new(rx, vec![Box::new(detector)], default_scoring().await, state.clone(), enforcer);
        let ips: Vec<IpAddr> = (0..12u8).map(|i| format!("209.50.164.{}", i + 1).parse().unwrap()).collect();
        for ip in &ips {
            tx.send(NormalizedEvent {
                timestamp: Utc::now(),
                source_ip: *ip,
                event_type: EventType::HttpRequest,
                source_name: "nginx".into(),
                raw_line: String::new(),
                metadata: HashMap::from([
                    ("method".into(), "POST".into()),
                    ("path".into(), "/wp-login.php".into()),
                    ("status_code".into(), "200".into()),
                    ("user_agent".into(), "Goosee-Audit/1.0 (+internal-security-audit)".into()),
                ]),
            })
            .await
            .unwrap();
        }
        drop(tx);
        pipeline.run().await;
        let st = state.lock().await;
        for ip in &ips {
            let banned = st.ban_store().is_banned(ip).is_some();
            assert_eq!(banned, *ip != whitelisted, "{ip}");
        }
        assert!(st.ban_store().get_all_bans().iter().all(|b| b.subject.prefix_len() == 32));
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

    /// Counts `apply_ban` calls; one per subject is the invariant under test.
    #[derive(Default)]
    struct CountingEnforcer {
        applied: Arc<std::sync::Mutex<Vec<ipnet::IpNet>>>,
    }

    #[async_trait::async_trait]
    impl Enforcer for CountingEnforcer {
        async fn apply_ban(&mut self, subject: &ipnet::IpNet) -> Result<(), hiveguard_core::errors::HiveGuardError> {
            self.applied.lock().unwrap().push(*subject);
            Ok(())
        }
        async fn remove_ban(&mut self, _: &ipnet::IpNet) -> Result<(), hiveguard_core::errors::HiveGuardError> {
            Ok(())
        }
        async fn sync_full(&mut self, _: &[ipnet::IpNet]) -> Result<(), hiveguard_core::errors::HiveGuardError> {
            Ok(())
        }
        async fn get_current_bans(&self) -> Result<Vec<ipnet::IpNet>, hiveguard_core::errors::HiveGuardError> {
            Ok(self.applied.lock().unwrap().clone())
        }
    }

    fn probe_event(ip: IpAddr, path: &str) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("path".to_string(), path.to_string());
        metadata.insert("method".to_string(), "GET".to_string());
        metadata.insert("user_agent".to_string(), "scanner/1.0".to_string());
        metadata.insert("status_code".to_string(), "404".to_string());
        NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: ip,
            event_type: EventType::Http4xx,
            source_name: "nginx".to_string(),
            raw_line: format!("GET {path} HTTP/1.1"),
            metadata,
        }
    }

    /// Reproduces node-d 2026-09-10 16:10:30: a scanner's 23 probe
    /// requests reached the pipeline in one log chunk. Each one alone crosses
    /// the threshold (path_probe 200 > 100), so each produced a fresh
    /// "Ban issued" and an nft `add element` — 23 bans for one address.
    #[tokio::test]
    async fn pipeline_burst_from_one_ip_issues_one_ban() {
        use hiveguard_core::detectors::PathProbeDetector;

        let dir = tempfile::TempDir::new().unwrap();
        let state = Arc::new(Mutex::new(
            StateManager::new(dir.path(), WalSyncMode::None).unwrap(),
        ));
        let counting = CountingEnforcer::default();
        let applied = Arc::clone(&counting.applied);
        let enforcer: Arc<Mutex<Box<dyn Enforcer>>> = Arc::new(Mutex::new(Box::new(counting)));

        let (tx, rx) = mpsc::channel(100);
        let detectors: Vec<Box<dyn Detector>> = vec![Box::new(PathProbeDetector::new())];
        let scoring = default_scoring().await;
        let mut pipeline = Pipeline::new(rx, detectors, scoring, state.clone(), enforcer.clone());

        let ip: IpAddr = "94.154.46.246".parse().unwrap();
        for path in ["/.git/config", "/.env", "/wp-login.php", "/.env", "/phpmyadmin"]
            .iter()
            .cycle()
            .take(23)
        {
            tx.send(probe_event(ip, path)).await.unwrap();
        }
        drop(tx);
        pipeline.run().await;

        let applied = applied.lock().unwrap().clone();
        assert_eq!(
            applied,
            vec!["94.154.46.246/32".parse::<ipnet::IpNet>().unwrap()],
            "one burst must yield exactly one enforcer ban"
        );
        let st = state.lock().await;
        assert_eq!(st.ban_store().get_all_bans().len(), 1);
    }

    /// A ban issued through another path (socket `ban`, REST, cluster) while
    /// signals keep arriving must not be duplicated by the pipeline either.
    #[tokio::test]
    async fn pipeline_skips_subject_banned_elsewhere() {
        use hiveguard_core::detectors::PathProbeDetector;
        use hiveguard_core::models::{BanRecord, BanSource};

        let dir = tempfile::TempDir::new().unwrap();
        let state = Arc::new(Mutex::new(
            StateManager::new(dir.path(), WalSyncMode::None).unwrap(),
        ));
        state
            .lock()
            .await
            .add_ban(BanRecord {
                subject: "35.205.92.0/24".parse().unwrap(),
                created_at: Utc::now(),
                expires_at: Some(Utc::now() + chrono::Duration::days(30)),
                severity: 200,
                reason: "manual".into(),
                evidence_hash: [0u8; 32],
                source: BanSource::ManualAdmin,
                geo_info: None,
            })
            .unwrap();
        let counting = CountingEnforcer::default();
        let applied = Arc::clone(&counting.applied);
        let enforcer: Arc<Mutex<Box<dyn Enforcer>>> = Arc::new(Mutex::new(Box::new(counting)));

        let (tx, rx) = mpsc::channel(100);
        let detectors: Vec<Box<dyn Detector>> = vec![Box::new(PathProbeDetector::new())];
        let mut pipeline =
            Pipeline::new(rx, detectors, default_scoring().await, state.clone(), enforcer.clone());

        let ip: IpAddr = "35.205.92.82".parse().unwrap();
        tx.send(probe_event(ip, "/.env")).await.unwrap();
        tx.send(probe_event(ip, "/.git/config")).await.unwrap();
        drop(tx);
        pipeline.run().await;

        assert!(applied.lock().unwrap().is_empty(), "covered by the /24 ban");
        assert_eq!(state.lock().await.ban_store().get_all_bans().len(), 1);
    }
}
