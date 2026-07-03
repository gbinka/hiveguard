# F-5: Migracja z `prometheus` na `prometheus-client`

## Problem

Crate `prometheus 0.13.4` zależy od `protobuf 2.28.0`, który ma znane CVE **RUSTSEC-2024-0437** — crash przez niekontrolowaną rekurencję w deserializacji protobuf. Podatność dotyczy ścieżki `prometheus → protobuf`, nie jest bezpośrednio eksploatowalna przez sieć w typowym wdrożeniu (wymaga kontroli nad metrykami lub Prometheus scrape'em), ale stanowi ryzyko DoS.

**CVSS 3.1: 7.5** (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

Crate `prometheus-client` to oficjalna implementacja OpenMetrics (następca Prometheus text format), utrzymywana przez zespół Prometheus. Nie ma zależności od `protobuf`.

---

## Stan aktualny

### Zależność (`hiveguard-daemon/Cargo.toml`)
```toml
prometheus = "0.13"
```

### Typy metryk w użyciu (`metrics.rs`)

| Typ prometheus | Ile | Użycie |
|----------------|-----|--------|
| `IntGauge` | 4 | active_bans, whitelisted_count, peer_count, memory_usage_bytes |
| `IntCounterVec` | 3 | events_processed_total, bans_created_total, detection_signals_total |
| `IntCounter` | 1 | bans_expired_total |
| `HistogramVec` | 2 | event_processing_duration_seconds, enforcement_duration_seconds |
| `Registry` | 1 | Centralny rejestr |
| `TextEncoder` | 1 | Rendering metryk |

### Interfejs renderowania (`rest_api.rs`)
```rust
// Endpoint GET /metrics — poza auth middleware (celowo, dla Prometheus scraper)
async fn get_metrics(State(app_state): State<AppState>) -> impl IntoResponse {
    // ...
    let body = m.render();
    (StatusCode::OK, [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")], body)
}
```

### Miejsca aktualizacji metryk (`pipeline.rs`)
```rust
// Countery z labelami
m.events_processed_total.with_label_values(&[&source_name]).inc();
m.detection_signals_total.with_label_values(&[detector.name()]).inc();
m.bans_created_total.with_label_values(&[detector.name()]).inc();

// Prosty counter
m.bans_expired_total.inc();

// Gauge set
m.active_bans.set(count as i64);
m.whitelisted_count.set(count as i64);

// Histogram observe
m.event_processing_duration_seconds.with_label_values(&[&source_name]).observe(elapsed);
m.enforcement_duration_seconds.with_label_values(&["apply"]).observe(elapsed);
```

---

## Projektowane rozwiązanie

### Nowa zależność

```toml
# hiveguard-daemon/Cargo.toml
[dependencies]
# Usuń: prometheus = "0.13"
prometheus-client = "0.22"
```

### Mapowanie typów

| prometheus 0.13 | prometheus-client 0.22 |
|-----------------|------------------------|
| `Registry` | `Registry` |
| `IntGauge` | `Gauge<i64, AtomicI64>` |
| `IntCounter` | `Counter<u64, AtomicU64>` |
| `IntCounterVec` | `Family<Vec<(String, String)>, Counter>` |
| `HistogramVec` | `Family<Vec<(String, String)>, Histogram>` |
| `TextEncoder::encode()` | `prometheus_client::encoding::text::encode()` |

### Nowa struktura `Metrics` (`metrics.rs`)

```rust
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::Registry;

pub struct Metrics {
    pub registry: Registry,

    // Gauges
    pub active_bans: Gauge<i64, AtomicI64>,
    pub whitelisted_count: Gauge<i64, AtomicI64>,
    pub peer_count: Gauge<i64, AtomicI64>,
    pub memory_usage_bytes: Gauge<i64, AtomicI64>,

    // Counters
    pub events_processed_total: Family<Vec<(String, String)>, Counter>,
    pub bans_created_total: Family<Vec<(String, String)>, Counter>,
    pub bans_expired_total: Counter,
    pub detection_signals_total: Family<Vec<(String, String)>, Counter>,

    // Histograms
    pub event_processing_duration_seconds: Family<Vec<(String, String)>, Histogram>,
    pub enforcement_duration_seconds: Family<Vec<(String, String)>, Histogram>,
}
```

### Rejestracja metryk

```rust
impl Metrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();

        let active_bans = Gauge::<i64, AtomicI64>::default();
        registry.register("hiveguard_active_bans", "Number of currently active bans", active_bans.clone());

        let events_processed_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register("hiveguard_events_processed_total", "Total events processed", events_processed_total.clone());

        // ... analogicznie dla pozostałych metryk

        Self { registry, active_bans, events_processed_total, /* ... */ }
    }
}
```

### Zmiany w aktualizacji metryk (`pipeline.rs`)

```rust
// Przed (prometheus 0.13):
m.events_processed_total.with_label_values(&["ssh"]).inc();

// Po (prometheus-client 0.22):
m.events_processed_total
    .get_or_create(&vec![("source".to_string(), "ssh".to_string())])
    .inc();
```

```rust
// Histogram — observe
m.event_processing_duration_seconds
    .get_or_create(&vec![("source".to_string(), source_name.clone())])
    .observe(elapsed);
```

### Rendering (`metrics.rs` → `rest_api.rs`)

```rust
pub fn render(&self) -> String {
    let mut buffer = String::new();
    if let Err(e) = encode(&mut buffer, &self.registry) {
        error!("Failed to encode metrics: {e}");
        return "# error encoding metrics\n".to_string();
    }
    buffer
}
```

Content-Type zmienia się z `text/plain; version=0.0.4` na `application/openmetrics-text; version=1.0.0; charset=utf-8` (OpenMetrics). Prometheus ≥ 2.5 obsługuje oba formaty.

---

## Pliki do modyfikacji

| Plik | Zmiana |
|------|--------|
| `hiveguard-daemon/Cargo.toml` | `prometheus = "0.13"` → `prometheus-client = "0.22"` |
| `hiveguard-daemon/src/metrics.rs` | Przebudowa: nowe typy, rejestracja, render |
| `hiveguard-daemon/src/rest_api.rs` | Content-Type header |
| `hiveguard-daemon/src/pipeline.rs` | `.with_label_values()` → `.get_or_create()` |

---

## Kluczowe różnice API

| Operacja | prometheus 0.13 | prometheus-client 0.22 |
|----------|----------------|------------------------|
| Nowy counter z labels | `IntCounterVec::new(Opts::new(...), &["source"])` | `Family::<..., Counter>::default()` + register |
| Increment z labelami | `.with_label_values(&["ssh"]).inc()` | `.get_or_create(&vec![("source", "ssh")]).inc()` |
| Gauge set | `.set(42_i64)` | `.set(42_i64)` ← **identycznie** |
| Counter inc | `.inc()` | `.inc()` ← **identycznie** |
| Histogram observe | `.observe(0.5)` | `.observe(0.5)` ← **identycznie** |
| Render | `TextEncoder::encode(&families, &mut buf)` | `encode(&mut string, &registry)` |
| Rejestracja | `registry.register(Box::new(metric))` | `registry.register(name, help, metric)` |

### Custom buckets dla histogramów

```rust
// Jawna lista buckets (jak obecnie):
let buckets = vec![0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0];
let histogram = Histogram::new(buckets.into_iter());
```

---

## Migracja

1. Zmień zależność w `Cargo.toml`
2. Przepisz `Metrics::new()` — nowe typy i rejestracja
3. Zmień `Metrics::render()` — nowy encoder
4. Zaktualizuj `pipeline.rs` — nowy API label access
5. Zmień Content-Type w `rest_api.rs`
6. Uruchom testy — sprawdź format output

**Kompatybilność wsteczna:** Prometheus scraper obsługuje format OpenMetrics od wersji 2.5 (2019). Nie wymaga zmian w konfiguracji Prometheus.

---

## Testy

- Test: `Metrics::new()` nie panikuje
- Test: `render()` zwraca valid OpenMetrics text
- Test: counter increment i gauge set działają
- Test: histogram observe z custom buckets
- Test integracyjny: GET /metrics zwraca poprawne metryki
