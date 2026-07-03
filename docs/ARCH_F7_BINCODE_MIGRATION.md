# F-7: Migracja z `bincode 1` na `postcard`

## Problem

Crate `bincode 1.3.3` jest oznaczony jako **unmaintained** (RUSTSEC-2025-0141). Nie będzie otrzymywał łatek bezpieczeństwa. Znane problemy obejmują panicking deserializację na malformed input w starszych wersjach — krytyczne, ponieważ bincode deserializuje dane z:

1. **WAL (Write-Ahead Log)** — odtwarzanie stanu po crashu
2. **Snapshot-y** — pełny obraz stanu (backup/restore)
3. **Fuzzing ClusterMessage** — symulacja wire protocol

**CVSS 3.1: 5.3** (AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L)

---

## Dlaczego `postcard` zamiast `bincode 2`

| Kryterium | postcard | bincode 2 |
|-----------|----------|-----------|
| Rozmiar output | Najkompaktniejszy (varint encoding) | Kompaktowy |
| `no_std` support | ✅ natywny | ✅ |
| Aktywne utrzymanie | ✅ (James Munns, embedded community) | ✅ |
| Stabilność formatu | ✅ specyfikacja formatu | Brak gwarancji stabilności |
| Bezpieczeństwo deserializacji | ✅ bounded, nie panikuje | ✅ |
| API ergonomia | `to_allocvec()` / `from_bytes()` | Konfigurowalny, bardziej rozbudowany |
| Embedded adoption | Dominujący w embedded Rust | Mniej popularny |
| Migracja z bincode 1 | Wymaga konwersji formatu | Wymaga konwersji formatu |

**Wybór: `postcard`** — prosty, bezpieczny, stabilny format, minimalny rozmiar.

---

## Stan aktualny

### Zależność
```toml
# hiveguard-core/Cargo.toml
bincode = "1"

# fuzz/Cargo.toml
bincode = "1.3"
```

### Format WAL (`wal.rs`)

Struktura rekordu WAL na dysku:
```
[4 bajty: length u32 LE] [payload: bincode(WalEntry)] [4 bajty: CRC32 LE]
```

```rust
pub enum WalEntry {
    AddBan(BanRecord),
    RemoveBan(String),
    AddWhitelist(IpNet),
    RemoveWhitelist(IpNet),
    AddCrdtBan(CrdtBanRecord),
    TombstoneCrdtBan { subject: IpNet, node_id: String },
}
```

Serializacja (`WalWriter::append`):
```rust
let payload = bincode::serialize(entry)?;       // linia 77
// + length prefix + CRC32
```

Deserializacja (`WalReader::replay`):
```rust
let entry: WalEntry = bincode::deserialize(&payload)?;  // linia 200
```

### Format snapshot (`snapshot.rs`)

Struktura pliku:
```
[8 bajtów: magic "HVGD0002"] [reszta: bincode(SnapshotDataV2)]
```

```rust
pub struct SnapshotDataV2 {
    pub bans: Vec<BanRecord>,
    pub whitelist: Vec<IpNet>,
    pub crdt_bans: Vec<CrdtBanRecord>,
}
```

Serializacja (`save_snapshot_v2`):
```rust
let encoded = bincode::serialize(&data)?;       // linia 57
```

Deserializacja (`load_snapshot_v2`):
```rust
let data: SnapshotDataV2 = bincode::deserialize(&encoded)?;  // linia 106
// Fallback:
let data: SnapshotDataV1 = bincode::deserialize(&encoded)?;  // linia 114
```

### Fuzz targets
```rust
// fuzz_cluster_message.rs
bincode::deserialize::<ClusterMessage>(data)    // linia 10

// fuzz_wal_replay.rs i fuzz_snapshot_load.rs — testują pełne ścieżki replay/load
```

---

## Projektowane rozwiązanie

### Nowa zależność

```toml
# hiveguard-core/Cargo.toml
[dependencies]
# Usuń: bincode = "1"
postcard = { version = "1", features = ["alloc"] }

# fuzz/Cargo.toml
# Usuń: bincode = "1.3"
postcard = { version = "1", features = ["alloc"] }
```

### Mapowanie API

| bincode 1 | postcard 1 |
|-----------|------------|
| `bincode::serialize(&T) -> Result<Vec<u8>>` | `postcard::to_allocvec(&T) -> Result<Vec<u8>>` |
| `bincode::deserialize::<T>(&[u8]) -> Result<T>` | `postcard::from_bytes::<T>(&[u8]) -> Result<T>` |

### Zmiany w WAL (`wal.rs`)

```rust
// Przed:
let payload = bincode::serialize(entry)?;
// Po:
let payload = postcard::to_allocvec(entry)
    .map_err(|e| HiveGuardError::Storage(format!("WAL serialize error: {e}")))?;

// Przed:
let entry: WalEntry = bincode::deserialize(&payload)?;
// Po:
let entry: WalEntry = postcard::from_bytes(&payload)
    .map_err(|e| HiveGuardError::Storage(format!("WAL deserialize error: {e}")))?;
```

### Zmiany w snapshot (`snapshot.rs`)

```rust
// Nowy magic header dla postcard format
const SNAPSHOT_MAGIC_V3: &[u8; 8] = b"HVGD0003";

// Serializacja — zawsze v3 (postcard)
let encoded = postcard::to_allocvec(&data)
    .map_err(|e| HiveGuardError::Storage(format!("snapshot serialize: {e}")))?;

// Deserializacja — tryb z wsteczną kompatybilnością
match &magic {
    SNAPSHOT_MAGIC_V3 => {
        postcard::from_bytes::<SnapshotDataV2>(&encoded)?
    }
    SNAPSHOT_MAGIC_V2 => {
        // Legacy: użyj bincode do odczytu starych snapshotów
        bincode::deserialize::<SnapshotDataV2>(&encoded)?
    }
    SNAPSHOT_MAGIC_V1 => {
        bincode::deserialize::<SnapshotDataV1>(&encoded)?
    }
}
```

### Zmiany w fuzz targets

```rust
// fuzz_cluster_message.rs
postcard::from_bytes::<ClusterMessage>(data)
```

---

## Strategia migracji danych

### WAL

WAL jest **efemeryczny** — po snapshot jest kompaktowany (usuwany). Migracja:

1. Przy starcie daemon, replay istniejącego WAL **ze starym bincode**
2. Po replay, stwórz nowy snapshot (v3, postcard)
3. Skompaktuj (usuń) stary WAL
4. Nowe wpisy WAL zapisuj w postcard

Wymaga tymczasowego zachowania `bincode` jako zależności dev/migration.

### Snapshot

Użyj nowego magic header `HVGD0003` dla postcard format:

1. **Odczyt:** Obsługuj V1 (bincode), V2 (bincode) i V3 (postcard) na podstawie magic
2. **Zapis:** Zawsze V3 (postcard)
3. Po pierwszym uruchomieniu z nową wersją, stary snapshot V2 zostaje odczytany i zastąpiony nowym V3

### Przejściowy `Cargo.toml`

```toml
[dependencies]
postcard = { version = "1", features = ["alloc"] }
bincode = { version = "1", optional = true }

[features]
legacy-bincode = ["bincode"]  # do odczytu starych plików
```

Domyślnie `legacy-bincode` włączone. Po kilku wersjach i upewnieniu się, że wszyscy zmigrowali — usunięcie.

---

## Pliki do modyfikacji

| Plik | Zmiana |
|------|--------|
| `hiveguard-core/Cargo.toml` | `bincode = "1"` → `postcard`, opcjonalne `bincode` do legacy compat |
| `hiveguard-core/src/persistence/wal.rs` | `bincode::serialize/deserialize` → `postcard::to_allocvec/from_bytes` |
| `hiveguard-core/src/persistence/snapshot.rs` | Nowy magic V3, nowy format, backward compat reader |
| `fuzz/Cargo.toml` | `bincode` → `postcard` |
| `fuzz/fuzz_targets/fuzz_cluster_message.rs` | `bincode::deserialize` → `postcard::from_bytes` |
| `fuzz/fuzz_targets/fuzz_wal_replay.rs` | Aktualizacja do nowego formatu WAL |
| `fuzz/fuzz_targets/fuzz_snapshot_load.rs` | Aktualizacja do nowego magic V3 |

---

## Ryzyka i uwagi

| Ryzyko | Mitygacja |
|--------|-----------|
| **Niekompatybilny format binarny** — postcard i bincode mają kompletnie różne formaty wire | Magic header i versioning w snapshot; WAL kompaktowany po snapshot |
| **Rolling upgrade w klastrze** — node z postcard nie odczyta WAL z bincode | Każdy node migruje niezależnie (WAL jest per-node). Snapshot też per-node. |
| **Wire protocol** — jeśli ClusterMessage użyje postcard, wszystkie nody muszą być zaktualizowane jednocześnie | ClusterMessage aktualnie NIE używa bincode (testy JSON). Wire format to osobna decyzja. |
| **Utrata danych przy cofnięciu wersji** — nowy snapshot V3 nie będzie czytelny dla starej wersji | Backup snapshot przed upgrade (dokumentacja) |

---

## Wire format (ClusterMessage) — osobna decyzja

Aktualnie `ClusterMessage` ma `derive(Serialize, Deserialize)` ale w kodzie produkcyjnym nie ma jeszcze ustalonego wire format (fuzz target testuje bincode hipotetycznie). Przy okazji migracji warto ustalić:

| Opcja | Zalety | Wady |
|-------|--------|------|
| **postcard** | Spójność z WAL/snapshot, kompaktowy | Mniej samodokumentujący |
| **CBOR (ciborium)** | Standardowy, self-describing | Większy overhead |
| **MessagePack (rmp)** | Standardowy, kompaktowy | Dodatkowa zależność |

Rekomendacja: **postcard** dla spójności wewnętrznej + dodać version byte w nagłówku wiadomości.

---

## Testy

- Test: WAL roundtrip z postcard (write → read)
- Test: snapshot V3 roundtrip
- Test: backward compat — odczyt snapshot V2 (bincode) z nowym kodem
- Test: legacy WAL replay (bincode) → snapshot postcard
- Test: corrupted postcard input nie panikuje (covered by existing fuzz)
- Benchmark: porównanie rozmiaru i szybkości bincode vs postcard na typowym BanRecord/CrdtBanRecord
