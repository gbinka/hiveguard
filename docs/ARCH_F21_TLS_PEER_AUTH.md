# F-21: Kryptograficzna autentykacja peerów w protokole gossip

## Problem

`PermissiveCertVerifier` i `PermissiveServerVerifier` w `hiveguard-net/src/transport.rs` akceptują **dowolny** certyfikat TLS bez weryfikacji. Mutual TLS wymaga jedynie *posiadania* certyfikatu (po fixie F-22), ale nie sprawdza *jakiego*. Pole `sender_id: String` w `ClusterMessage` jest ustawiane przez nadawcę i może mieć dowolną wartość.

**Konsekwencje:**
- Atakujący z dowolnym self-signed certem może dołączyć do klastra
- MitM między nodami jest trywialny
- Impersonacja dowolnego node_id wymaga jedynie ustawienia stringa

**CVSS 3.1: 8.1** (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)

---

## Stan aktualny

### Generowanie tożsamości (`identity.rs`)
```rust
// NodeIdentity::generate() — Ed25519 keypair + self-signed X.509 cert
// Fingerprint = blake3::hash(public_key_raw()) → 64-char hex string
```
- Klucz zapisywany w `identity/node.key` (z fixem F-28: permissions 0o600)
- Certyfikat w `identity/node.crt`
- Fingerprint jest unikalnym identyfikatorem noda

### PeerInfo (`peer.rs`)
```rust
pub struct PeerInfo {
    pub node_id: String,
    pub address: SocketAddr,
    pub fingerprint: String,      // ← pole istnieje, ale nie jest weryfikowane
    pub trust_score: f64,
    pub state: PeerState,
    pub last_seen: DateTime<Utc>,
}
```

### ClusterMessage (`messages.rs`)
```rust
pub enum ClusterMessage {
    Ping { sender_id: String, digest: Vec<u8> },
    Pong { sender_id: String, digest: Vec<u8> },
    PingReq { sender_id: String, target_id: String },
    BanSync { records: Vec<BanRecord> },           // ← brak sender_id!
    DigestExchange { merkle_root: Vec<u8> },
    DiffRequest { missing_keys: Vec<String> },
    DiffResponse { records: Vec<BanRecord> },
    MembershipUpdate { peers: Vec<PeerInfo> },
}
```

### Konfiguracja seed peers (`config.example.yaml`)
```yaml
node:
  seeds:
    - "10.0.1.1:7946"
    - "10.0.1.2:7946"
  # brak pola fingerprint!
```

---

## Projektowane rozwiązanie

### Warstwa 1: Ekstrakcja fingerprint z TLS sesji

Po nawiązaniu połączenia QUIC, extract certyfikat peera i oblicz fingerprint:

```rust
// W transport.rs — nowa funkcja
pub fn extract_peer_fingerprint(conn: &quinn::Connection) -> Option<String> {
    let identity = conn.peer_identity()?;
    let certs = identity.downcast_ref::<Vec<CertificateDer>>()?;
    let end_entity = certs.first()?;
    // Wyciągnij klucz publiczny z DER, oblicz blake3
    let public_key = extract_public_key_from_der(end_entity)?;
    Some(hex::encode(blake3::hash(&public_key).as_bytes()))
}
```

### Warstwa 2: Rejestr dozwolonych fingerprint-ów

Dodaj `allowed_fingerprints` do konfiguracji — mapowanie fingerprint → node_id:

```yaml
node:
  seeds:
    - address: "10.0.1.1:7946"
      fingerprint: "a3f2c8...64hex..."
    - address: "10.0.1.2:7946"
      fingerprint: "b7e1d4...64hex..."
```

```rust
// W config.rs
pub struct SeedPeer {
    pub address: SocketAddr,
    pub fingerprint: String,
}

pub struct NodeConfig {
    pub seeds: Vec<SeedPeer>,
    // ...
}
```

### Warstwa 3: Walidacja na połączeniu

Rozszerz `PeerManager` o rejestr fingerprint-ów:

```rust
impl PeerManager {
    /// Zaakceptuj połączenie tylko jeśli fingerprint jest na allow-liście
    /// lub tryb open-cluster jest włączony (development).
    pub fn validate_peer_connection(
        &self,
        conn: &quinn::Connection,
        claimed_node_id: &str,
    ) -> Result<(), HiveGuardError> {
        let fp = extract_peer_fingerprint(conn)
            .ok_or(HiveGuardError::Protocol("no peer certificate"))?;

        match self.get_peer(claimed_node_id) {
            Some(known) if known.fingerprint == fp => Ok(()),
            Some(known) => Err(HiveGuardError::Protocol(format!(
                "fingerprint mismatch for {}: expected {}, got {}",
                claimed_node_id, known.fingerprint, fp
            ))),
            None if self.auto_accept_enabled() => {
                // Nowy peer — zarejestruj fingerprint
                self.register_new_peer(claimed_node_id, fp, conn.remote_address());
                Ok(())
            }
            None => Err(HiveGuardError::Protocol(
                "unknown peer, auto-accept disabled"
            )),
        }
    }
}
```

### Warstwa 4: Binding sender_id→fingerprint w każdej wiadomości

W pętli odbioru wiadomości z QUIC stream:

```rust
async fn handle_incoming_stream(conn: &quinn::Connection, stream: &mut RecvStream) {
    let peer_fp = extract_peer_fingerprint(conn).unwrap_or_default();
    let buf = read_bounded_message(stream).await?;
    let msg: ClusterMessage = deserialize(&buf)?;

    // Walidacja: sender_id w wiadomości musi zgadzać się z zarejestrowanym fingerprint
    if let Some(claimed_id) = msg.sender_id() {
        if !peer_manager.verify_sender(claimed_id, &peer_fp) {
            warn!("sender_id mismatch: {} claims to be {}", peer_fp, claimed_id);
            return;
        }
    }
    // ... przekaż do gossip engine
}
```

---

## Pliki do modyfikacji

| Plik | Zmiana |
|------|--------|
| `hiveguard-net/src/transport.rs` | Dodać `extract_peer_fingerprint()`, nowa publiczna funkcja |
| `hiveguard-net/src/peer.rs` | Rozszerzyć `PeerManager` o rejestr fingerprintów i `validate_peer_connection()` |
| `hiveguard-net/src/messages.rs` | Dodać `sender_id()` accessor do `ClusterMessage`, dodać sender_id do `BanSync` |
| `hiveguard-net/src/gossip.rs` | Integracja weryfikacji fingerprint w obsłudze wiadomości |
| `hiveguard-net/src/membership.rs` | Weryfikacja fingerprint w `handle_pong()` i `handle_ping()` |
| `hiveguard-core/src/config.rs` | Zmiana `seeds: Vec<String>` na `seeds: Vec<SeedPeer>` z polem `fingerprint` |
| `config.example.yaml` | Nowy format seed peers z fingerprintami |
| `hiveguard-net/src/identity.rs` | (opcjonalnie) Eksportować `extract_public_key_from_der()` |

---

## Tryby pracy

| Tryb | Opis | Przypadek użycia |
|------|------|------------------|
| **Strict** (domyślny!) | Tylko peery z `allowed_fingerprints` w configu | Produkcja |
| **Auto-accept** | Rejestruj nowych peerów automatycznie, loguj fingerprint | Development, szybki bootstrap |
| **Join token** (przyszłość) | Jednorazowy token zatwierdzający nowy node | Zarządzane klastry |

```yaml
cluster:
  mode: strict         # strict | auto-accept
  allowed_fingerprints:
    - node_id: "web-prod-01"
      fingerprint: "a3f2c8..."
    - node_id: "web-prod-02"
      fingerprint: "b7e1d4..."
```

---

## Migracja

1. **Wersja N** — Dodaj ekstrakcję i logowanie fingerprint-ów na INFO level przy każdym połączeniu. Brak enforcement. Zbieranie fingerprintów z logów.
2. **Wersja N+1** — Dodaj `cluster.mode: auto-accept` jako domyślny. Rejestruj fingerprinty w pamięci. Loguj WARN przy nieznanym peerze.
3. **Wersja N+2** — Zmień domyślny `cluster.mode` na `strict`. Wymagaj `allowed_fingerprints` w konfiguracji.

---

## Testy

- Test: połączenie z poprawnym fingerprint → akceptacja
- Test: połączenie z nieznanym fingerprint (strict mode) → odrzucenie
- Test: impersonacja — peer A wysyła sender_id peera B → odrzucenie
- Test: auto-accept — nowy peer → rejestracja fingerprint
- Test integracyjny: 3-node cluster z wzajemną weryfikacją fingerprint
- Proptest: losowe fingerprint pary → deterministyczna walidacja
