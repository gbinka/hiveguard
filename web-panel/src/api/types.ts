// ---------------------------------------------------------------------------
// API response types – must mirror hiveguard-daemon's Rust structs
// ---------------------------------------------------------------------------

export interface Stats {
  uptime_secs: number;
  total_bans: number;
  total_whitelisted: number;
  version: string;
}

export interface BanInfo {
  subject: string;
  /** Not provided by the consolidated `ui.rest` API; kept optional for the UI. */
  created_at?: string;
  expires_at: string | null;
  severity: number;
  reason: string;
  source: string;
}

export interface BanListResponse {
  bans: BanInfo[];
  total: number;
  page: number;
  limit: number;
}

export interface BotStats {
  name: string;
  org: string;
  policy: 'allow' | 'block' | 'monitor';
  request_count: number;
  last_seen_ip: string;
  last_seen_ua: string;
  known: boolean;
}

export interface PeerInfo {
  node_id: string;
  address: string;
  trust_score: number;
  state: string;
}

export interface PeersResponse {
  peers: PeerInfo[];
}

export interface WhitelistResponse {
  entries: string[];
}

export interface MessageResponse {
  message: string;
}

export interface ApiError {
  error: string;
}

// ---------------------------------------------------------------------------
// Config / detectors types
// ---------------------------------------------------------------------------

export interface DetectorBase {
  enabled: boolean;
  threshold?: number;
  window?: string;
  ban_duration?: string;
  paths?: string[];
}

export interface DetectorsConfig {
  ssh_bruteforce: DetectorBase;
  ssh_user_enum: DetectorBase;
  path_probe: DetectorBase;
  http_4xx_flood: DetectorBase;
  http_login_bruteforce: DetectorBase;
  scanner_fingerprint: DetectorBase;
  smtp_bruteforce: DetectorBase;
  port_scan: DetectorBase;
  distributed_slow: DetectorBase;
  honeypot: DetectorBase;
  entropy: DetectorBase;
  timing: DetectorBase;
}

export interface ConfigContentResponse {
  content: string;
}

// ---------------------------------------------------------------------------
// Fail2ban types
// ---------------------------------------------------------------------------

export interface Fail2banBanInfo {
  jail: string;
  ip: string;
  banned_at: string;
  expires_at: string | null;
}

export interface Fail2banPreviewResponse {
  bans: Fail2banBanInfo[];
  total: number;
}

export interface Fail2banImportResponse {
  imported: number;
  skipped: number;
  errors: string[];
}

// ---------------------------------------------------------------------------
// Frontend-only types
// ---------------------------------------------------------------------------

/** A single data point for the ban trend sparkline. */
export interface TrendPoint {
  /** Formatted HH:MM:SS for chart x-axis label */
  time: string;
  bans: number;
  whitelisted: number;
}
