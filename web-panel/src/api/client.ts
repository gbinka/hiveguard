import type {
  BanInfo,
  BanListResponse,
  BotStats,
  ConfigContentResponse,
  DetectorsConfig,
  Fail2banBanInfo,
  Fail2banImportResponse,
  Fail2banPreviewResponse,
  MessageResponse,
  PeersResponse,
  Stats,
  WhitelistResponse,
} from './types'

// ---------------------------------------------------------------------------
// Auth token management
// ---------------------------------------------------------------------------

const TOKEN_KEY = 'hg-token'

export function getToken(): string {
  return localStorage.getItem(TOKEN_KEY) ?? ''
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token)
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY)
}

// ---------------------------------------------------------------------------
// Core fetch wrapper
// ---------------------------------------------------------------------------

type Method = 'GET' | 'POST' | 'DELETE' | 'PUT'

export class ApiUnauthorizedError extends Error {
  constructor() {
    super('Unauthorized')
    this.name = 'ApiUnauthorizedError'
  }
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

async function request<T>(
  path: string,
  method: Method = 'GET',
  body?: unknown,
): Promise<T> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }

  const resp = await fetch(path, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })

  if (resp.status === 401) {
    throw new ApiUnauthorizedError()
  }

  if (!resp.ok) {
    const data = await resp.json().catch(() => ({}))
    throw new ApiError(resp.status, (data as { error?: string }).error ?? `HTTP ${resp.status}`)
  }

  // 204 No Content
  if (resp.status === 204) return undefined as T

  return resp.json() as Promise<T>
}

// ---------------------------------------------------------------------------
// Typed API functions
// ---------------------------------------------------------------------------

export const api = {
  // Stats
  getStats: (): Promise<Stats> => request('/api/stats'),

  // Bans — the consolidated `ui.rest` surface returns a flat array
  // (`GET /api/bans` → `BanInfo[]`); the daemon does not paginate server-side,
  // so we wrap + slice client-side to keep the paginated UI contract.
  getBans: async (page = 1, limit = 50): Promise<BanListResponse> => {
    const all = await request<BanInfo[]>('/api/bans')
    const total = all.length
    const start = (page - 1) * limit
    const bans = all.slice(start, start + limit)
    return { bans, total, page, limit }
  },

  createBan: async (
    ip: string,
    duration = '24h',
    reason = 'manual admin ban',
  ): Promise<MessageResponse> => {
    const match = /^(\d+)([smhd])$/.exec(duration)
    const units: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 }
    const secs = match ? Number(match[1]) * units[match[2]] : NaN
    if (!Number.isSafeInteger(secs) || secs <= 0) {
      throw new Error('Duration must be a positive number followed by s, m, h or d')
    }
    const subject = ip.includes('/') ? ip : `${ip}/${ip.includes(':') ? 128 : 32}`
    return request('/api/bans', 'POST', { subject, duration: { secs, nanos: 0 }, reason })
  },

  deleteBan: (ip: string): Promise<MessageResponse> =>
    request(`/api/bans/${encodeURIComponent(ip)}`, 'DELETE'),

  // Whitelist
  getWhitelist: (): Promise<WhitelistResponse> => request('/api/whitelist'),

  addWhitelist: (cidr: string): Promise<MessageResponse> =>
    request('/api/whitelist', 'POST', { cidr }),

  removeWhitelist: (cidr: string): Promise<MessageResponse> =>
    request(`/api/whitelist/${encodeURIComponent(cidr)}`, 'DELETE'),

  // Bots
  getBots: (): Promise<{ bots: BotStats[] }> => request('/api/bots'),

  setBotPolicy: (
    name: string,
    policy: string,
  ): Promise<MessageResponse> =>
    request(`/api/bots/${encodeURIComponent(name)}/policy`, 'POST', { policy }),

  // Peers / Cluster
  getPeers: (): Promise<PeersResponse> => request('/api/peers'),

  // Config
  getConfig: (): Promise<ConfigContentResponse> => request('/api/config'),

  saveConfig: (content: string): Promise<MessageResponse> =>
    request('/api/config', 'PUT', { content }),

  getDetectors: (): Promise<DetectorsConfig> => request('/api/config/detectors'),

  saveDetectors: (detectors: DetectorsConfig): Promise<MessageResponse> =>
    request('/api/config/detectors', 'PUT', detectors),

  // Fail2ban
  fail2banPreview: (db?: string, jail?: string): Promise<Fail2banPreviewResponse> => {
    const params = new URLSearchParams()
    if (db) params.set('db', db)
    if (jail) params.set('jail', jail)
    const qs = params.toString()
    return request(`/api/fail2ban/preview${qs ? `?${qs}` : ''}`)
  },

  fail2banImport: (db?: string, jail?: string): Promise<Fail2banImportResponse> =>
    request('/api/fail2ban/import', 'POST', { db, jail }),
}

// ---------------------------------------------------------------------------
// Probe – used on startup to detect if auth is required
// ---------------------------------------------------------------------------

/** Returns true if the request succeeds (server is reachable and auth is OK). */
export async function probe(): Promise<{ ok: boolean; needsAuth: boolean }> {
  const token = getToken()
  const headers: Record<string, string> = {}
  if (token) headers['Authorization'] = `Bearer ${token}`

  try {
    const resp = await fetch('/api/stats', { headers })
    if (resp.ok) return { ok: true, needsAuth: false }
    if (resp.status === 401) return { ok: false, needsAuth: true }
    return { ok: false, needsAuth: false }
  } catch {
    return { ok: false, needsAuth: false }
  }
}
