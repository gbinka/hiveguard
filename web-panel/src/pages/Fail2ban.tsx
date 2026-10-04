import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import {
  Download,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  Search,
  Filter,
  Upload,
  Info,
} from 'lucide-react'
import { api, ApiError } from '../api/client'
import type { Fail2banBanInfo, Fail2banPreviewResponse } from '../api/types'

const DEFAULT_DB = '/var/lib/fail2ban/fail2ban.sqlite3'

function ExpiresCell({ ts }: { ts: string | null }) {
  if (!ts) return <span className="text-orange-400 text-xs font-medium">Permanent</span>
  const d = new Date(ts)
  const now = Date.now()
  const diff = d.getTime() - now
  const color = diff < 3600_000 ? 'text-yellow-400' : 'text-gray-400'
  return (
    <span className={`text-xs ${color}`} title={d.toISOString()}>
      {d.toLocaleString()}
    </span>
  )
}

export default function Fail2ban() {
  const [db, setDb] = useState(DEFAULT_DB)
  const [jailFilter, setJailFilter] = useState('')
  const [preview, setPreview] = useState<Fail2banPreviewResponse | null>(null)

  // Preview mutation
  const previewMut = useMutation({
    mutationFn: () =>
      api.fail2banPreview(
        db || undefined,
        jailFilter.trim() || undefined,
      ),
    onSuccess: data => setPreview(data),
  })

  // Import mutation
  const importMut = useMutation({
    mutationFn: () =>
      api.fail2banImport(
        db || undefined,
        jailFilter.trim() || undefined,
      ),
  })

  // Unique jail names from preview
  const jails = preview
    ? Array.from(new Set(preview.bans.map(b => b.jail))).sort()
    : []

  const filteredBans: Fail2banBanInfo[] = preview
    ? jailFilter
      ? preview.bans.filter(b => b.jail === jailFilter)
      : preview.bans
    : []

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-lg font-semibold text-gray-100">Fail2ban Import</h1>
        <p className="text-xs text-gray-500 mt-0.5">
          Import active bans from a fail2ban SQLite database into HiveGuard
        </p>
      </div>

      {/* Info */}
      <div className="flex items-start gap-2 p-3 rounded-lg bg-blue-900/20 border border-blue-700/30 text-blue-300 text-xs">
        <Info size={14} className="shrink-0 mt-0.5" />
        <span>
          Preview loads the current active bans without importing. Import adds them to HiveGuard's
          ban store and enforces them via nftables. Already-banned IPs are skipped automatically.
          Requires <code className="font-mono bg-blue-900/30 px-1 rounded">sqlite3</code> CLI
          installed on the server.
        </span>
      </div>

      {/* Controls */}
      <div className="card p-4 space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <label className="flex flex-col gap-1.5">
            <span className="text-xs text-gray-400 uppercase tracking-wider">
              Fail2ban database path
            </span>
            <input
              type="text"
              value={db}
              onChange={e => setDb(e.target.value)}
              className="input text-sm font-mono"
              placeholder={DEFAULT_DB}
            />
          </label>
          <label className="flex flex-col gap-1.5">
            <span className="text-xs text-gray-400 uppercase tracking-wider flex items-center gap-1">
              <Filter size={11} /> Jail filter (optional)
            </span>
            {jails.length > 0 ? (
              <select
                value={jailFilter}
                onChange={e => setJailFilter(e.target.value)}
                className="input text-sm"
              >
                <option value="">All jails</option>
                {jails.map(j => (
                  <option key={j} value={j}>{j}</option>
                ))}
              </select>
            ) : (
              <input
                type="text"
                value={jailFilter}
                onChange={e => setJailFilter(e.target.value)}
                className="input text-sm font-mono"
                placeholder="sshd, nginx-http-auth, …"
              />
            )}
          </label>
        </div>

        <div className="flex gap-3">
          <button
            onClick={() => previewMut.mutate()}
            disabled={previewMut.isPending}
            className="btn-secondary text-sm px-4 py-2 flex items-center gap-2"
          >
            {previewMut.isPending
              ? <RefreshCw size={14} className="animate-spin" />
              : <Search size={14} />}
            Preview
          </button>
          <button
            onClick={() => importMut.mutate()}
            disabled={importMut.isPending || !preview || filteredBans.length === 0}
            className="btn-primary text-sm px-4 py-2 flex items-center gap-2 disabled:opacity-40"
          >
            {importMut.isPending
              ? <RefreshCw size={14} className="animate-spin" />
              : <Upload size={14} />}
            Import {filteredBans.length > 0 ? `(${filteredBans.length})` : ''}
          </button>
        </div>
      </div>

      {/* Errors */}
      {previewMut.isError && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-red-900/20 border border-red-700/40 text-red-300 text-sm">
          <AlertTriangle size={15} />
          {previewMut.error instanceof ApiError
            ? previewMut.error.message
            : 'Preview failed'}
        </div>
      )}

      {/* Import result */}
      {importMut.data && (
        <div className="card p-4 space-y-3">
          <div className="flex items-center gap-2 text-green-400 font-semibold text-sm">
            <CheckCircle size={16} />
            Import complete
          </div>
          <div className="grid grid-cols-3 gap-3 text-center">
            <div className="bg-green-900/20 rounded-lg p-3">
              <div className="text-2xl font-bold text-green-300">{importMut.data.imported}</div>
              <div className="text-xs text-gray-400 mt-0.5">Imported</div>
            </div>
            <div className="bg-gray-800/40 rounded-lg p-3">
              <div className="text-2xl font-bold text-gray-300">{importMut.data.skipped}</div>
              <div className="text-xs text-gray-400 mt-0.5">Skipped</div>
            </div>
            <div className={`rounded-lg p-3 ${importMut.data.errors.length > 0 ? 'bg-red-900/20' : 'bg-gray-800/40'}`}>
              <div className={`text-2xl font-bold ${importMut.data.errors.length > 0 ? 'text-red-300' : 'text-gray-300'}`}>
                {importMut.data.errors.length}
              </div>
              <div className="text-xs text-gray-400 mt-0.5">Errors</div>
            </div>
          </div>
          {importMut.data.errors.length > 0 && (
            <div className="bg-red-900/10 border border-red-700/30 rounded p-3">
              <div className="text-xs font-medium text-red-400 mb-2">Errors:</div>
              <ul className="space-y-0.5">
                {importMut.data.errors.map((e, i) => (
                  <li key={i} className="text-xs text-red-300 font-mono">{e}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Preview table */}
      {preview && (
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-sm text-gray-400">
            <Download size={14} />
            <span>
              {filteredBans.length} active ban{filteredBans.length !== 1 ? 's' : ''}
              {jailFilter ? ` in jail "${jailFilter}"` : ' across all jails'}
            </span>
          </div>

          {filteredBans.length === 0 ? (
            <div className="card p-8 text-center text-gray-500 text-sm">
              No active bans found{jailFilter ? ` for jail "${jailFilter}"` : ''}.
            </div>
          ) : (
            <div className="card overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-700/50">
                      <th className="text-left px-4 py-3 text-xs font-medium text-gray-400 uppercase tracking-wider">IP</th>
                      <th className="text-left px-4 py-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Jail</th>
                      <th className="text-left px-4 py-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Banned At</th>
                      <th className="text-left px-4 py-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Expires</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-700/30">
                    {filteredBans.map((ban, i) => (
                      <tr key={i} className="hover:bg-gray-700/20 transition-colors">
                        <td className="px-4 py-3 font-mono text-xs text-gray-200">{ban.ip}</td>
                        <td className="px-4 py-3">
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-purple-900/40 text-purple-300">
                            {ban.jail}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs text-gray-400">
                          {new Date(ban.banned_at).toLocaleString()}
                        </td>
                        <td className="px-4 py-3">
                          <ExpiresCell ts={ban.expires_at} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
