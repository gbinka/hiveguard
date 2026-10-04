import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Save, RefreshCw, AlertTriangle, CheckCircle, ToggleLeft, ToggleRight } from 'lucide-react'
import { api, ApiError } from '../api/client'
import type { DetectorsConfig, DetectorBase } from '../api/types'

// Human-readable labels for each detector
const DETECTOR_META: Record<
  keyof DetectorsConfig,
  { label: string; desc: string; hasThreshold: boolean; hasWindow: boolean; hasPaths?: boolean }
> = {
  ssh_bruteforce:        { label: 'SSH Brute-force',         desc: 'Failed SSH login attempts',                hasThreshold: true,  hasWindow: true  },
  ssh_user_enum:         { label: 'SSH User Enumeration',    desc: 'Probing for valid usernames via SSH',      hasThreshold: true,  hasWindow: true  },
  path_probe:            { label: 'Path Probe',              desc: 'Scans for WP/PHPMyAdmin/etc.',             hasThreshold: false, hasWindow: false, hasPaths: true },
  http_4xx_flood:        { label: 'HTTP 4xx Flood',          desc: 'Excessive 4xx responses per IP',           hasThreshold: true,  hasWindow: true  },
  http_login_bruteforce: { label: 'HTTP Login Brute-force',  desc: 'POST flood on login paths',                hasThreshold: true,  hasWindow: true,  hasPaths: true },
  scanner_fingerprint:   { label: 'Scanner Fingerprint',     desc: 'Known scanner/exploit tool signatures',    hasThreshold: false, hasWindow: false },
  smtp_bruteforce:       { label: 'SMTP Brute-force',        desc: 'Postfix/Dovecot auth failures',            hasThreshold: true,  hasWindow: true  },
  port_scan:             { label: 'Port Scan',               desc: 'SYN/connection scan detection',            hasThreshold: true,  hasWindow: true  },
  distributed_slow:      { label: 'Distributed Slow Attack', desc: 'Coordinated slow-rate attacks',            hasThreshold: true,  hasWindow: true  },
  honeypot:              { label: 'Honeypot',                desc: 'Requests to decoy/trap URLs',              hasThreshold: false, hasWindow: false },
  entropy:               { label: 'Entropy Anomaly',         desc: 'Request entropy / randomness analysis',    hasThreshold: false, hasWindow: false },
  timing:                { label: 'Timing Anomaly',          desc: 'Request timing pattern analysis',          hasThreshold: false, hasWindow: false },
}

function DetectorCard({
  name,
  det,
  onChange,
}: {
  name: keyof DetectorsConfig
  det: DetectorBase
  onChange: (updated: DetectorBase) => void
}) {
  const meta = DETECTOR_META[name]

  return (
    <div
      className={`card p-4 transition-opacity ${det.enabled ? '' : 'opacity-60'}`}
    >
      {/* Header row */}
      <div className="flex items-start justify-between gap-3 mb-3">
        <div>
          <div className="text-sm font-semibold text-gray-100">{meta.label}</div>
          <div className="text-xs text-gray-500 mt-0.5">{meta.desc}</div>
        </div>
        <button
          onClick={() => onChange({ ...det, enabled: !det.enabled })}
          className={`shrink-0 transition-colors ${
            det.enabled ? 'text-blue-400 hover:text-blue-300' : 'text-gray-600 hover:text-gray-400'
          }`}
          title={det.enabled ? 'Disable' : 'Enable'}
        >
          {det.enabled
            ? <ToggleRight size={28} />
            : <ToggleLeft size={28} />}
        </button>
      </div>

      {/* Fields */}
      <div className="grid grid-cols-2 gap-2 text-xs">
        {meta.hasThreshold && (
          <label className="flex flex-col gap-1">
            <span className="text-gray-500 uppercase tracking-wider text-[10px]">Threshold</span>
            <input
              type="number"
              min={1}
              value={det.threshold ?? ''}
              onChange={e => onChange({ ...det, threshold: Number(e.target.value) || undefined })}
              className="input text-xs py-1"
              disabled={!det.enabled}
            />
          </label>
        )}
        {meta.hasWindow && (
          <label className="flex flex-col gap-1">
            <span className="text-gray-500 uppercase tracking-wider text-[10px]">Window</span>
            <input
              type="text"
              placeholder="5m"
              value={det.window ?? ''}
              onChange={e => onChange({ ...det, window: e.target.value })}
              className="input text-xs py-1"
              disabled={!det.enabled}
            />
          </label>
        )}
        {det.ban_duration !== undefined && (
          <label className="flex flex-col gap-1">
            <span className="text-gray-500 uppercase tracking-wider text-[10px]">Ban Duration</span>
            <input
              type="text"
              placeholder="24h"
              value={det.ban_duration ?? ''}
              onChange={e => onChange({ ...det, ban_duration: e.target.value })}
              className="input text-xs py-1"
              disabled={!det.enabled}
            />
          </label>
        )}
      </div>

      {/* Paths (editable list) */}
      {meta.hasPaths && det.paths !== undefined && (
        <div className="mt-3">
          <span className="text-gray-500 uppercase tracking-wider text-[10px]">Paths</span>
          <textarea
            rows={3}
            value={det.paths.join('\n')}
            onChange={e =>
              onChange({
                ...det,
                paths: e.target.value
                  .split('\n')
                  .map(s => s.trim())
                  .filter(Boolean),
              })
            }
            className="w-full mt-1 input text-xs font-mono py-1.5 resize-none"
            disabled={!det.enabled}
          />
        </div>
      )}
    </div>
  )
}

export default function Rules() {
  const qc = useQueryClient()
  const [draft, setDraft] = useState<DetectorsConfig | null>(null)
  const [saved, setSaved] = useState(false)

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['detectors'],
    queryFn: api.getDetectors,
    staleTime: 30_000,
  })

  // Sync draft when fresh data arrives (and user hasn't edited yet)
  useEffect(() => {
    if (data && draft === null) {
      setDraft(data)
    }
  }, [data, draft])

  const detectors = draft ?? data

  const mutation = useMutation({
    mutationFn: (d: DetectorsConfig) => api.saveDetectors(d),
    onSuccess: () => {
      setSaved(true)
      qc.invalidateQueries({ queryKey: ['detectors'] })
      qc.invalidateQueries({ queryKey: ['config'] })
      setTimeout(() => setSaved(false), 3000)
    },
  })

  const isDirty =
    draft !== null && JSON.stringify(draft) !== JSON.stringify(data)

  function handleChange(name: keyof DetectorsConfig, updated: DetectorBase) {
    setDraft(prev => (prev ? { ...prev, [name]: updated } : prev))
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-400">
        <RefreshCw size={20} className="animate-spin mr-2" />
        Loading rules…
      </div>
    )
  }

  if (isError || !detectors) {
    const msg = error instanceof ApiError ? error.message : 'Cannot load detectors'
    return (
      <div className="flex items-center gap-3 p-4 rounded-lg bg-red-900/20 border border-red-700/40 text-red-300">
        <AlertTriangle size={18} />
        {msg}
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-gray-100">Detector Rules</h1>
          <p className="text-xs text-gray-500 mt-0.5">
            Enable / disable detectors and tune thresholds. Restart daemon to apply.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {isDirty && (
            <span className="text-xs text-yellow-400 flex items-center gap-1">
              <AlertTriangle size={12} /> Unsaved changes
            </span>
          )}
          {saved && (
            <span className="text-xs text-green-400 flex items-center gap-1">
              <CheckCircle size={12} /> Saved
            </span>
          )}
          <button
            onClick={() => setDraft(data ?? null)}
            disabled={!isDirty}
            className="btn-secondary text-xs px-3 py-1.5 disabled:opacity-40"
          >
            Reset
          </button>
          <button
            onClick={() => detectors && mutation.mutate(detectors)}
            disabled={!isDirty || mutation.isPending}
            className="btn-primary text-xs px-3 py-1.5 flex items-center gap-1.5 disabled:opacity-40"
          >
            {mutation.isPending ? (
              <RefreshCw size={13} className="animate-spin" />
            ) : (
              <Save size={13} />
            )}
            Save Rules
          </button>
        </div>
      </div>

      {/* Error */}
      {mutation.isError && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-red-900/20 border border-red-700/40 text-red-300 text-sm">
          <AlertTriangle size={15} />
          {mutation.error instanceof ApiError
            ? mutation.error.message
            : 'Save failed'}
        </div>
      )}

      {/* Success message */}
      {mutation.data && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-yellow-900/20 border border-yellow-700/30 text-yellow-300 text-xs">
          <CheckCircle size={14} />
          {mutation.data.message}
        </div>
      )}

      {/* Detector cards grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
        {(Object.keys(DETECTOR_META) as (keyof DetectorsConfig)[]).map(name => (
          <DetectorCard
            key={name}
            name={name}
            det={detectors[name]}
            onChange={updated => handleChange(name, updated)}
          />
        ))}
      </div>
    </div>
  )
}
