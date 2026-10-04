import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { RefreshCw, Loader2 } from 'lucide-react'
import { api } from '../api/client'
import { PolicyBadge } from '../components/Badges'
import { useToast } from '../components/Toast'
import type { BotStats } from '../api/types'

const POLICIES = ['allow', 'block', 'monitor'] as const

export default function Bots() {
  const qc = useQueryClient()
  const toast = useToast()

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['bots'],
    queryFn: api.getBots,
    refetchInterval: 30_000,
  })

  const policyMutation = useMutation({
    mutationFn: ({ name, policy }: { name: string; policy: string }) =>
      api.setBotPolicy(name, policy),
    onSuccess: (res) => {
      toast.success(res.message)
      qc.invalidateQueries({ queryKey: ['bots'] })
    },
    onError: (err: Error) => toast.error(err.message),
  })

  const bots: BotStats[] = (data?.bots ?? []).slice().sort((a, b) => b.request_count - a.request_count)

  const [knownFilter, setKnownFilter] = useState<'all' | 'known' | 'unknown'>('all')
  const filtered = bots.filter(b => {
    if (knownFilter === 'known') return b.known
    if (knownFilter === 'unknown') return !b.known
    return true
  })

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-gray-100">Bots</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            {bots.length} bot{bots.length !== 1 ? 's' : ''} tracked
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex rounded-md overflow-hidden border border-gray-700/60 text-sm">
            {(['all', 'known', 'unknown'] as const).map(f => (
              <button
                key={f}
                onClick={() => setKnownFilter(f)}
                className={`px-3 py-1.5 capitalize transition-colors
                  ${knownFilter === f
                    ? 'bg-gray-700 text-gray-100'
                    : 'bg-transparent text-gray-400 hover:bg-gray-700/50'}`}
              >
                {f}
              </button>
            ))}
          </div>
          <button onClick={() => refetch()} className="btn-ghost py-1.5 px-2" title="Refresh">
            <RefreshCw size={15} />
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="card overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-xs text-gray-500 uppercase tracking-wide border-b border-gray-700/40">
              <th className="px-5 py-3 text-left font-medium">Bot Name</th>
              <th className="px-5 py-3 text-left font-medium">Org</th>
              <th className="px-5 py-3 text-left font-medium">Type</th>
              <th className="px-5 py-3 text-left font-medium">Requests</th>
              <th className="px-5 py-3 text-left font-medium">Last IP</th>
              <th className="px-5 py-3 text-left font-medium">Policy</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700/30">
            {isLoading && (
              <tr>
                <td colSpan={6} className="px-5 py-8 text-center text-gray-500">
                  <Loader2 size={20} className="animate-spin mx-auto" />
                </td>
              </tr>
            )}
            {!isLoading && filtered.length === 0 && (
              <tr>
                <td colSpan={6} className="px-5 py-8 text-center text-gray-600">
                  No bots tracked yet.
                </td>
              </tr>
            )}
            {filtered.map(bot => (
              <tr key={bot.name} className="table-row-hover">
                <td className="px-5 py-3">
                  <p className="font-medium text-gray-200">{bot.name}</p>
                  <p
                    className="text-xs text-gray-600 font-mono truncate max-w-[240px]"
                    title={bot.last_seen_ua}
                  >
                    {bot.last_seen_ua || '—'}
                  </p>
                </td>
                <td className="px-5 py-3 text-gray-400">{bot.org || '—'}</td>
                <td className="px-5 py-3">
                  <span className={`badge ${bot.known
                    ? 'bg-blue-500/20 text-blue-300 ring-1 ring-blue-500/30'
                    : 'bg-gray-500/20 text-gray-400 ring-1 ring-gray-500/30'}`}>
                    {bot.known ? 'Known' : 'Discovered'}
                  </span>
                </td>
                <td className="px-5 py-3 font-mono tabular-nums text-gray-300">
                  {bot.request_count.toLocaleString()}
                </td>
                <td className="px-5 py-3 font-mono text-xs text-gray-400">
                  {bot.last_seen_ip || '—'}
                </td>
                <td className="px-5 py-3">
                  {bot.known ? (
                    <PolicySelect
                      value={bot.policy}
                      onChange={policy => policyMutation.mutate({ name: bot.name, policy })}
                      disabled={policyMutation.isPending}
                    />
                  ) : (
                    <PolicyBadge policy={bot.policy} />
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function PolicySelect({
  value,
  onChange,
  disabled,
}: {
  value: string
  onChange: (v: string) => void
  disabled?: boolean
}) {
  const colorMap: Record<string, string> = {
    allow:   'text-emerald-300',
    block:   'text-red-300',
    monitor: 'text-blue-300',
  }
  return (
    <select
      value={value}
      onChange={e => onChange(e.target.value)}
      disabled={disabled}
      className={`select text-xs ${colorMap[value] ?? ''}`}
    >
      {POLICIES.map(p => (
        <option key={p} value={p} className="text-gray-100 bg-gray-800">
          {p.charAt(0).toUpperCase() + p.slice(1)}
        </option>
      ))}
    </select>
  )
}
