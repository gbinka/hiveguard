import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ShieldOff, Clock, ShieldCheck, Activity, RefreshCw } from 'lucide-react'
import { api } from '../api/client'
import StatCard from '../components/StatCard'
import BanTrendChart from '../components/BanTrendChart'
import { SeverityBadge } from '../components/Badges'
import type { TrendPoint } from '../api/types'

function formatUptime(secs: number): string {
  const d = Math.floor(secs / 86400)
  const h = Math.floor((secs % 86400) / 3600)
  const m = Math.floor((secs % 3600) / 60)
  if (d > 0) return `${d}d ${h}h ${m}m`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m ${secs % 60}s`
}

function formatTime(d: Date): string {
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export default function Dashboard() {
  const trendRef = useRef<TrendPoint[]>([])
  const [trend, setTrend] = useState<TrendPoint[]>([])

  const { data: stats, isLoading: statsLoading, dataUpdatedAt, refetch } = useQuery({
    queryKey: ['stats'],
    queryFn: api.getStats,
    refetchInterval: 10_000,
  })

  const { data: recentBans } = useQuery({
    queryKey: ['bans', 'dashboard'],
    queryFn: () => api.getBans(1, 8),
    refetchInterval: 15_000,
  })

  const { data: botsData } = useQuery({
    queryKey: ['bots', 'dashboard'],
    queryFn: api.getBots,
    refetchInterval: 30_000,
  })

  // Append a data point every time stats update
  useEffect(() => {
    if (!stats) return
    const point: TrendPoint = {
      time: formatTime(new Date()),
      bans: stats.total_bans,
      whitelisted: stats.total_whitelisted,
    }
    const next = [...trendRef.current, point].slice(-60) // keep last 60 points
    trendRef.current = next
    setTrend([...next])
  }, [stats])

  const topBots = (botsData?.bots ?? [])
    .slice()
    .sort((a, b) => b.request_count - a.request_count)
    .slice(0, 5)

  const lastUpdated = dataUpdatedAt ? new Date(dataUpdatedAt).toLocaleTimeString() : '—'

  return (
    <div className="p-6 space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-100">Dashboard</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            {stats ? `HiveGuard v${stats.version}` : 'Loading…'}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-gray-600">Updated {lastUpdated}</span>
          <button
            onClick={() => refetch()}
            className="btn-ghost py-1 px-2"
            title="Refresh now"
          >
            <RefreshCw size={15} />
          </button>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <StatCard
          title="Active Bans"
          value={statsLoading ? '…' : (stats?.total_bans ?? 0).toLocaleString()}
          icon={<ShieldOff />}
          color="red"
          subtitle="Currently enforced"
        />
        <StatCard
          title="Uptime"
          value={statsLoading ? '…' : formatUptime(stats?.uptime_secs ?? 0)}
          icon={<Clock />}
          color="blue"
          subtitle="Since last restart"
        />
        <StatCard
          title="Whitelisted"
          value={statsLoading ? '…' : (stats?.total_whitelisted ?? 0).toLocaleString()}
          icon={<ShieldCheck />}
          color="emerald"
          subtitle="Trusted networks"
        />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Ban trend */}
        <div className="card p-5 lg:col-span-2">
          <div className="flex items-center gap-2 mb-4">
            <Activity size={16} className="text-gray-400" />
            <h2 className="text-sm font-semibold text-gray-200">Ban Trend</h2>
            <span className="text-xs text-gray-600 ml-auto">Live · 10 s interval</span>
          </div>
          <div className="h-52">
            <BanTrendChart data={trend} />
          </div>
        </div>

        {/* Top bots */}
        <div className="card p-5">
          <h2 className="text-sm font-semibold text-gray-200 mb-4">Top Bots by Requests</h2>
          {topBots.length === 0 ? (
            <p className="text-sm text-gray-600">No bot activity yet.</p>
          ) : (
            <ul className="space-y-2.5">
              {topBots.map(bot => (
                <li key={bot.name} className="flex items-center justify-between gap-2">
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-gray-200 truncate">{bot.name}</p>
                    <p className="text-xs text-gray-500 truncate">{bot.org}</p>
                  </div>
                  <span className="text-sm tabular-nums font-mono text-gray-400 shrink-0">
                    {bot.request_count.toLocaleString()}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {/* Recent bans table */}
      <div className="card">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-700/40">
          <h2 className="text-sm font-semibold text-gray-200">Recent Bans</h2>
          <a href="/bans" className="text-xs text-blue-400 hover:text-blue-300 transition-colors">
            View all →
          </a>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-gray-500 uppercase tracking-wide border-b border-gray-700/40">
                <th className="px-5 py-3 text-left font-medium">IP / CIDR</th>
                <th className="px-5 py-3 text-left font-medium">Reason</th>
                <th className="px-5 py-3 text-left font-medium">Severity</th>
                <th className="px-5 py-3 text-left font-medium">Expires</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700/30">
              {(recentBans?.bans ?? []).map(ban => (
                <tr key={ban.subject} className="table-row-hover">
                  <td className="px-5 py-3 font-mono text-xs text-gray-200">{ban.subject}</td>
                  <td className="px-5 py-3 text-gray-400 max-w-xs truncate" title={ban.reason}>
                    {ban.reason}
                  </td>
                  <td className="px-5 py-3">
                    <SeverityBadge severity={ban.severity} />
                  </td>
                  <td className="px-5 py-3 text-gray-500 text-xs font-mono whitespace-nowrap">
                    {ban.expires_at
                      ? new Date(ban.expires_at).toLocaleString()
                      : <span className="text-red-400">Permanent</span>}
                  </td>
                </tr>
              ))}
              {(recentBans?.bans ?? []).length === 0 && (
                <tr>
                  <td colSpan={4} className="px-5 py-8 text-center text-gray-600">
                    No active bans
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
