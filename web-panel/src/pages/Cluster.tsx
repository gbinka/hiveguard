import { useQuery } from '@tanstack/react-query'
import { RefreshCw, Loader2, Network } from 'lucide-react'
import { api } from '../api/client'
import { PeerStateBadge } from '../components/Badges'

export default function Cluster() {
  const { data, isLoading, refetch, dataUpdatedAt } = useQuery({
    queryKey: ['peers'],
    queryFn: api.getPeers,
    refetchInterval: 30_000,
  })

  const peers = data?.peers ?? []
  const lastUpdated = dataUpdatedAt ? new Date(dataUpdatedAt).toLocaleTimeString() : '—'

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-gray-100">Cluster</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            {peers.length} peer node{peers.length !== 1 ? 's' : ''} · Updated {lastUpdated}
          </p>
        </div>
        <button onClick={() => refetch()} className="btn-ghost py-1.5 px-2" title="Refresh">
          <RefreshCw size={15} />
        </button>
      </div>

      {/* Info */}
      <div className="flex items-start gap-3 rounded-lg bg-blue-900/20 border border-blue-700/30 px-4 py-3 text-sm text-blue-300">
        <Network size={16} className="shrink-0 mt-0.5" />
        <span>
          Cluster peers share ban decisions via gossip protocol with CRDT-based conflict
          resolution. Trust scores are used to detect and mitigate poisoning attacks.
        </span>
      </div>

      {/* Table */}
      <div className="card overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-xs text-gray-500 uppercase tracking-wide border-b border-gray-700/40">
              <th className="px-5 py-3 text-left font-medium">Node ID</th>
              <th className="px-5 py-3 text-left font-medium">Address</th>
              <th className="px-5 py-3 text-left font-medium">Trust Score</th>
              <th className="px-5 py-3 text-left font-medium">State</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700/30">
            {isLoading && (
              <tr>
                <td colSpan={4} className="px-5 py-8 text-center text-gray-500">
                  <Loader2 size={20} className="animate-spin mx-auto" />
                </td>
              </tr>
            )}
            {!isLoading && peers.length === 0 && (
              <tr>
                <td colSpan={4} className="px-5 py-8 text-center text-gray-600">
                  No cluster peers. This node is running in standalone mode.
                </td>
              </tr>
            )}
            {peers.map(peer => (
              <tr key={peer.node_id} className="table-row-hover">
                <td className="px-5 py-3 font-mono text-xs text-gray-300">{peer.node_id}</td>
                <td className="px-5 py-3 font-mono text-xs text-gray-400">{peer.address}</td>
                <td className="px-5 py-3">
                  <TrustBar score={peer.trust_score} />
                </td>
                <td className="px-5 py-3">
                  <PeerStateBadge state={peer.state} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/** Mini visual trust score bar */
function TrustBar({ score }: { score: number }) {
  // score is typically 0-2+ (higher = less trusted / more suspicious)
  // Normalize: 0 = fully trusted (green), ≥2 = suspicious (red)
  const normalized = Math.min(1, score / 2)
  const color = normalized < 0.4 ? '#10b981' : normalized < 0.75 ? '#f59e0b' : '#ef4444'

  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-1.5 rounded-full bg-gray-700 overflow-hidden">
        <div
          className="h-full rounded-full transition-all"
          style={{ width: `${(1 - normalized) * 100}%`, background: color }}
        />
      </div>
      <span className="text-xs font-mono text-gray-400 tabular-nums">
        {score.toFixed(2)}
      </span>
    </div>
  )
}
