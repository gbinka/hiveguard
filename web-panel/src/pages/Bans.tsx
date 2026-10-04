import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, ChevronLeft, ChevronRight, Search, RefreshCw, Loader2 } from 'lucide-react'
import { api } from '../api/client'
import { SeverityBadge } from '../components/Badges'
import Modal from '../components/Modal'
import { useToast } from '../components/Toast'

const PAGE_SIZE = 50

export default function Bans() {
  const qc = useQueryClient()
  const toast = useToast()

  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [addOpen, setAddOpen] = useState(false)

  // Form state
  const [newIp, setNewIp] = useState('')
  const [newDuration, setNewDuration] = useState('24h')
  const [newReason, setNewReason] = useState('')

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['bans', page],
    queryFn: () => api.getBans(page, PAGE_SIZE),
    refetchInterval: 30_000,
  })

  const addMutation = useMutation({
    mutationFn: () => api.createBan(newIp.trim(), newDuration.trim() || undefined, newReason.trim() || undefined),
    onSuccess: (res) => {
      toast.success(res.message)
      qc.invalidateQueries({ queryKey: ['bans'] })
      qc.invalidateQueries({ queryKey: ['stats'] })
      setAddOpen(false)
      setNewIp('')
      setNewDuration('24h')
      setNewReason('')
    },
    onError: (err: Error) => toast.error(err.message),
  })

  const removeMutation = useMutation({
    mutationFn: (ip: string) => api.deleteBan(ip),
    onSuccess: (res) => {
      toast.success(res.message)
      qc.invalidateQueries({ queryKey: ['bans'] })
      qc.invalidateQueries({ queryKey: ['stats'] })
    },
    onError: (err: Error) => toast.error(err.message),
  })

  const bans = data?.bans ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const filtered = search.trim()
    ? bans.filter(
        b =>
          b.subject.includes(search) ||
          b.reason.toLowerCase().includes(search.toLowerCase()),
      )
    : bans

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-gray-100">Bans</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            {total.toLocaleString()} active ban{total !== 1 ? 's' : ''}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => refetch()} className="btn-ghost py-1.5 px-2" title="Refresh">
            <RefreshCw size={15} />
          </button>
          <button onClick={() => setAddOpen(true)} className="btn-primary">
            <Plus size={15} />
            Add Ban
          </button>
        </div>
      </div>

      {/* Search */}
      <div className="relative max-w-sm">
        <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
        <input
          type="text"
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Filter by IP or reason…"
          className="input pl-9"
        />
      </div>

      {/* Table */}
      <div className="card overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-xs text-gray-500 uppercase tracking-wide border-b border-gray-700/40">
              <th className="px-5 py-3 text-left font-medium">IP / CIDR</th>
              <th className="px-5 py-3 text-left font-medium">Reason</th>
              <th className="px-5 py-3 text-left font-medium">Source</th>
              <th className="px-5 py-3 text-left font-medium">Severity</th>
              <th className="px-5 py-3 text-left font-medium">Created</th>
              <th className="px-5 py-3 text-left font-medium">Expires</th>
              <th className="px-5 py-3 text-left font-medium w-10"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700/30">
            {isLoading && (
              <tr>
                <td colSpan={7} className="px-5 py-8 text-center text-gray-500">
                  <Loader2 size={20} className="animate-spin mx-auto" />
                </td>
              </tr>
            )}
            {!isLoading && filtered.length === 0 && (
              <tr>
                <td colSpan={7} className="px-5 py-8 text-center text-gray-600">
                  {search ? 'No bans match your filter.' : 'No active bans. 🎉'}
                </td>
              </tr>
            )}
            {filtered.map(ban => (
              <tr key={ban.subject} className="table-row-hover group">
                <td className="px-5 py-3 font-mono text-xs text-gray-100 whitespace-nowrap">
                  {ban.subject}
                </td>
                <td className="px-5 py-3 text-gray-400 max-w-xs truncate" title={ban.reason}>
                  {ban.reason}
                </td>
                <td className="px-5 py-3 text-gray-500 text-xs font-mono truncate max-w-[180px]" title={ban.source}>
                  {ban.source}
                </td>
                <td className="px-5 py-3">
                  <SeverityBadge severity={ban.severity} />
                </td>
                <td className="px-5 py-3 text-gray-500 text-xs font-mono whitespace-nowrap">
                  {ban.created_at ? new Date(ban.created_at).toLocaleString() : '—'}
                </td>
                <td className="px-5 py-3 text-xs font-mono whitespace-nowrap">
                  {ban.expires_at ? (
                    <span className="text-gray-500">{new Date(ban.expires_at).toLocaleString()}</span>
                  ) : (
                    <span className="text-red-400">Permanent</span>
                  )}
                </td>
                <td className="px-5 py-3">
                  <button
                    onClick={() => removeMutation.mutate(ban.subject)}
                    disabled={removeMutation.isPending}
                    className="opacity-0 group-hover:opacity-100 text-gray-600 hover:text-red-400
                               transition-all disabled:cursor-wait"
                    title={`Unban ${ban.subject}`}
                  >
                    {removeMutation.isPending ? (
                      <Loader2 size={15} className="animate-spin" />
                    ) : (
                      <Trash2 size={15} />
                    )}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between text-sm text-gray-400">
          <span>
            Page {page} of {totalPages} ({total.toLocaleString()} total)
          </span>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="btn-ghost py-1 px-2 disabled:opacity-30"
            >
              <ChevronLeft size={16} />
            </button>
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="btn-ghost py-1 px-2 disabled:opacity-30"
            >
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      )}

      {/* Add ban modal */}
      <Modal title="Add Ban" open={addOpen} onClose={() => setAddOpen(false)}>
        <form
          onSubmit={e => {
            e.preventDefault()
            addMutation.mutate()
          }}
          className="space-y-4"
        >
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1 uppercase tracking-wider">
              IP / CIDR *
            </label>
            <input
              type="text"
              value={newIp}
              onChange={e => setNewIp(e.target.value)}
              placeholder="1.2.3.4 or 1.2.3.0/24"
              required
              className="input font-mono"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1 uppercase tracking-wider">
              Duration
            </label>
            <select
              value={newDuration}
              onChange={e => setNewDuration(e.target.value)}
              className="select w-full"
            >
              <option value="1h">1 hour</option>
              <option value="6h">6 hours</option>
              <option value="24h">24 hours</option>
              <option value="7d">7 days</option>
              <option value="30d">30 days</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1 uppercase tracking-wider">
              Reason
            </label>
            <input
              type="text"
              value={newReason}
              onChange={e => setNewReason(e.target.value)}
              placeholder="Manual ban – suspicious activity"
              className="input"
            />
          </div>
          <div className="flex justify-end gap-2 pt-1">
            <button type="button" onClick={() => setAddOpen(false)} className="btn-ghost">
              Cancel
            </button>
            <button type="submit" disabled={addMutation.isPending} className="btn-primary">
              {addMutation.isPending && <Loader2 size={14} className="animate-spin" />}
              Ban IP
            </button>
          </div>
        </form>
      </Modal>
    </div>
  )
}
