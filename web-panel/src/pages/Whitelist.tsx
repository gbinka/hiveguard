import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, RefreshCw, Loader2, ShieldCheck } from 'lucide-react'
import { api } from '../api/client'
import { useToast } from '../components/Toast'
import Modal from '../components/Modal'

export default function Whitelist() {
  const qc = useQueryClient()
  const toast = useToast()

  const [addOpen, setAddOpen] = useState(false)
  const [newCidr, setNewCidr] = useState('')

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['whitelist'],
    queryFn: api.getWhitelist,
    refetchInterval: 30_000,
  })

  const addMutation = useMutation({
    mutationFn: () => api.addWhitelist(newCidr.trim()),
    onSuccess: (res) => {
      toast.success(res.message)
      qc.invalidateQueries({ queryKey: ['whitelist'] })
      qc.invalidateQueries({ queryKey: ['stats'] })
      setAddOpen(false)
      setNewCidr('')
    },
    onError: (err: Error) => toast.error(err.message),
  })

  const removeMutation = useMutation({
    mutationFn: (cidr: string) => api.removeWhitelist(cidr),
    onSuccess: (res) => {
      toast.success(res.message)
      qc.invalidateQueries({ queryKey: ['whitelist'] })
      qc.invalidateQueries({ queryKey: ['stats'] })
    },
    onError: (err: Error) => toast.error(err.message),
  })

  const entries = data?.entries ?? []

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-gray-100">Whitelist</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            {entries.length} trusted network{entries.length !== 1 ? 's' : ''}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => refetch()} className="btn-ghost py-1.5 px-2" title="Refresh">
            <RefreshCw size={15} />
          </button>
          <button onClick={() => setAddOpen(true)} className="btn-primary">
            <Plus size={15} />
            Add Network
          </button>
        </div>
      </div>

      {/* Info banner */}
      <div className="flex items-start gap-3 rounded-lg bg-emerald-900/20 border border-emerald-700/30 px-4 py-3 text-sm text-emerald-300">
        <ShieldCheck size={16} className="shrink-0 mt-0.5" />
        <span>
          Whitelisted IPs and networks are <strong>never banned</strong>, even if their
          behaviour triggers detectors. Use for trusted internal ranges (VPN, office).
        </span>
      </div>

      {/* Entries */}
      <div className="card">
        {isLoading ? (
          <div className="px-5 py-8 text-center text-gray-500">
            <Loader2 size={20} className="animate-spin mx-auto" />
          </div>
        ) : entries.length === 0 ? (
          <div className="px-5 py-8 text-center text-gray-600">
            No whitelisted networks.
          </div>
        ) : (
          <ul className="divide-y divide-gray-700/30">
            {entries.map(cidr => (
              <li
                key={cidr}
                className="flex items-center justify-between px-5 py-3 group table-row-hover"
              >
                <span className="font-mono text-sm text-gray-200">{cidr}</span>
                <button
                  onClick={() => removeMutation.mutate(cidr)}
                  disabled={removeMutation.isPending}
                  className="opacity-0 group-hover:opacity-100 text-gray-600 hover:text-red-400
                             transition-all disabled:cursor-wait"
                  title={`Remove ${cidr}`}
                >
                  {removeMutation.isPending ? (
                    <Loader2 size={15} className="animate-spin" />
                  ) : (
                    <Trash2 size={15} />
                  )}
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Add modal */}
      <Modal title="Add Trusted Network" open={addOpen} onClose={() => setAddOpen(false)}>
        <form
          onSubmit={e => {
            e.preventDefault()
            addMutation.mutate()
          }}
          className="space-y-4"
        >
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1 uppercase tracking-wider">
              IP or CIDR *
            </label>
            <input
              type="text"
              value={newCidr}
              onChange={e => setNewCidr(e.target.value)}
              placeholder="10.0.0.0/8 or 192.168.1.1"
              required
              className="input font-mono"
              autoFocus
            />
          </div>
          <p className="text-xs text-gray-600">
            Examples: <code className="font-mono">10.0.0.0/8</code>,{' '}
            <code className="font-mono">192.168.0.0/16</code>,{' '}
            <code className="font-mono">172.16.0.1</code>
          </p>
          <div className="flex justify-end gap-2 pt-1">
            <button type="button" onClick={() => setAddOpen(false)} className="btn-ghost">
              Cancel
            </button>
            <button type="submit" disabled={addMutation.isPending} className="btn-primary">
              {addMutation.isPending && <Loader2 size={14} className="animate-spin" />}
              Add
            </button>
          </div>
        </form>
      </Modal>
    </div>
  )
}
