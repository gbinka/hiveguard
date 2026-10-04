import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Save, RefreshCw, AlertTriangle, CheckCircle, Info } from 'lucide-react'
import { api } from '../api/client'
import { ApiError } from '../api/client'

export default function Config() {
  const qc = useQueryClient()
  const [draft, setDraft] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['config'],
    queryFn: api.getConfig,
    staleTime: 30_000,
  })

  const content = draft ?? data?.content ?? ''

  const mutation = useMutation({
    mutationFn: (yaml: string) => api.saveConfig(yaml),
    onSuccess: () => {
      setSaved(true)
      setDraft(null)
      qc.invalidateQueries({ queryKey: ['config'] })
      setTimeout(() => setSaved(false), 3000)
    },
  })

  const isDirty = draft !== null && draft !== data?.content

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-400">
        <RefreshCw size={20} className="animate-spin mr-2" />
        Loading config…
      </div>
    )
  }

  if (isError) {
    const msg = error instanceof ApiError ? error.message : 'Cannot load config'
    return (
      <div className="flex items-center gap-3 p-4 rounded-lg bg-red-900/20 border border-red-700/40 text-red-300">
        <AlertTriangle size={18} />
        {msg}
      </div>
    )
  }

  return (
    <div className="space-y-4 h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-gray-100">Configuration</h1>
          <p className="text-xs text-gray-500 mt-0.5">
            Raw YAML editor — changes take effect after daemon restart
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
            onClick={() => setDraft(null)}
            disabled={!isDirty}
            className="btn-secondary text-xs px-3 py-1.5 disabled:opacity-40"
          >
            Reset
          </button>
          <button
            onClick={() => mutation.mutate(content)}
            disabled={!isDirty || mutation.isPending}
            className="btn-primary text-xs px-3 py-1.5 flex items-center gap-1.5 disabled:opacity-40"
          >
            {mutation.isPending ? (
              <RefreshCw size={13} className="animate-spin" />
            ) : (
              <Save size={13} />
            )}
            Save
          </button>
        </div>
      </div>

      {/* Error from save */}
      {mutation.isError && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-red-900/20 border border-red-700/40 text-red-300 text-sm">
          <AlertTriangle size={15} />
          {mutation.error instanceof ApiError
            ? mutation.error.message
            : 'Save failed'}
        </div>
      )}

      {/* Info banner */}
      <div className="flex items-start gap-2 p-3 rounded-lg bg-blue-900/20 border border-blue-700/30 text-blue-300 text-xs">
        <Info size={14} className="shrink-0 mt-0.5" />
        <span>
          Saving writes to the config file on the server. The daemon must be restarted
          for changes to take effect. Use <strong className="font-semibold">Rules</strong> tab
          for a structured detector editor.
        </span>
      </div>

      {/* YAML editor */}
      <div className="flex-1 min-h-0">
        <textarea
          value={content}
          onChange={e => setDraft(e.target.value)}
          spellCheck={false}
          className="w-full h-full min-h-[500px] rounded-lg border border-gray-700/60
            bg-gray-900/80 text-gray-200 text-xs font-mono p-4 resize-none
            focus:outline-none focus:ring-1 focus:ring-blue-500/50
            leading-5 placeholder-gray-600"
          placeholder="# Loading…"
        />
      </div>
    </div>
  )
}
