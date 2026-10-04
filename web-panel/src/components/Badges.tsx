/** Coloured pill badge for ban severity (0-255). */
export function SeverityBadge({ severity }: { severity: number }) {
  let cls = ''
  let label = ''

  if (severity >= 200) {
    cls = 'bg-red-500/20 text-red-300 ring-red-500/30'
    label = 'Critical'
  } else if (severity >= 150) {
    cls = 'bg-orange-500/20 text-orange-300 ring-orange-500/30'
    label = 'High'
  } else if (severity >= 80) {
    cls = 'bg-amber-500/20 text-amber-300 ring-amber-500/30'
    label = 'Medium'
  } else {
    cls = 'bg-blue-500/20 text-blue-300 ring-blue-500/30'
    label = 'Low'
  }

  return (
    <span className={`badge ring-1 ${cls}`}>
      {label} <span className="ml-1 opacity-70">({severity})</span>
    </span>
  )
}

/** Coloured pill for bot policy. */
export function PolicyBadge({ policy }: { policy: 'allow' | 'block' | 'monitor' | string }) {
  const map: Record<string, string> = {
    allow:   'bg-emerald-500/20 text-emerald-300 ring-emerald-500/30',
    block:   'bg-red-500/20 text-red-300 ring-red-500/30',
    monitor: 'bg-blue-500/20 text-blue-300 ring-blue-500/30',
  }
  const cls = map[policy] ?? 'bg-gray-500/20 text-gray-300 ring-gray-500/30'
  return (
    <span className={`badge ring-1 capitalize ${cls}`}>{policy}</span>
  )
}

/** Coloured dot for peer state. */
export function PeerStateBadge({ state }: { state: string }) {
  const isActive = state.toLowerCase() === 'active' || state.toLowerCase() === 'connected'
  return (
    <span className="flex items-center gap-1.5 text-sm">
      <span className={`inline-block size-2 rounded-full ${isActive ? 'bg-emerald-400' : 'bg-gray-500'}`} />
      <span className={isActive ? 'text-emerald-300' : 'text-gray-400'}>{state}</span>
    </span>
  )
}
