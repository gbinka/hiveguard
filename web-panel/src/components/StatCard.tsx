import React from 'react'

interface StatCardProps {
  title: string
  value: string | number
  subtitle?: string
  icon: React.ReactNode
  /** Tailwind colour key: 'red' | 'blue' | 'emerald' | 'amber' | 'purple' */
  color?: 'red' | 'blue' | 'emerald' | 'amber' | 'purple' | 'gray'
  trend?: { value: number; label: string }
}

const colorMap: Record<NonNullable<StatCardProps['color']>, { icon: string; value: string; bg: string }> = {
  red:     { icon: 'text-red-400',     value: 'text-red-300',     bg: 'bg-red-500/10 ring-red-500/20' },
  blue:    { icon: 'text-blue-400',    value: 'text-blue-300',    bg: 'bg-blue-500/10 ring-blue-500/20' },
  emerald: { icon: 'text-emerald-400', value: 'text-emerald-300', bg: 'bg-emerald-500/10 ring-emerald-500/20' },
  amber:   { icon: 'text-amber-400',   value: 'text-amber-300',   bg: 'bg-amber-500/10 ring-amber-500/20' },
  purple:  { icon: 'text-purple-400',  value: 'text-purple-300',  bg: 'bg-purple-500/10 ring-purple-500/20' },
  gray:    { icon: 'text-gray-400',    value: 'text-gray-300',    bg: 'bg-gray-500/10 ring-gray-500/20' },
}

export default function StatCard({ title, value, subtitle, icon, color = 'blue', trend }: StatCardProps) {
  const c = colorMap[color]

  return (
    <div className="card p-5 flex items-start gap-4 hover:border-gray-600/60 transition-colors">
      {/* Icon bubble */}
      <div className={`shrink-0 flex items-center justify-center rounded-lg w-11 h-11 ring-1 ${c.bg}`}>
        <span className={`[&>svg]:size-5 ${c.icon}`}>{icon}</span>
      </div>

      {/* Text */}
      <div className="flex-1 min-w-0">
        <p className="text-xs font-medium text-gray-400 uppercase tracking-wider">{title}</p>
        <p className={`mt-1 text-2xl font-bold tabular-nums ${c.value}`}>{value}</p>
        {subtitle && (
          <p className="mt-0.5 text-xs text-gray-500 truncate">{subtitle}</p>
        )}
        {trend !== undefined && (
          <p className={`mt-1 text-xs ${trend.value >= 0 ? 'text-red-400' : 'text-emerald-400'}`}>
            {trend.value >= 0 ? '▲' : '▼'} {Math.abs(trend.value)} {trend.label}
          </p>
        )}
      </div>
    </div>
  )
}
