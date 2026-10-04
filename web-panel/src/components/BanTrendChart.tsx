import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts'
import type { TrendPoint } from '../api/types'

interface Props {
  data: TrendPoint[]
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function CustomTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-lg border border-gray-600/60 bg-gray-800/95 px-3 py-2 text-xs shadow-xl">
      <p className="mb-1 font-mono text-gray-400">{label}</p>
      {payload.map((p: { name: string; value: number; color: string }) => (
        <p key={p.name} style={{ color: p.color }} className="font-medium">
          {p.name}: <span className="tabular-nums">{p.value.toLocaleString()}</span>
        </p>
      ))}
    </div>
  )
}

export default function BanTrendChart({ data }: Props) {
  if (data.length < 2) {
    return (
      <div className="flex h-full items-center justify-center text-sm text-gray-500">
        Collecting data… (refresh interval: 10 s)
      </div>
    )
  }

  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={data} margin={{ top: 4, right: 8, left: -16, bottom: 0 }}>
        <defs>
          <linearGradient id="gradBans" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#ef4444" stopOpacity={0.25} />
            <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="gradWhitelisted" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#10b981" stopOpacity={0.20} />
            <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
          </linearGradient>
        </defs>

        <CartesianGrid strokeDasharray="3 3" stroke="#374151" strokeOpacity={0.4} />

        <XAxis
          dataKey="time"
          tick={{ fill: '#6b7280', fontSize: 11, fontFamily: 'monospace' }}
          tickLine={false}
          axisLine={{ stroke: '#374151' }}
          interval="preserveStartEnd"
        />
        <YAxis
          tick={{ fill: '#6b7280', fontSize: 11 }}
          tickLine={false}
          axisLine={false}
          allowDecimals={false}
        />

        <Tooltip content={<CustomTooltip />} />

        <Legend
          wrapperStyle={{ fontSize: 12, color: '#9ca3af', paddingTop: 8 }}
        />

        <Area
          type="monotone"
          dataKey="bans"
          name="Active Bans"
          stroke="#ef4444"
          strokeWidth={2}
          fill="url(#gradBans)"
          dot={false}
          activeDot={{ r: 4, fill: '#ef4444' }}
        />
        <Area
          type="monotone"
          dataKey="whitelisted"
          name="Whitelisted"
          stroke="#10b981"
          strokeWidth={2}
          fill="url(#gradWhitelisted)"
          dot={false}
          activeDot={{ r: 4, fill: '#10b981' }}
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}
