import { useEffect, useMemo, useState } from 'react'
import axios from 'axios'
import clsx from 'clsx'
import { useTranslation } from 'react-i18next'
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { Minus, TrendingDown, TrendingUp } from 'lucide-react'
import { RatingHistory, RatingPoint } from '../types/report'
import { fmtShort, gradeChipColor, td, th } from './assetTable'

// Distinguishable line palette, tuned for the light theme
export const RATING_COLORS = [
  '#0891b2', '#7c3aed', '#d97706', '#059669',
  '#e11d48', '#2563eb', '#c026d3', '#65a30d',
]

export const ratingColor = (i: number) => RATING_COLORS[i % RATING_COLORS.length]

const fmtDay = (iso: string) => {
  const d = new Date(iso)
  if (isNaN(d.getTime())) return '—'
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })
}

export function DeltaBadge({ delta }: { delta: number | null }) {
  if (delta == null) return <span className="text-dark-400 text-xs font-mono">—</span>
  const Icon = delta > 0 ? TrendingUp : delta < 0 ? TrendingDown : Minus
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1 text-xs font-semibold font-mono',
        delta > 0 ? 'text-emerald-600' : delta < 0 ? 'text-red-600' : 'text-dark-400',
      )}
    >
      <Icon className="w-3.5 h-3.5" />
      {delta > 0 ? `+${delta}` : `${delta}`}
    </span>
  )
}

// Points without timestamp or score can't be charted; the rest are grouped
// per domain and sorted chronologically
export function groupByDomain(points: RatingPoint[] | undefined): [string, RatingPoint[]][] {
  const valid = (points ?? [])
    .filter((p) => p.completed_at && typeof p.score === 'number')
    .sort((a, b) => (a.completed_at ?? '').localeCompare(b.completed_at ?? ''))
  const map = new Map<string, RatingPoint[]>()
  for (const p of valid) {
    const arr = map.get(p.domain) ?? []
    arr.push(p)
    map.set(p.domain, arr)
  }
  return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]))
}

export default function RatingTrendCard({ companyId }: { companyId: number }) {
  const { t } = useTranslation()
  const [history, setHistory] = useState<RatingHistory | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(false)
    setHistory(null)
    axios
      .get<RatingHistory>(`/api/companies/${companyId}/rating-history`)
      .then(({ data }) => { if (!cancelled) setHistory(data) })
      .catch(() => { if (!cancelled) setError(true) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [companyId])

  const domains = useMemo(() => groupByDomain(history?.points), [history])

  const chartData = useMemo(() => {
    const rows = new Map<string, Record<string, number | string>>()
    for (const [domain, pts] of domains) {
      for (const p of pts) {
        const key = p.completed_at as string
        const row = rows.get(key) ?? { ts: key, date: fmtDay(key) }
        row[domain] = p.score as number
        rows.set(key, row)
      }
    }
    return [...rows.values()].sort((a, b) => String(a.ts).localeCompare(String(b.ts)))
  }, [domains])

  return (
    <div className="card space-y-4">
      <h3 className="text-[15px] font-semibold tracking-tight text-dark-100">
        {t('dashboard.ratingTrend')}
      </h3>

      {loading ? (
        <p className="text-center text-dark-500 py-10 text-sm animate-pulse">
          {t('dashboard.ratingTrendLoading')}
        </p>
      ) : error ? (
        <p className="text-center text-dark-500 py-10 text-sm">
          {t('dashboard.ratingTrendError')}
        </p>
      ) : domains.length === 0 ? (
        <p className="text-center text-dark-500 py-10 text-sm">
          {t('dashboard.ratingTrendEmpty')}
        </p>
      ) : (
        <>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData} margin={{ top: 8, right: 12, bottom: 0, left: -18 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e6e9f0" vertical={false} />
                <XAxis
                  dataKey="date"
                  tick={{ fontSize: 11, fill: '#6b7280' }}
                  tickLine={false}
                  axisLine={{ stroke: '#e6e9f0' }}
                />
                <YAxis
                  domain={[0, 100]}
                  tick={{ fontSize: 11, fill: '#6b7280' }}
                  tickLine={false}
                  axisLine={false}
                />
                <Tooltip
                  formatter={(value: number, name: string) => [value, name]}
                  labelFormatter={(_, payload) => {
                    const ts = payload?.[0]?.payload?.ts
                    return typeof ts === 'string' ? fmtShort(ts) : ''
                  }}
                  contentStyle={{
                    backgroundColor: '#ffffff',
                    border: '1px solid #e6e9f0',
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                />
                <Legend verticalAlign="bottom" wrapperStyle={{ fontSize: 12, paddingTop: 8 }} />
                {domains.map(([domain], i) => (
                  <Line
                    key={domain}
                    type="monotone"
                    dataKey={domain}
                    stroke={ratingColor(i)}
                    strokeWidth={2}
                    dot={{ r: 3, strokeWidth: 0, fill: ratingColor(i) }}
                    activeDot={{ r: 4 }}
                    connectNulls
                    isAnimationActive={false}
                  />
                ))}
              </LineChart>
            </ResponsiveContainer>
          </div>

          <div className="overflow-x-auto -mx-4 px-4">
            <table className="w-full">
              <thead>
                <tr>
                  <th className={th}>{t('dashboard.table.domain')}</th>
                  <th className={th}>{t('dashboard.table.grade')}</th>
                  <th className={th}>{t('dashboard.table.delta')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-dark-800">
                {domains.map(([domain, pts], i) => {
                  const last = pts[pts.length - 1]
                  const prev = pts.length > 1 ? pts[pts.length - 2] : null
                  const delta =
                    last?.score != null && prev?.score != null ? last.score - prev.score : null
                  return (
                    <tr key={domain} className="hover:bg-dark-800/40">
                      <td className={td}>
                        <span className="inline-flex items-center gap-2">
                          <span
                            className="w-2.5 h-2.5 rounded-full shrink-0"
                            style={{ backgroundColor: ratingColor(i) }}
                          />
                          {domain}
                        </span>
                      </td>
                      <td className={td}>
                        <span
                          className={clsx(
                            'text-xs px-2 py-0.5 rounded-full font-semibold border inline-block w-8 text-center',
                            gradeChipColor(last?.grade),
                          )}
                        >
                          {last?.grade ?? '—'}
                        </span>
                      </td>
                      <td className={td}><DeltaBadge delta={delta} /></td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  )
}
