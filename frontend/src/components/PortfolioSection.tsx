import { useEffect, useMemo, useState } from 'react'
import axios from 'axios'
import clsx from 'clsx'
import { useTranslation } from 'react-i18next'
import { Line, LineChart, YAxis } from 'recharts'
import { ChevronDown } from 'lucide-react'
import { Company, RatingHistory, RatingPoint } from '../types/report'
import { fmtShort, gradeChipColor, td, th } from './assetTable'
import { DeltaBadge, groupByDomain } from './RatingTrend'

const SPARK_POINTS = 10

interface Props {
  companies: Company[]
  onOpenCompany: (company: Company) => void
}

interface Row {
  company: Company
  history: RatingHistory | null
}

interface Summary {
  currentScore: number | null
  delta: number | null
  grade: string | null
  lastScan: string | null
  spark: { score: number }[]
}

function summarize(points: RatingPoint[] | undefined): Summary {
  const domains = groupByDomain(points)
  const latest = domains.map(([, pts]) => pts[pts.length - 1])
  const scores = latest.map((p) => p.score).filter((s): s is number => typeof s === 'number')
  const currentScore = scores.length > 0
    ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length)
    : null

  const prevScores = domains
    .map(([, pts]) => (pts.length > 1 ? pts[pts.length - 2].score : null))
    .filter((s): s is number => typeof s === 'number')
  const delta = currentScore != null && prevScores.length > 0
    ? currentScore - Math.round(prevScores.reduce((a, b) => a + b, 0) / prevScores.length)
    : null

  const mostRecent = [...latest].sort((a, b) =>
    (b.completed_at ?? '').localeCompare(a.completed_at ?? ''),
  )[0]

  // Company score per scan moment (avg across domains), last N moments
  const byTs = new Map<string, number[]>()
  for (const p of points ?? []) {
    if (!p.completed_at || typeof p.score !== 'number') continue
    const arr = byTs.get(p.completed_at) ?? []
    arr.push(p.score)
    byTs.set(p.completed_at, arr)
  }
  const spark = [...byTs.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .slice(-SPARK_POINTS)
    .map(([, ss]) => ({ score: Math.round(ss.reduce((a, b) => a + b, 0) / ss.length) }))

  return {
    currentScore,
    delta,
    grade: mostRecent?.grade ?? null,
    lastScan: mostRecent?.completed_at ?? null,
    spark,
  }
}

function Sparkline({ data }: { data: { score: number }[] }) {
  if (data.length === 0) return <span className="text-dark-400 text-xs">—</span>
  return (
    <LineChart width={110} height={30} data={data} margin={{ top: 4, right: 2, bottom: 4, left: 2 }}>
      <YAxis hide domain={[0, 100]} />
      <Line
        type="monotone"
        dataKey="score"
        stroke="#0891b2"
        strokeWidth={1.5}
        dot={data.length === 1 ? { r: 2.5, strokeWidth: 0, fill: '#0891b2' } : false}
        isAnimationActive={false}
      />
    </LineChart>
  )
}

export default function PortfolioSection({ companies, onOpenCompany }: Props) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(true)
  const [rows, setRows] = useState<Row[]>([])
  const [loading, setLoading] = useState(true)

  const idsKey = companies.map((c) => c.id).join(',')

  useEffect(() => {
    if (companies.length === 0) {
      setRows([])
      setLoading(false)
      return
    }
    let cancelled = false
    setLoading(true)
    Promise.allSettled(
      companies.map(async (company) => {
        const { data } = await axios.get<RatingHistory>(`/api/companies/${company.id}/rating-history`)
        return { company, history: data }
      }),
    ).then((results) => {
      if (cancelled) return
      setRows(results.map((r, i) =>
        r.status === 'fulfilled' ? r.value : { company: companies[i], history: null },
      ))
      setLoading(false)
    })
    return () => { cancelled = true }
    // refetch only when the company id set changes (not on every render)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [idsKey])

  const summaries = useMemo(
    () => new Map(rows.map((r) => [r.company.id, summarize(r.history?.points)])),
    [rows],
  )
  const failed = rows.filter((r) => r.history == null).map((r) => r.company.name)

  return (
    <div className="card space-y-3">
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center gap-2 text-left"
        title={open ? t('dashboard.collapse') : t('dashboard.expand')}
      >
        <ChevronDown
          className={clsx('w-4 h-4 text-dark-500 transition-transform duration-150', !open && '-rotate-90')}
        />
        <h3 className="text-[15px] font-semibold tracking-tight text-dark-100 flex-1">
          {t('dashboard.portfolio')}
        </h3>
        <span className="text-xs text-dark-500 font-mono">{companies.length}</span>
      </button>

      {open && (
        loading ? (
          <p className="text-center text-dark-500 py-8 text-sm animate-pulse">
            {t('dashboard.portfolioLoading')}
          </p>
        ) : (
          <>
            {failed.length > 0 && (
              <p className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">
                {t('dashboard.portfolioPartial', { names: failed.join(', ') })}
              </p>
            )}
            <div className="overflow-x-auto -mx-4 px-4">
              <table className="w-full">
                <thead>
                  <tr>
                    <th className={th}>{t('dashboard.table.company')}</th>
                    <th className={th}>{t('dashboard.table.domains')}</th>
                    <th className={th}>{t('dashboard.table.assets')}</th>
                    <th className={th}>{t('dashboard.table.grade')}</th>
                    <th className={th}>{t('dashboard.table.score')}</th>
                    <th className={th}>{t('dashboard.table.delta')}</th>
                    <th className={th}>{t('dashboard.table.lastScan')}</th>
                    <th className={th}>{t('dashboard.table.trend')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-dark-800">
                  {rows.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="px-3 py-8 text-center text-dark-500 text-sm">
                        {t('dashboard.noCompaniesYet')}
                      </td>
                    </tr>
                  ) : rows.map((r) => {
                    const s = summaries.get(r.company.id)
                    const noHistory = !s || s.currentScore == null
                    return (
                      <tr
                        key={r.company.id}
                        onClick={() => onOpenCompany(r.company)}
                        className="hover:bg-dark-800/40 cursor-pointer"
                        title={t('dashboard.filterToCompanyTitle', { name: r.company.name })}
                      >
                        <td className="px-3 py-2">
                          <span className="text-cyber-700 font-semibold break-all">{r.company.name}</span>
                        </td>
                        <td className={td}>{r.company.domains.length}</td>
                        <td className={clsx(td, 'font-mono font-semibold')}>{r.company.assets_count ?? '—'}</td>
                        <td className={td}>
                          {noHistory ? (
                            <span className="text-dark-400 text-xs">{t('dashboard.portfolioNoHistory')}</span>
                          ) : (
                            <span
                              className={clsx(
                                'text-xs px-2 py-0.5 rounded-full font-semibold border inline-block w-8 text-center',
                                gradeChipColor(s.grade),
                              )}
                            >
                              {s.grade ?? '—'}
                            </span>
                          )}
                        </td>
                        <td className={td}>{s?.currentScore ?? '—'}</td>
                        <td className={td}><DeltaBadge delta={s?.delta ?? null} /></td>
                        <td className={clsx(td, 'whitespace-nowrap')} title={s?.lastScan ?? undefined}>
                          {s?.lastScan ? fmtShort(s.lastScan) : '—'}
                        </td>
                        <td className={td}><Sparkline data={s?.spark ?? []} /></td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </>
        )
      )}
    </div>
  )
}
