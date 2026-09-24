import { useEffect, useState } from 'react'
import axios from 'axios'
import clsx from 'clsx'
import { useTranslation } from 'react-i18next'
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import {
  ArrowLeft,
  Cpu,
  Download,
  FileWarning,
  Globe,
  Lock,
  Network,
  Radio,
  Route,
  ScanSearch,
  ShieldAlert,
  Smartphone,
  Users,
  type LucideIcon,
} from 'lucide-react'
import { AssetSummary, Company } from '../types/report'
import { getToken } from '../auth'
import { LinkifyText, PAGE_SIZE, Pager, RiskBadge } from './ui'

interface FindingRow {
  module: string
  finding: string
  risk: 'low' | 'medium' | 'high' | 'critical' | 'info'
  category?: 'vulnerability' | 'misconfiguration' | 'exposure' | 'info'
}

interface DomainFindings {
  domain: string
  scan_id: string | null
  grade: string | null
  score: number | null
  overall_risk: string | null
  completed_at: string | null
  findings: FindingRow[]
}

interface CategoryTotals {
  vulnerability: number
  misconfiguration: number
  exposure: number
}

interface CompanyFindingsResponse {
  company_id: number
  company_name: string
  generated_at: string
  totals: { critical: number; high: number; medium: number; low: number; info: number }
  category_totals: CategoryTotals
  domains: DomainFindings[]
}

// Same categories the scoring model weighs (vulnerability 1.0 / misconfiguration
// 0.6 / exposure 0.25) — `info` findings never affect the score and are
// deliberately left out of this chart.
const CATEGORY_COLORS: Record<keyof CategoryTotals, string> = {
  vulnerability: '#e11d48',
  misconfiguration: '#d97706',
  exposure: '#0891b2',
}

interface Props {
  company: Company
  onBack: () => void
  onOpenReport: (scanId: string) => void
}

const RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

// Full findings list of one domain, severity-sorted (critical first) and
// paginated with its own local page state.
function DomainFindingsList({ findings, domain }: { findings: FindingRow[]; domain: string }) {
  const [page, setPage] = useState(1)
  const sorted = [...findings].sort((a, b) => (RANK[a.risk] ?? 9) - (RANK[b.risk] ?? 9))
  const pageItems = sorted.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)
  const baseUrl = `https://${domain}`
  return (
    <div className="space-y-2">
      <ul className="divide-y divide-dark-800">
        {pageItems.map((f, i) => (
          <li key={i} className="py-2 flex items-start gap-3">
            <RiskBadge risk={f.risk} />
            <span className="text-[10px] px-1.5 py-0.5 rounded-full border bg-dark-900 text-dark-500 border-dark-700 font-mono whitespace-nowrap">
              {f.module}
            </span>
            <LinkifyText text={f.finding} baseUrl={baseUrl} className="text-sm text-dark-200" />
          </li>
        ))}
      </ul>
      <Pager page={page} total={findings.length} onPage={setPage} />
    </div>
  )
}

const gradeChipBig = (g: string | null) =>
  clsx(
    'inline-flex items-center justify-center w-11 h-11 rounded-xl text-lg font-bold border shrink-0',
    g === 'A' && 'bg-emerald-50 text-emerald-700 border-emerald-200',
    g === 'B' && 'bg-cyan-50 text-cyan-700 border-cyan-200',
    g === 'C' && 'bg-amber-50 text-amber-700 border-amber-200',
    g === 'D' && 'bg-orange-50 text-orange-700 border-orange-200',
    g === 'F' && 'bg-red-50 text-red-700 border-red-200',
    !g && 'bg-dark-900 text-dark-500 border-dark-800',
  )

function CategoryBreakdownCard({ totals }: { totals: CategoryTotals }) {
  const { t } = useTranslation()
  const chartData = (['vulnerability', 'misconfiguration', 'exposure'] as const).map((key) => ({
    key,
    label: t(`companyReport.category.${key}`),
    value: totals[key],
  }))
  const total = chartData.reduce((sum, c) => sum + c.value, 0)

  return (
    <div className="card space-y-3">
      <div className="flex items-center gap-2">
        <ShieldAlert className="w-4 h-4 text-cyber-600" />
        <h3 className="text-[15px] font-semibold tracking-tight text-dark-100 flex-1">
          {t('companyReport.categoryBreakdown')}
        </h3>
        <span className="text-xs text-dark-500 font-mono">{total}</span>
      </div>
      <p className="text-xs text-dark-500">{t('companyReport.categoryBreakdownHint')}</p>
      {total === 0 ? (
        <p className="text-sm text-dark-500 text-center py-4">{t('companyReport.categoryNone')}</p>
      ) : (
        <div className="h-32">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData} layout="vertical" margin={{ top: 0, right: 16, bottom: 0, left: 0 }}>
              <XAxis type="number" allowDecimals={false} tick={{ fontSize: 11, fill: '#6b7280' }} tickLine={false} axisLine={{ stroke: '#e6e9f0' }} />
              <YAxis type="category" dataKey="label" width={110} tick={{ fontSize: 11, fill: '#1c2740' }} tickLine={false} axisLine={false} />
              <Tooltip
                cursor={{ fill: '#f8fafc' }}
                contentStyle={{ backgroundColor: '#ffffff', border: '1px solid #e6e9f0', borderRadius: 8, fontSize: 12 }}
              />
              <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={18} isAnimationActive={false}>
                {chartData.map((c) => (
                  <Cell key={c.key} fill={CATEGORY_COLORS[c.key]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  )
}

const ASSET_CARDS: { key: keyof AssetSummary; labelKey: string; icon: LucideIcon }[] = [
  { key: 'subdomains', labelKey: 'subdomains', icon: Globe },
  { key: 'ips', labelKey: 'ips', icon: Network },
  { key: 'endpoints', labelKey: 'endpoints', icon: Route },
  { key: 'technologies', labelKey: 'technologies', icon: Cpu },
  { key: 'admin_panels', labelKey: 'admin_panels', icon: Lock },
  { key: 'exposed_files', labelKey: 'exposed_files', icon: FileWarning },
  { key: 'open_ports', labelKey: 'ports', icon: Radio },
  { key: 'apps', labelKey: 'apps', icon: Smartphone },
  { key: 'neighbors', labelKey: 'neighbors', icon: Users },
]

export default function CompanyReportView({ company, onBack, onOpenReport }: Props) {
  const { t } = useTranslation()
  const [data, setData] = useState<CompanyFindingsResponse | null>(null)
  const [assets, setAssets] = useState<AssetSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [downloadingPdf, setDownloadingPdf] = useState(false)

  const handleDownloadPdf = async () => {
    setDownloadingPdf(true)
    try {
      const res = await fetch(`/api/companies/${company.id}/report.pdf`, {
        headers: { Authorization: `Bearer ${getToken() ?? ''}` },
      })
      if (!res.ok) {
        let detail = `HTTP ${res.status}`
        try { const j = await res.json(); detail = j.detail || detail } catch {}
        throw new Error(detail)
      }
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `sauron_${company.name.replace(/[^a-z0-9]+/gi, '_')}.pdf`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      alert(t('report.pdfError', { msg: e instanceof Error ? e.message : String(e) }))
    } finally {
      setDownloadingPdf(false)
    }
  }

  const load = async () => {
    setLoading(true)
    setError('')
    const [findingsRes, assetsRes] = await Promise.allSettled([
      axios.get<CompanyFindingsResponse>(`/api/companies/${company.id}/findings`),
      axios.get<{ summary: AssetSummary }>(`/api/companies/${company.id}/assets`),
    ])
    if (findingsRes.status === 'fulfilled') {
      setData(findingsRes.value.data)
    } else {
      const err = findingsRes.reason
      setError(axios.isAxiosError(err) ? err.response?.data?.detail || err.message : t('companyReport.loadError'))
    }
    if (assetsRes.status === 'fulfilled') {
      setAssets(assetsRes.value.data.summary)
    }
    setLoading(false)
  }

  useEffect(() => { load() }, [company.id]) // eslint-disable-line react-hooks/exhaustive-deps

  const scanned = data?.domains.filter((d) => d.scan_id) ?? []
  const scores = scanned.map((d) => d.score).filter((s): s is number => s != null)
  const avgScore = scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : null

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-3">
        <button onClick={onBack} className="btn-secondary inline-flex items-center gap-1.5">
          <ArrowLeft className="w-4 h-4" /> {t('common.back')}
        </button>
        <div className="flex-1 min-w-[200px]">
          <h2 className="text-xl font-semibold tracking-tight text-dark-100">{t('companyReport.reportTitle', { name: company.name })}</h2>
          {data && (
            <div className="text-xs text-dark-500">
              {t('companyReport.latestPerDomain')} · {t('companyReport.generated', { date: new Date(data.generated_at).toLocaleString() })}
              {avgScore != null && (
                <>
                  {' · '}{t('companyReport.averageScore')}{' '}
                  <span className="font-mono font-semibold text-dark-200">{avgScore}/100</span>{' '}
                  {t('companyReport.acrossScanned', { count: scanned.length })}
                </>
              )}
            </div>
          )}
        </div>
        {data && (
          <div className="flex items-center gap-2">
            {(['critical', 'high', 'medium', 'low', 'info'] as const).map((r) => (
              <span key={r} className="inline-flex items-center gap-1.5 text-xs">
                <RiskBadge risk={r} />
                <span className="font-mono font-semibold text-dark-200">{data.totals[r]}</span>
              </span>
            ))}
          </div>
        )}
        <button
          onClick={handleDownloadPdf}
          disabled={downloadingPdf}
          className="btn-secondary inline-flex items-center gap-1.5 disabled:opacity-50"
        >
          <Download className="w-4 h-4" /> {t('companyReport.downloadPdf')}
        </button>
      </div>

      {error && (
        <div className="card border-red-200 bg-red-50 text-red-700 text-sm">{error}</div>
      )}

      {loading && !data && (
        <div className="space-y-4">
          {[0, 1].map((i) => (
            <div key={i} className="card space-y-3 animate-pulse">
              <div className="flex items-center gap-3">
                <div className="w-11 h-11 rounded-xl bg-dark-800" />
                <div className="h-4 w-40 rounded bg-dark-800" />
              </div>
              <div className="h-3 w-full rounded bg-dark-800" />
              <div className="h-3 w-2/3 rounded bg-dark-800" />
            </div>
          ))}
        </div>
      )}

      {data && scanned.length === 0 && !error && (
        <div className="card text-center text-dark-500 py-12 text-sm space-y-3">
          <ScanSearch className="w-8 h-8 mx-auto text-dark-600" />
          <p>{t('companyReport.noScans')}</p>
          <p className="text-xs">{t('companyReport.noScansHint')}</p>
        </div>
      )}

      {data && scanned.length > 0 && <CategoryBreakdownCard totals={data.category_totals} />}

      {/* Per-domain cards */}
      {data?.domains.map((d) => {
        const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
        for (const f of d.findings) {
          if (f.risk in counts) counts[f.risk]++
        }
        return (
          <div key={d.domain} className="card space-y-3">
            <div className="flex items-center gap-3 flex-wrap">
              <span className={gradeChipBig(d.grade)}>{d.grade ?? '—'}</span>
              <div>
                <div className="font-mono font-semibold text-dark-100">{d.domain}</div>
                <div className="text-xs text-dark-500">
                  {d.score != null && <span className="font-mono">{d.score}/100 · </span>}
                  {d.completed_at
                    ? t('companyReport.scannedAt', { date: new Date(d.completed_at).toLocaleString() })
                    : t('companyReport.neverScanned')}
                </div>
              </div>
              {d.overall_risk && <RiskBadge risk={d.overall_risk as FindingRow['risk']} />}
              <span className="flex-1" />
              {d.scan_id && (
                <div className="flex items-center gap-2">
                  {(['critical', 'high', 'medium', 'low', 'info'] as const).map((r) => (
                    <span key={r} className="inline-flex items-center gap-1 text-[11px]" title={`${counts[r]} ${r}`}>
                      <RiskBadge risk={r} />
                      <span className="font-mono font-semibold text-dark-200">{counts[r]}</span>
                    </span>
                  ))}
                </div>
              )}
              {d.scan_id && (
                <button
                  onClick={() => onOpenReport(d.scan_id!)}
                  className="btn-secondary inline-flex items-center gap-1.5"
                >
                  <FileWarning className="w-4 h-4" /> {t('companyReport.viewFullReport')}
                </button>
              )}
            </div>
            {!d.scan_id ? (
              <p className="text-sm text-dark-500">{t('companyReport.noDomainScans')}</p>
            ) : d.findings.length === 0 ? (
              <p className="text-sm text-dark-500">{t('companyReport.noFindings')}</p>
            ) : (
              <DomainFindingsList findings={d.findings} domain={d.domain} />
            )}
          </div>
        )
      })}

      {/* Asset inventory summary */}
      {assets && (
        <div className="card space-y-3">
          <div className="flex items-center gap-2">
            <h3 className="text-[15px] font-semibold tracking-tight text-dark-100 flex-1">
              {t('companyReport.assetSummary')}
            </h3>
            {assets.new_last_cycle > 0 && (
              <span className="text-[10px] px-1.5 py-0.5 rounded-full font-semibold border bg-emerald-50 text-emerald-700 border-emerald-200">
                {t('common.newItems', { count: assets.new_last_cycle })}
              </span>
            )}
          </div>
          <div className="grid grid-cols-3 sm:grid-cols-5 gap-3">
            {ASSET_CARDS.map(({ key, labelKey, icon: Icon }) => (
              <div key={key} className="rounded-lg border border-dark-800 bg-dark-900/40 px-3 py-2.5">
                <div className="flex items-center gap-1.5 text-dark-500 text-[11px]">
                  <Icon className="w-3.5 h-3.5" />
                  {t(`dashboard.categories.${labelKey}`)}
                </div>
                <div className="text-lg font-bold font-mono text-dark-100 mt-0.5">
                  {assets[key] ?? 0}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
