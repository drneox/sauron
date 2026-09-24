import { Fragment, useEffect, useMemo, useState } from 'react'
import axios from 'axios'
import clsx from 'clsx'
import { useTranslation } from 'react-i18next'
import {
  ArrowLeft,
  Check,
  ChevronDown,
  ChevronRight,
  ClipboardCheck,
  RefreshCw,
  ShieldCheck,
  Undo2,
} from 'lucide-react'
import { Company } from '../types/report'
import { PAGE_SIZE, Pager, RiskBadge } from './ui'

export interface RemediationFinding {
  id: number
  module: string
  text: string
  risk: 'low' | 'medium' | 'high' | 'critical' | 'info'
  category: string
  frameworks: string[]
  status: 'open' | 'accepted' | 'fixed'
  notes: string
  first_seen_scan_id: string
  last_seen_scan_id: string
  first_seen_at: string | null
  last_seen_at: string | null
  fixed_at: string | null
}

interface RemediationDomain {
  domain: string
  counts: Record<string, number>
  findings: RemediationFinding[]
}

interface RemediationsResponse {
  company_id: number
  company_name: string
  generated_at: string
  totals: {
    open: number
    accepted: number
    fixed: number
    by_risk: Record<string, number>
    auto_fixed_week: number
  }
  domains: RemediationDomain[]
}

interface Props {
  company: Company
  readOnly?: boolean
  onBack: () => void
}

type StatusFilter = 'all' | 'open' | 'accepted' | 'fixed'

type Row = RemediationFinding & { domain: string }

const STATUS_STYLE: Record<string, string> = {
  open: 'bg-red-50 text-red-700 border-red-200',
  accepted: 'bg-amber-50 text-amber-700 border-amber-200',
  fixed: 'bg-emerald-50 text-emerald-700 border-emerald-200',
}

const FRAMEWORK_STYLE = 'bg-violet-50 text-violet-700 border-violet-200'

const fmtDate = (iso: string | null) => (iso ? new Date(iso).toLocaleDateString() : '—')

export default function RemediationView({ company, readOnly = false, onBack }: Props) {
  const { t } = useTranslation()
  const [data, setData] = useState<RemediationsResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState<StatusFilter>('open')
  const [page, setPage] = useState(1)
  const [expanded, setExpanded] = useState<number | null>(null)
  const [busy, setBusy] = useState<number | null>(null)

  const load = async () => {
    setLoading(true)
    setError('')
    try {
      const { data } = await axios.get<RemediationsResponse>(`/api/companies/${company.id}/remediations`)
      setData(data)
    } catch (err) {
      setError(axios.isAxiosError(err) ? err.response?.data?.detail || err.message : t('remediation.loadError'))
    }
    setLoading(false)
  }

  useEffect(() => { load() }, [company.id]) // eslint-disable-line react-hooks/exhaustive-deps

  const rows = useMemo<Row[]>(() => {
    if (!data) return []
    return data.domains.flatMap((d) => d.findings.map((f) => ({ ...f, domain: d.domain })))
  }, [data])

  const filtered = rows.filter((r) => filter === 'all' || r.status === filter)
  const pageItems = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  const updateStatus = async (row: Row, status: 'accepted' | 'fixed' | 'open') => {
    const confirmMsg = status === 'fixed'
      ? t('remediation.confirmFixed', { text: row.text.slice(0, 120) })
      : status === 'accepted'
        ? t('remediation.confirmAccept', { text: row.text.slice(0, 120) })
        : t('remediation.confirmReopen', { text: row.text.slice(0, 120) })
    if (!window.confirm(confirmMsg)) return
    setBusy(row.id)
    try {
      const { data: updated } = await axios.put<RemediationFinding>(`/api/findings/${row.id}/status`, { status })
      setData((prev) => {
        if (!prev) return prev
        const before = prev.domains.flatMap((d) => d.findings).find((f) => f.id === row.id)
        const totals = { ...prev.totals }
        if (before && before.status !== updated.status) {
          totals[before.status] = Math.max(0, (totals[before.status] ?? 0) - 1)
          totals[updated.status] = (totals[updated.status] ?? 0) + 1
        }
        return {
          ...prev,
          totals,
          domains: prev.domains.map((d) => ({
            ...d,
            findings: d.findings.map((f) => (f.id === row.id ? { ...f, ...updated } : f)),
          })),
        }
      })
    } catch (err) {
      alert(axios.isAxiosError(err) ? err.response?.data?.detail || err.message : t('remediation.updateError'))
    }
    setBusy(null)
  }

  const FILTERS: { key: StatusFilter; label: string }[] = [
    { key: 'all', label: t('remediation.filterAll') },
    { key: 'open', label: t('remediation.status.open') },
    { key: 'accepted', label: t('remediation.status.accepted') },
    { key: 'fixed', label: t('remediation.status.fixed') },
  ]

  const th = 'text-left text-[10px] font-semibold text-dark-500 uppercase tracking-wider px-3 py-2'

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-3">
        <button onClick={onBack} className="btn-secondary inline-flex items-center gap-1.5">
          <ArrowLeft className="w-4 h-4" /> {t('common.back')}
        </button>
        <div className="flex-1 min-w-[200px]">
          <h2 className="text-xl font-semibold tracking-tight text-dark-100 flex items-center gap-2">
            <ClipboardCheck className="w-5 h-5 text-cyber-600" />
            {t('remediation.title', { name: company.name })}
          </h2>
          {data && (
            <div className="text-xs text-dark-500">
              {t('remediation.counts', {
                open: data.totals.open,
                accepted: data.totals.accepted,
                fixed: data.totals.auto_fixed_week,
              })}
            </div>
          )}
        </div>
        {data && (
          <div className="flex items-center gap-2">
            {(['critical', 'high', 'medium', 'low', 'info'] as const).map((r) => (
              <span key={r} className="inline-flex items-center gap-1.5 text-xs" title={t('remediation.openByRisk')}>
                <RiskBadge risk={r} />
                <span className="font-mono font-semibold text-dark-200">{data.totals.by_risk[r] ?? 0}</span>
              </span>
            ))}
          </div>
        )}
        <button onClick={load} disabled={loading} className="btn-secondary disabled:cursor-wait">
          <RefreshCw className={clsx('w-3.5 h-3.5', loading && 'animate-spin')} />
          {t('dashboard.refresh')}
        </button>
      </div>

      {error && <div className="card border-red-200 bg-red-50 text-red-700 text-sm">{error}</div>}

      {/* Status filter */}
      <div className="flex items-center gap-1.5">
        {FILTERS.map((f) => (
          <button
            key={f.key}
            onClick={() => { setFilter(f.key); setPage(1) }}
            className={clsx(
              'text-xs px-3 py-1.5 border rounded-lg transition-colors duration-150',
              filter === f.key
                ? 'bg-cyber-50 border-cyber-400 text-cyber-700 font-medium'
                : 'bg-white hover:bg-dark-900 border-dark-700 text-dark-200',
            )}
          >
            {f.label}
            {data && f.key !== 'all' && (
              <span className="ml-1.5 font-mono text-[10px] text-dark-500">
                {f.key === 'open' ? data.totals.open : f.key === 'accepted' ? data.totals.accepted : data.totals.fixed}
              </span>
            )}
          </button>
        ))}
      </div>

      {loading && !data && (
        <div className="card text-center text-dark-500 py-12 text-sm animate-pulse">{t('common.loading')}</div>
      )}

      {data && filtered.length === 0 && !loading && (
        <div className="card text-center text-dark-500 py-12 text-sm space-y-2">
          <ShieldCheck className="w-8 h-8 mx-auto text-dark-600" />
          <p>{t('remediation.empty')}</p>
        </div>
      )}

      {data && filtered.length > 0 && (
        <div className="card p-0 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-dark-900/40 border-b border-dark-800">
                <tr>
                  <th className={th}></th>
                  <th className={th}>{t('remediation.col.risk')}</th>
                  <th className={th}>{t('remediation.col.category')}</th>
                  <th className={th}>{t('remediation.col.finding')}</th>
                  <th className={th}>{t('remediation.col.module')}</th>
                  <th className={th}>{t('remediation.col.domain')}</th>
                  <th className={th}>{t('remediation.col.frameworks')}</th>
                  <th className={th}>{t('remediation.col.firstSeen')}</th>
                  <th className={th}>{t('remediation.col.lastSeen')}</th>
                  <th className={th}>{t('remediation.col.status')}</th>
                  {!readOnly && <th className={th}></th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-dark-800">
                {pageItems.map((row) => (
                  <Fragment key={row.id}>
                    <tr
                      onClick={() => setExpanded(expanded === row.id ? null : row.id)}
                      className="hover:bg-dark-900/40 cursor-pointer transition-colors duration-100"
                    >
                      <td className="px-2 py-2 text-dark-500">
                        {expanded === row.id ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                      </td>
                      <td className="px-3 py-2"><RiskBadge risk={row.risk} /></td>
                      <td className="px-3 py-2">
                        <span className="text-[10px] px-1.5 py-0.5 rounded-full border bg-dark-900 text-dark-500 border-dark-700 whitespace-nowrap">
                          {t(`remediation.category.${row.category}`, { defaultValue: row.category })}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-xs text-dark-200 max-w-md">
                        <span className="line-clamp-2">{row.text}</span>
                      </td>
                      <td className="px-3 py-2">
                        <span className="text-[10px] px-1.5 py-0.5 rounded-full border bg-dark-900 text-dark-500 border-dark-700 font-mono whitespace-nowrap">
                          {row.module}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-xs font-mono text-dark-300 whitespace-nowrap">{row.domain}</td>
                      <td className="px-3 py-2">
                        <div className="flex flex-wrap gap-1">
                          {(row.frameworks ?? []).map((fw) => (
                            <span key={fw} className={clsx('text-[10px] px-1.5 py-0.5 rounded-full border font-medium whitespace-nowrap', FRAMEWORK_STYLE)}>
                              {fw}
                            </span>
                          ))}
                          {(row.frameworks ?? []).length === 0 && <span className="text-dark-600 text-xs">—</span>}
                        </div>
                      </td>
                      <td className="px-3 py-2 text-xs text-dark-500 whitespace-nowrap">{fmtDate(row.first_seen_at)}</td>
                      <td className="px-3 py-2 text-xs text-dark-500 whitespace-nowrap">{fmtDate(row.last_seen_at)}</td>
                      <td className="px-3 py-2">
                        <span className={clsx('text-[10px] px-2 py-0.5 rounded-full border font-semibold uppercase tracking-wide whitespace-nowrap', STATUS_STYLE[row.status])}>
                          {t(`remediation.status.${row.status}`)}
                        </span>
                      </td>
                      {!readOnly && (
                        <td className="px-3 py-2 whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                          <div className="flex items-center gap-1">
                            {row.status === 'open' && (
                              <>
                                <button
                                  onClick={() => updateStatus(row, 'accepted')}
                                  disabled={busy === row.id}
                                  className="text-[11px] px-2 py-1 rounded-md border border-dark-700 text-dark-300 hover:bg-amber-50 hover:text-amber-700 hover:border-amber-200 transition-colors duration-150 disabled:opacity-40"
                                >
                                  {t('remediation.accept')}
                                </button>
                                <button
                                  onClick={() => updateStatus(row, 'fixed')}
                                  disabled={busy === row.id}
                                  className="text-[11px] px-2 py-1 rounded-md border border-dark-700 text-dark-300 hover:bg-emerald-50 hover:text-emerald-700 hover:border-emerald-200 transition-colors duration-150 disabled:opacity-40 inline-flex items-center gap-1"
                                >
                                  <Check className="w-3 h-3" /> {t('remediation.markFixed')}
                                </button>
                              </>
                            )}
                            {row.status !== 'open' && (
                              <button
                                onClick={() => updateStatus(row, 'open')}
                                disabled={busy === row.id}
                                className="text-[11px] px-2 py-1 rounded-md border border-dark-700 text-dark-300 hover:bg-red-50 hover:text-red-700 hover:border-red-200 transition-colors duration-150 disabled:opacity-40 inline-flex items-center gap-1"
                              >
                                <Undo2 className="w-3 h-3" /> {t('remediation.reopen')}
                              </button>
                            )}
                          </div>
                        </td>
                      )}
                    </tr>
                    {expanded === row.id && (
                      <tr key={`${row.id}-detail`} className="bg-dark-900/30">
                        <td colSpan={readOnly ? 10 : 11} className="px-6 py-3">
                          <div className="text-xs space-y-1.5">
                            <p className="text-dark-200 leading-relaxed">{row.text}</p>
                            <div className="flex flex-wrap gap-x-6 gap-y-1 text-dark-500">
                              <span>{t('remediation.col.firstSeen')}: <span className="font-mono">{row.first_seen_at ? new Date(row.first_seen_at).toLocaleString() : '—'}</span></span>
                              <span>{t('remediation.col.lastSeen')}: <span className="font-mono">{row.last_seen_at ? new Date(row.last_seen_at).toLocaleString() : '—'}</span></span>
                              {row.fixed_at && (
                                <span>{t('remediation.fixedAt')}: <span className="font-mono">{new Date(row.fixed_at).toLocaleString()}</span></span>
                              )}
                              <span>Scan: <span className="font-mono">{row.last_seen_scan_id.slice(0, 8)}…</span></span>
                            </div>
                            {row.notes && <p className="text-dark-400 italic">{t('remediation.notes')}: {row.notes}</p>}
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
          <div className="px-3 py-2 border-t border-dark-800 flex justify-end">
            <Pager page={page} total={filtered.length} onPage={setPage} />
          </div>
        </div>
      )}
    </div>
  )
}
