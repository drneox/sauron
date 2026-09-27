import { Fragment, useEffect, useMemo, useState } from 'react'
import axios from 'axios'
import clsx from 'clsx'
import { useTranslation } from 'react-i18next'
import {
  ArrowLeft,
  Bot,
  Check,
  ChevronDown,
  ChevronRight,
  ClipboardCheck,
  RefreshCw,
  Search,
  ShieldCheck,
  Undo2,
} from 'lucide-react'
import { Company } from '../types/report'
import { LinkifyText, PAGE_SIZE, Pager, RiskBadge } from './ui'

export interface RemediationFinding {
  id: number
  module: string
  text: string
  /** The specific host the finding is about (may be a subdomain of `domain`
   * below, when it came from a fanned-out host scan); null when no single
   * host applies (e.g. a secret-verification note). */
  host: string | null
  /** Extra structured context the module's own result had (e.g. a leak
   * source, an HTTP status/size, a response snippet) — plain key/value,
   * shown in the expanded row when the one-line text isn't enough. */
  evidence: Record<string, string | number | string[]> | null
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

interface LeakcheckResult {
  status: 'ok' | 'not_configured' | 'error'
  found?: number
  records?: Record<string, unknown>[]
  error?: string
}

// One row's worth of manual LeakCheck lookup state, keyed by finding id so
// each expanded row remembers its own term/result independently.
function LeakcheckLookup({ available }: { available: boolean }) {
  const { t } = useTranslation()
  const [term, setTerm] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<LeakcheckResult | null>(null)

  const run = async () => {
    const clean = term.trim()
    if (!clean) return
    setLoading(true)
    setResult(null)
    try {
      const { data } = await axios.get<LeakcheckResult>('/api/leakcheck/query', { params: { term: clean } })
      setResult(data)
    } catch (err) {
      setResult({ status: 'error', error: axios.isAxiosError(err) ? err.response?.data?.detail || err.message : String(err) })
    }
    setLoading(false)
  }

  if (!available) {
    return <p className="text-[11px] text-dark-500 italic">{t('remediation.leakcheck.unavailable')}</p>
  }

  return (
    <div className="rounded-md bg-dark-900/50 border border-dark-800 px-3 py-2 mt-1 space-y-2">
      <div className="flex items-center gap-1.5">
        <Search className="w-3.5 h-3.5 text-dark-500 shrink-0" />
        <span className="text-[11px] text-dark-500">{t('remediation.leakcheck.label')}</span>
      </div>
      <div className="flex items-center gap-1.5" onClick={(e) => e.stopPropagation()}>
        <input
          type="text"
          value={term}
          onChange={(e) => setTerm(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') run() }}
          placeholder={t('remediation.leakcheck.placeholder')}
          spellCheck={false}
          className="flex-1 min-w-0 bg-white border border-dark-700 rounded-lg px-2.5 py-1 text-xs font-mono text-dark-200 placeholder:text-dark-600 focus:outline-none focus:border-cyber-500"
        />
        <button
          onClick={run}
          disabled={loading || !term.trim()}
          className="btn-secondary text-[11px] px-2.5 py-1 disabled:opacity-50 disabled:cursor-wait"
        >
          {loading ? t('common.loading') : t('remediation.leakcheck.check')}
        </button>
      </div>
      <p className="text-[10px] text-dark-600">{t('remediation.leakcheck.disclaimer')}</p>
      {result?.status === 'not_configured' && (
        <p className="text-[11px] text-amber-600">{t('remediation.leakcheck.notConfigured')}</p>
      )}
      {result?.status === 'error' && (
        <p className="text-[11px] text-red-600">{t('remediation.leakcheck.error', { msg: result.error })}</p>
      )}
      {result?.status === 'ok' && (result.found ?? 0) === 0 && (
        <p className="text-[11px] text-emerald-600">{t('remediation.leakcheck.clean')}</p>
      )}
      {result?.status === 'ok' && (result.records ?? []).length > 0 && (
        <div className="space-y-1.5">
          {(result.records ?? []).map((rec, i) => (
            <dl key={i} className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-0.5 border border-dark-800 rounded px-2 py-1.5">
              {Object.entries(rec).map(([key, value]) => (
                <Fragment key={key}>
                  <dt className="text-dark-500 whitespace-nowrap">{key}</dt>
                  <dd className="text-dark-200 font-mono break-all">
                    {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                  </dd>
                </Fragment>
              ))}
            </dl>
          ))}
        </div>
      )}
    </div>
  )
}

type StatusFilter = 'all' | 'open' | 'accepted' | 'fixed'
type CategoryFilter = 'all' | 'vulnerability' | 'misconfiguration' | 'exposure' | 'info'

type Row = RemediationFinding & { domain: string }

// The agent tags each finding with the tool that produced it ("[mine_js] JS
// bundle exposes..."); split that off so the text reads naturally and the
// tool becomes its own badge instead of bracket noise in the sentence.
const AGENT_TOOL_RE = /^\[(\w+)\] (.*)$/s
function splitAgentTool(module: string, text: string): { tool: string | null; text: string } {
  if (module !== 'agent') return { tool: null, text }
  const m = AGENT_TOOL_RE.exec(text)
  return m ? { tool: m[1], text: m[2] } : { tool: null, text }
}

/** One evidence value: a short list inlines, a longer one collapses behind
 * "+N more"; a plain scalar just renders as text. */
function EvidenceValue({ value }: { value: string | number | string[] }) {
  const { t } = useTranslation()
  const [expanded, setExpanded] = useState(false)
  if (!Array.isArray(value)) return <>{value}</>
  const shown = expanded ? value : value.slice(0, 8)
  const hidden = value.length - shown.length
  return (
    <span>
      {shown.join(', ')}
      {hidden > 0 && (
        <button
          type="button"
          onClick={(e) => { e.stopPropagation(); setExpanded(true) }}
          className="ml-1 text-cyber-700 hover:underline font-sans"
        >
          {t('remediation.evidenceMore', { count: hidden })}
        </button>
      )}
      {expanded && value.length > 8 && (
        <button
          type="button"
          onClick={(e) => { e.stopPropagation(); setExpanded(false) }}
          className="ml-1 text-cyber-700 hover:underline font-sans"
        >
          {t('remediation.evidenceLess')}
        </button>
      )}
    </span>
  )
}

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
  const [leakcheckAvailable, setLeakcheckAvailable] = useState(false)
  const [filter, setFilter] = useState<StatusFilter>('open')
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilter>('all')
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

  useEffect(() => {
    axios.get<{ leakcheck?: { configured: boolean } }>('/api/settings')
      .then(({ data }) => setLeakcheckAvailable(data.leakcheck?.configured === true))
      .catch(() => setLeakcheckAvailable(false))
  }, [])

  const rows = useMemo<Row[]>(() => {
    if (!data) return []
    return data.domains.flatMap((d) => d.findings.map((f) => ({ ...f, domain: d.domain })))
  }, [data])

  const filtered = rows.filter((r) => (filter === 'all' || r.status === filter)
    && (categoryFilter === 'all' || r.category === categoryFilter))
  const categoryCounts = rows.reduce<Record<string, number>>((acc, r) => {
    if (filter === 'all' || r.status === filter) acc[r.category] = (acc[r.category] ?? 0) + 1
    return acc
  }, {})
  const pageItems = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  const updateStatus = async (row: Row, status: 'accepted' | 'fixed' | 'open') => {
    const plainText = splitAgentTool(row.module, row.text).text.slice(0, 120)
    const confirmMsg = status === 'fixed'
      ? t('remediation.confirmFixed', { text: plainText })
      : status === 'accepted'
        ? t('remediation.confirmAccept', { text: plainText })
        : t('remediation.confirmReopen', { text: plainText })
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

  const CATEGORY_FILTERS: { key: CategoryFilter; label: string }[] = [
    { key: 'all', label: t('remediation.filterAll') },
    { key: 'vulnerability', label: t('remediation.category.vulnerability') },
    { key: 'misconfiguration', label: t('remediation.category.misconfiguration') },
    { key: 'exposure', label: t('remediation.category.exposure') },
    { key: 'info', label: t('remediation.category.info') },
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
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5">
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
        <div className="flex items-center gap-1.5">
          {CATEGORY_FILTERS.map((f) => (
            <button
              key={f.key}
              title={f.key === 'all' ? undefined : t(`categoryHelp.${f.key}`, { defaultValue: '' })}
              onClick={() => { setCategoryFilter(f.key); setPage(1) }}
              className={clsx(
                'text-xs px-3 py-1.5 border rounded-lg transition-colors duration-150',
                categoryFilter === f.key
                  ? 'bg-violet-50 border-violet-400 text-violet-700 font-medium'
                  : 'bg-white hover:bg-dark-900 border-dark-700 text-dark-200',
              )}
            >
              {f.label}
              {f.key !== 'all' && (
                <span className="ml-1.5 font-mono text-[10px] text-dark-500">{categoryCounts[f.key] ?? 0}</span>
              )}
            </button>
          ))}
        </div>
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
                {pageItems.map((row) => {
                  const agentTag = splitAgentTool(row.module, row.text)
                  return (
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
                        <button
                          type="button"
                          onClick={(e) => { e.stopPropagation(); setCategoryFilter(row.category as CategoryFilter); setPage(1) }}
                          title={t(`categoryHelp.${row.category}`, { defaultValue: '' })}
                          className="text-[10px] px-1.5 py-0.5 rounded-full border bg-dark-900 text-dark-500 border-dark-700 whitespace-nowrap cursor-help hover:bg-violet-50 hover:text-violet-700 hover:border-violet-300"
                        >
                          {t(`remediation.category.${row.category}`, { defaultValue: row.category })}
                        </button>
                      </td>
                      <td className="px-3 py-2 text-xs text-dark-200 max-w-md">
                        <span className="line-clamp-2">
                          <LinkifyText text={agentTag.text} baseUrl={`https://${row.host ?? row.domain}`} />
                        </span>
                      </td>
                      <td className="px-3 py-2">
                        <div className="flex flex-wrap items-center gap-1">
                          {agentTag.tool && (
                            <span
                              title={t('remediation.agentFoundThis')}
                              className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded-full border bg-violet-50 text-violet-700 border-violet-200 whitespace-nowrap"
                            >
                              <Bot className="w-3 h-3" /> {t('remediation.agent')}
                            </span>
                          )}
                          <span className="text-[10px] px-1.5 py-0.5 rounded-full border bg-dark-900 text-dark-500 border-dark-700 font-mono whitespace-nowrap">
                            {agentTag.tool ?? row.module}
                          </span>
                        </div>
                      </td>
                      <td className="px-3 py-2 text-xs font-mono text-dark-300 whitespace-nowrap">
                        {row.host && row.host !== row.domain ? (
                          <span title={t('remediation.hostVsDomain', { domain: row.domain })}>{row.host}</span>
                        ) : row.domain}
                      </td>
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
                            {agentTag.tool && (
                              <p className="inline-flex items-center gap-1 text-[11px] text-violet-700">
                                <Bot className="w-3.5 h-3.5" /> {t('remediation.agentFoundThis')}
                              </p>
                            )}
                            <p className="text-dark-200 leading-relaxed">
                              <LinkifyText text={agentTag.text} baseUrl={`https://${row.host ?? row.domain}`} />
                            </p>
                            {row.host && (
                              <p className="text-dark-500">
                                {t('remediation.col.host')}: <span className="font-mono text-dark-300">{row.host}</span>
                                {row.host !== row.domain && <span> ({t('remediation.hostVsDomain', { domain: row.domain })})</span>}
                              </p>
                            )}
                            {row.module === 'breach' && <LeakcheckLookup available={leakcheckAvailable} />}
                            {row.evidence && Object.keys(row.evidence).length > 0 && (
                              <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-0.5 rounded-md bg-dark-900/50 border border-dark-800 px-3 py-2 mt-1">
                                {Object.entries(row.evidence).map(([key, value]) => (
                                  <Fragment key={key}>
                                    <dt className="text-dark-500 whitespace-nowrap">{t(`remediation.evidence.${key}`, { defaultValue: key })}</dt>
                                    <dd className="text-dark-200 font-mono break-all"><EvidenceValue value={value} /></dd>
                                  </Fragment>
                                ))}
                              </dl>
                            )}
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
                )})}
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
