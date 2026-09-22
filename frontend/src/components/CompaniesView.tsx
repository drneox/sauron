import { useEffect, useRef, useState } from 'react'
import axios from 'axios'
import clsx from 'clsx'
import { useTranslation } from 'react-i18next'
import { Company, CompanyDomain, DiscoveredDomain, DiscoveryResult } from '../types/report'
import { Bot, CalendarClock, Check, ExternalLink, Play, Plus, Radar, Search, Smartphone, Trash2, X } from 'lucide-react'

interface Props {
  readOnly?: boolean
  isAdmin?: boolean
  onScanStarted: (scanId: string) => void
  onOpenDashboard: (company: Company) => void
}

const gradeColor = (g: string | null) => {
  if (g === 'A') return 'bg-emerald-50 text-emerald-700 border-emerald-200'
  if (g === 'B') return 'bg-cyan-50 text-cyan-700 border-cyan-200'
  if (g === 'C') return 'bg-amber-50 text-amber-700 border-amber-200'
  if (g === 'D') return 'bg-orange-50 text-orange-700 border-orange-200'
  if (g === 'F') return 'bg-red-50 text-red-700 border-red-200'
  return 'bg-dark-900 text-dark-500 border-dark-800'
}

const SCHEDULE_OPTIONS = [
  { key: 'off', value: 'off' },
  { key: 'daily', value: '24' },
  { key: 'weekly', value: '168' },
  { key: 'monthly', value: '720' },
]

const DISCOVERY_OPTIONS = [
  { key: 'off', value: 'off' },
  { key: 'daily', value: '24' },
  { key: 'weekly', value: '168' },
  { key: 'monthly', value: '720' },
]

const scheduleValue = (d: CompanyDomain) => {
  const s = d.schedule
  if (!s || !s.enabled) return 'off'
  if (s.interval_hours === 24) return '24'
  if (s.interval_hours === 168) return '168'
  return String(s.interval_hours)
}

const discoverValue = (d: CompanyDomain) => {
  const s = d.schedule
  if (!s || !s.discover_enabled || !s.discover_interval_hours) return 'off'
  if (s.discover_interval_hours === 168) return '168'
  if (s.discover_interval_hours === 720) return '720'
  return String(s.discover_interval_hours)
}

const errorMessage = (err: unknown, fallback: string) =>
  axios.isAxiosError(err)
    ? err.response?.data?.detail || err.message || fallback
    : fallback

function DomainRow({
  domain,
  companyName,
  readOnly,
  onChanged,
  onScanStarted,
  onError,
}: {
  domain: CompanyDomain
  companyName: string
  readOnly: boolean
  onChanged: () => void
  onScanStarted: (scanId: string) => void
  onError: (msg: string) => void
}) {
  const { t } = useTranslation()
  const [busy, setBusy] = useState(false)

  const handleScan = async () => {
    setBusy(true)
    try {
      const { data } = await axios.post('/api/scan', { domain: domain.domain, company_name: companyName })
      onScanStarted(data.scan_id)
    } catch (err) {
      onError(errorMessage(err, t('companies.scanError', { domain: domain.domain })))
      setBusy(false)
    }
  }

  const handleSchedule = async (value: string) => {
    setBusy(true)
    try {
      const agentMode = domain.schedule?.agent_mode ?? false
      const payload =
        value === 'off'
          ? { interval_hours: domain.schedule?.interval_hours ?? 24, enabled: false, agent_mode: agentMode }
          : { interval_hours: Number(value), enabled: true, agent_mode: agentMode }
      await axios.put(`/api/domains/${domain.id}/schedule`, payload)
      onChanged()
    } catch (err) {
      onError(errorMessage(err, t('companies.scheduleError', { domain: domain.domain })))
    } finally {
      setBusy(false)
    }
  }

  const handleDiscoverSchedule = async (value: string) => {
    setBusy(true)
    try {
      // Preserve the vuln-scan track — only the discover_* fields change.
      const s = domain.schedule
      const payload = {
        interval_hours: s?.interval_hours ?? 24,
        enabled: s?.enabled ?? false,
        agent_mode: s?.agent_mode ?? false,
        ...(value === 'off'
          ? { discover_enabled: false, discover_interval_hours: s?.discover_interval_hours ?? 168 }
          : { discover_enabled: true, discover_interval_hours: Number(value) }),
      }
      await axios.put(`/api/domains/${domain.id}/schedule`, payload)
      onChanged()
    } catch (err) {
      onError(errorMessage(err, t('companies.scheduleError', { domain: domain.domain })))
    } finally {
      setBusy(false)
    }
  }

  const handleAgentToggle = async (checked: boolean) => {
    setBusy(true)
    try {
      await axios.put(`/api/domains/${domain.id}/schedule`, {
        interval_hours: domain.schedule?.interval_hours ?? 24,
        enabled: domain.schedule?.enabled ?? false,
        agent_mode: checked,
      })
      onChanged()
    } catch (err) {
      onError(errorMessage(err, t('companies.agentModeError', { domain: domain.domain })))
    } finally {
      setBusy(false)
    }
  }

  const handleDelete = async () => {
    if (!confirm(t('companies.confirmDeleteDomain', { domain: domain.domain }))) return
    setBusy(true)
    try {
      await axios.delete(`/api/domains/${domain.id}`)
      onChanged()
    } catch (err) {
      onError(errorMessage(err, t('companies.deleteError', { domain: domain.domain })))
      setBusy(false)
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-3 py-2 border-t border-dark-800 first:border-0">
      <div className="flex-1 min-w-[180px]">
        <div className="text-sm text-dark-100 font-semibold break-all">
          {domain.domain}
          {domain.origin === 'ai' && (
            <span
              className="ml-2 align-middle inline-flex items-center px-1.5 py-0.5 rounded-full text-[10px] font-semibold bg-purple-50 text-purple-700 border border-purple-200"
              title={t('companies.aiOriginTitle')}
            >
              {t('companies.aiOrigin')}
            </span>
          )}
        </div>
        <div className="text-dark-500 text-xs">
          {domain.last_scan_at
            ? t('companies.lastScan', { date: new Date(domain.last_scan_at).toLocaleString() })
            : t('common.neverScanned')}
          {domain.schedule?.enabled && (
            <> · {t('companies.nextRun', { date: domain.schedule.next_run_at ? new Date(domain.schedule.next_run_at).toLocaleString() : '—' })}</>
          )}
          {domain.schedule?.discover_enabled && (
            <> · {t('companies.nextDiscover', { date: domain.schedule.next_discover_at ? new Date(domain.schedule.next_discover_at).toLocaleString() : '—' })}</>
          )}
        </div>
      </div>
      <span className={clsx(
        'text-xs px-2 py-0.5 rounded-full font-bold border w-8 text-center',
        gradeColor(domain.last_grade),
      )}>
        {domain.last_grade ?? '—'}
      </span>
      {!readOnly && (
        <>
          <label className="inline-flex items-center gap-1.5 text-xs text-dark-400">
            <span>{t('companies.vulnScanLabel')}</span>
            <select
              value={scheduleValue(domain)}
              disabled={busy}
              onChange={(e) => handleSchedule(e.target.value)}
              className="bg-white border border-dark-700 rounded-lg px-2 py-1.5 text-xs text-dark-200 focus:outline-none focus:border-cyber-500 disabled:opacity-50 transition-colors duration-150"
            >
              {SCHEDULE_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{t(`companies.schedule.${o.key}`)}</option>
              ))}
            </select>
          </label>
          <label className="inline-flex items-center gap-1.5 text-xs text-dark-400">
            <Radar className="w-3.5 h-3.5 text-dark-500" />
            <span>{t('companies.discoveryLabel')}</span>
            <select
              value={discoverValue(domain)}
              disabled={busy}
              onChange={(e) => handleDiscoverSchedule(e.target.value)}
              className="bg-white border border-dark-700 rounded-lg px-2 py-1.5 text-xs text-dark-200 focus:outline-none focus:border-cyber-500 disabled:opacity-50 transition-colors duration-150"
            >
              {DISCOVERY_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{t(`companies.discoverySchedule.${o.key}`)}</option>
              ))}
            </select>
          </label>
          <label
            className="flex items-center gap-1.5 cursor-pointer select-none"
            title={t('companies.includeAgentTitle')}
          >
            <input
              type="checkbox"
              checked={domain.schedule?.agent_mode ?? false}
              disabled={busy}
              onChange={(e) => handleAgentToggle(e.target.checked)}
              className="accent-purple-600 disabled:opacity-40"
            />
            <span className="text-xs text-dark-400 inline-flex items-center gap-1">
              <Bot className="w-3.5 h-3.5 text-purple-600" /> {t('companies.includeAgent')}
            </span>
          </label>
          <button
            onClick={handleScan}
            disabled={busy}
            className="text-xs px-3 py-1.5 bg-cyber-600 hover:bg-cyber-700 disabled:opacity-50 disabled:cursor-wait rounded-lg text-white font-medium transition-colors duration-150"
          >
            {t('companies.scanNow')}
          </button>
          <button
            onClick={handleDelete}
            disabled={busy}
            className="p-1.5 text-dark-500 hover:text-red-600 hover:bg-red-50 disabled:opacity-50 rounded-lg transition-colors duration-150"
            title={t('companies.deleteDomain')}
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </>
      )}
    </div>
  )
}

const confidenceColor = (c: DiscoveredDomain['confidence']) => {
  if (c === 'high') return 'bg-emerald-50 text-emerald-700 border-emerald-200'
  if (c === 'medium') return 'bg-amber-50 text-amber-700 border-amber-200'
  return 'bg-dark-900 text-dark-500 border-dark-800'
}

const sourceColor = (s: DiscoveredDomain['source']) =>
  s === 'crt.sh'
    ? 'bg-cyan-50 text-cyan-700 border-cyan-200'
    : s === 'llm'
      ? 'bg-purple-100 text-purple-700 border-purple-300 font-semibold'
      : 'bg-purple-50 text-purple-700 border-purple-200'

const sourceLabel = (s: DiscoveredDomain['source'] | string, t: (k: string) => string) =>
  s === 'llm' ? t('companies.discovery.aiBrainstorm') : s

function DiscoveryPanel({
  company,
  onClose,
  onAdded,
}: {
  company: Company
  onClose: () => void
  onAdded: () => void
}) {
  const { t } = useTranslation()
  const [phase, setPhase] = useState<'searching' | 'done' | 'error'>('searching')
  const [result, setResult] = useState<DiscoveryResult | null>(null)
  const [error, setError] = useState('')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [adding, setAdding] = useState(false)
  const [addErrors, setAddErrors] = useState<Record<string, string>>({})
  const [duplicates, setDuplicates] = useState<Set<string>>(new Set())

  const existing = new Set(company.domains.map((d) => d.domain.toLowerCase()))

  useEffect(() => {
    let cancelled = false
    let failures = 0
    let timer: ReturnType<typeof setInterval> | null = null

    const start = async () => {
      try {
        const { data } = await axios.post('/api/discover', { company_name: company.name })
        if (cancelled) return
        const discoveryId: string = data.discovery_id
        timer = setInterval(async () => {
          try {
            const { data: poll } = await axios.get<DiscoveryResult>(`/api/discover/${discoveryId}`)
            failures = 0
            if (cancelled) return
            if (poll.status === 'completed') {
              if (timer) clearInterval(timer)
              setResult(poll)
              // High-confidence candidates come pre-selected by default
              const highConfidence = (poll.candidates ?? [])
                .filter((c) => c.confidence === 'high' && !company.domains.some((d) => d.domain === c.domain))
                .map((c) => c.domain)
              setSelected(new Set(highConfidence))
              setPhase('done')
            } else if (poll.status === 'error') {
              if (timer) clearInterval(timer)
              setError(poll.error || t('companies.discovery.failed'))
              setPhase('error')
            }
          } catch {
            failures += 1
            if (failures >= 3 && !cancelled) {
              if (timer) clearInterval(timer)
              setError(t('companies.discovery.lostConnection'))
              setPhase('error')
            }
          }
        }, 2000)
      } catch (err) {
        if (!cancelled) {
          setError(errorMessage(err, t('companies.discovery.startError', { name: company.name })))
          setPhase('error')
        }
      }
    }
    start()

    return () => {
      cancelled = true
      if (timer) clearInterval(timer)
    }
  }, [company.name])

  const toggle = (domain: string) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(domain)) next.delete(domain)
      else next.add(domain)
      return next
    })
  }

  const handleAddSelected = async () => {
    setAdding(true)
    setAddErrors({})
    const failures: Record<string, string> = {}
    const dupes = new Set(duplicates)
    await Promise.allSettled(
      [...selected].map(async (domain) => {
        try {
          await axios.post(`/api/companies/${company.id}/domains`, { domain })
        } catch (err) {
          if (axios.isAxiosError(err) && err.response?.status === 409) {
            dupes.add(domain)
          } else {
            failures[domain] = errorMessage(err, t('companies.discovery.addError', { domain }))
          }
        }
      }),
    )
    setDuplicates(dupes)
    setAddErrors(failures)
    setAdding(false)
    onAdded()
    if (Object.keys(failures).length === 0) onClose()
  }

  const candidates = result?.candidates ?? []
  const discoveredApps = result?.apps ?? []

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-dark-50/40 backdrop-blur-sm p-4">
      <div className="card w-full max-w-2xl max-h-[80vh] flex flex-col shadow-lg">
        <div className="flex items-center gap-3 mb-3">
          <h3 className="text-base font-semibold tracking-tight text-dark-100 flex-1">
            {t('companies.discovery.title', { name: company.name })}
          </h3>
          <button
            onClick={onClose}
            className="p-1.5 text-dark-500 hover:text-dark-200 hover:bg-dark-900 rounded-lg transition-colors duration-150 shrink-0"
            title={t('common.close')}
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {error && (
          <div className="mb-3 px-3 py-2 rounded-lg border border-red-200 bg-red-50 text-red-700 text-sm flex items-center justify-between gap-4">
            <span>{error}</span>
            <button
              onClick={() => setError('')}
              className="text-red-400 hover:text-red-600 shrink-0 transition-colors"
              title={t('common.dismiss')}
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {phase === 'searching' && (
          <div className="text-center py-12 space-y-3">
            <div className="w-12 h-12 mx-auto rounded-full bg-purple-50 border border-purple-200 flex items-center justify-center animate-pulse">
              <img src="/logo.svg" alt="Sauron" className="w-8 h-8" />
            </div>
            <p className="text-sm text-dark-200 font-medium">
              {t('companies.discovery.searching')}
            </p>
            <p className="text-xs text-dark-500 max-w-sm mx-auto">
              {t('companies.discovery.searchingDesc')}
            </p>
          </div>
        )}

        {phase === 'done' && candidates.length === 0 && discoveredApps.length === 0 && (
          <div className="text-center text-dark-500 py-12 text-sm">
            {t('companies.discovery.none')}
          </div>
        )}

        {phase === 'done' && candidates.length > 0 && (
          <>
            <div className="overflow-y-auto flex-1 -mx-1 px-1">
              {candidates.map((c) => {
                const alreadyAdded = existing.has(c.domain.toLowerCase()) || duplicates.has(c.domain)
                return (
                  <div
                    key={c.domain}
                    className="flex items-start gap-3 py-2 border-t border-dark-800 first:border-0"
                  >
                    <input
                      type="checkbox"
                      checked={selected.has(c.domain)}
                      disabled={alreadyAdded || adding}
                      onChange={() => toggle(c.domain)}
                      className="mt-1 accent-cyber-600 disabled:opacity-40"
                    />
                    <div className="flex-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm text-dark-100 font-semibold break-all">{c.domain}</span>
                        <span className={clsx('text-xs px-2 py-0.5 rounded-full font-bold border', confidenceColor(c.confidence))}>
                          {c.confidence}
                        </span>
                        <span className={clsx('text-xs px-2 py-0.5 rounded-full border', sourceColor(c.source))}>
                          {sourceLabel(c.source, t)}
                        </span>
                        {c.resolves && (
                          <span className="text-xs text-emerald-600 inline-flex items-center gap-1">
                            <Check className="w-3.5 h-3.5" /> {t('companies.discovery.resolves')}
                          </span>
                        )}
                        {c.http_status != null && (
                          <span className="text-xs text-dark-400">HTTP {c.http_status}</span>
                        )}
                      </div>
                      <div className="text-dark-500 text-xs mt-0.5">
                        {alreadyAdded ? t('companies.discovery.alreadyAdded') : c.evidence}
                      </div>
                      {addErrors[c.domain] && (
                        <div className="text-red-400 text-xs mt-0.5">{addErrors[c.domain]}</div>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
            <div className="flex justify-end gap-2 mt-4">
              <button
                onClick={onClose}
                disabled={adding}
                className="btn-secondary"
              >
                {t('common.cancel')}
              </button>
              <button
                onClick={handleAddSelected}
                disabled={adding || selected.size === 0}
                className="text-xs px-4 py-1.5 bg-cyber-600 hover:bg-cyber-700 disabled:opacity-50 text-white font-semibold rounded-lg transition-colors duration-150"
              >
                {adding ? t('companies.adding') : t('companies.discovery.addSelected', { count: selected.size })}
              </button>
            </div>
          </>
        )}
        {phase === 'done' && discoveredApps.length > 0 && (
          <div className="mt-4">
            <h4 className="text-xs font-semibold text-dark-500 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <Smartphone className="w-3.5 h-3.5 text-cyber-600" />
              {t('companies.discovery.appsTitle', { count: discoveredApps.length })}
            </h4>
            <div className="space-y-1.5 max-h-48 overflow-y-auto">
              {discoveredApps.map((a, i) => (
                <div key={`${a.store}:${a.name}:${i}`} className="flex items-center gap-2.5 px-3 py-2 rounded-lg border border-dark-800 text-sm">
                  <span className={clsx(
                    'text-[10px] px-1.5 py-0.5 rounded-full font-semibold border shrink-0',
                    a.store === 'app_store'
                      ? 'bg-sky-50 text-sky-700 border-sky-200'
                      : 'bg-emerald-50 text-emerald-700 border-emerald-200',
                  )}>
                    {a.store === 'app_store' ? 'App Store' : 'Google Play'}
                  </span>
                  <span className="text-dark-100 font-medium truncate flex-1">{a.name}</span>
                  {a.version && <span className="text-xs text-dark-500 font-mono shrink-0">v{a.version}</span>}
                  {a.llm_verdict && (
                    <span className={clsx(
                      'text-[10px] px-1.5 py-0.5 rounded-full font-semibold border shrink-0',
                      a.llm_verdict === 'official'
                        ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        : 'bg-amber-50 text-amber-700 border-amber-200',
                    )}>
                      {a.llm_verdict}
                    </span>
                  )}
                  {a.url && (
                    <a href={a.url} target="_blank" rel="noopener noreferrer" className="text-dark-500 hover:text-cyber-600 shrink-0">
                      <ExternalLink className="w-3.5 h-3.5" />
                    </a>
                  )}
                </div>
              ))}
            </div>
            <p className="text-[11px] text-dark-600 mt-1.5">{t('companies.discovery.appsHint')}</p>
          </div>
        )}
      </div>
    </div>
  )
}

function CompanyCard({
  company,
  readOnly,
  isAdmin,
  onChanged,
  onScanStarted,
  onOpenDashboard,
  onError,
}: {
  company: Company
  readOnly: boolean
  isAdmin: boolean
  onChanged: () => void
  onScanStarted: (scanId: string) => void
  onOpenDashboard: (company: Company) => void
  onError: (msg: string) => void
}) {
  const { t } = useTranslation()
  const [domain, setDomain] = useState('')
  const [adding, setAdding] = useState(false)
  const [discovering, setDiscovering] = useState(false)
  const [batchBusy, setBatchBusy] = useState(false)
  // The company-level AI checkbox reflects the persisted per-domain schedules
  // (on = every domain has schedule.agent_mode). agentOverride only covers the
  // optimistic window between the toggle click and the reload landing.
  const persistedAgentAll = company.domains.length > 0
    && company.domains.every((d) => d.schedule?.agent_mode === true)
  const [agentOverride, setAgentOverride] = useState<boolean | null>(null)
  const agentMode = agentOverride ?? persistedAgentAll
  useEffect(() => { setAgentOverride(null) }, [persistedAgentAll])
  const [notice, setNotice] = useState('')

  const handleDiscoverAssets = async () => {
    setBatchBusy(true)
    try {
      const { data } = await axios.post(`/api/companies/${company.id}/discover-assets`)
      const enqueued = data?.enqueued ?? 0
      const skipped = data?.skipped_in_flight ?? 0
      setNotice(
        t('companies.noticeDiscovery', { count: enqueued })
        + (skipped > 0 ? t('companies.noticeAlreadyRunning', { count: skipped }) : ''),
      )
    } catch (err) {
      onError(errorMessage(err, t('companies.discoverAssetsError', { name: company.name })))
    } finally {
      setBatchBusy(false)
    }
  }

  const handleScanAll = async () => {
    setBatchBusy(true)
    try {
      const { data } = await axios.post(`/api/companies/${company.id}/scan-all`, { agent_mode: agentMode })
      const enqueued = data?.enqueued ?? 0
      const skipped = data?.skipped_in_flight ?? 0
      setNotice(
        t('companies.noticeScans', { count: enqueued })
        + (skipped > 0 ? t('companies.noticeAlreadyRunning', { count: skipped }) : ''),
      )
    } catch (err) {
      onError(errorMessage(err, t('companies.scanAllError', { name: company.name })))
    } finally {
      setBatchBusy(false)
    }
  }

  const handleScheduleAll = async (value: string) => {
    setBatchBusy(true)
    try {
      const payload =
        value === 'off'
          ? { interval_hours: 24, enabled: false, agent_mode: agentMode }
          : { interval_hours: Number(value), enabled: true, agent_mode: agentMode }
      const { data } = await axios.post(`/api/companies/${company.id}/schedule-all`, payload)
      const updated = data?.domains_updated ?? 0
      setNotice(
        value === 'off'
          ? t('companies.noticeScheduleOff', { count: updated })
          : t('companies.noticeScheduled', {
              count: updated,
              interval: value === '24' ? t('companies.intervalDaily') : t('companies.intervalWeekly'),
            }),
      )
      onChanged()
    } catch (err) {
      onError(errorMessage(err, t('companies.scheduleAllError', { name: company.name })))
    } finally {
      setBatchBusy(false)
    }
  }

  const handleDiscoverAll = async (value: string) => {
    setBatchBusy(true)
    try {
      // Discovery-only payload: per-domain vuln schedules are preserved.
      const payload =
        value === 'off'
          ? { discover_enabled: false }
          : { discover_enabled: true, discover_interval_hours: Number(value) }
      const { data } = await axios.post(`/api/companies/${company.id}/schedule-all`, payload)
      const updated = data?.domains_updated ?? 0
      setNotice(
        value === 'off'
          ? t('companies.noticeDiscoveryOff', { count: updated })
          : t('companies.noticeDiscoveryScheduled', {
              count: updated,
              interval: value === '168' ? t('companies.intervalWeekly') : t('companies.intervalMonthly'),
            }),
      )
      onChanged()
    } catch (err) {
      onError(errorMessage(err, t('companies.scheduleAllError', { name: company.name })))
    } finally {
      setBatchBusy(false)
    }
  }

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault()
    const clean = domain.trim().toLowerCase()
    if (!clean) return
    setAdding(true)
    try {
      await axios.post(`/api/companies/${company.id}/domains`, { domain: clean })
      setDomain('')
      onChanged()
    } catch (err) {
      onError(errorMessage(err, t('companies.addDomainError', { domain: clean })))
    } finally {
      setAdding(false)
    }
  }

  const handleDelete = async () => {
    if (!confirm(t('companies.confirmDeleteCompany', { name: company.name }))) return
    try {
      await axios.delete(`/api/companies/${company.id}`)
      onChanged()
    } catch (err) {
      onError(errorMessage(err, t('companies.deleteCompanyError', { name: company.name })))
    }
  }

  const handleAgentModeAll = async (checked: boolean) => {
    setAgentOverride(checked)
    setBatchBusy(true)
    try {
      // Propagate to every domain, preserving each one's interval/enabled
      const results = await Promise.allSettled(
        company.domains.map((d) =>
          axios.put(`/api/domains/${d.id}/schedule`, {
            interval_hours: d.schedule?.interval_hours ?? 24,
            enabled: d.schedule?.enabled ?? false,
            agent_mode: checked,
          }),
        ),
      )
      const failed = results.filter((r) => r.status === 'rejected').length
      setNotice(
        failed === 0
          ? t(checked ? 'companies.noticeAgentOn' : 'companies.noticeAgentOff', { count: company.domains.length })
          : t('companies.noticeAgentErrors', { count: failed }),
      )
      onChanged()
    } finally {
      setBatchBusy(false)
    }
  }

  return (
    <div className="card">
      <div className="flex items-center gap-3 mb-3">
        <h3 className="text-base font-semibold tracking-tight text-dark-100 flex-1">{company.name}</h3>
        <span className="text-xs text-dark-500">
          {t('companies.domainCount', { count: company.domains.length })}
          {company.assets_count != null && (
            <> · {t('companies.assetsCount', { count: company.assets_count })}</>
          )}
        </span>
        <button
          onClick={() => onOpenDashboard(company)}
          className="btn-secondary"
        >
          {t('companies.dashboard')}
        </button>
        {!readOnly && (
          <button
            onClick={() => setDiscovering(true)}
            className="btn-secondary"
          >
            {t('companies.discoverDomains')}
          </button>
        )}
        {isAdmin && (
          <button
            onClick={handleDelete}
            className="btn-secondary text-red-600 hover:bg-red-50 hover:border-red-300"
            title={t('companies.deleteCompanyTitle')}
          >
            <Trash2 className="w-4 h-4" />
          </button>
        )}
      </div>

      {!readOnly && company.domains.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 mb-3 pb-3 border-b border-dark-800">
          <button
            onClick={handleDiscoverAssets}
            disabled={batchBusy}
            className="btn-secondary disabled:opacity-50 disabled:cursor-wait"
            title={t('companies.discoverAssetsTitle')}
          >
            <Radar className="w-3.5 h-3.5" />
            {t('companies.discoverAssets')}
          </button>
          <button
            onClick={handleScanAll}
            disabled={batchBusy}
            className="btn-secondary disabled:opacity-50 disabled:cursor-wait"
            title={t('companies.scanAllTitle')}
          >
            <Play className="w-3.5 h-3.5" />
            {t('companies.scanAll')}
          </button>
          <label className="inline-flex items-center gap-1.5 text-xs text-dark-400">
            <CalendarClock className="w-3.5 h-3.5 text-dark-500" />
            <select
              defaultValue=""
              disabled={batchBusy}
              onChange={(e) => {
                if (e.target.value) handleScheduleAll(e.target.value)
                e.target.value = ''
              }}
              className="bg-white border border-dark-700 rounded-lg px-2 py-1.5 text-xs text-dark-200 focus:outline-none focus:border-cyber-500 disabled:opacity-50 transition-colors duration-150"
              title={t('companies.scheduleAllTitle')}
            >
              <option value="" disabled>{t('companies.scheduleAll')}</option>
              {SCHEDULE_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{t(`companies.schedule.${o.key}`)}</option>
              ))}
            </select>
          </label>
          <label className="inline-flex items-center gap-1.5 text-xs text-dark-400">
            <Radar className="w-3.5 h-3.5 text-dark-500" />
            <select
              defaultValue=""
              disabled={batchBusy}
              onChange={(e) => {
                if (e.target.value) handleDiscoverAll(e.target.value)
                e.target.value = ''
              }}
              className="bg-white border border-dark-700 rounded-lg px-2 py-1.5 text-xs text-dark-200 focus:outline-none focus:border-cyber-500 disabled:opacity-50 transition-colors duration-150"
              title={t('companies.discoverScheduleAllTitle')}
            >
              <option value="" disabled>{t('companies.discoverScheduleAll')}</option>
              {DISCOVERY_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{t(`companies.discoverySchedule.${o.key}`)}</option>
              ))}
            </select>
          </label>
          <label
            className="flex items-center gap-1.5 cursor-pointer select-none"
            title={t('companies.includeAgentAllTitle')}
          >
            <input
              type="checkbox"
              checked={agentMode}
              disabled={batchBusy}
              onChange={(e) => handleAgentModeAll(e.target.checked)}
              className="accent-purple-600 disabled:opacity-40"
            />
            <span className="text-xs text-dark-400 inline-flex items-center gap-1">
              <Bot className="w-3.5 h-3.5 text-purple-600" /> {t('companies.includeAgent')}
            </span>
          </label>
        </div>
      )}

      {notice && (
        <div className="mb-3 px-3 py-2 rounded-lg border border-emerald-200 bg-emerald-50 text-emerald-700 text-sm flex items-center justify-between gap-4">
          <span>{notice}</span>
          <button
            onClick={() => setNotice('')}
            className="text-emerald-500 hover:text-emerald-700 shrink-0 transition-colors"
            title={t('common.dismiss')}
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {discovering && (
        <DiscoveryPanel
          company={company}
          onClose={() => setDiscovering(false)}
          onAdded={onChanged}
        />
      )}

      {company.domains.map((d) => (
        <DomainRow
          key={d.id}
          domain={d}
          companyName={company.name}
          readOnly={readOnly}
          onChanged={onChanged}
          onScanStarted={onScanStarted}
          onError={onError}
        />
      ))}

      {!readOnly && (
        <form onSubmit={handleAdd} className="flex gap-2 mt-3">
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder={t('companies.addDomainPlaceholder')}
            spellCheck={false}
            className="flex-1 bg-white border border-dark-700 rounded-lg px-3 py-1.5 text-xs font-mono text-dark-100 placeholder:text-dark-600 focus:outline-none focus:border-cyber-500 focus:ring-2 focus:ring-cyber-500/20 transition-colors duration-150"
          />
          <button
            type="submit"
            disabled={adding || !domain.trim()}
            className="btn-secondary"
          >
            <Plus className="w-3.5 h-3.5" />
            {adding ? t('companies.adding') : t('companies.addDomain')}
          </button>
        </form>
      )}
    </div>
  )
}

// Single search-or-create control: typing filters the company list below AND
// opens a dropdown with quick-jump matches plus a "Create" action when the
// typed name doesn't already exist. Replaces the old pair of separate boxes
// (a create form always on top, a filter input that only showed past 3
// companies) with one control that does both.
function SearchOrCreateBar({
  companies,
  query,
  onQueryChange,
  onView,
  onCreate,
  creating,
}: {
  companies: Company[]
  query: string
  onQueryChange: (q: string) => void
  onView: (company: Company) => void
  onCreate: (name: string) => void
  creating: boolean
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const onOutside = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onOutside)
    return () => document.removeEventListener('mousedown', onOutside)
  }, [])

  const trimmed = query.trim()
  const matches = trimmed
    ? companies.filter((c) => c.name.toLowerCase().includes(trimmed.toLowerCase())).slice(0, 8)
    : []
  const exactMatch = trimmed
    ? companies.some((c) => c.name.toLowerCase() === trimmed.toLowerCase())
    : true // no create action while empty

  const submitCreate = () => {
    if (!trimmed || exactMatch || creating) return
    onCreate(trimmed)
    setOpen(false)
  }

  return (
    <div ref={containerRef} className="relative">
      <div className="card flex items-center gap-2 py-2.5">
        <Search className="w-4 h-4 text-dark-500 shrink-0" />
        <input
          type="text"
          value={query}
          onChange={(e) => { onQueryChange(e.target.value); setOpen(true) }}
          onFocus={() => setOpen(true)}
          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); submitCreate() } }}
          placeholder={t('companies.searchOrCreatePlaceholder')}
          className="flex-1 bg-transparent text-sm text-dark-100 placeholder:text-dark-500 focus:outline-none"
        />
      </div>

      {open && trimmed && (matches.length > 0 || !exactMatch) && (
        <div className="absolute z-20 mt-1.5 w-full card p-1.5 shadow-lg max-h-72 overflow-y-auto">
          {matches.map((c) => (
            <button
              key={c.id}
              onClick={() => { onView(c); setOpen(false) }}
              className="w-full flex items-center gap-2 px-2.5 py-2 rounded-lg text-left hover:bg-dark-900 transition-colors duration-150"
            >
              <span className="text-sm text-dark-100 font-medium flex-1 truncate">{c.name}</span>
              <span className="text-xs text-cyber-700 font-medium inline-flex items-center gap-1 shrink-0">
                {t('companies.viewAction')} <Check className="w-3.5 h-3.5" />
              </span>
            </button>
          ))}
          {!exactMatch && (
            <button
              onClick={submitCreate}
              disabled={creating}
              className="w-full flex items-center gap-2 px-2.5 py-2 rounded-lg text-left hover:bg-cyber-50 disabled:opacity-50 transition-colors duration-150"
            >
              <Plus className="w-3.5 h-3.5 text-cyber-600 shrink-0" />
              <span className="text-sm text-cyber-700 font-medium truncate">
                {creating ? t('companies.creating') : t('companies.createOption', { name: trimmed })}
              </span>
            </button>
          )}
        </div>
      )}
    </div>
  )
}

export default function CompaniesView({ readOnly = false, isAdmin = false, onScanStarted, onOpenDashboard }: Props) {
  const { t } = useTranslation()
  const [companies, setCompanies] = useState<Company[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [creating, setCreating] = useState(false)
  const [query, setQuery] = useState('')

  const load = async () => {
    try {
      const { data } = await axios.get('/api/companies')
      setCompanies([...data].sort((a, b) => a.name.localeCompare(b.name)))
      setError('')
    } catch (err) {
      setError(errorMessage(err, t('companies.loadError')))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    setLoading(true)
    load()
  }, [])

  const reload = () => { load() }
  const showError = (msg: string) => setError(msg)
  const visibleCompanies = query.trim()
    ? companies.filter((c) => c.name.toLowerCase().includes(query.trim().toLowerCase()))
    : companies

  const handleCreate = async (rawName: string) => {
    const clean = rawName.trim()
    if (!clean) return
    setCreating(true)
    try {
      await axios.post('/api/companies', { name: clean })
      setQuery('')
      await load()
    } catch (err) {
      setError(errorMessage(err, t('companies.createError', { name: clean })))
    } finally {
      setCreating(false)
    }
  }

  return (
    <div className="max-w-4xl mx-auto space-y-4">
      <h2 className="text-xl font-semibold tracking-tight text-dark-100">{t('companies.title')}</h2>

      {!readOnly && (
        <SearchOrCreateBar
          companies={companies}
          query={query}
          onQueryChange={setQuery}
          onView={(c) => setQuery(c.name)}
          onCreate={handleCreate}
          creating={creating}
        />
      )}

      {error && (
        <div className="card border-red-200 bg-red-50 text-red-700 text-sm flex items-center justify-between gap-4">
          <span>{error}</span>
          <button
            onClick={() => setError('')}
            className="text-red-400 hover:text-red-600 shrink-0 transition-colors"
            title={t('common.dismiss')}
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {loading ? (
        <div className="card text-center text-dark-500 py-12 text-sm animate-pulse">
          {t('companies.loading')}
        </div>
      ) : companies.length === 0 && !error ? (
        <div className="card text-center text-dark-500 py-12 text-sm">
          {t('companies.empty')}
        </div>
      ) : (
        <div className="space-y-4">
          {visibleCompanies.map((c) => (
            <CompanyCard
              key={c.id}
              company={c}
              readOnly={readOnly}
              isAdmin={isAdmin}
              onChanged={reload}
              onScanStarted={onScanStarted}
              onOpenDashboard={onOpenDashboard}
              onError={showError}
            />
          ))}
          {visibleCompanies.length === 0 && (
            <div className="card text-center text-dark-500 py-8 text-sm">
              {t('companies.noFilterResults', 'No companies match the filter.')}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
