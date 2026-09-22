import { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'
import { useTranslation } from 'react-i18next'
import { AgentScanStatus, Finding, RiskLevel } from '../types/report'
import { RiskBadge, SectionCard } from './ui'
import { AgentStepCard } from './AgentStepCard'
import { AlertTriangle, Globe, Sparkles } from 'lucide-react'

interface Props {
  onBack: () => void
  scanId?: string
}

// ── Minimal markdown rendering (same pattern as AiSummarySection) ────
function renderInline(text: string, keyPrefix: string) {
  const parts = text.split(/\*\*(.+?)\*\*/g)
  return parts.map((p, i) =>
    i % 2 === 1
      ? <strong key={`${keyPrefix}-${i}`} className="text-dark-50 font-semibold">{p}</strong>
      : <span key={`${keyPrefix}-${i}`}>{p}</span>
  )
}

function MarkdownBlock({ text }: { text: string }) {
  const lines = text.split('\n')
  return (
    <div className="space-y-1">
      {lines.map((line, i) => {
        const trimmed = line.trim()
        if (!trimmed) return null
        if (trimmed.startsWith('- ') || trimmed.startsWith('* ')) {
          return (
            <div key={i} className="flex gap-2 text-sm text-dark-200">
              <span className="text-cyber-600 shrink-0">•</span>
              <span>{renderInline(trimmed.slice(2), `l${i}`)}</span>
            </div>
          )
        }
        return (
          <p key={i} className="text-sm text-dark-200 leading-relaxed">
            {renderInline(trimmed, `l${i}`)}
          </p>
        )
      })}
    </div>
  )
}

// ── Domain validation (same regex as DomainInput) ────────────────────
function validateDomain(v: string): string | null {
  const clean = v.trim().toLowerCase()
    .replace(/^https?:\/\//, '')
    .split('/')[0]
  const re = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/
  return re.test(clean) ? clean : null
}

// ── Main view ────────────────────────────────────────────────────────
export default function AgentScanView({ onBack, scanId }: Props) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  // Launch form state
  const [domain, setDomain] = useState('')
  const [companyName, setCompanyName] = useState('')
  const [maxSteps, setMaxSteps] = useState('15')
  const [formError, setFormError] = useState('')
  const [aiNotConfigured, setAiNotConfigured] = useState(false)
  const [launching, setLaunching] = useState(false)

  // Live scan state — seeded from the route when arriving from New Scan
  const [agentScanId, setAgentScanId] = useState<string | null>(scanId ?? null)
  const [scan, setScan] = useState<AgentScanStatus | null>(null)
  const [scanPhase, setScanPhase] = useState<{ progress: number; current_module: string | null; phase?: string } | null>(null)
  const [pollError, setPollError] = useState<string | null>(null)

  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const failuresRef = useRef(0)
  const feedEndRef = useRef<HTMLDivElement | null>(null)

  const stopPolling = useCallback(() => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current)
      intervalRef.current = null
    }
  }, [])

  const handleStart = async (e: React.FormEvent) => {
    e.preventDefault()
    const clean = validateDomain(domain)
    if (!clean) {
      setFormError(t('agent.invalidDomain'))
      return
    }
    const steps = parseInt(maxSteps, 10)
    if (maxSteps.trim() !== '' && (isNaN(steps) || steps < 1 || steps > 30)) {
      setFormError(t('agent.maxStepsError'))
      return
    }
    setFormError('')
    setAiNotConfigured(false)
    setLaunching(true)
    try {
      const payload: { domain: string; company_name?: string; max_steps?: number } = { domain: clean }
      if (companyName.trim()) payload.company_name = companyName.trim()
      if (maxSteps.trim() !== '') payload.max_steps = steps
      const { data } = await axios.post('/api/agent-scan', payload)
      setAgentScanId(data.agent_scan_id)
      setScan({ agent_scan_id: data.agent_scan_id, status: 'running', domain: clean, steps: [] })
      setPollError(null)
      failuresRef.current = 0
    } catch (err: unknown) {
      if (axios.isAxiosError(err)) {
        const status = err.response?.status
        const detail = err.response?.data?.detail || err.message
        if (status === 503) {
          setAiNotConfigured(true)
        } else {
          setFormError(t('agent.startError', { detail }))
        }
      } else {
        setFormError(t('agent.unknownError'))
      }
    } finally {
      setLaunching(false)
    }
  }

  // Polling: every 3s while running; 3 consecutive network failures → visible error
  useEffect(() => {
    if (!agentScanId) return
    const poll = async () => {
      try {
        const [agentRes, scanRes] = await Promise.allSettled([
          axios.get<AgentScanStatus>(`/api/agent-scan/${agentScanId}`),
          axios.get(`/api/scan/${agentScanId}`),
        ])
        failuresRef.current = 0
        setPollError(null)
        if (scanRes.status === 'fulfilled') {
          const sd = scanRes.value.data
          if (sd.status !== 'completed') {
            setScanPhase({ progress: sd.progress ?? 0, current_module: sd.current_module ?? null, phase: sd.phase })
          }
        }
        if (agentRes.status === 'fulfilled') {
          const data = agentRes.value.data
          setScan(data)
          if (data.status !== 'running') stopPolling()
        } else if (agentRes.status === 'rejected') {
          throw agentRes.reason
        }
      } catch (err: unknown) {
        failuresRef.current += 1
        if (failuresRef.current >= 3) {
          stopPolling()
          const msg = axios.isAxiosError(err)
            ? err.response?.data?.detail || err.message
            : t('agent.networkError')
          setPollError(t('agent.pollError', { msg }))
        }
      }
    }
    intervalRef.current = setInterval(poll, 3000)
    poll()
    return stopPolling
  }, [agentScanId, stopPolling])

  // Auto-scroll to latest step
  const stepCount = scan?.steps?.length ?? 0
  useEffect(() => {
    feedEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [stepCount])

  const steps = scan?.steps ?? []
  const running = scan?.status === 'running'
  const completed = scan?.status === 'completed'
  const errored = scan?.status === 'error'

  // Findings grouped by risk (critical first)
  const riskOrder: RiskLevel[] = ['critical', 'high', 'medium', 'low']
  const findingsByRisk = (scan?.findings ?? []).reduce<Record<RiskLevel, Finding[]>>(
    (acc, f) => {
      const r = riskOrder.includes(f.risk) ? f.risk : 'low'
      acc[r].push(f)
      return acc
    },
    { critical: [], high: [], medium: [], low: [] }
  )

  // ── Launch form ──
  if (!agentScanId) {
    return (
      <div className="max-w-2xl mx-auto mt-8 space-y-6">
        <div className="text-center space-y-2">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 bg-purple-50 border border-purple-200 rounded-full text-purple-700 text-xs font-medium">
            <Sparkles className="w-3.5 h-3.5" /> {t('agent.llmDriven')}
          </div>
          <h2 className="text-2xl font-bold tracking-tight text-dark-100">{t('agent.title')}</h2>
          <p className="text-dark-400 text-sm max-w-md mx-auto leading-relaxed">
            {t('agent.desc')}
          </p>
        </div>

        {aiNotConfigured && (
          <div className="bg-amber-50 border border-amber-200 rounded-xl px-4 py-3 text-sm text-amber-800">
            {t('agent.aiNotConfigured')}
          </div>
        )}

        <form onSubmit={handleStart} className="card space-y-4">
          <div className="space-y-1">
            <label className="text-xs font-semibold text-dark-500 uppercase tracking-wider">{t('agent.targetDomain')}</label>
            <div className="relative">
              <Globe className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-dark-600 pointer-events-none" />
              <input
                type="text"
                value={domain}
                onChange={(e) => { setDomain(e.target.value); setFormError('') }}
                placeholder={t('home.placeholder')}
                autoFocus
                spellCheck={false}
                className="w-full bg-white border border-dark-700 rounded-xl pl-9 pr-4 py-3 font-mono text-sm text-dark-100 placeholder:text-dark-600 focus:outline-none focus:border-cyber-500 focus:ring-2 focus:ring-cyber-500/20 transition-colors duration-150"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-1">
              <label className="text-xs font-semibold text-dark-500 uppercase tracking-wider">
                {t('agent.companyName')} <span className="text-dark-600 normal-case font-normal">{t('agent.optional')}</span>
              </label>
              <input
                type="text"
                value={companyName}
                onChange={(e) => setCompanyName(e.target.value)}
                placeholder="Acme Corp"
                spellCheck={false}
                className="w-full bg-white border border-dark-700 rounded-xl px-4 py-2.5 text-dark-100 placeholder:text-dark-600 focus:outline-none focus:border-cyber-500 focus:ring-2 focus:ring-cyber-500/20 transition-colors duration-150 text-sm"
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-semibold text-dark-500 uppercase tracking-wider">
                {t('agent.maxSteps')} <span className="text-dark-600 normal-case font-normal">{t('agent.maxStepsHint')}</span>
              </label>
              <input
                type="number"
                min={1}
                max={30}
                value={maxSteps}
                onChange={(e) => setMaxSteps(e.target.value)}
                className="w-full bg-white border border-dark-700 rounded-xl px-4 py-2.5 text-dark-100 placeholder:text-dark-600 focus:outline-none focus:border-cyber-500 focus:ring-2 focus:ring-cyber-500/20 transition-colors duration-150 text-sm"
              />
            </div>
          </div>

          {formError && <p className="text-red-600 text-xs bg-red-50 border border-red-200 rounded-lg px-3 py-2">{formError}</p>}

          <div className="flex items-center gap-3">
            <button
              type="submit"
              disabled={launching}
              className="px-6 py-3 bg-purple-600 hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition-colors duration-150 text-sm flex items-center gap-2 shadow-sm shadow-purple-600/20"
            >
              {launching && (
                <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
                </svg>
              )}
              {launching ? t('agent.starting') : t('agent.start')}
            </button>
            <button
              type="button"
              onClick={onBack}
              className="text-sm text-dark-500 hover:text-dark-200 transition-colors duration-150"
            >
              {t('common.back')}
            </button>
          </div>
        </form>
      </div>
    )
  }

  // ── Live feed / result ──
  return (
    <div className="max-w-3xl mx-auto mt-4 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="space-y-1">
          <div className="inline-flex items-center gap-2 px-3 py-1 bg-purple-50 border border-purple-200 rounded-full text-purple-700 text-xs font-medium">
            {running && <span className="w-2 h-2 bg-purple-500 rounded-full animate-ping" />}
            {running ? t('agent.running') : completed ? t('agent.finished') : t('agent.error')}
          </div>
          <h2 className="text-xl font-bold tracking-tight text-dark-100 font-mono">{scan?.domain ?? domain}</h2>
        </div>
        <div className="flex items-center gap-2">
          {completed && agentScanId && (
            <button
              onClick={() => navigate(`/report/${agentScanId}`)}
              className="btn-secondary"
            >
              {t('agent.viewFullReport', 'View full report')}
            </button>
          )}
          <button
            onClick={() => { stopPolling(); onBack() }}
            className="btn-secondary"
          >
            {t('common.back')}
          </button>
        </div>
      </div>

      {/* Error banner (terminal error or polling failure) */}
      {(errored || pollError) && (
        <div className="bg-red-50 border border-red-200 rounded-xl px-4 py-3 text-sm text-red-700">
          {scan?.error || pollError}
        </div>
      )}

      {/* Steps feed */}
      <div className="space-y-3">
        {steps.length === 0 && running && !pollError && scanPhase?.phase !== 'agent' && (
          <div className="card space-y-3">
            <div className="flex items-center justify-between text-sm">
              <span className="font-medium text-dark-200">{t('agent.detPhase', 'Deterministic scan in progress')}</span>
              <span className="font-mono text-cyber-700 font-semibold">{scanPhase?.progress ?? 0}%</span>
            </div>
            <div className="w-full bg-dark-800 rounded-full h-2 overflow-hidden">
              <div
                className="bg-purple-500 h-2 rounded-full transition-all duration-700"
                style={{ width: `${scanPhase?.progress ?? 0}%` }}
              />
            </div>
            <p className="text-xs text-dark-500">
              {scanPhase?.current_module
                ? t('agent.runningModule', { module: scanPhase.current_module.replace(/_/g, ' ') })
                : t('agent.waitingFirst')}
              {' '}— {t('agent.agentStartsAfter', 'the AI agent takes over when it finishes')}.
            </p>
          </div>
        )}
        {steps.length === 0 && running && !pollError && scanPhase?.phase === 'agent' && (
          <p className="text-dark-500 text-sm text-center py-8 animate-pulse">
            {t('agent.waitingFirst')}
          </p>
        )}
        {steps.map((s) => <AgentStepCard key={s.n} step={s} />)}
        {running && !pollError && steps.length > 0 && (
          <div className="flex items-center gap-2 text-purple-600 text-sm animate-pulse pl-2">
            <span className="w-2 h-2 bg-purple-500 rounded-full" />
            {t('agent.thinking')}
          </div>
        )}
        <div ref={feedEndRef} />
      </div>

      {/* Final panel */}
      {completed && (
        <div className="space-y-4">
          {/* Counters */}
          <div className="grid grid-cols-3 gap-3">
            <div className="card text-center">
              <p className="text-2xl font-bold text-cyber-700 font-mono">{steps.length}</p>
              <p className="text-[10px] text-dark-500 uppercase tracking-wider font-semibold mt-1">{t('agent.steps')}</p>
            </div>
            <div className="card text-center">
              <p className="text-2xl font-bold text-amber-600 font-mono">{scan?.findings?.length ?? 0}</p>
              <p className="text-[10px] text-dark-500 uppercase tracking-wider font-semibold mt-1">{t('agent.findings')}</p>
            </div>
            <div className="card text-center">
              <p className="text-2xl font-bold text-emerald-600 font-mono">{scan?.assets_discovered ?? 0}</p>
              <p className="text-[10px] text-dark-500 uppercase tracking-wider font-semibold mt-1">{t('agent.assetsFound')}</p>
            </div>
          </div>

          {scan?.final_summary && (
            <SectionCard title={t('agent.finalSummary')} icon={<Sparkles />}>
              <MarkdownBlock text={scan.final_summary} />
            </SectionCard>
          )}

          {(scan?.findings?.length ?? 0) > 0 && (
            <SectionCard title={t('agent.findingsByRisk')} icon={<AlertTriangle />}>
              <div className="space-y-4">
                {riskOrder.map((r) => {
                  const group = findingsByRisk[r]
                  if (!group.length) return null
                  return (
                    <div key={r} className="space-y-2">
                      <div className="flex items-center gap-2">
                        <RiskBadge risk={r} />
                        <span className="text-xs text-dark-500">{group.length}</span>
                      </div>
                      <ul className="space-y-1.5">
                        {group.map((f, i) => (
                          <li key={i} className="flex items-start gap-2 text-sm text-dark-200">
                            <span className="text-dark-600 shrink-0">•</span>
                            <span>
                              <span className="text-dark-500 text-xs mr-2 font-mono">[{f.module}]</span>
                              {f.finding}
                            </span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )
                })}
              </div>
            </SectionCard>
          )}
        </div>
      )}
    </div>
  )
}
