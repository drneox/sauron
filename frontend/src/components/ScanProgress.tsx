import { useState, useEffect, useRef, type ComponentType } from 'react'
import axios from 'axios'
import clsx from 'clsx'
import { useTranslation } from 'react-i18next'
import { ScanReport, AgentScanStep } from '../types/report'
import { AgentStepCard } from './AgentStepCard'
import {
  Ban,
  Bot,
  Check,
  Cloud,
  Cookie,
  Crosshair,
  Dna,
  DoorOpen,
  FileSearch,
  FileText,
  FolderOpen,
  Globe,
  History,
  KeyRound,
  Link2,
  Lock,
  Mail,
  Network,
  Package,
  Plug,
  Radar,
  Search,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Skull,
  Smartphone,
  X,
  Zap,
} from 'lucide-react'

export const MODULE_LABELS: Record<string, string> = {
  whois:        'WHOIS Lookup',
  dns:          'DNS Enumeration',
  dnssec:       'DNSSEC Validation',
  subdomains:   'Subdomain Discovery',
  ssl:          'SSL/TLS Analysis',
  tls:          'TLS Configuration Audit',
  headers:      'HTTP Security Headers',
  cors:         'CORS Policy',
  cookies:      'Cookie Security',
  email:        'Email Security (SPF/DKIM/DMARC)',
  tech:         'Technology Fingerprinting',
  mobile_apps:  'Mobile Apps Discovery',
  waf:          'WAF / CDN Detection',
  robots:       'Robots.txt & Sitemap',
  admin:        'Admin Panel Discovery',
  frontend_cve: 'Frontend CVE Detection',
  js_secrets:   'JS Secrets Scanner',
  secret_verification: 'Secret Verification',
  smart_fuzz:   'Smart Fuzzing',
  blacklist:    'IP Reputation / Blacklists',
  exposed:      'Exposed Files Scanner',
  breach:       'Breach & Leak Detection',
  cloud_storage:'Cloud Storage Exposure',
  api_exposure: 'API Endpoint Exposure',
  wayback:      'Wayback Machine Secrets',
  ports:        'Port Scanning',
  reverse_ip:   'Reverse IP Lookup',
  nuclei:       'Nuclei Vulnerability Scan',
  agent:        'AI Agent Investigation',
  subdomain_eval: 'Chained Evaluation',
}

const MODULE_ICONS: Record<string, ComponentType<{ className?: string }>> = {
  whois:        FileText,
  dns:          Globe,
  dnssec:       ShieldCheck,
  subdomains:   Search,
  ssl:          Lock,
  tls:          Lock,
  headers:      Shield,
  cors:         Globe,
  cookies:      Cookie,
  email:        Mail,
  tech:         Zap,
  waf:          ShieldAlert,
  robots:       FileSearch,
  admin:        DoorOpen,
  frontend_cve: Package,
  js_secrets:   KeyRound,
  secret_verification: KeyRound,
  smart_fuzz:   Crosshair,
  blacklist:    Ban,
  exposed:      FolderOpen,
  breach:       Skull,
  cloud_storage:Cloud,
  api_exposure: Link2,
  wayback:      History,
  ports:        Plug,
  reverse_ip:   Network,
  nuclei:       Dna,
  mobile_apps:  Smartphone,
  subdomain_eval: Radar,
  agent:        Bot,
}

// Must match exact backend execution order in main.py
const MODULE_ORDER = [
  'whois', 'dns', 'dnssec', 'subdomains', 'subdomain_eval',
  'ssl', 'tls', 'headers', 'cors', 'cookies',
  'email', 'tech', 'mobile_apps', 'waf', 'robots',
  'admin', 'frontend_cve', 'js_secrets', 'secret_verification', 'smart_fuzz',
  'blacklist', 'exposed', 'breach',
  'cloud_storage', 'api_exposure', 'wayback',
  'ports', 'reverse_ip', 'nuclei',
  'agent',
]

// Phase grouping for the stepper (order matters)
const PHASES: { key: string; modules: string[] }[] = [
  { key: 'recon',   modules: ['whois', 'dns', 'dnssec', 'subdomains', 'subdomain_eval', 'reverse_ip'] },
  { key: 'web',     modules: ['ssl', 'tls', 'headers', 'cors', 'cookies', 'tech', 'mobile_apps', 'waf', 'robots', 'frontend_cve'] },
  { key: 'secrets', modules: ['admin', 'js_secrets', 'secret_verification', 'smart_fuzz', 'exposed', 'wayback'] },
  { key: 'leaks',   modules: ['email', 'breach', 'blacklist'] },
  { key: 'cloud',   modules: ['cloud_storage', 'api_exposure'] },
  { key: 'vulns',   modules: ['ports', 'nuclei'] },
  { key: 'ai',      modules: ['agent'] },
]

interface ModuleDone {
  name: string
  status: string
  findings: number
  risk: string
  duration: number
}

interface Props {
  scanId: string
  onComplete: (report: ScanReport) => void
}

const RISK_DOT: Record<string, string> = {
  low: 'bg-dark-500',
  medium: 'bg-amber-400',
  high: 'bg-orange-500',
  critical: 'bg-red-500',
}

export default function ScanProgress({ scanId, onComplete }: Props) {
  const { t } = useTranslation()
  const [progress, setProgress] = useState(0)
  const [currentModule, setCurrentModule] = useState<string | null>(null)
  const [status, setStatus] = useState('queued')
  const [domain, setDomain] = useState('')
  const [kind, setKind] = useState<string | null>(null)
  const [agentSteps, setAgentSteps] = useState<AgentScanStep[]>([])
  const [agentPhaseSeen, setAgentPhaseSeen] = useState(false)
  const [plannedModules, setPlannedModules] = useState<string[] | null>(null)
  const [modulesDone, setModulesDone] = useState<ModuleDone[]>([])
  const [elapsed, setElapsed] = useState(0)
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const startRef = useRef<number | null>(null)
  const feedEndRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    const poll = async () => {
      try {
        const { data } = await axios.get(`/api/scan/${scanId}`)
        if (data.status === 'completed') {
          if (intervalRef.current) clearInterval(intervalRef.current)
          setProgress(100)
          setCurrentModule(null)
          setStatus('completed')
          setDomain(data.domain)
          setTimeout(() => onComplete(data), 600)
        } else {
          if (data.status === 'running' && startRef.current === null) {
            const serverStart = data.started_at ? Date.parse(data.started_at) : NaN
            startRef.current = Number.isNaN(serverStart) ? Date.now() : serverStart
          }
          if (startRef.current !== null) {
            setElapsed(Math.floor((Date.now() - startRef.current) / 1000))
          }
          setProgress(data.progress ?? 0)
          setCurrentModule(data.current_module ?? null)
          setStatus(data.status)
          setDomain(data.domain ?? '')
          if (data.kind) setKind(data.kind)
          if (Array.isArray(data.planned_modules)) setPlannedModules(data.planned_modules)
          if (Array.isArray(data.modules_done)) setModulesDone(data.modules_done)
          if (data.phase === 'agent' || data.current_module === 'agent') {
            setAgentPhaseSeen(true)
          }
          if (Array.isArray(data.agent_steps)) {
            setAgentSteps(data.agent_steps)
          }
        }
      } catch { /* ignore */ }
    }
    intervalRef.current = setInterval(poll, 1500)
    poll()
    return () => { if (intervalRef.current) clearInterval(intervalRef.current) }
  }, [scanId, onComplete])

  // Auto-scroll the live feed
  useEffect(() => {
    feedEndRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
  }, [modulesDone.length, agentSteps.length])

  const fmtElapsed = (s: number) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`
  const agentPhase = currentModule === 'agent'
  // Only the modules this scan will actually run (backend-planned); fallback
  // to the full static order for queued/legacy scans.
  const baseModules = plannedModules ?? MODULE_ORDER
  const visibleModules = agentPhaseSeen || plannedModules
    ? baseModules
    : baseModules.filter((m) => m !== 'agent')
  const doneNames = new Set(modulesDone.map((m) => m.name))
  const doneCount = progress === 100 ? visibleModules.length : doneNames.size

  // Phases filtered to the modules this scan will run
  const visiblePhases = PHASES
    .map((p) => ({ ...p, modules: p.modules.filter((m) => visibleModules.includes(m)) }))
    .filter((p) => p.modules.length > 0)

  const phaseState = (mods: string[]): 'done' | 'active' | 'pending' => {
    if (currentModule && mods.includes(currentModule)) return 'active'
    if (mods.every((m) => doneNames.has(m) || progress === 100)) return 'done'
    return 'pending'
  }

  return (
    <div className="max-w-4xl mx-auto mt-8 space-y-6">
      {/* Header card */}
      <div className="card space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <span className={clsx(
            'inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium border',
            agentPhase
              ? 'bg-purple-50 border-purple-200 text-purple-700'
              : 'bg-cyber-50 border-cyber-200 text-cyber-700',
          )}>
            <span className={clsx('w-2 h-2 rounded-full animate-ping', agentPhase ? 'bg-purple-500' : 'bg-cyber-500')} />
            {agentPhase ? t('scan.agentPhase') : status === 'queued' ? t('scan.queued') : t('scan.scanning')}
          </span>
          {kind === 'discover' && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border bg-cyan-50 border-cyan-200 text-cyan-700">
              <Radar className="w-3.5 h-3.5" /> {t('scan.discoveryBadge')}
            </span>
          )}
          {kind === 'host' && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border bg-cyan-50 border-cyan-200 text-cyan-700">
              {t('scan.hostBadge')}
            </span>
          )}
          {kind === 'module' && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border bg-amber-50 border-amber-200 text-amber-700">
              {t('scan.moduleBadge')}
            </span>
          )}
          <span className="ml-auto text-xs text-dark-500 font-mono tabular-nums">{fmtElapsed(elapsed)}</span>
        </div>

        <h2 className="text-xl font-bold tracking-tight text-dark-100 font-mono break-all">{domain}</h2>

        <div className="space-y-1.5">
          <div className="flex justify-between text-xs text-dark-500">
            <span>
              {currentModule
                ? t('scan.runningModule', { module: MODULE_LABELS[currentModule] ?? currentModule })
                : status === 'queued' ? t('scan.queued') : t('scan.finalizing')}
            </span>
            <span className="font-semibold text-cyber-700 font-mono">{progress}%</span>
          </div>
          <div className="h-2 bg-dark-800 rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-cyber-600 to-cyber-400 rounded-full transition-all duration-700"
              style={{ width: `${progress}%` }}
            />
          </div>
          <p className="text-[11px] text-dark-600 font-mono">
            {plannedModules || status !== 'queued'
              ? t('scan.modulesDone', { done: doneCount, total: visibleModules.length })
              : ''}
          </p>
        </div>
      </div>

      {(plannedModules || status !== 'queued') && (
      <div className="grid grid-cols-1 md:grid-cols-[220px,1fr] gap-4 items-start">
        {/* Phase stepper */}
        <div className="card !p-3 space-y-1 md:sticky md:top-20">
          {visiblePhases.map((p) => {
            const state = phaseState(p.modules)
            const doneInPhase = p.modules.filter((m) => doneNames.has(m)).length
            return (
              <div key={p.key} className={clsx(
                'px-3 py-2 rounded-lg border transition-all duration-150',
                state === 'active' ? 'bg-cyber-50 border-cyber-200'
                  : state === 'done' ? 'bg-emerald-50/50 border-emerald-100'
                  : 'border-transparent',
              )}>
                <div className="flex items-center gap-2">
                  <span className={clsx(
                    'w-4 h-4 flex items-center justify-center shrink-0',
                    state === 'done' ? 'text-emerald-600' : state === 'active' ? 'text-cyber-600' : 'text-dark-600',
                  )}>
                    {state === 'done'
                      ? <Check className="w-3.5 h-3.5" strokeWidth={2.5} />
                      : state === 'active'
                        ? <span className="w-2 h-2 bg-cyber-500 rounded-full animate-ping" />
                        : <span className="w-1.5 h-1.5 rounded-full bg-dark-700" />}
                  </span>
                  <span className={clsx(
                    'text-xs font-medium flex-1',
                    state === 'done' ? 'text-emerald-700' : state === 'active' ? 'text-cyber-700' : 'text-dark-500',
                  )}>
                    {t(`scan.phases.${p.key}`)}
                  </span>
                  <span className="text-[10px] text-dark-600 font-mono">{doneInPhase}/{p.modules.length}</span>
                </div>
                {state === 'active' && (
                  <div className="mt-1.5 ml-6 space-y-1">
                    {p.modules.map((m) => {
                      const Icon = MODULE_ICONS[m] ?? Globe
                      const mDone = doneNames.has(m)
                      const mActive = m === currentModule
                      return (
                        <div key={m} className={clsx(
                          'flex items-center gap-1.5 text-[11px]',
                          mActive ? 'text-cyber-700 font-medium' : mDone ? 'text-emerald-600' : 'text-dark-500',
                        )}>
                          <Icon className="w-3 h-3 shrink-0" />
                          <span className="truncate">{MODULE_LABELS[m]}</span>
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>
            )
          })}
        </div>

        {/* Live feed */}
        <div className="card max-h-[520px] overflow-y-auto">
          <h3 className="text-xs font-semibold text-dark-500 uppercase tracking-wider mb-3">{t('scan.liveFeed')}</h3>
          {modulesDone.length === 0 && !agentPhase && (
            <p className="text-dark-500 text-sm text-center py-8 animate-pulse">
              {status === 'queued' ? t('scan.queued') : t('scan.waitingFirst')}
            </p>
          )}
          <div className="space-y-1">
            {modulesDone.map((m, i) => {
              const Icon = MODULE_ICONS[m.name] ?? Globe
              return (
                <div key={`${m.name}-${i}`} className="flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg hover:bg-dark-900/50 text-sm">
                  <Icon className="w-3.5 h-3.5 text-dark-500 shrink-0" />
                  <span className="text-dark-200 text-xs flex-1 truncate">{MODULE_LABELS[m.name] ?? m.name}</span>
                  {m.status === 'error' ? (
                    <span className="inline-flex items-center gap-1 text-[10px] text-red-600 font-medium">
                      <X className="w-3 h-3" /> {t('scan.moduleError')}
                    </span>
                  ) : m.status === 'skipped' ? (
                    <span className="text-[10px] text-dark-600">{t('scan.moduleSkipped')}</span>
                  ) : (
                    <span className={clsx(
                      'text-[10px] font-mono',
                      m.findings > 0 ? 'text-amber-600 font-semibold' : 'text-dark-600',
                    )}>
                      {t('scan.findingsCount', { count: m.findings })}
                    </span>
                  )}
                  <span className={clsx('w-1.5 h-1.5 rounded-full shrink-0', RISK_DOT[m.risk] ?? RISK_DOT.low)}
                    title={`risk: ${m.risk}`} />
                  <span className="text-[10px] text-dark-600 font-mono tabular-nums shrink-0">{m.duration}s</span>
                </div>
              )
            })}
            {currentModule && currentModule !== 'agent' && (
              <div className="flex items-center gap-2.5 px-2.5 py-1.5 text-sm">
                <span className="flex gap-1 shrink-0 w-3.5 justify-center">
                  {[0, 1, 2].map(i => (
                    <span key={i} className="w-1 h-1 bg-cyber-500 rounded-full animate-bounce"
                      style={{ animationDelay: `${i * 0.15}s` }} />
                  ))}
                </span>
                <span className="text-cyber-700 text-xs font-medium truncate">
                  {MODULE_LABELS[currentModule] ?? currentModule}
                </span>
              </div>
            )}
            <div ref={feedEndRef} />
          </div>

          {/* Agent steps live inside the feed column */}
          {agentPhaseSeen && (
            <div className="mt-4 pt-4 border-t border-dark-800 space-y-3">
              <h4 className="text-xs font-semibold text-dark-500 uppercase tracking-wider inline-flex items-center gap-1.5">
                <Bot className="w-3.5 h-3.5 text-purple-600" /> {t('scan.agentSteps')}
              </h4>
              {agentSteps.length === 0 && agentPhase && (
                <p className="text-dark-500 text-sm text-center py-6 animate-pulse">
                  {t('scan.waitingFirst')}
                </p>
              )}
              {agentSteps.map((s) => <AgentStepCard key={s.n} step={s} />)}
              {agentPhase && agentSteps.length > 0 && (
                <div className="flex items-center gap-2 text-purple-600 text-sm animate-pulse pl-2">
                  <span className="w-2 h-2 bg-purple-500 rounded-full" />
                  {t('scan.agentThinking')}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
      )}
    </div>
  )
}
