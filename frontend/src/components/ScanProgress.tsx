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
  Zap,
} from 'lucide-react'

const MODULE_LABELS: Record<string, string> = {
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

interface Props {
  scanId: string
  onComplete: (report: ScanReport) => void
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
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

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
          setProgress(data.progress ?? 0)
          setCurrentModule(data.current_module ?? null)
          setStatus(data.status)
          setDomain(data.domain ?? '')
          if (data.kind) setKind(data.kind)
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

  const currentIdx = currentModule ? MODULE_ORDER.indexOf(currentModule) : -1
  const agentPhase = currentModule === 'agent'
  const visibleModules = agentPhaseSeen ? MODULE_ORDER : MODULE_ORDER.filter((m) => m !== 'agent')

  return (
    <div className="max-w-2xl mx-auto mt-12 space-y-8">
      <div className="text-center space-y-3">
        <div className={clsx(
          'inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium border',
          agentPhase
            ? 'bg-purple-50 border-purple-200 text-purple-700'
            : 'bg-cyber-50 border-cyber-200 text-cyber-700',
        )}>
          <span className={clsx('w-2 h-2 rounded-full animate-ping', agentPhase ? 'bg-purple-500' : 'bg-cyber-500')} />
          {agentPhase ? t('scan.agentPhase') : t('scan.scanning')}
        </div>
        <h2 className="text-2xl font-bold tracking-tight text-dark-100 font-mono">{domain}</h2>
        {kind === 'discover' && (
          <div>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border bg-cyan-50 border-cyan-200 text-cyan-700">
              <Radar className="w-3.5 h-3.5" /> {t('scan.discoveryBadge')}
            </span>
          </div>
        )}
        <p className="text-dark-500 text-xs">
          {currentModule
            ? t('scan.runningModule', { module: MODULE_LABELS[currentModule] ?? currentModule })
            : status === 'queued' ? t('scan.queued') : t('scan.finalizing')}
        </p>
      </div>

      <div className="space-y-2">
        <div className="flex justify-between text-xs text-dark-500">
          <span>{t('scan.overallProgress')}</span>
          <span className="font-semibold text-cyber-700 font-mono">{progress}%</span>
        </div>
        <div className="h-2 bg-dark-800 rounded-full overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-cyber-600 to-cyber-400 rounded-full transition-all duration-700"
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>

      <div className="card space-y-1">
        <h3 className="text-xs font-semibold text-dark-500 uppercase tracking-wider mb-3">{t('scan.modules')}</h3>
        {visibleModules.map((mod, idx) => {
          const done = idx < currentIdx || progress === 100
          const active = mod === currentModule
          const Icon = MODULE_ICONS[mod] ?? Globe
          return (
            <div key={mod} className={clsx(
              'flex items-center gap-3 px-3 py-2 rounded-lg transition-all duration-150 border',
              active
                ? 'bg-cyber-50 border-cyber-200'
                : done
                  ? 'bg-emerald-50/60 border-emerald-100'
                  : 'border-transparent opacity-40',
            )}>
              <span className={clsx(
                'w-5 flex justify-center',
                active ? 'text-cyber-600' : done ? 'text-emerald-600' : 'text-dark-500',
              )}>
                <Icon className="w-4 h-4" />
              </span>
              <span className={clsx(
                'flex-1 text-sm',
                active ? 'text-cyber-700 font-medium' : done ? 'text-emerald-700' : 'text-dark-400',
              )}>
                {MODULE_LABELS[mod]}
              </span>
              {done && <Check className="w-4 h-4 text-emerald-500" strokeWidth={2.5} />}
              {active && (
                <span className="flex gap-1">
                  {[0, 1, 2].map(i => (
                    <span key={i} className="w-1 h-1 bg-cyber-500 rounded-full animate-bounce"
                      style={{ animationDelay: `${i * 0.15}s` }} />
                  ))}
                </span>
              )}
            </div>
          )
        })}
      </div>

      {agentPhaseSeen && (
        <div className="space-y-3">
          <h3 className="text-xs font-semibold text-dark-500 uppercase tracking-wider inline-flex items-center gap-1.5">
            <Bot className="w-3.5 h-3.5 text-purple-600" /> {t('scan.agentSteps')}
          </h3>
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
  )
}
