import { useEffect, useState } from 'react'
import axios from 'axios'
import clsx from 'clsx'
import { useTranslation } from 'react-i18next'
import { AppSettings } from '../types/report'
import { SectionCard } from './ui'
import {
  BadgeCheck,
  Bell,
  Bot,
  Clock,
  Cloud,
  Globe,
  KeyRound,
  Languages,
  Mail,
  Network,
  Puzzle,
  Radar,
  X,
  type LucideIcon,
} from 'lucide-react'

const errorMessage = (err: unknown, fallback: string) =>
  axios.isAxiosError(err)
    ? err.response?.data?.detail || err.message || fallback
    : fallback

const MODULE_GROUPS: { key: string; icon: LucideIcon; modules: string[] }[] = [
  { key: 'recon', icon: Radar, modules: ['whois', 'dns', 'subdomains', 'dnssec', 'robots', 'blacklist'] },
  { key: 'network', icon: Network, modules: ['ports', 'ssl', 'tls', 'waf'] },
  { key: 'web', icon: Globe, modules: ['headers', 'cors', 'cookies', 'tech', 'frontend_cve', 'api_exposure', 'admin'] },
  { key: 'secrets', icon: KeyRound, modules: ['exposed', 'js_secrets', 'secret_verification', 'wayback'] },
  { key: 'cloud', icon: Cloud, modules: ['cloud_storage', 'breach', 'nuclei'] },
  { key: 'email', icon: Mail, modules: ['email'] },
]

const MODULE_LABELS: Record<string, string> = {
  whois: 'WHOIS',
  dns: 'DNS Records',
  subdomains: 'Subdomain Enum',
  dnssec: 'DNSSEC',
  robots: 'Robots & Sitemap',
  blacklist: 'Blacklist / Reputation',
  ports: 'Port Scan',
  ssl: 'SSL Certificate',
  tls: 'TLS Audit',
  waf: 'WAF / CDN Detection',
  headers: 'Security Headers',
  cors: 'CORS',
  cookies: 'Cookie Security',
  tech: 'Tech Fingerprint',
  frontend_cve: 'Frontend CVEs',
  api_exposure: 'API Exposure',
  admin: 'Admin Panel Discovery',
  exposed: 'Exposed Files',
  js_secrets: 'JS Secrets',
  secret_verification: 'Secret Verification',
  wayback: 'Wayback Secrets',
  cloud_storage: 'Cloud Storage',
  breach: 'Breaches & Leaks',
  nuclei: 'Nuclei Templates',
  email: 'Email Security',
  mobile_apps: 'Mobile Apps',
  reverse_ip: 'Reverse IP',
  subdomain_eval: 'Chained Evaluation',
  smart_fuzz: 'Smart Fuzzing',
}

const moduleLabel = (key: string) =>
  MODULE_LABELS[key] ?? key.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())

function Switch({ checked, disabled, onChange }: {
  checked: boolean
  disabled?: boolean
  onChange: (next: boolean) => void
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={clsx(
        'relative inline-flex h-5 w-9 shrink-0 rounded-full transition-colors duration-200',
        checked ? 'bg-cyber-600' : 'bg-dark-700',
        disabled && 'opacity-50 cursor-not-allowed',
      )}
    >
      <span
        className={clsx(
          'absolute top-[3px] h-3.5 w-3.5 rounded-full bg-white shadow transition-transform duration-200',
          checked ? 'translate-x-[19px]' : 'translate-x-[3px]',
        )}
      />
    </button>
  )
}

function StatusChip({ ok, okLabel, badLabel }: { ok: boolean; okLabel: string; badLabel: string }) {
  return (
    <span className={clsx(
      'chip',
      ok
        ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
        : 'bg-amber-50 text-amber-700 border-amber-200',
    )}>
      {ok && <BadgeCheck className="w-3 h-3" />}
      {ok ? okLabel : badLabel}
    </span>
  )
}

export default function SettingsView() {
  const { t, i18n } = useTranslation()
  const [settings, setSettings] = useState<AppSettings | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [stepsInput, setStepsInput] = useState('')
  const [savingSteps, setSavingSteps] = useState(false)

  useEffect(() => {
    let cancelled = false
    axios.get<AppSettings>('/api/settings')
      .then(({ data }) => {
        if (cancelled) return
        setSettings(data)
        setStepsInput(String(data.agent_default_steps ?? ''))
      })
      .catch((err) => {
        if (!cancelled) setError(errorMessage(err, t('settings.loadError')))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => { cancelled = true }
  }, [])

  const toggleModule = async (key: string, enabled: boolean) => {
    if (!settings) return
    const prev = settings
    setSettings({ ...settings, enabled_modules: { ...settings.enabled_modules, [key]: enabled } })
    try {
      const { data } = await axios.put<AppSettings>('/api/settings', { enabled_modules: { [key]: enabled } })
      setSettings(data)
      setError('')
    } catch (err) {
      setSettings(prev)
      setError(errorMessage(err, t('settings.moduleError', { module: moduleLabel(key) })))
    }
  }

  const saveSteps = async () => {
    if (!settings || savingSteps) return
    const n = Math.round(Number(stepsInput))
    if (!Number.isFinite(n) || n < 1 || n > 30) {
      setStepsInput(String(settings.agent_default_steps ?? ''))
      return
    }
    if (n === settings.agent_default_steps) return
    const prev = settings
    setSettings({ ...settings, agent_default_steps: n })
    setSavingSteps(true)
    try {
      const { data } = await axios.put<AppSettings>('/api/settings', { agent_default_steps: n })
      setSettings(data)
      setStepsInput(String(data.agent_default_steps ?? n))
      setError('')
    } catch (err) {
      setSettings(prev)
      setStepsInput(String(prev.agent_default_steps ?? ''))
      setError(errorMessage(err, t('settings.stepsError')))
    } finally {
      setSavingSteps(false)
    }
  }

  const saveInterval = async (hours: number) => {
    if (!settings) return
    const prev = settings
    setSettings({ ...settings, default_interval_hours: hours })
    try {
      const { data } = await axios.put<AppSettings>('/api/settings', { default_interval_hours: hours })
      setSettings(data)
      setError('')
    } catch (err) {
      setSettings(prev)
      setError(errorMessage(err, t('settings.intervalError')))
    }
  }

  const saveChainEval = async (patch: {
    chain_eval_enabled?: boolean
    chain_eval_max_targets?: number
    chain_eval_fuzz?: boolean
    chain_eval_scope?: 'new' | 'all'
    ai_domain_suggestions?: boolean
  }) => {
    if (!settings) return
    const prev = settings
    setSettings({ ...settings, ...patch } as AppSettings)
    try {
      const { data } = await axios.put<AppSettings>('/api/settings', patch)
      setSettings(data)
      setError('')
    } catch (err) {
      setSettings(prev)
      setError(errorMessage(err, t('settings.chainError')))
    }
  }

  const saveScanning = async (patch: {
    vuln_scan_enabled?: boolean
    discovery_enabled?: boolean
    default_discover_interval_hours?: number
    skip_discovery_default?: boolean
  }) => {
    if (!settings) return
    const prev = settings
    setSettings({ ...settings, ...patch } as AppSettings)
    try {
      const { data } = await axios.put<AppSettings>('/api/settings', patch)
      setSettings(data)
      setError('')
    } catch (err) {
      setSettings(prev)
      setError(errorMessage(err, t('settings.scanningError')))
    }
  }

  const enabledModules = settings?.enabled_modules ?? {}
  const knownKeys = new Set(MODULE_GROUPS.flatMap((g) => g.modules))
  const otherKeys = Object.keys(enabledModules).filter((k) => !knownKeys.has(k)).sort()
  const groups = [
    ...MODULE_GROUPS.map((g) => ({
      ...g,
      label: t(`settings.groups.${g.key}`),
      modules: g.modules.filter((m) => m in enabledModules),
    })).filter((g) => g.modules.length > 0),
    ...(otherKeys.length > 0
      ? [{ label: t('settings.groups.other'), icon: Puzzle, modules: otherKeys }]
      : []),
  ]

  return (
    <div className="max-w-4xl mx-auto space-y-4">
      <h2 className="text-xl font-semibold tracking-tight text-dark-100">{t('settings.title')}</h2>

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
          {t('settings.loading')}
        </div>
      ) : !settings ? null : (
        <>
          {/* Language */}
          <SectionCard title={t('settings.languageTitle')} icon={<Languages />}>
            <p className="text-xs text-dark-500 mb-4">
              {t('settings.languageDesc')}
            </p>
            <div className="flex flex-wrap items-center gap-3">
              <label className="text-sm text-dark-500" htmlFor="language-select">
                {t('nav.language')}
              </label>
              <select
                id="language-select"
                value={i18n.language}
                onChange={(e) => i18n.changeLanguage(e.target.value)}
                className="bg-white border border-dark-700 rounded-lg px-3 py-1.5 text-sm text-dark-200 focus:outline-none focus:border-cyber-500 transition-colors duration-150"
              >
                <option value="en">{t('settings.english')}</option>
                <option value="es">{t('settings.spanish')}</option>
              </select>
            </div>
          </SectionCard>

          {/* Scan modules */}
          <SectionCard title={t('settings.modulesTitle')} icon={<Puzzle />}>
            <p className="text-xs text-dark-500 mb-4">
              {t('settings.modulesDesc')}
            </p>
            <div className="space-y-5">
              {groups.map((g) => (
                <div key={g.label}>
                  <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-dark-500 mb-2">
                    <g.icon className="w-3.5 h-3.5" />
                    {g.label}
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-6 gap-y-2">
                    {g.modules.map((key) => (
                      <div key={key} className="flex items-center justify-between gap-3 py-1">
                        <span className="text-sm text-dark-200 truncate" title={key}>
                          {moduleLabel(key)}
                        </span>
                        <Switch
                          checked={!!enabledModules[key]}
                          onChange={(next) => toggleModule(key, next)}
                        />
                      </div>
                    ))}
                  </div>
                </div>
              ))}
              {groups.length === 0 && (
                <p className="text-sm text-dark-500 italic">{t('settings.noModules')}</p>
              )}
            </div>
          </SectionCard>

          {/* AI Agent */}
          <SectionCard title={t('settings.aiTitle')} icon={<Bot />}>
            <div className="space-y-4">
              <div className="flex flex-wrap items-center gap-3">
                <StatusChip
                  ok={!!settings.ai?.configured}
                  okLabel={`${t('settings.configured')}${settings.ai?.model ? ` — ${settings.ai.model}` : ''}`}
                  badLabel={t('settings.notConfigured')}
                />
                {!settings.ai?.configured && (
                  <span className="text-xs text-amber-700">
                    {t('settings.setAiKey')}
                  </span>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <label className="text-sm text-dark-500" htmlFor="agent-steps">
                  {t('settings.defaultMaxSteps')}
                </label>
                <input
                  id="agent-steps"
                  type="number"
                  min={1}
                  max={30}
                  value={stepsInput}
                  disabled={savingSteps}
                  onChange={(e) => setStepsInput(e.target.value)}
                  onBlur={saveSteps}
                  onKeyDown={(e) => { if (e.key === 'Enter') (e.target as HTMLInputElement).blur() }}
                  className="w-20 bg-white border border-dark-700 rounded-lg px-3 py-1.5 text-sm text-dark-100 font-mono focus:outline-none focus:border-cyber-500 focus:ring-2 focus:ring-cyber-500/20 transition-colors duration-150 disabled:opacity-50"
                />
                <span className="text-xs text-dark-500">{t('settings.stepsHint')}</span>
              </div>
            </div>
          </SectionCard>

          {/* Chained Evaluation */}
          <SectionCard title={t('settings.chainTitle')} icon={<Network />}>
            <div className="space-y-4">
              <div className="flex flex-wrap items-center gap-3">
                <Switch
                  checked={settings.chain_eval_enabled ?? true}
                  onChange={(next) => saveChainEval({ chain_eval_enabled: next })}
                />
                <span className="text-sm text-dark-200">
                  {t('settings.chainToggle')}
                </span>
              </div>
              <p className="text-xs text-dark-500 leading-relaxed">
                {t('settings.chainDesc')}
              </p>
              <div className="flex flex-wrap items-center gap-3">
                <label className="text-sm text-dark-500" htmlFor="chain-max">
                  {t('settings.chainMax')}
                </label>
                <input
                  id="chain-max"
                  type="number"
                  min={1}
                  max={50}
                  defaultValue={settings.chain_eval_max_targets ?? 10}
                  onBlur={(e) => {
                    const n = Math.round(Number(e.target.value))
                    if (Number.isFinite(n) && n >= 1 && n <= 50) saveChainEval({ chain_eval_max_targets: n })
                  }}
                  className="w-20 bg-white border border-dark-700 rounded-lg px-3 py-1.5 text-sm text-dark-100 font-mono focus:outline-none focus:border-cyber-500 focus:ring-2 focus:ring-cyber-500/20 transition-colors duration-150"
                />
                <span className="text-xs text-dark-500">{t('settings.chainMaxHint')}</span>
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <Switch
                  checked={settings.chain_eval_fuzz ?? true}
                  onChange={(next) => saveChainEval({ chain_eval_fuzz: next })}
                />
                <div>
                  <span className="text-sm text-dark-200">{t('settings.chainFuzzToggle')}</span>
                  <p className="text-xs text-dark-500 leading-relaxed">{t('settings.chainFuzzDesc')}</p>
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <label className="text-sm text-dark-500" htmlFor="chain-scope">
                  {t('settings.chainScope')}
                </label>
                <select
                  id="chain-scope"
                  value={settings.chain_eval_scope ?? 'new'}
                  onChange={(e) => saveChainEval({ chain_eval_scope: e.target.value as 'new' | 'all' })}
                  className="bg-white border border-dark-700 rounded-lg px-3 py-1.5 text-sm text-dark-200 focus:outline-none focus:border-cyber-500 transition-colors duration-150"
                >
                  <option value="new">{t('settings.chainScopeNew')}</option>
                  <option value="all">{t('settings.chainScopeAll')}</option>
                </select>
                <span className="text-xs text-dark-500">{t('settings.chainScopeHint')}</span>
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <Switch
                  checked={settings.ai_domain_suggestions ?? false}
                  onChange={(next) => saveChainEval({ ai_domain_suggestions: next })}
                />
                <div>
                  <span className="text-sm text-dark-200">{t('settings.aiDomainSuggToggle')}</span>
                  <p className="text-xs text-dark-500 leading-relaxed">{t('settings.aiDomainSuggDesc')}</p>
                </div>
              </div>
            </div>
          </SectionCard>

          {/* Scanning: vuln scans and asset discovery scheduled independently */}
          <SectionCard title={t('settings.scanningTitle')} icon={<Clock />}>
            <div className="space-y-5">
              <div>
                <div className="text-[11px] font-semibold uppercase tracking-wider text-dark-500 mb-2">
                  {t('settings.vulnScansTitle')}
                </div>
                <div className="flex flex-wrap items-center gap-3">
                  <Switch
                    checked={settings.vuln_scan_enabled ?? true}
                    onChange={(next) => saveScanning({ vuln_scan_enabled: next })}
                  />
                  <span className="text-sm text-dark-200">
                    {t('settings.vulnScansToggle')}
                  </span>
                </div>
                <p className="text-xs text-dark-500 mt-1 mb-3 leading-relaxed">
                  {t('settings.vulnScansDesc')}
                </p>
                <div className="flex flex-wrap items-center gap-3 mb-3">
                  <Switch
                    checked={settings.skip_discovery_default ?? false}
                    onChange={(next) => saveScanning({ skip_discovery_default: next })}
                  />
                  <div>
                    <span className="text-sm text-dark-200">{t('settings.skipDiscoveryToggle')}</span>
                    <p className="text-xs text-dark-500 leading-relaxed">{t('settings.skipDiscoveryDesc')}</p>
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-3">
                  <label className="text-sm text-dark-500" htmlFor="default-interval">
                    {t('settings.defaultInterval')}
                  </label>
                  <select
                    id="default-interval"
                    value={settings.default_interval_hours ?? 24}
                    onChange={(e) => saveInterval(Number(e.target.value))}
                    className="bg-white border border-dark-700 rounded-lg px-3 py-1.5 text-sm text-dark-200 focus:outline-none focus:border-cyber-500 transition-colors duration-150"
                  >
                    <option value={24}>{t('settings.every24')}</option>
                    <option value={168}>{t('settings.weekly')}</option>
                    <option value={720}>{t('settings.monthly')}</option>
                  </select>
                  <span className="text-xs text-dark-500">{t('settings.intervalHint')}</span>
                </div>
              </div>
              <div className="pt-4 border-t border-dark-800">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-dark-500 mb-2">
                  {t('settings.discoveryBlockTitle')}
                </div>
                <div className="flex flex-wrap items-center gap-3">
                  <Switch
                    checked={settings.discovery_enabled ?? true}
                    onChange={(next) => saveScanning({ discovery_enabled: next })}
                  />
                  <span className="text-sm text-dark-200">
                    {t('settings.discoveryToggle')}
                  </span>
                </div>
                <p className="text-xs text-dark-500 mt-1 mb-3 leading-relaxed">
                  {t('settings.discoveryDesc')}
                </p>
                <div className="flex flex-wrap items-center gap-3">
                  <label className="text-sm text-dark-500" htmlFor="default-discover-interval">
                    {t('settings.defaultDiscoverInterval')}
                  </label>
                  <select
                    id="default-discover-interval"
                    value={settings.default_discover_interval_hours ?? 720}
                    onChange={(e) => saveScanning({ default_discover_interval_hours: Number(e.target.value) })}
                    className="bg-white border border-dark-700 rounded-lg px-3 py-1.5 text-sm text-dark-200 focus:outline-none focus:border-cyber-500 transition-colors duration-150"
                  >
                    <option value={24}>{t('settings.every24')}</option>
                    <option value={168}>{t('settings.weekly')}</option>
                    <option value={720}>{t('settings.monthly')}</option>
                  </select>
                  <span className="text-xs text-dark-500">{t('settings.discoverIntervalHint')}</span>
                </div>
              </div>
            </div>
          </SectionCard>

          {/* Integrations (read-only) */}
          <SectionCard title={t('settings.integrationsTitle')} icon={<Network />}>
            <div className="divide-y divide-dark-800">
              <div className="flex flex-wrap items-center gap-3 py-2.5">
                <span className="text-sm text-dark-100 font-medium min-w-[140px]">{t('settings.proxyPool')}</span>
                <StatusChip
                  ok={!!settings.proxy?.enabled}
                  okLabel={t('settings.enabledProxies', { count: settings.proxy?.pool_size ?? 0 })}
                  badLabel={t('settings.disabled')}
                />
                {!settings.proxy?.enabled && (
                  <span className="text-xs text-dark-500">
                    {t('settings.setProxy')}
                  </span>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-3 py-2.5">
                <span className="text-sm text-dark-100 font-medium min-w-[140px] inline-flex items-center gap-1.5">
                  <Bell className="w-3.5 h-3.5 text-dark-500" />
                  {t('settings.notifications')}
                </span>
                <StatusChip
                  ok={!!settings.notify?.configured}
                  okLabel={t('settings.configured')}
                  badLabel={t('settings.notConfigured')}
                />
                {!settings.notify?.configured && (
                  <span className="text-xs text-dark-500">
                    {t('settings.setNotify')}
                  </span>
                )}
              </div>
            </div>
            <p className="text-xs text-dark-500 mt-3">
              {t('settings.integrationsNote')}
            </p>
          </SectionCard>
        </>
      )}
    </div>
  )
}
