// Copyright 2026 Carlos Ganoza
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import axios from 'axios'
import clsx from 'clsx'
import {
  Bot,
  Crosshair,
  Globe,
  History,
  Play,
  Puzzle,
  Radar,
  ShieldCheck,
  Zap,
} from 'lucide-react'
import { Company } from '../types/report'
import { MODULE_LABELS } from './ScanProgress'

type Profile = 'full' | 'discover' | 'host' | 'module'

const PROFILES: { key: Profile; icon: typeof ShieldCheck }[] = [
  { key: 'full', icon: ShieldCheck },
  { key: 'discover', icon: Radar },
  { key: 'host', icon: Crosshair },
  { key: 'module', icon: Puzzle },
]

// Modules offered in the module picker (subdomain_eval is chained-only)
const MODULE_CHOICES = Object.keys(MODULE_LABELS).filter(
  (m) => m !== 'agent' && m !== 'subdomain_eval',
)

function validateTarget(v: string): string | null {
  const clean = v.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0]
  const re = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/
  return re.test(clean) ? clean : null
}

export default function NewScanView() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [companies, setCompanies] = useState<Company[]>([])
  const [target, setTarget] = useState('')
  const [profile, setProfile] = useState<Profile>('full')
  const [agentMode, setAgentMode] = useState(false)
  const [skipDiscovery, setSkipDiscovery] = useState(false)
  const [pickedModules, setPickedModules] = useState<string[]>([])
  const [companyName, setCompanyName] = useState('')
  const [error, setError] = useState('')
  const [launching, setLaunching] = useState(false)
  const [recent, setRecent] = useState<{ scan_id: string; target: string; status: string; kind: string; started_at: string | null }[]>([])

  useEffect(() => {
    axios.get<Company[]>('/api/companies').then(({ data }) => setCompanies(data)).catch(() => {})
    axios.get('/api/scans').then(({ data }) => {
      const rows = Array.isArray(data) ? data : data.scans ?? []
      setRecent(rows.slice(0, 5))
    }).catch(() => {})
  }, [])

  const knownDomains = useMemo(() => {
    const out: { domain: string; company: string }[] = []
    for (const c of companies) {
      for (const d of c.domains ?? []) out.push({ domain: d.domain, company: c.name })
    }
    return out
  }, [companies])

  const cleanTarget = target.trim().toLowerCase()
  const suggestions = useMemo(() => {
    if (!cleanTarget) return knownDomains.slice(0, 8)
    return knownDomains.filter((d) => d.domain.includes(cleanTarget)).slice(0, 8)
  }, [knownDomains, cleanTarget])

  const matched = knownDomains.find((d) => d.domain === cleanTarget)
  const effectiveCompany = matched?.company || companyName

  const toggleModule = (m: string) => {
    setPickedModules((prev) =>
      prev.includes(m) ? prev.filter((x) => x !== m) : prev.length >= 5 ? prev : [...prev, m],
    )
  }

  const launch = async () => {
    const clean = validateTarget(target)
    if (!clean) { setError(t('newScan.invalidTarget')); return }
    if (profile === 'module' && pickedModules.length === 0) { setError(t('newScan.pickModules')); return }
    setError('')
    setLaunching(true)
    try {
      if (profile === 'host') {
        const { data } = await axios.post('/api/host-scan', { host: clean })
        navigate(`/scanning/${data.scan_id}`)
        return
      }
      const payload: Record<string, unknown> = { domain: clean }
      if (profile === 'module') payload.modules = pickedModules
      if (profile === 'full' && agentMode) payload.agent_mode = true
      if (profile === 'full' && skipDiscovery) payload.skip_discovery = true
      if (!matched && effectiveCompany) payload.company_name = effectiveCompany
      const { data } = await axios.post('/api/scan', payload)
      navigate(profile === 'full' && agentMode ? `/agent/${data.scan_id}` : `/scanning/${data.scan_id}`)
    } catch (err: unknown) {
      const msg = axios.isAxiosError(err) ? err.response?.data?.detail || err.message : String(err)
      setError(t('newScan.launchError', { msg }))
      setLaunching(false)
    }
  }

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div>
        <h1 className="text-xl font-bold tracking-tight text-dark-100">{t('newScan.title')}</h1>
        <p className="text-sm text-dark-500 mt-1">{t('newScan.sub')}</p>
      </div>

      {/* Target */}
      <div className="card space-y-3">
        <label className="text-xs font-semibold text-dark-500 uppercase tracking-wider">{t('newScan.target')}</label>
        <div className="relative">
          <Globe className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-dark-600 pointer-events-none" />
          <input
            type="text"
            value={target}
            onChange={(e) => { setTarget(e.target.value); setError('') }}
            placeholder="domain.com"
            autoFocus
            spellCheck={false}
            list="known-targets"
            className="w-full bg-white border border-dark-700 rounded-xl pl-9 pr-4 py-3 font-mono text-sm text-dark-100 placeholder:text-dark-600 focus:outline-none focus:border-cyber-500 focus:ring-2 focus:ring-cyber-500/20 transition-colors duration-150"
          />
          <datalist id="known-targets">
            {suggestions.map((s) => <option key={s.domain} value={s.domain} />)}
          </datalist>
        </div>
        {matched && (
          <p className="text-xs text-dark-500">
            {t('newScan.knownTarget')} <span className="font-semibold text-dark-300">{matched.company}</span>
          </p>
        )}
        {!matched && cleanTarget && validateTarget(target) && (
          <div className="flex items-center gap-2">
            <span className="text-xs text-dark-500">{t('newScan.assignCompany')}</span>
            <select
              value={companyName}
              onChange={(e) => setCompanyName(e.target.value)}
              className="bg-white border border-dark-700 rounded-lg px-2.5 py-1.5 text-xs text-dark-200 focus:outline-none focus:border-cyber-500"
            >
              <option value="">{t('newScan.noCompany')}</option>
              {companies.map((c) => <option key={c.id} value={c.name}>{c.name}</option>)}
            </select>
          </div>
        )}
      </div>

      {/* Profile cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2.5">
        {PROFILES.map((p) => (
          <button
            key={p.key}
            onClick={() => setProfile(p.key)}
            className={clsx(
              'card !p-3.5 text-left transition-all duration-150 border',
              profile === p.key
                ? 'border-cyber-500 ring-2 ring-cyber-500/20 bg-cyber-50/50'
                : 'hover:border-dark-600',
            )}
          >
            <p.icon className={clsx('w-4 h-4 mb-2', profile === p.key ? 'text-cyber-600' : 'text-dark-500')} />
            <div className={clsx('text-sm font-semibold', profile === p.key ? 'text-cyber-700' : 'text-dark-200')}>
              {t(`newScan.profiles.${p.key}`)}
            </div>
            <div className="text-[11px] text-dark-500 mt-0.5 leading-snug">{t(`newScan.profilesDesc.${p.key}`)}</div>
          </button>
        ))}
      </div>

      {/* Module picker */}
      {profile === 'module' && (
        <div className="card space-y-2.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-dark-500 uppercase tracking-wider">{t('newScan.modules')}</span>
            <span className="text-xs text-dark-500 font-mono">{pickedModules.length}/5</span>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {MODULE_CHOICES.map((m) => (
              <button
                key={m}
                onClick={() => toggleModule(m)}
                className={clsx(
                  'px-2.5 py-1 rounded-full text-xs border transition-colors duration-150',
                  pickedModules.includes(m)
                    ? 'bg-cyber-100 border-cyber-300 text-cyber-700 font-medium'
                    : 'bg-white border-dark-700 text-dark-400 hover:border-dark-500',
                )}
              >
                {MODULE_LABELS[m]}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Options */}
      {profile === 'full' && (
        <div className="card flex flex-wrap gap-x-6 gap-y-3">
          <label className="flex items-center gap-2.5 cursor-pointer select-none group">
            <input type="checkbox" checked={agentMode} onChange={(e) => setAgentMode(e.target.checked)} className="accent-purple-600 w-3.5 h-3.5" />
            <span className="text-xs text-dark-500 group-hover:text-dark-300 inline-flex items-center gap-1.5 transition-colors duration-150">
              <Bot className="w-3.5 h-3.5 text-purple-600" /> {t('home.agentMode')}
            </span>
          </label>
          <label className="flex items-center gap-2.5 cursor-pointer select-none group">
            <input type="checkbox" checked={skipDiscovery} onChange={(e) => setSkipDiscovery(e.target.checked)} className="accent-cyber-600 w-3.5 h-3.5" />
            <span className="text-xs text-dark-500 group-hover:text-dark-300 inline-flex items-center gap-1.5 transition-colors duration-150">
              <Zap className="w-3.5 h-3.5 text-cyber-600" /> {t('newScan.skipDiscovery')}
            </span>
          </label>
        </div>
      )}

      {error && <p className="text-red-600 text-xs bg-red-50 border border-red-200 rounded-lg px-3 py-2">{error}</p>}

      <button
        onClick={launch}
        disabled={launching}
        className="w-full py-3 bg-cyber-600 hover:bg-cyber-700 active:bg-cyber-800 disabled:opacity-50 text-white font-semibold rounded-xl transition-colors duration-150 text-sm inline-flex items-center justify-center gap-2"
      >
        <Play className="w-4 h-4" />
        {launching ? t('newScan.launching') : t(`newScan.launch.${profile}`)}
      </button>

      {/* Recent scans */}
      {recent.length > 0 && (
        <div className="card">
          <h3 className="text-xs font-semibold text-dark-500 uppercase tracking-wider mb-2.5 inline-flex items-center gap-1.5">
            <History className="w-3.5 h-3.5" /> {t('newScan.recent')}
          </h3>
          <div className="space-y-1">
            {recent.map((s) => (
              <button
                key={s.scan_id}
                onClick={() => navigate(s.status === 'completed' ? `/report/${s.scan_id}` : `/scanning/${s.scan_id}`)}
                className="w-full flex items-center gap-3 px-2.5 py-1.5 rounded-lg hover:bg-dark-900 text-left transition-colors duration-150"
              >
                <span className="font-mono text-xs text-dark-200 truncate flex-1">{s.target}</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded-full border bg-dark-900 text-dark-400 border-dark-700">{s.kind}</span>
                <span className={clsx(
                  'text-[10px] px-1.5 py-0.5 rounded-full font-semibold border',
                  s.status === 'completed' ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                    : s.status === 'running' || s.status === 'queued' ? 'bg-cyber-50 text-cyber-700 border-cyber-200'
                    : 'bg-red-50 text-red-700 border-red-200',
                )}>
                  {t(`history.status.${s.status}`, s.status)}
                </span>
                <span className="text-[10px] text-dark-600 font-mono shrink-0">
                  {s.started_at ? new Date(s.started_at).toLocaleDateString() : ''}
                </span>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
