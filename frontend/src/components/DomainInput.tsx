import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  ArrowRight,
  Bot,
  FileSearch,
  Gauge,
  Globe,
  Lock,
  Mail,
  Network,
  Radar,
  ShieldCheck,
  Zap,
} from 'lucide-react'

interface Props {
  onScan: (domain: string, agentMode: boolean) => void
}

const EXAMPLES = ['github.com', 'apache.org', 'mozilla.org', 'cloudflare.com']

const FEATURES = [
  { icon: Network, key: 'subdomains' },
  { icon: Lock, key: 'ssl' },
  { icon: Globe, key: 'ports' },
  { icon: Mail, key: 'email' },
  { icon: ShieldCheck, key: 'headers' },
  { icon: Zap, key: 'tech' },
  { icon: FileSearch, key: 'whois' },
  { icon: Gauge, key: 'risk' },
] as const

export default function DomainInput({ onScan }: Props) {
  const { t } = useTranslation()
  const [domain, setDomain] = useState('')
  const [agentMode, setAgentMode] = useState(false)
  const [error, setError] = useState('')

  const validate = (v: string) => {
    const clean = v.trim().toLowerCase()
      .replace(/^https?:\/\//, '')
      .split('/')[0]
    const re = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/
    return re.test(clean) ? clean : null
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const clean = validate(domain)
    if (!clean) {
      setError(t('home.invalidDomain'))
      return
    }
    setError('')
    onScan(clean, agentMode)
  }

  return (
    <div className="relative -mx-4 px-4">
      <div className="absolute inset-x-0 top-0 h-[420px] bg-dots opacity-70 pointer-events-none [mask-image:linear-gradient(to_bottom,black,transparent)]" />

      <div className="relative max-w-3xl pt-14 pb-8 space-y-10">
        {/* Hero */}
        <div className="space-y-5">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyber-50 border border-cyber-200 text-cyber-700 text-xs font-medium">
            <Radar className="w-3.5 h-3.5" />
            {t('home.badge')}
          </div>
          <h1 className="text-[44px] leading-[1.08] font-bold tracking-tight text-dark-100">
            {t('home.title1')}
            <br />
            <span className="text-cyber-600">{t('home.title2')}</span>
          </h1>
          <p className="text-dark-500 max-w-xl text-[15px] leading-relaxed">
            {t('home.sub')}
          </p>
        </div>

        {/* Input form */}
        <form onSubmit={handleSubmit} className="space-y-3">
          <div className="flex items-stretch bg-white border border-dark-700 rounded-xl shadow-sm shadow-dark-800/40 focus-within:border-cyber-500 focus-within:ring-2 focus-within:ring-cyber-500/20 transition-shadow duration-150">
            <Globe className="w-4 h-4 ml-4 self-center text-dark-600 shrink-0" />
            <input
              type="text"
              value={domain}
              onChange={(e) => { setDomain(e.target.value); setError('') }}
              placeholder={t('home.placeholder')}
              autoFocus
              spellCheck={false}
              className="flex-1 bg-transparent px-3 py-3.5 font-mono text-sm text-dark-100 placeholder:text-dark-600 focus:outline-none"
            />
            <button
              type="submit"
              className="m-1.5 px-5 bg-cyber-600 hover:bg-cyber-700 active:bg-cyber-800 text-white font-semibold rounded-lg transition-colors duration-150 text-sm inline-flex items-center gap-2"
            >
              {t('home.scan')}
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
          {error && (
            <p className="text-red-600 text-xs">{error}</p>
          )}
          <label className="flex items-center gap-2.5 cursor-pointer select-none w-fit group"
            title={t('home.agentModeTitle')}
          >
            <input
              type="checkbox"
              checked={agentMode}
              onChange={(e) => setAgentMode(e.target.checked)}
              className="accent-purple-600 w-3.5 h-3.5"
            />
            <span className="text-xs text-dark-500 group-hover:text-dark-300 transition-colors duration-150 inline-flex items-center gap-1.5">
              <Bot className="w-3.5 h-3.5 text-purple-600" />
              {t('home.agentMode')} <span className="text-dark-600">{t('home.agentModeHint')}</span>
            </span>
          </label>
        </form>

        {/* Examples */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-dark-500 text-xs">{t('home.tryLabel')}</span>
          {EXAMPLES.map((ex) => (
            <button
              key={ex}
              onClick={() => setDomain(ex)}
              className="text-xs font-mono text-cyber-700 hover:text-cyber-800 bg-cyber-50 hover:bg-cyber-100 border border-cyber-200 rounded-full px-3 py-1 transition-colors duration-150"
            >
              {ex}
            </button>
          ))}
        </div>

        {/* Features grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-2">
          {FEATURES.map((f) => (
            <div
              key={f.key}
              className="bg-white/80 border border-dark-800 rounded-lg px-3 py-2.5 text-xs text-dark-300 font-medium flex items-center gap-2"
            >
              <f.icon className="w-4 h-4 text-cyber-600 shrink-0" />
              {t(`home.features.${f.key}`)}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
