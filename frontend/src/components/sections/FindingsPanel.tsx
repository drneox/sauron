import { Finding } from '../../types/report'
import { LinkifyText } from '../ui'
import clsx from 'clsx'
import { AlertCircle, AlertOctagon, AlertTriangle, Info, Search, type LucideIcon } from 'lucide-react'
import { useTranslation } from 'react-i18next'

const RISK_ICON: Record<string, LucideIcon> = {
  critical: AlertOctagon, high: AlertTriangle, medium: AlertCircle, low: Info,
}

const RISK_COLOR: Record<string, string> = {
  critical: 'border-l-red-500 bg-red-50 text-red-600',
  high: 'border-l-orange-500 bg-orange-50 text-orange-600',
  medium: 'border-l-amber-500 bg-amber-50 text-amber-600',
  low: 'border-l-emerald-500 bg-emerald-50 text-emerald-600',
}

const MODULE_LABEL: Record<string, string> = {
  whois: 'WHOIS', dns: 'DNS', ssl: 'SSL/TLS', headers: 'Headers',
  email: 'Email', tech: 'Technology', ports: 'Ports', subdomains: 'Subdomains',
  js_secrets: 'JS Secrets', secret_verification: 'Secret Verification',
  smart_fuzz: 'Smart Fuzzing', subdomain_eval: 'Chained Eval',
  mobile_apps: 'Mobile Apps', reverse_ip: 'Reverse IP',
}

interface Props {
  findings: Finding[]
}

export default function FindingsPanel({ findings }: Props) {
  const { t } = useTranslation()
  const list = findings ?? []
  const grouped = ['critical', 'high', 'medium', 'low'].flatMap(risk =>
    list.filter(f => f.risk === risk)
  )

  return (
    <div className="card h-full">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-[15px] font-semibold tracking-tight text-dark-100 flex items-center gap-2"><Search className="w-4 h-4 text-cyber-600" /> {t('report.findings.title')}</h2>
        <div className="flex gap-2 text-xs">
          {['critical', 'high', 'medium', 'low'].map(r => {
            const count = list.filter(f => f.risk === r).length
            if (!count) return null
            return (
              <span key={r} className={clsx(
                'px-2 py-0.5 rounded-full border font-bold uppercase',
                r === 'critical' && 'bg-red-100 text-red-600 border-red-200',
                r === 'high' && 'bg-orange-100 text-orange-600 border-orange-300/50',
                r === 'medium' && 'bg-amber-100 text-amber-600 border-amber-200',
                r === 'low' && 'bg-emerald-100 text-emerald-600 border-emerald-200',
              )}>
                {count} {r}
              </span>
            )
          })}
        </div>
      </div>

      {list.length === 0 ? (
        <div className="text-center text-dark-500 py-8 text-sm">
          {t('report.findings.empty')}
        </div>
      ) : (
        <div className="space-y-1.5 max-h-96 overflow-y-auto pr-1">
          {grouped.map((f, i) => (
            <div
              key={i}
              className={clsx('border-l-2 pl-3 py-2 rounded-r-lg text-xs', RISK_COLOR[f.risk])}
            >
              <div className="flex items-start gap-2">
                {(() => { const RiskIcon = RISK_ICON[f.risk] ?? Info; return <RiskIcon className="w-3.5 h-3.5 mt-px shrink-0" /> })()}
                <div className="flex-1">
                  <span className="text-dark-400 text-[10px] uppercase tracking-wider">
                    [{MODULE_LABEL[f.module] ?? f.module}]
                  </span>
                  <p className="text-dark-200 mt-0.5 leading-snug">
                    <LinkifyText text={typeof f.finding === 'string' ? f.finding : JSON.stringify(f.finding)} />
                  </p>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
