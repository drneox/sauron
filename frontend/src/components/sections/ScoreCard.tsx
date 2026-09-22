import { Scorecard, ScanReport } from '../../types/report'
import { useTranslation } from 'react-i18next'

const RISK_ORDER = { low: 0, medium: 1, high: 2, critical: 3 }

interface Props {
  scorecard: Scorecard
  modules: ScanReport['modules']
}

const gradeColor = (g: string) => {
  if (g === 'A') return 'text-emerald-600'
  if (g === 'B') return 'text-cyan-700'
  if (g === 'C') return 'text-amber-600'
  if (g === 'D') return 'text-orange-600'
  return 'text-red-600'
}

const MODULE_LABELS: Record<string, string> = {
  whois: 'WHOIS', dns: 'DNS', dnssec: 'DNSSEC',
  ssl: 'SSL/TLS', tls: 'TLS Audit',
  headers: 'Headers', cors: 'CORS', cookies: 'Cookies',
  email: 'Email Security', tech: 'Technology',
  waf: 'WAF / CDN', robots: 'Robots/Sitemap',
  admin: 'Admin Panels', js_secrets: 'JS Secrets',
  secret_verification: 'Secret Verification',
  blacklist: 'Blacklists', exposed: 'Exposed Files',
  breach: 'Breaches', ports: 'Ports', subdomains: 'Subdomains',
  mobile_apps: 'Mobile Apps', reverse_ip: 'Reverse IP',
  subdomain_eval: 'Chained Eval', smart_fuzz: 'Smart Fuzzing',
  wayback: 'Wayback', cloud_storage: 'Cloud Storage',
  api_exposure: 'API Exposure', frontend_cve: 'Frontend CVEs',
}

const RISK_COLOR: Record<string, string> = {
  low: 'text-emerald-600',
  medium: 'text-amber-600',
  high: 'text-orange-600',
  critical: 'text-red-600',
}

export default function ScoreCard({ scorecard, modules }: Props) {
  const { t } = useTranslation()
  if (!scorecard) return null
  const moduleRisks = Object.entries(modules ?? {}).map(([name, mod]) => ({
    name,
    risk: (mod as { risk?: string } | null)?.risk ?? 'low',
  })).sort((a, b) => RISK_ORDER[b.risk as keyof typeof RISK_ORDER] - RISK_ORDER[a.risk as keyof typeof RISK_ORDER])

  return (
    <div className="card flex flex-col gap-4">
      {/* Grade */}
      <div className="text-center border-b border-dark-800 pb-4">
        {scorecard.grade == null || scorecard.score == null ? (
          <>
            <div className="text-7xl font-bold text-dark-400">—</div>
            <div className="text-dark-500 text-sm mt-1">{t('report.scorecard.discoveryPass')}</div>
          </>
        ) : (
          <>
            <div className={`text-7xl font-bold ${gradeColor(scorecard.grade)}`}>
              {scorecard.grade}
            </div>
            <div className="text-dark-500 text-sm mt-1">{t('report.scorecard.securityScore')}</div>
            <div className="mt-2">
              <div className="h-2 bg-dark-800 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all ${
                    scorecard.score >= 75 ? 'bg-emerald-500' :
                    scorecard.score >= 50 ? 'bg-yellow-500' : 'bg-red-500'
                  }`}
                  style={{ width: `${scorecard.score}%` }}
                />
              </div>
              <div className="text-dark-500 text-xs mt-1">{scorecard.score}/100</div>
            </div>
          </>
        )}
      </div>

      {/* Module risk breakdown */}
      <div className="space-y-2">
        <h3 className="text-xs font-semibold text-dark-500 uppercase tracking-wider">{t('report.scorecard.moduleRisks')}</h3>
        {moduleRisks.map(({ name, risk }) => (
          <div key={name} className="flex justify-between text-xs">
            <span className="text-dark-400">{MODULE_LABELS[name] ?? name}</span>
            <span className={`font-semibold capitalize ${RISK_COLOR[risk] ?? 'text-dark-400'}`}>{risk}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
