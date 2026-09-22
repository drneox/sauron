import { TechResult, FrontendCveResult, FrontendCveVuln, RiskLevel } from '../../types/report'
import { SectionCard, KeyValue, FindingsList } from '../ui'
import ModuleErrorNote, { isModuleError } from './ModuleErrorNote'
import { Cpu } from 'lucide-react'
import { useTranslation } from 'react-i18next'

const SEV_COLOR: Record<string, string> = {
  critical: 'bg-red-100 border-red-700 text-red-700',
  high:     'bg-orange-100 border-orange-300 text-orange-700',
  medium:   'bg-amber-100 border-amber-300 text-amber-700',
  low:      'bg-dark-800 border-dark-700 text-dark-300',
  unknown:  'bg-dark-800 border-dark-700 text-dark-400',
}

const BADGE_COLOR: Record<string, string> = {
  critical: 'bg-red-600 text-white',
  high:     'bg-orange-600 text-white',
  medium:   'bg-yellow-600 text-black',
  low:      'bg-dark-600 text-dark-200',
  unknown:  'bg-dark-600 text-dark-200',
}

function libMaxSeverity(npm: string, vulns: FrontendCveVuln[]): string {
  const order: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 }
  const lib = vulns.filter(v => (v.library ?? '').toLowerCase() === npm.toLowerCase() || v.library === npm)
  if (!lib.length) return 'none'
  return lib.reduce((best, v) => (
    (order[v.severity] ?? 0) > (order[best] ?? 0) ? v.severity : best
  ), 'unknown')
}

const RISK_ORDER: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 }
function maxRisk(...risks: (string | undefined)[]): RiskLevel {
  return risks.reduce<string>((best, r) =>
    (RISK_ORDER[r ?? 'low'] ?? 0) > (RISK_ORDER[best] ?? 0) ? (r ?? best) : best, 'low') as RiskLevel
}

interface Props {
  data: TechResult
  frontendCve?: FrontendCveResult
}

export default function TechSection({ data, frontendCve }: Props) {
  const { t } = useTranslation()
  if (!data) return null
  if (isModuleError(data)) {
    return (
      <SectionCard title={t('report.tech.title')} icon={<Cpu />}>
        <ModuleErrorNote error={data.error} />
      </SectionCard>
    )
  }
  const cveData = frontendCve && !isModuleError(frontendCve) ? frontendCve : undefined
  const detected = cveData?.detected ?? []
  const vulns    = cveData?.vulnerabilities ?? []
  const risk     = maxRisk(data.risk, cveData?.risk)

  return (
    <SectionCard title={t('report.tech.title')} icon={<Cpu />} risk={risk}>
      <div className="space-y-0 mb-4">
        <KeyValue label={t('report.tech.server')} value={data.server} />
        <KeyValue label={t('report.tech.poweredBy')} value={data.powered_by} />
      </div>

      {(data.technologies?.length ?? 0) > 0 && (
        <div className="mb-4">
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-2">
            {t('report.withCount', { label: t('report.tech.detected'), count: data.technologies.length })}
          </h4>
          <div className="flex flex-wrap gap-1.5">
            {(data.technologies ?? []).map((t) => (
              <span key={t} className="bg-dark-800 border border-dark-700 text-dark-200 text-xs px-2.5 py-0.5 rounded-full">
                {t}
              </span>
            ))}
          </div>
        </div>
      )}

      {detected.length > 0 && (
        <div className="mb-4">
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-2">
            {t('report.withCount', { label: t('report.tech.frontendLibs'), count: detected.length })}
            {(frontendCve?.cve_count ?? 0) > 0 && (
              <span className="ml-2 text-red-600 normal-case tracking-normal font-normal">
                {t('report.tech.cvesFound', { count: frontendCve!.cve_count })}
              </span>
            )}
          </h4>
          <div className="flex flex-wrap gap-1.5">
            {detected.map((lib) => {
              const sev = lib.vuln_count > 0 ? libMaxSeverity(lib.name, vulns) : 'none'
              const chipCls = sev !== 'none'
                ? SEV_COLOR[sev] ?? SEV_COLOR.unknown
                : 'bg-dark-800 border-dark-700 text-dark-200'
              return (
                <span
                  key={lib.npm}
                  className={`border text-xs px-2.5 py-0.5 rounded-full flex items-center gap-1.5 ${chipCls}`}
                  title={lib.vuln_count > 0 ? vulns.filter(v => v.library === lib.name).map(v => `${v.cve}: ${v.summary}`).join('\n') : undefined}
                >
                  <span className="font-medium">{lib.name}</span>
                  <span className="opacity-60 text-[10px]">{lib.version}</span>
                  {lib.vuln_count > 0 && (
                    <span className={`text-[10px] font-bold px-1 rounded ${BADGE_COLOR[sev] ?? BADGE_COLOR.unknown}`}>
                      {t('report.tech.cveBadge', { count: lib.vuln_count })}
                    </span>
                  )}
                </span>
              )
            })}
          </div>

          {vulns.length > 0 && (
            <details className="mt-3">
              <summary className="text-[10px] text-dark-500 cursor-pointer hover:text-dark-300 select-none">
                {t('report.tech.viewDetails', { count: vulns.length })}
              </summary>
              <div className="mt-2 space-y-1.5">
                {vulns.map((v, i) => (
                  <div key={i} className={`border rounded px-2.5 py-1.5 text-xs ${SEV_COLOR[v.severity] ?? SEV_COLOR.unknown}`}>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-bold font-mono">{v.cve}</span>
                      <span className="opacity-70">{v.library} {v.detected_version}</span>
                      <span className={`text-[10px] font-bold px-1.5 py-px rounded uppercase ${BADGE_COLOR[v.severity] ?? BADGE_COLOR.unknown}`}>
                        {v.severity}
                      </span>
                      {(v.fixed_versions ?? []).length > 0 && (
                        <span className="text-emerald-600 text-[10px]">
                          {t('report.tech.fix', { version: v.fixed_versions[0] })}
                        </span>
                      )}
                    </div>
                    {v.summary && (
                      <p className="mt-0.5 opacity-80 leading-snug">{v.summary}</p>
                    )}
                  </div>
                ))}
              </div>
            </details>
          )}
        </div>
      )}

      {(data.cookies?.length ?? 0) > 0 && (
        <div>
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-2">
            {t('report.withCount', { label: t('report.tech.cookies'), count: data.cookies.length })}
          </h4>
          <div className="space-y-1">
            {(data.cookies ?? []).map((c, i) => (
              <div key={i} className="flex items-center gap-2 text-xs">
                <span className="text-dark-300 font-mono">{c.name}</span>
                <span className={c.secure ? 'text-emerald-600' : 'text-red-600'} title={t('report.tech.secureFlag')}>Sec</span>
                <span className={c.httponly ? 'text-emerald-600' : 'text-red-600'} title={t('report.tech.httpOnlyFlag')}>Http</span>
                {c.samesite && <span className="text-dark-500">SameSite={c.samesite}</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      <FindingsList findings={[...(data.findings ?? []), ...(frontendCve?.findings ?? [])]} />
    </SectionCard>
  )
}
