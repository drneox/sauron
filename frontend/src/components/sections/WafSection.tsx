import { WafResult } from '../../types/report'
import { SectionCard, FindingsList } from '../ui'
import ModuleErrorNote, { isModuleError } from './ModuleErrorNote'
import clsx from 'clsx'
import { ShieldCheck } from 'lucide-react'
import { useTranslation } from 'react-i18next'

const CAT_COLOR: Record<string, string> = {
  'WAF': 'text-emerald-600 bg-emerald-50 border-emerald-200',
  'CDN/WAF': 'text-cyan-700 bg-cyan-50 border-cyan-200',
  'CDN': 'text-blue-600 bg-blue-50 border-blue-200',
  'CDN/Hosting': 'text-blue-600 bg-blue-50 border-blue-200',
  'Web Server': 'text-dark-400 bg-dark-900 border-dark-800',
}

export default function WafSection({ data }: { data: WafResult }) {
  const { t } = useTranslation()
  if (!data) return null
  if (isModuleError(data)) {
    return (
      <SectionCard title={t('report.waf.title')} icon={<ShieldCheck />}>
        <ModuleErrorNote error={data.error} />
      </SectionCard>
    )
  }
  const detected = data.detected ?? []
  const wafNames = data.waf_names ?? []
  const cdnNames = data.cdn_names ?? []
  const serverNames = data.server_names ?? []

  return (
    <SectionCard title={t('report.waf.title')} icon={<ShieldCheck />} risk={data.risk}>
      {/* Status summary */}
      <div className="flex flex-wrap gap-2 mb-4">
        <span className={clsx('text-[11px] font-semibold px-2 py-1 rounded border',
          data.waf_found
            ? 'text-emerald-600 bg-emerald-50 border-emerald-200'
            : 'text-orange-600 bg-orange-50 border-orange-200')}>
          {data.waf_found ? `WAF: ${wafNames.join(', ')}` : t('report.waf.noWaf')}
        </span>
        {data.cdn_found && (
          <span className="text-[11px] font-semibold px-2 py-1 rounded border text-blue-600 bg-blue-50 border-blue-200">
            CDN: {cdnNames.join(', ')}
          </span>
        )}
        {serverNames.length > 0 && (
          <span className="text-[11px] font-semibold px-2 py-1 rounded border text-dark-400 bg-dark-900 border-dark-800">
            {t('report.waf.server')} {serverNames.join(', ')}
          </span>
        )}
      </div>

      {detected.length > 0 && (
        <div>
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-2">{t('report.waf.detected')}</h4>
          <div className="space-y-2">
            {detected.map((d, i) => (
              <div key={i} className={clsx('rounded-lg border px-3 py-2', CAT_COLOR[d.category] ?? CAT_COLOR['Web Server'])}>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold">{d.name}</span>
                  <span className="text-[10px] opacity-60">{t('report.waf.confidence', { pct: d.confidence })}</span>
                </div>
                <div className="text-[10px] opacity-60 mt-0.5">{d.category}</div>
                <div className="flex flex-wrap gap-1 mt-1">
                  {(d.signals ?? []).slice(0, 6).map((sig, j) => (
                    <span key={j} className="text-[9px] font-mono bg-white/70 border border-dark-800 px-1 py-0.5 rounded opacity-80">{sig}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <FindingsList findings={data.findings ?? []} />
    </SectionCard>
  )
}
