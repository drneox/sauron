import { DnsResult } from '../../types/report'
import { SectionCard, FindingsList } from '../ui'
import ModuleErrorNote, { isModuleError } from './ModuleErrorNote'
import { AlertTriangle, Globe } from 'lucide-react'
import { useTranslation } from 'react-i18next'

const RECORD_COLORS: Record<string, string> = {
  A: 'text-blue-600', AAAA: 'text-blue-700', MX: 'text-purple-700',
  TXT: 'text-amber-600', NS: 'text-cyan-700', CNAME: 'text-emerald-600',
  SOA: 'text-orange-600', CAA: 'text-red-600', SRV: 'text-pink-600',
}

export default function DnsSection({ data }: { data: DnsResult }) {
  const { t } = useTranslation()
  if (!data) return null
  if (isModuleError(data)) {
    return (
      <SectionCard title={t('report.dns.title')} icon={<Globe />}>
        <ModuleErrorNote error={data.error} />
      </SectionCard>
    )
  }
  const entries = Object.entries(data.records ?? {})

  return (
    <SectionCard title={t('report.dns.title')} icon={<Globe />} risk={data.risk}>
      {data.zone_transfer_vulnerable && (
        <div className="mb-3 px-3 py-2 bg-red-50 border border-red-200 rounded-lg text-red-700 text-xs font-semibold flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          {t('report.dns.zoneTransfer')}
        </div>
      )}
      {entries.length === 0 ? (
        <p className="text-dark-500 text-sm">{t('report.dns.empty')}</p>
      ) : (
        <div className="space-y-3">
          {entries.map(([type, values]) => (
            <div key={type}>
              <span className={`text-xs font-bold ${RECORD_COLORS[type] ?? 'text-dark-300'} mr-2`}>
                {type}
              </span>
              <div className="mt-1 space-y-0.5">
                {(Array.isArray(values) ? values : []).map((v, i) => (
                  <div key={i} className="text-xs text-dark-300 font-mono bg-dark-800/50 px-2 py-1 rounded break-all">
                    {v}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
      <FindingsList findings={data.findings ?? []} />
    </SectionCard>
  )
}
