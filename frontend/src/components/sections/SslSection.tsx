import { SslResult } from '../../types/report'
import { SectionCard, KeyValue, CheckIcon, FindingsList } from '../ui'
import ModuleErrorNote, { isModuleError } from './ModuleErrorNote'
import { Lock } from 'lucide-react'
import { useTranslation } from 'react-i18next'

export default function SslSection({ data }: { data: SslResult }) {
  const { t } = useTranslation()
  if (!data) return null
  if (isModuleError(data)) {
    return (
      <SectionCard title={t('report.ssl.title')} icon={<Lock />}>
        <ModuleErrorNote error={data.error} />
      </SectionCard>
    )
  }
  const daysRemaining = data.days_remaining ?? null
  return (
    <SectionCard title={t('report.ssl.title')} icon={<Lock />} risk={data.risk}>
      {!data.has_ssl ? (
        <p className="text-red-600 text-sm">{t('report.ssl.noHttps')}</p>
      ) : (
        <div className="space-y-0">
          <KeyValue label={t('report.ssl.protocol')} value={data.protocol} />
          <KeyValue label={t('report.ssl.cipher')} value={data.cipher} />
          <KeyValue label={t('report.ssl.validFrom')} value={data.valid_from?.split('T')[0]} />
          <KeyValue label={t('report.ssl.validTo')} value={
            <span className={daysRemaining !== null && daysRemaining < 30 ? 'text-red-600 font-bold' : ''}>
              {data.valid_to?.split('T')[0]}
              {daysRemaining !== null && (
                <span className="text-dark-500 ml-2">
                  ({daysRemaining < 0 ? t('report.ssl.expired') : t('report.ssl.daysLeft', { days: daysRemaining })})
                </span>
              )}
            </span>
          } />
          <KeyValue label={t('report.ssl.issuerCn')} value={data.issuer?.commonName ?? data.issuer?.organizationName} />
          <KeyValue label={t('report.ssl.subjectCn')} value={data.subject?.commonName} />
          <KeyValue label={t('report.ssl.selfSigned')} value={<CheckIcon ok={!data.self_signed} />} />
          <KeyValue label={t('report.ssl.expiredLabel')} value={<CheckIcon ok={!data.expired} />} />
          {(data.deprecated_protocols?.length ?? 0) > 0 && (
            <KeyValue label={t('report.ssl.deprecatedProtocols')} value={
              <span className="text-red-600">{(data.deprecated_protocols ?? []).join(', ')}</span>
            } />
          )}
          {(data.san?.length ?? 0) > 0 && (
            <KeyValue label={t('report.ssl.sans', { count: data.san.length })} value={
              <div className="flex flex-wrap gap-1">
                {(data.san ?? []).slice(0, 8).map((s, i) => (
                  <span key={i} className="bg-dark-900 border border-dark-800 px-1.5 py-0.5 rounded text-[11px] font-mono">{s}</span>
                ))}
                {data.san.length > 8 && <span className="text-dark-500 text-xs">{t('report.ssl.more', { count: data.san.length - 8 })}</span>}
              </div>
            } />
          )}
        </div>
      )}
      <FindingsList findings={data.findings ?? []} />
    </SectionCard>
  )
}
