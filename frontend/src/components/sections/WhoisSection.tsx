import { WhoisResult } from '../../types/report'
import { SectionCard, KeyValue, FindingsList } from '../ui'
import ModuleErrorNote, { isModuleError } from './ModuleErrorNote'
import { FileText } from 'lucide-react'
import { useTranslation } from 'react-i18next'

export default function WhoisSection({ data }: { data: WhoisResult }) {
  const { t } = useTranslation()
  if (!data) return null
  if (isModuleError(data)) {
    return (
      <SectionCard title={t('report.whois.title')} icon={<FileText />}>
        <ModuleErrorNote error={data.error} />
      </SectionCard>
    )
  }
  const exp = data.expiration_date ? new Date(data.expiration_date) : null
  const daysLeft = exp ? Math.round((exp.getTime() - Date.now()) / 86400000) : null

  return (
    <SectionCard title={t('report.whois.title')} icon={<FileText />} risk={data.risk}>
      <div className="space-y-0">
        <KeyValue label={t('report.whois.registrar')} value={data.registrar} />
        <KeyValue label={t('report.whois.organization')} value={data.org} />
        <KeyValue label={t('report.whois.country')} value={data.registrant_country} />
        <KeyValue label={t('report.whois.created')} value={data.creation_date?.split('T')[0]} />
        <KeyValue label={t('report.whois.updated')} value={data.updated_date?.split('T')[0]} />
        <KeyValue label={t('report.whois.expires')} value={
          <span className={daysLeft !== null && daysLeft < 30 ? 'text-red-600 font-semibold' : ''}>
            {data.expiration_date?.split('T')[0]}
            {daysLeft !== null && <span className="text-dark-500 ml-2">({daysLeft}d)</span>}
          </span>
        } />
        <KeyValue label="DNSSEC" value={data.dnssec ?? t('report.whois.dnssecNotEnabled')} />
        <KeyValue label={t('report.whois.nameServers')} value={
          (data.name_servers?.length ?? 0)
            ? <ul className="space-y-0.5">{(data.name_servers ?? []).map((ns, i) => <li key={i}>{ns}</li>)}</ul>
            : undefined
        } />
        {(data.emails?.length ?? 0) > 0 && (
          <KeyValue label={t('report.whois.contactEmails')} value={(data.emails ?? []).join(', ')} />
        )}
      </div>
      <FindingsList findings={data.findings ?? []} />
    </SectionCard>
  )
}
