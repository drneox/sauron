import { BlacklistResult } from '../../types/report'
import { SectionCard, FindingsList } from '../ui'
import ModuleErrorNote, { isModuleError } from './ModuleErrorNote'
import { AlertOctagon, Ban, ShieldCheck } from 'lucide-react'
import { useTranslation } from 'react-i18next'

export default function BlacklistSection({ data }: { data: BlacklistResult }) {
  const { t } = useTranslation()
  if (!data) return null
  if (isModuleError(data)) {
    return (
      <SectionCard title={t('report.blacklist.title')} icon={<Ban />}>
        <ModuleErrorNote error={data.error} />
      </SectionCard>
    )
  }
  return (
    <SectionCard title={t('report.blacklist.title')} icon={<Ban />} risk={data.risk}>
      {/* Status banner */}
      <div
        className={`rounded-lg px-4 py-3 mb-4 text-sm font-semibold flex items-center gap-3 ${
          data.clean
            ? 'bg-emerald-50 border border-emerald-200 text-emerald-600'
            : 'bg-red-50 border border-red-200 text-red-600'
        }`}
      >
        {data.clean
          ? <ShieldCheck className="w-5 h-5 shrink-0" />
          : <AlertOctagon className="w-5 h-5 shrink-0" />}
        {data.clean
          ? t('report.blacklist.clean')
          : t('report.blacklist.listed', { count: data.listing_count })}
      </div>

      {/* IP info */}
      <div className="mb-4 text-xs text-dark-400">
        {t('report.blacklist.primaryIp')}{' '}
        <span className="font-mono text-dark-200">{data.ip || 'N/A'}</span>
        {(data.all_ips?.length ?? 0) > 1 && (
          <span className="ml-2 text-dark-600">
            {t('report.blacklist.moreIps', { count: data.all_ips.length - 1, ips: data.all_ips.slice(1).join(', ') })}
          </span>
        )}
      </div>

      {/* DNSBL listings */}
      {(data.listed_on?.length ?? 0) > 0 && (
        <div className="mb-4">
          <p className="text-xs text-dark-400 mb-2">{t('report.blacklist.listedOn')}</p>
          <div className="flex flex-wrap gap-1.5">
            {(data.listed_on ?? []).map((bl, i) => (
              <span
                key={i}
                className="text-xs font-mono px-2 py-0.5 rounded-full bg-red-50 border border-red-200 text-red-700"
              >
                {bl.list || bl.dnsbl}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* URLhaus */}
      {data.urlhaus?.found && (
        <div className="mb-3 rounded-lg border border-orange-200 bg-orange-50 px-3 py-2 text-xs">
          <p className="text-orange-600 font-semibold mb-1">
            {t('report.blacklist.urlhaus', { count: data.urlhaus.url_count })}
          </p>
          {(data.urlhaus.urls?.length ?? 0) > 0 && (
            <ul className="space-y-0.5 text-dark-400 font-mono">
              {(data.urlhaus.urls ?? []).slice(0, 5).map((u, i) => (
                <li key={i} className="truncate">{u.url}</li>
              ))}
            </ul>
          )}
        </div>
      )}

      {/* ThreatFox */}
      {data.threatfox?.found && (
        <div className="mb-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs">
          <p className="text-red-600 font-semibold mb-1">
            {t('report.blacklist.threatfox', { count: data.threatfox.ioc_count })}
          </p>
          {(data.threatfox.iocs?.length ?? 0) > 0 && (
            <ul className="space-y-0.5 text-dark-400">
              {(data.threatfox.iocs ?? []).slice(0, 5).map((ioc, i) => (
                <li key={i}>
                  <span className="font-mono">{ioc.ioc}</span>
                  <span className="ml-2 text-dark-600">({ioc.threat_type})</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      <FindingsList findings={data.findings ?? []} />
    </SectionCard>
  )
}
