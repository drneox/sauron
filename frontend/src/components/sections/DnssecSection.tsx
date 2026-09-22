import { DnssecResult } from '../../types/report'
import { SectionCard, FindingsList } from '../ui'
import ModuleErrorNote, { isModuleError } from './ModuleErrorNote'
import clsx from 'clsx'
import { Check as CheckMark, ShieldCheck, X as XMark } from 'lucide-react'
import { useTranslation } from 'react-i18next'

function Check({ ok, label, description }: { ok: boolean; label: string; description?: string }) {
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="w-4 shrink-0">
        {ok
          ? <CheckMark className="w-4 h-4 text-emerald-600" strokeWidth={2.5} />
          : <XMark className="w-4 h-4 text-red-500" strokeWidth={2.5} />}
      </span>
      <span className={clsx(ok ? 'text-dark-300' : 'text-dark-500')}>{label}</span>
      {description && <span className="text-dark-600 text-[10px]">— {description}</span>}
    </div>
  )
}

export default function DnssecSection({ data }: { data: DnssecResult }) {
  const { t } = useTranslation()
  if (!data) return null
  if (isModuleError(data)) {
    return (
      <SectionCard title="DNSSEC" icon={<ShieldCheck />}>
        <ModuleErrorNote error={data.error} />
      </SectionCard>
    )
  }
  return (
    <SectionCard title="DNSSEC" icon={<ShieldCheck />} risk={data.risk}>
      {/* Status banner */}
      <div className={clsx(
        'rounded-lg border px-3 py-2 mb-4 text-sm font-semibold',
        data.signed && data.validated
          ? 'text-emerald-600 bg-emerald-50 border-emerald-200'
          : data.signed
          ? 'text-amber-600 bg-amber-50 border-amber-200'
          : 'text-red-600 bg-red-50 border-red-200'
      )}>
        {data.signed && data.validated
          ? t('report.dnssec.signedValidated')
          : data.signed
          ? t('report.dnssec.signedNotValidated')
          : t('report.dnssec.notConfigured')}
      </div>

      <div className="space-y-2 mb-4">
        <Check ok={data.has_dnskey} label={t('report.dnssec.dnskey')} description={data.dnskey_count > 0 ? t('report.dnssec.dnskeyCount', { count: data.dnskey_count }) : undefined} />
        <Check ok={data.has_ds} label={t('report.dnssec.dsRecord')} />
        <Check ok={data.has_rrsig} label={t('report.dnssec.rrsig')} />
        <Check ok={data.ad_flag} label={t('report.dnssec.adFlag')} />
        <Check ok={data.has_nsec3} label={t('report.dnssec.nsec3')} />
        {data.has_nsec && !data.has_nsec3 && (
          <div className="text-[11px] text-orange-600 ml-6">{t('report.dnssec.nsecWarning')}</div>
        )}
      </div>

      {(data.ds_records ?? []).length > 0 && (
        <div className="mb-3">
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-1.5">{t('report.dnssec.dsRecords')}</h4>
          <div className="space-y-0.5">
            {(data.ds_records ?? []).map((r, i) => (
              <div key={i} className="text-[10px] font-mono text-dark-500 bg-dark-800/50 rounded px-2 py-0.5 truncate">{r}</div>
            ))}
          </div>
        </div>
      )}

      <FindingsList findings={data.findings ?? []} />
    </SectionCard>
  )
}
