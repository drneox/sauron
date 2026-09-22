import { TlsAuditResult } from '../../types/report'
import { SectionCard, FindingsList } from '../ui'
import ModuleErrorNote, { isModuleError } from './ModuleErrorNote'
import clsx from 'clsx'
import { Check, Lock, X } from 'lucide-react'
import { useTranslation } from 'react-i18next'

function ProtocolBadge({ label, supported, deprecated }: { label: string; supported: boolean; deprecated?: boolean }) {
  return (
    <span className={clsx(
      'text-[11px] font-semibold px-2 py-1 rounded-lg border inline-flex items-center gap-1',
      !supported ? 'text-dark-600 bg-dark-900 border-dark-800'
      : deprecated ? 'text-red-600 bg-red-50 border-red-200'
      : 'text-emerald-600 bg-emerald-50 border-emerald-200'
    )}>
      {label}
      {supported
        ? (deprecated
          ? <X className="w-3 h-3" strokeWidth={3} />
          : <Check className="w-3 h-3" strokeWidth={3} />)
        : '—'}
    </span>
  )
}

export default function TlsAuditSection({ data }: { data: TlsAuditResult }) {
  const { t } = useTranslation()
  if (!data) return null
  if (isModuleError(data)) {
    return (
      <SectionCard title={t('report.tls.title')} icon={<Lock />}>
        <ModuleErrorNote error={data.error} />
      </SectionCard>
    )
  }
  const hsts = data.hsts ?? {}
  const cipher = data.cipher ?? {}

  return (
    <SectionCard title={t('report.tls.title')} icon={<Lock />} risk={data.risk}>
      {/* Protocol support */}
      <div className="mb-4">
        <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-2">{t('report.tls.protocolSupport')}</h4>
        <div className="flex flex-wrap gap-1.5">
          <ProtocolBadge label="TLS 1.3" supported={data.supports_tls13} />
          <ProtocolBadge label="TLS 1.2" supported={data.supports_tls12} />
          <ProtocolBadge label="TLS 1.1" supported={data.supports_tls11} deprecated />
          <ProtocolBadge label="TLS 1.0" supported={data.supports_tls10} deprecated />
        </div>
        {data.protocol && (
          <p className="text-[10px] text-dark-500 mt-1.5">
            {t('report.tls.negotiated')} <span className="text-dark-300 font-mono">{data.protocol}</span>
          </p>
        )}
      </div>

      {/* Cipher */}
      {cipher.name && (
        <div className="mb-4">
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-1.5">{t('report.tls.activeCipherSuite')}</h4>
          <div className={clsx('rounded border px-2 py-1.5 text-[11px] font-mono flex items-center gap-2',
            data.weak_cipher ? 'text-red-700 bg-red-50 border-red-200' : 'text-emerald-700 bg-dark-900 border-dark-800')}>
            <span className="flex-1">{cipher.name}</span>
            {cipher.bits && <span className="text-dark-500">{cipher.bits} bits</span>}
            {data.weak_cipher && <span className="text-red-600 font-bold text-[10px]">WEAK</span>}
          </div>
        </div>
      )}

      {/* HSTS */}
      <div className="mb-4">
        <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-1.5">HSTS</h4>
        <div className="space-y-1 text-[11px]">
          {[
            { ok: hsts.present, label: t('report.tls.hstsHeaderPresent') },
            { ok: hsts.include_subdomains, label: 'includeSubDomains' },
            { ok: hsts.preload, label: 'preload flag' },
            { ok: hsts.preload_eligible, label: t('report.tls.preloadEligible') },
          ].map(({ ok, label }) => (
            <div key={label} className="flex items-center gap-2">
              {ok
                ? <Check className="w-3.5 h-3.5 text-emerald-500 shrink-0" strokeWidth={2.5} />
                : <X className="w-3.5 h-3.5 text-dark-600 shrink-0" />}
              <span className={ok ? 'text-dark-300' : 'text-dark-600'}>{label}</span>
            </div>
          ))}
          {hsts.max_age > 0 && (
            <p className="text-dark-500 ml-5">
              max-age: <span className="text-dark-400 font-mono">{hsts.max_age.toLocaleString()}s</span>
              {hsts.max_age < 31536000 && <span className="text-orange-600 ml-1">{t('report.tls.recommended')}</span>}
            </p>
          )}
        </div>
      </div>

      <FindingsList findings={data.findings ?? []} />
    </SectionCard>
  )
}
