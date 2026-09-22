import { EmailResult } from '../../types/report'
import { SectionCard, CheckIcon, FindingsList } from '../ui'
import ModuleErrorNote, { isModuleError } from './ModuleErrorNote'
import clsx from 'clsx'
import { Building2, Chrome, HelpCircle, Mail, Server, type LucideIcon } from 'lucide-react'
import { useTranslation } from 'react-i18next'

const POLICY_COLOR: Record<string, string> = {
  '-all': 'text-emerald-600',
  '~all': 'text-amber-600',
  '+all': 'text-red-600',
  '?all': 'text-orange-600',
}

const DMARC_POLICY_COLOR: Record<string, string> = {
  reject: 'text-emerald-600',
  quarantine: 'text-amber-600',
  none: 'text-red-600',
}

const PROVIDER_META: Record<string, { icon: LucideIcon; labelKey?: string; cls: string }> = {
  google:      { icon: Chrome,     cls: 'text-blue-700 bg-blue-50 border-blue-200' },
  microsoft:   { icon: Building2,  cls: 'text-sky-700 bg-sky-50 border-sky-200' },
  'self-hosted': { icon: Server,   labelKey: 'report.email.selfHosted',      cls: 'text-dark-300 bg-dark-900 border-dark-800' },
  unknown:     { icon: HelpCircle, labelKey: 'report.email.unknownProvider', cls: 'text-dark-400 bg-dark-900 border-dark-800' },
}

export default function EmailSection({ data }: { data: EmailResult }) {
  const { t } = useTranslation()
  if (!data) return null
  if (isModuleError(data)) {
    return (
      <SectionCard title={t('report.email.title')} icon={<Mail />}>
        <ModuleErrorNote error={data.error} />
      </SectionCard>
    )
  }
  const d = data
  const spf = d.spf ?? ({} as NonNullable<EmailResult['spf']>)
  const dmarc = d.dmarc ?? ({} as NonNullable<EmailResult['dmarc']>)
  const dkim = d.dkim ?? ({} as NonNullable<EmailResult['dkim']>)
  const mta_sts = d.mta_sts
  const bimi = d.bimi
  const provider = d.provider
  const pm = PROVIDER_META[provider?.provider ?? 'unknown'] ?? PROVIDER_META.unknown
  const providerFindings = provider?.findings ?? []
  const allFindings = [
    ...(spf.findings ?? []),
    ...(dmarc.findings ?? []),
    ...(dkim.findings ?? []),
    ...providerFindings,
  ]

  return (
    <SectionCard title={t('report.email.title')} icon={<Mail />} risk={data.risk}>
      <div className="space-y-3">
        {/* Provider banner */}
        {provider && (
          <div className={clsx('border rounded-lg px-3 py-2 flex items-center justify-between gap-2 text-xs', pm.cls)}>
            <span className="font-semibold inline-flex items-center gap-1.5"><pm.icon className="w-3.5 h-3.5" /> {pm.labelKey ? t(pm.labelKey) : provider.provider === 'google' ? 'Google Workspace' : 'Microsoft 365'}</span>
            <div className="flex items-center gap-3 text-[11px] text-dark-400">
              {provider.tenant_id && (
                <span title={`Tenant ID: ${provider.tenant_id}`}>
                  {t('report.email.tenant')} <code className="text-dark-300">{provider.tenant_id.slice(0, 8)}…</code>
                </span>
              )}
              {provider.tenant_name && (
                <span><code className="text-dark-300">{provider.tenant_name}</code></span>
              )}
              {provider.realm_type && (
                <span className={clsx(
                  'px-1.5 py-0.5 rounded font-mono',
                  provider.realm_type === 'Managed'   ? 'bg-emerald-100 text-emerald-600' :
                  provider.realm_type === 'Federated' ? 'bg-amber-100 text-amber-600' :
                                                        'bg-dark-800 text-dark-400'
                )}>
                  {provider.realm_type}
                </span>
              )}
              {(provider.detection_method ?? []).length > 0 && (
                <span className="text-dark-600">{t('report.email.via')} {provider.detection_method.join(', ')}</span>
              )}
            </div>
          </div>
        )}

        {/* SPF */}
        <div className="border border-dark-700 rounded-lg p-3">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-bold text-dark-200">SPF</span>
            <CheckIcon ok={spf.exists} />
          </div>
          {spf.record ? (
            <div>
              <code className="text-[11px] text-dark-400 break-all">{spf.record.slice(0, 100)}</code>
              {spf.policy && (
                <div className="mt-1 text-xs">
                  {t('report.email.policy')} <span className={clsx('font-bold', POLICY_COLOR[spf.policy] ?? 'text-dark-300')}>
                    {spf.policy}
                  </span>
                </div>
              )}
            </div>
          ) : (
            <p className="text-red-600 text-xs">{t('report.email.notConfigured')}</p>
          )}
        </div>

        {/* DMARC */}
        <div className="border border-dark-700 rounded-lg p-3">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-bold text-dark-200">DMARC</span>
            <CheckIcon ok={dmarc.exists} />
          </div>
          {dmarc.record ? (
            <div>
              <code className="text-[11px] text-dark-400 break-all">{dmarc.record.slice(0, 120)}</code>
              <div className="mt-1 flex gap-4 text-xs">
                {dmarc.policy && (
                  <span>{t('report.email.policy')} <span className={clsx('font-bold', DMARC_POLICY_COLOR[dmarc.policy] ?? 'text-dark-300')}>
                    {dmarc.policy}
                  </span></span>
                )}
                <span className="text-dark-500">pct={dmarc.pct}%</span>
                {dmarc.rua && <span className="text-dark-500 truncate">{t('report.email.ruaConfigured')}</span>}
              </div>
            </div>
          ) : (
            <p className="text-red-600 text-xs">{t('report.email.notConfigured')}</p>
          )}
        </div>

        {/* DKIM */}
        <div className="border border-dark-700 rounded-lg p-3">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-bold text-dark-200">DKIM</span>
            <CheckIcon ok={dkim.exists} />
          </div>
          {(dkim.selectors_found ?? []).length > 0 ? (
            <div className="flex flex-wrap gap-1">
              {(dkim.selectors_found ?? []).map((s) => (
                <span key={s.selector} className="bg-dark-800 px-2 py-0.5 rounded text-xs text-emerald-600">
                  {s.selector}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-amber-600 text-xs">{t('report.email.noSelectors')}</p>
          )}
        </div>

        {/* MTA-STS & BIMI */}
        <div className="grid grid-cols-2 gap-2">
          <div className="border border-dark-700 rounded-lg p-2.5">
            <div className="flex justify-between items-center">
              <span className="text-xs font-bold text-dark-200">MTA-STS</span>
              <CheckIcon ok={mta_sts?.exists ?? false} />
            </div>
          </div>
          <div className="border border-dark-700 rounded-lg p-2.5">
            <div className="flex justify-between items-center">
              <span className="text-xs font-bold text-dark-200">BIMI</span>
              <CheckIcon ok={bimi?.exists ?? false} />
            </div>
          </div>
        </div>
      </div>

      <FindingsList findings={allFindings} />
    </SectionCard>
  )
}
