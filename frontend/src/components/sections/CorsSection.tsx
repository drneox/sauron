import { CorsResult } from '../../types/report'
import { SectionCard, FindingsList } from '../ui'
import ModuleErrorNote, { isModuleError } from './ModuleErrorNote'
import clsx from 'clsx'
import { ArrowLeftRight, Check, X } from 'lucide-react'
import { useTranslation } from 'react-i18next'

export default function CorsSection({ data }: { data: CorsResult }) {
  const { t } = useTranslation()
  if (!data) return null
  if (isModuleError(data)) {
    return (
      <SectionCard title={t('report.cors.title')} icon={<ArrowLeftRight />}>
        <ModuleErrorNote error={data.error} />
      </SectionCard>
    )
  }
  const tests = data.cors_tests ?? []

  const statusColor = (test: any) => {
    if (test.error) return 'text-dark-500'
    if (test.reflected || (test.wildcard && test.allow_credentials)) return 'text-red-600'
    if (test.wildcard) return 'text-orange-600'
    return 'text-emerald-600'
  }

  return (
    <SectionCard title={t('report.cors.title')} icon={<ArrowLeftRight />} risk={data.risk}>
      {/* Summary badges */}
      <div className="flex flex-wrap gap-2 mb-4">
        <span className={clsx('text-[11px] font-semibold px-2 py-1 rounded-lg border',
          data.reflected_origin
            ? 'text-red-600 bg-red-50 border-red-200'
            : 'text-emerald-600 bg-dark-900 border-dark-800')}>
          {data.reflected_origin ? t('report.cors.originReflected') : t('report.cors.originNotReflected')}
        </span>
        <span className={clsx('text-[11px] font-semibold px-2 py-1 rounded-lg border',
          data.allows_null_origin
            ? 'text-orange-600 bg-orange-50 border-orange-200'
            : 'text-emerald-600 bg-dark-900 border-dark-800')}>
          {data.allows_null_origin ? t('report.cors.nullOriginAllowed') : t('report.cors.nullOriginBlocked')}
        </span>
        <span className={clsx('text-[11px] font-semibold px-2 py-1 rounded-lg border',
          data.allows_credentials_wildcard
            ? 'text-red-600 bg-red-50 border-red-200'
            : 'text-emerald-600 bg-dark-900 border-dark-800')}>
          {data.allows_credentials_wildcard ? t('report.cors.wildcardCreds') : t('report.cors.noWildcardCreds')}
        </span>
      </div>

      {/* Test results table */}
      {tests.length > 0 && (
        <div>
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-2">{t('report.cors.originTests')}</h4>
          <div className="space-y-1">
            {tests.map((t, i) => (
              <div key={i} className="flex items-center gap-2 text-[11px] bg-dark-800/40 rounded px-2 py-1.5">
                <span className="font-mono text-dark-400 flex-1 truncate">{t.tested_origin}</span>
                {t.error ? (
                  <span className="text-dark-600">error</span>
                ) : (
                  <>
                    <span className={clsx('font-mono', statusColor(t))}>{t.acao ?? '—'}</span>
                    {t.reflected && <span className="text-red-600 text-[10px] font-bold">REFLECTED</span>}
                    {t.wildcard && <span className="text-orange-600 text-[10px]">*</span>}
                    {t.allow_credentials && <span className="text-amber-600 text-[10px]">+creds</span>}
                  </>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {!data.misconfigured && (
        <p className="text-emerald-600 text-sm text-center py-3 inline-flex items-center gap-1.5 w-full justify-center"><Check className="w-4 h-4" /> {t('report.cors.configuredOk')}</p>
      )}

      <FindingsList findings={data.findings ?? []} />
    </SectionCard>
  )
}
