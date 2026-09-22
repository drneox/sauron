import { HeadersResult } from '../../types/report'
import { SectionCard, CheckIcon, FindingsList } from '../ui'
import ModuleErrorNote, { isModuleError } from './ModuleErrorNote'
import clsx from 'clsx'
import { Check, Shield, X } from 'lucide-react'
import { useTranslation } from 'react-i18next'

export default function HeadersSection({ data }: { data: HeadersResult }) {
  const { t } = useTranslation()
  if (!data) return null
  if (isModuleError(data)) {
    return (
      <SectionCard title={t('report.headers.title')} icon={<Shield />}>
        <ModuleErrorNote error={data.error} />
      </SectionCard>
    )
  }
  const headersPresent = data.headers_present ?? {}
  const headersMissing = data.headers_missing ?? []
  const leakyHeaders = data.leaky_headers ?? {}
  return (
    <SectionCard title={t('report.headers.title')} icon={<Shield />} risk={data.risk}>
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-dark-400">
          {t('report.headers.score')} <span className={clsx(
            'font-bold',
            data.score >= 75 ? 'text-emerald-600' : data.score >= 50 ? 'text-amber-600' : 'text-red-600'
          )}>{data.score}/100</span>
        </div>
        <div className="flex items-center gap-1.5 text-xs text-dark-400">
          {t('report.headers.httpsRedirect')} <CheckIcon ok={data.redirects_to_https} />
        </div>
      </div>

      {/* Present headers */}
      {Object.keys(headersPresent).length > 0 && (
        <div className="mb-3">
          <h4 className="text-[10px] font-semibold text-dark-500 uppercase tracking-wider mb-2">{t('report.headers.present')}</h4>
          <div className="space-y-1">
            {Object.entries(headersPresent).map(([h, info]) => (
              <div key={h} className="flex items-start gap-2 text-xs">
                <Check className="w-3.5 h-3.5 text-emerald-500 mt-0.5 shrink-0" strokeWidth={2.5} />
                <div>
                  <span className="text-dark-200 font-semibold">{h}</span>
                  <span className="text-dark-600 ml-2 font-normal truncate max-w-xs">{String(info?.value ?? '').slice(0, 60)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Missing headers */}
      {headersMissing.length > 0 && (
        <div className="mb-3">
          <h4 className="text-[10px] font-semibold text-dark-500 uppercase tracking-wider mb-2">{t('report.headers.missing')}</h4>
          <div className="space-y-1">
            {headersMissing.map((m) => (
              <div key={m.header} className="flex items-start gap-2 text-xs">
                <X className={clsx(
                  'w-3.5 h-3.5 mt-0.5 shrink-0',
                  m.severity === 'high' ? 'text-red-500' : m.severity === 'medium' ? 'text-amber-500' : 'text-dark-500'
                )} strokeWidth={2.5} />
                <div>
                  <span className="text-dark-300 font-semibold">{m.header}</span>
                  <span className="text-dark-600 ml-2">{m.description}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Leaky headers */}
      {Object.keys(leakyHeaders).length > 0 && (
        <div>
          <h4 className="text-[10px] font-bold text-orange-600/70 uppercase tracking-wider mb-2">{t('report.headers.infoDisclosure')}</h4>
          {Object.entries(leakyHeaders).map(([h, v]) => (
            <div key={h} className="text-xs bg-orange-50 border border-orange-200 rounded px-2 py-1 mb-1">
              <span className="text-orange-600 font-bold">{h}:</span>
              <span className="text-dark-300 ml-2">{v}</span>
            </div>
          ))}
        </div>
      )}

      <FindingsList findings={data.findings ?? []} />
    </SectionCard>
  )
}
