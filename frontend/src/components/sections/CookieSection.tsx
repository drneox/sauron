import { CookieSecurityResult } from '../../types/report'
import { SectionCard, FindingsList } from '../ui'
import ModuleErrorNote, { isModuleError } from './ModuleErrorNote'
import clsx from 'clsx'
import { Check, Cookie, X } from 'lucide-react'
import { useTranslation } from 'react-i18next'

function Flag({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span className={clsx(
      'text-[10px] font-semibold px-1.5 py-0.5 rounded border inline-flex items-center gap-1',
      ok ? 'text-emerald-600 bg-emerald-50 border-emerald-200'
         : 'text-red-600 bg-red-50 border-red-200'
    )}>
      {ok
        ? <Check className="w-3 h-3" strokeWidth={3} />
        : <X className="w-3 h-3" strokeWidth={3} />}
      {label}
    </span>
  )
}

export default function CookieSection({ data }: { data: CookieSecurityResult }) {
  const { t } = useTranslation()
  if (!data) return null
  if (isModuleError(data)) {
    return (
      <SectionCard title={t('report.cookies.title')} icon={<Cookie />}>
        <ModuleErrorNote error={data.error} />
      </SectionCard>
    )
  }
  const cookies = data.cookies ?? []

  return (
    <SectionCard title={t('report.cookies.title')} icon={<Cookie />} risk={data.risk}>
      {/* Summary */}
      <div className="grid grid-cols-3 gap-3 mb-4">
        <div className="rounded-lg border border-dark-700 bg-dark-800/50 p-3 text-center">
          <div className="text-2xl font-bold text-dark-300">{cookies.length}</div>
          <div className="text-dark-500 text-[10px] mt-0.5">{t('report.cookies.total')}</div>
        </div>
        <div className={clsx('rounded-lg border p-3 text-center',
          data.insecure_count > 0 ? 'bg-red-50 border-red-200' : 'bg-dark-900 border-dark-800')}>
          <div className={clsx('text-2xl font-bold', data.insecure_count > 0 ? 'text-red-600' : 'text-emerald-600')}>
            {data.insecure_count}
          </div>
          <div className="text-dark-500 text-[10px] mt-0.5">{t('report.cookies.insecure')}</div>
        </div>
        <div className={clsx('rounded-lg border p-3 text-center',
          (data.session_cookies_insecure ?? []).length > 0 ? 'bg-orange-50 border-orange-200' : 'bg-dark-900 border-dark-800')}>
          <div className={clsx('text-2xl font-bold', (data.session_cookies_insecure ?? []).length > 0 ? 'text-orange-600' : 'text-emerald-600')}>
            {(data.session_cookies_insecure ?? []).length}
          </div>
          <div className="text-dark-500 text-[10px] mt-0.5">{t('report.cookies.sessionInsecure')}</div>
        </div>
      </div>

      {cookies.length > 0 && (
        <div>
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-2">{t('report.cookies.flags')}</h4>
          <div className="space-y-1.5">
            {cookies.map((c, i) => (
              <div key={i} className="bg-dark-800/40 rounded px-2 py-1.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs font-mono text-dark-200 flex-1 truncate">{c.name}</span>
                  <Flag ok={c.secure} label="Secure" />
                  <Flag ok={c.httponly} label="HttpOnly" />
                  <Flag ok={!!c.samesite} label={c.samesite ? `SameSite=${c.samesite}` : 'SameSite'} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {cookies.length === 0 && (
        <p className="text-dark-500 text-sm text-center py-3">{t('report.cookies.empty')}</p>
      )}

      <FindingsList findings={data.findings ?? []} />
    </SectionCard>
  )
}
