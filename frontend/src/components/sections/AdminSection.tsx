import { AdminDiscoveryResult } from '../../types/report'
import { SectionCard, FindingsList } from '../ui'
import ModuleErrorNote, { isModuleError } from './ModuleErrorNote'
import clsx from 'clsx'
import { Check, DoorOpen } from 'lucide-react'
import { useTranslation } from 'react-i18next'

const SEV_STYLES: Record<string, string> = {
  critical: 'text-red-700 bg-red-50 border-red-200',
  high: 'text-orange-700 bg-orange-50 border-orange-200',
  medium: 'text-amber-700 bg-amber-50 border-amber-200',
  info: 'text-dark-400 bg-dark-900 border-dark-800',
}

const STATUS_COLOR: Record<number, string> = {
  200: 'text-red-600',
  401: 'text-orange-600',
  403: 'text-amber-600',
  301: 'text-blue-600',
  302: 'text-blue-600',
}

export default function AdminSection({ data }: { data: AdminDiscoveryResult }) {
  const { t } = useTranslation()
  if (!data) return null
  if (isModuleError(data)) {
    return (
      <SectionCard title={t('report.admin.title')} icon={<DoorOpen />}>
        <ModuleErrorNote error={data.error} />
      </SectionCard>
    )
  }
  const found = data.found ?? []

  return (
    <SectionCard title={t('report.admin.title')} icon={<DoorOpen />} risk={data.risk}>
      {/* Summary */}
      <div className="grid grid-cols-3 gap-3 mb-4">
        <div className="rounded-lg border border-dark-700 bg-dark-800/50 p-3 text-center">
          <div className="text-2xl font-bold text-dark-400">{data.paths_probed ?? 0}</div>
          <div className="text-dark-500 text-[10px] mt-0.5">{t('report.admin.pathsProbed')}</div>
        </div>
        <div className={clsx('rounded-lg border p-3 text-center',
          (data.critical_count ?? 0) > 0 ? 'bg-red-50 border-red-200' : 'bg-dark-900 border-dark-800')}>
          <div className={clsx('text-2xl font-bold', (data.critical_count ?? 0) > 0 ? 'text-red-600' : 'text-emerald-600')}>
            {data.critical_count ?? 0}
          </div>
          <div className="text-dark-500 text-[10px] mt-0.5">{t('report.admin.critical')}</div>
        </div>
        <div className={clsx('rounded-lg border p-3 text-center',
          (data.high_count ?? 0) > 0 ? 'bg-orange-50 border-orange-200' : 'bg-dark-900 border-dark-800')}>
          <div className={clsx('text-2xl font-bold', (data.high_count ?? 0) > 0 ? 'text-orange-600' : 'text-emerald-600')}>
            {data.high_count ?? 0}
          </div>
          <div className="text-dark-500 text-[10px] mt-0.5">{t('report.admin.high')}</div>
        </div>
      </div>

      {found.length > 0 && (
        <div>
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-2">
            {t('report.withCount', { label: t('report.admin.found'), count: found.length })}
          </h4>
          <div className="space-y-1">
            {found.map((f, i) => (
              <div key={i} className={clsx('rounded border px-2 py-1.5 text-[11px] flex items-center gap-2', SEV_STYLES[f.severity] ?? SEV_STYLES.info)}>
                <span className={clsx('font-bold text-[12px] w-8 text-center shrink-0', STATUS_COLOR[f.status] ?? 'text-dark-400')}>
                  {f.status}
                </span>
                <a href={f.url} target="_blank" rel="noopener noreferrer"
                  className="font-mono hover:underline flex-1 truncate">
                  {f.path}
                </a>
                {f.redirect_to && (
                  <span className="text-[10px] text-dark-500 truncate max-w-[100px]">→ {f.redirect_to}</span>
                )}
                <span className="text-[9px] uppercase font-bold opacity-60 shrink-0">{f.severity}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {found.length === 0 && (
        <p className="text-emerald-600 text-sm text-center py-3 flex items-center justify-center gap-1.5"><Check className="w-4 h-4" /> {t('report.admin.empty')}</p>
      )}

      <FindingsList findings={data.findings ?? []} />
    </SectionCard>
  )
}
