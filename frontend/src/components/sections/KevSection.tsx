import { KevResult } from '../../types/report'
import { SectionCard, FindingsList } from '../ui'
import ModuleErrorNote, { isModuleError } from './ModuleErrorNote'
import { Check, ShieldAlert } from 'lucide-react'
import { useTranslation } from 'react-i18next'

export default function KevSection({ data }: { data: KevResult }) {
  const { t } = useTranslation()
  if (!data) return null

  if (isModuleError(data)) {
    return (
      <SectionCard title={t('report.kev.title')} icon={<ShieldAlert />}>
        <ModuleErrorNote error={data.error} />
      </SectionCard>
    )
  }

  if (data.status === 'skipped') {
    return (
      <SectionCard title={t('report.kev.title')} icon={<ShieldAlert />} risk="low">
        <p className="text-dark-500 text-sm">{t('report.kev.skipped')}</p>
      </SectionCard>
    )
  }

  const matches = data.matches ?? []
  const unverifiable = data.unverifiable ?? []
  const unverified = data.unverified ?? []

  return (
    <SectionCard title={t('report.kev.title')} icon={<ShieldAlert />} risk={data.risk}>
      <p className="text-xs text-dark-500 mb-3 leading-relaxed">{t('report.kev.intro')}</p>

      {matches.length > 0 ? (
        <div className="space-y-2">
          {matches.map((m) => (
            <div key={`${m.technology}:${m.cve}`} className="rounded border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800">
              <div className="flex items-start gap-2 flex-wrap">
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${m.cve}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono font-bold hover:underline shrink-0"
                >
                  {m.cve}
                </a>
                <span className="font-semibold flex-1">{m.name}</span>
                {m.ransomware && (
                  <span className="text-[9px] font-bold px-1.5 py-px rounded uppercase bg-red-600 text-white shrink-0">
                    {t('report.kev.ransomware')}
                  </span>
                )}
              </div>
              <div className="mt-1 opacity-80">
                <span className="font-mono">{m.technology} {m.version}</span>
                {' · '}{t('report.kev.affected', { range: m.affected_range })}
              </div>
              <div className="mt-0.5 text-[11px] opacity-60">
                {t('report.kev.added', { date: m.date_added })}
                {m.due_date ? ` · ${t('report.kev.due', { date: m.due_date })}` : ''}
              </div>
              {m.required_action && <div className="mt-1 text-[11px] opacity-70">{m.required_action}</div>}
            </div>
          ))}
          <p className="text-[11px] text-dark-500">{t('report.kev.verify')}</p>
        </div>
      ) : (
        <p className="text-emerald-600 text-sm py-2 flex items-center gap-1.5">
          <Check className="w-4 h-4" /> {t('report.kev.empty')}
        </p>
      )}

      {unverifiable.length > 0 && (
        <p className="mt-3 text-[11px] text-dark-500">
          {t('report.kev.unverifiable', { list: unverifiable.map((u) => u.technology).join(', ') })}
        </p>
      )}
      {unverified.length > 0 && (
        <p className="mt-1 text-[11px] text-dark-500">
          {t('report.kev.unverified', { count: unverified.length })}
        </p>
      )}

      <FindingsList findings={data.findings ?? []} />
    </SectionCard>
  )
}
