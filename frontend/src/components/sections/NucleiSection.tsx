import { NucleiResult } from '../../types/report'
import { SectionCard, FindingsList } from '../ui'
import ModuleErrorNote, { isModuleError } from './ModuleErrorNote'
import clsx from 'clsx'
import { Atom, Check, ExternalLink } from 'lucide-react'
import { useTranslation } from 'react-i18next'

const SEV_STYLES: Record<string, string> = {
  critical: 'text-red-700 bg-red-50 border-red-200',
  high:     'text-orange-700 bg-orange-50 border-orange-200',
  medium:   'text-amber-700 bg-amber-50 border-amber-200',
  low:      'text-dark-300 bg-dark-900 border-dark-800',
  info:     'text-blue-700 bg-blue-50 border-blue-200',
  unknown:  'text-dark-400 bg-dark-900 border-dark-800',
}

const SEV_BADGE: Record<string, string> = {
  critical: 'bg-red-600 text-white',
  high:     'bg-orange-600 text-white',
  medium:   'bg-yellow-500 text-black',
  low:      'bg-dark-600 text-dark-300',
  info:     'bg-blue-700 text-white',
  unknown:  'bg-dark-700 text-dark-400',
}

export default function NucleiSection({ data }: { data: NucleiResult }) {
  const { t } = useTranslation()
  if (!data) return null

  if (isModuleError(data)) {
    return (
      <SectionCard title={t('report.nuclei.title')} icon={<Atom />}>
        <ModuleErrorNote error={data.error} />
      </SectionCard>
    )
  }

  const findings = data.findings_detail ?? []
  const bySeverity = data.by_severity ?? {}

  if (data.status === 'skipped') {
    return (
      <SectionCard title={t('report.nuclei.title')} icon={<Atom />} risk="low">
        <div className="text-center py-4 text-dark-500 text-sm space-y-2">
          <p>{t('report.nuclei.skipped')}</p>
          <a
            href="https://github.com/projectdiscovery/nuclei#install"
            target="_blank"
            rel="noopener noreferrer"
            className="text-cyber-700 hover:underline text-xs inline-flex items-center gap-1"
          >
            {t('report.nuclei.install')} <ExternalLink className="w-3 h-3" />
          </a>
        </div>
      </SectionCard>
    )
  }

  return (
    <SectionCard title={t('report.nuclei.title')} icon={<Atom />} risk={data.risk}>
      {/* Stats */}
      <div className="flex flex-wrap gap-3 mb-4">
        {(['critical', 'high', 'medium', 'low', 'info'] as const).map(sev => {
          const count = bySeverity[sev] ?? 0
          if (!count) return null
          return (
            <div key={sev} className={clsx('rounded border px-3 py-1.5 text-center min-w-[56px]', SEV_STYLES[sev])}>
              <div className="text-lg font-bold">{count}</div>
              <div className="text-[10px] uppercase font-bold opacity-60">{sev}</div>
            </div>
          )
        })}
        {data.findings_count === 0 && (
          <div className="rounded-lg border border-dark-700 bg-dark-800/50 px-4 py-2 text-center">
            <div className="text-lg font-bold text-emerald-600">0</div>
            <div className="text-[10px] text-dark-500">{t('report.nuclei.issues')}</div>
          </div>
        )}
      </div>

      {findings.length > 0 ? (
        <div className="space-y-2">
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-2">
            {t('report.withCount', { label: t('report.nuclei.findings'), count: findings.length })}
          </h4>
          {findings.map((f, i) => (
            <div key={i} className={clsx('rounded border px-3 py-2 text-xs', SEV_STYLES[f.severity] ?? SEV_STYLES.unknown)}>
              <div className="flex items-start gap-2 flex-wrap">
                <span className={clsx('text-[9px] font-bold px-1.5 py-px rounded uppercase shrink-0', SEV_BADGE[f.severity] ?? SEV_BADGE.unknown)}>
                  {f.severity}
                </span>
                <span className="font-bold flex-1">{f.name}</span>
                <span className="font-mono text-[10px] opacity-50 shrink-0">{f.template_id}</span>
              </div>
              {f.description && (
                <p className="mt-1 opacity-70 leading-snug text-[11px]">{f.description}</p>
              )}
              {f.matched_at && (
                <code className="mt-1 block text-[10px] font-mono opacity-60 truncate">{f.matched_at}</code>
              )}
              <div className="mt-1.5 flex flex-wrap gap-1">
                {(f.cve_ids ?? []).map(cve => (
                  <span key={cve} className="text-[9px] font-mono bg-dark-900/60 border border-dark-700 px-1.5 py-px rounded">
                    {cve}
                  </span>
                ))}
                {(f.tags ?? []).slice(0, 5).map(tag => (
                  <span key={tag} className="text-[9px] opacity-50 bg-dark-900/40 border border-dark-800 px-1.5 py-px rounded">
                    {tag}
                  </span>
                ))}
              </div>
              {(f.references ?? []).length > 0 && (
                <div className="mt-1 flex flex-wrap gap-1.5">
                  {(f.references ?? []).slice(0, 3).map((ref, ri) => (
                    <a key={ri} href={ref} target="_blank" rel="noopener noreferrer"
                      className="text-[9px] opacity-50 hover:opacity-80 hover:underline truncate max-w-[200px]">
                      {ref}
                    </a>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        data.status !== 'skipped' && (
          <p className="text-emerald-600 text-sm text-center py-3 flex items-center justify-center gap-1.5"><Check className="w-4 h-4" /> {t('report.nuclei.empty')}</p>
        )
      )}

      <FindingsList findings={data.findings ?? []} />
    </SectionCard>
  )
}
