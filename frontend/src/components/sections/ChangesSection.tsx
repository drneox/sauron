import { ScanChanges } from '../../types/report'
import { SectionCard } from '../ui'
import { AlertTriangle, Diff, TrendingDown, TrendingUp } from 'lucide-react'
import { useTranslation } from 'react-i18next'

interface Props {
  changes: ScanChanges
}

const gradeColor = (g: string | null) => {
  if (g === 'A') return 'text-emerald-600'
  if (g === 'B') return 'text-cyan-700'
  if (g === 'C') return 'text-amber-600'
  if (g === 'D') return 'text-orange-600'
  if (g === 'F') return 'text-red-600'
  return 'text-dark-500'
}

export default function ChangesSection({ changes }: Props) {
  const { t } = useTranslation()
  if (!changes) return null

  if (!changes.previous_scan_id) {
    return (
      <SectionCard title={t('report.changes.title')} icon={<Diff />}>
        <p className="text-dark-500 text-sm">
          {t('report.changes.firstScan')}
        </p>
      </SectionCard>
    )
  }

  const delta = changes.score_delta
  const deltaBadge = delta === null || delta === undefined ? null : (
    <span className={`text-sm font-semibold inline-flex items-center gap-1 font-mono ${
      delta > 0 ? 'text-emerald-600' : delta < 0 ? 'text-red-600' : 'text-dark-400'
    }`}>
      {delta > 0 ? <TrendingUp className="w-3.5 h-3.5" /> : delta < 0 ? <TrendingDown className="w-3.5 h-3.5" /> : null}
      {delta > 0 ? '+' : ''}{delta}
    </span>
  )

  const newSubdomains = changes.new_subdomains ?? []
  const newEndpoints = changes.new_endpoints ?? []
  const newFindings = changes.new_findings ?? []

  const hasNew =
    newSubdomains.length > 0 ||
    newEndpoints.length > 0 ||
    newFindings.length > 0

  return (
    <SectionCard title={t('report.changes.title')} icon={<Diff />}>
      <div className="flex items-center gap-4 mb-3 text-sm">
        <span className="text-dark-400 text-xs uppercase tracking-wider">{t('report.changes.scoreDelta')}</span>
        {deltaBadge ?? <span className="text-dark-500 text-xs">—</span>}
        {changes.previous_grade && (
          <span className="text-xs text-dark-500">
            {t('report.changes.previousGrade')} <span className={`font-bold ${gradeColor(changes.previous_grade)}`}>{changes.previous_grade}</span>
          </span>
        )}
      </div>

      {!hasNew && (
        <p className="text-dark-500 text-sm">{t('report.changes.noNew')}</p>
      )}

      {newSubdomains.length > 0 && (
        <div className="mb-3">
          <h3 className="text-xs font-bold text-dark-500 uppercase tracking-wider mb-1">
            {t('report.changes.newSubdomains')}
            <span className="ml-2 text-[10px] px-1.5 py-0.5 rounded-full bg-cyber-50 text-cyber-700 border border-cyber-200 font-semibold">{t('report.newBadge')}</span>
          </h3>
          <ul className="space-y-0.5">
            {newSubdomains.map((s, i) => (
              <li key={i} className="text-xs text-dark-200 break-all">• {s}</li>
            ))}
          </ul>
        </div>
      )}

      {newEndpoints.length > 0 && (
        <div className="mb-3">
          <h3 className="text-xs font-bold text-dark-500 uppercase tracking-wider mb-1">
            {t('report.changes.newEndpoints')}
            <span className="ml-2 text-[10px] px-1.5 py-0.5 rounded-full bg-cyber-50 text-cyber-700 border border-cyber-200 font-semibold">{t('report.newBadge')}</span>
          </h3>
          <ul className="space-y-0.5">
            {newEndpoints.map((e, i) => (
              <li key={i} className="text-xs text-dark-200 break-all">
                • {e.path} <span className="text-dark-500">({e.source})</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {newFindings.length > 0 && (
        <div>
          <h3 className="text-xs font-bold text-dark-500 uppercase tracking-wider mb-1">
            {t('report.changes.newFindings')}
            <span className="ml-2 text-[10px] px-1.5 py-0.5 rounded-full bg-cyber-50 text-cyber-700 border border-cyber-200 font-semibold">{t('report.newBadge')}</span>
          </h3>
          <ul className="space-y-0.5">
            {newFindings.map((f, i) => (
              <li key={i} className="text-xs text-amber-700 break-all flex items-start gap-1.5"><AlertTriangle className="w-3.5 h-3.5 mt-px shrink-0 text-amber-500" /> {f}</li>
            ))}
          </ul>
        </div>
      )}
    </SectionCard>
  )
}
