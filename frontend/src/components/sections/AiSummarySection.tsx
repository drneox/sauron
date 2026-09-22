import { AiSummary } from '../../types/report'
import { SectionCard } from '../ui'
import clsx from 'clsx'
import { Sparkles, Swords } from 'lucide-react'
import { useTranslation } from 'react-i18next'

interface Props {
  summary: AiSummary
}

const badgeColor = (value: string) => {
  const v = (value ?? '').toLowerCase()
  if (v === 'high' || v === 'critical' || v === 'large') return 'bg-red-100 text-red-600 border-red-200'
  if (v === 'medium' || v === 'moderate') return 'bg-amber-100 text-amber-600 border-amber-200'
  if (v === 'low' || v === 'small' || v === 'trivial') return 'bg-emerald-100 text-emerald-600 border-emerald-200'
  return 'bg-dark-800 text-dark-400 border-dark-700'
}

function Badge({ value }: { value: string }) {
  return (
    <span className={clsx('text-[10px] px-1.5 py-0.5 rounded border font-bold uppercase tracking-wide', badgeColor(value))}>
      {value}
    </span>
  )
}

// Minimal markdown rendering: **bold**, "- " bullet lines, plain paragraphs.
function renderInline(text: string, keyPrefix: string) {
  const parts = text.split(/\*\*(.+?)\*\*/g)
  return parts.map((p, i) =>
    i % 2 === 1
      ? <strong key={`${keyPrefix}-${i}`} className="text-dark-50 font-semibold">{p}</strong>
      : <span key={`${keyPrefix}-${i}`}>{p}</span>
  )
}

function MarkdownBlock({ text }: { text: string }) {
  const lines = text.split('\n')
  return (
    <div className="space-y-1">
      {lines.map((line, i) => {
        const trimmed = line.trim()
        if (!trimmed) return null
        if (trimmed.startsWith('- ') || trimmed.startsWith('* ')) {
          return (
            <div key={i} className="flex gap-2 text-sm text-dark-200">
              <span className="text-cyber-600 shrink-0">•</span>
              <span>{renderInline(trimmed.slice(2), `l${i}`)}</span>
            </div>
          )
        }
        return (
          <p key={i} className="text-sm text-dark-200 leading-relaxed">
            {renderInline(trimmed, `l${i}`)}
          </p>
        )
      })}
    </div>
  )
}

export default function AiSummarySection({ summary }: Props) {
  const { t } = useTranslation()
  if (!summary) return null
  if (summary.status === 'skipped') return null

  if (summary.status === 'error') {
    return (
      <SectionCard title={t('report.aiSummary.title')} icon={<Sparkles />}>
        <p className="text-dark-500 text-xs">
          {t('report.aiSummary.unavailable')}{summary.error ? `: ${summary.error}` : '.'}
        </p>
      </SectionCard>
    )
  }

  return (
    <SectionCard title={t('report.aiSummary.title')} icon={<Sparkles />}>
      {typeof summary.executive_summary === 'string' && summary.executive_summary && (
        <MarkdownBlock text={summary.executive_summary} />
      )}

      {Array.isArray(summary.attack_scenarios) && summary.attack_scenarios.length > 0 && (
        <div className="mt-4">
          <h3 className="text-xs font-bold text-dark-500 uppercase tracking-wider mb-2">
            {t('report.aiSummary.attackScenarios')}
          </h3>
          <ul className="space-y-1.5">
            {summary.attack_scenarios.map((s, i) => (
              <li key={i} className="flex gap-2 text-sm text-dark-200">
                <Swords className="w-3.5 h-3.5 mt-1 text-red-500 shrink-0" />
                <span>{typeof s === 'string' ? s : JSON.stringify(s)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {Array.isArray(summary.remediation_plan) && summary.remediation_plan.length > 0 && (
        <div className="mt-4">
          <h3 className="text-xs font-bold text-dark-500 uppercase tracking-wider mb-2">
            {t('report.aiSummary.remediationPlan')}
          </h3>
          <ol className="space-y-2">
            {summary.remediation_plan.map((r, i) => (
              <li key={i} className="flex items-start gap-3 text-sm">
                <span className="text-cyber-700 font-semibold shrink-0 w-5 text-right font-mono">{i + 1}.</span>
                <span className="text-dark-200 flex-1">{typeof r.action === 'string' ? r.action : JSON.stringify(r.action)}</span>
                <span className="flex gap-1.5 shrink-0">
                  <Badge value={String(r.effort ?? '')} />
                  <Badge value={String(r.impact ?? '')} />
                </span>
              </li>
            ))}
          </ol>
        </div>
      )}
    </SectionCard>
  )
}
