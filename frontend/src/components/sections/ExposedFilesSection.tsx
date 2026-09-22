import { useState } from 'react'
import { ExposedFilesResult } from '../../types/report'
import { SectionCard, FindingsList } from '../ui'
import ModuleErrorNote, { isModuleError } from './ModuleErrorNote'
import clsx from 'clsx'
import { AlertCircle, AlertOctagon, AlertTriangle, Check, ChevronDown, ChevronUp, ExternalLink, FolderOpen, Info, ShieldCheck, type LucideIcon } from 'lucide-react'
import { useTranslation } from 'react-i18next'

const SEV_COLOR: Record<string, string> = {
  critical: 'text-red-600 bg-red-50 border-red-200',
  high: 'text-orange-600 bg-orange-50 border-orange-200',
  medium: 'text-amber-600 bg-amber-50 border-amber-200',
  low: 'text-blue-600 bg-blue-50 border-blue-200',
  info: 'text-dark-400 bg-dark-900 border-dark-800',
}

const SEV_ICON: Record<string, LucideIcon> = {
  critical: AlertOctagon,
  high: AlertTriangle,
  medium: AlertCircle,
  low: Info,
  info: Info,
}

const CONF_BADGE: Record<string, { label: string; cls: string }> = {
  confirmed: { label: 'confirmed',  cls: 'bg-emerald-50 text-emerald-700 border border-emerald-200' },
  high:      { label: 'verified',   cls: 'bg-blue-50 text-blue-700 border border-blue-200' },
  medium:    { label: 'unverified', cls: 'bg-amber-50 text-amber-700 border border-amber-200' },
}

const SHOWN_BY_DEFAULT = ['critical', 'high', 'medium']

export default function ExposedFilesSection({ data }: { data: ExposedFilesResult }) {
  const { t } = useTranslation()
  const [showAll, setShowAll] = useState(false)

  if (!data) return null
  if (isModuleError(data)) {
    return (
      <SectionCard title={t('report.exposed.title')} icon={<FolderOpen />}>
        <ModuleErrorNote error={data.error} />
      </SectionCard>
    )
  }

  const important = (data.exposed ?? []).filter(f => SHOWN_BY_DEFAULT.includes(f.severity))
  const infoItems = (data.exposed ?? []).filter(f => !SHOWN_BY_DEFAULT.includes(f.severity))
  const visible = showAll ? (data.exposed ?? []) : important

  const bl = data.baseline
  const wafNotice = bl?.waf_detected_baseline
  const unreliable403 = bl?.returns_403_for_random && !bl?.waf_detected_baseline

  return (
    <SectionCard title={t('report.exposed.title')} icon={<FolderOpen />} risk={data.risk}>
      {/* Summary */}
      <div className="flex flex-wrap items-center gap-4 mb-4 text-xs">
        <span className="text-dark-400">
          {t('report.exposed.totalFound')} <span className="text-dark-100 font-bold">{data.total}</span>
        </span>
        {data.critical_count > 0 && (
          <span className="text-red-600 font-bold">{data.critical_count} critical</span>
        )}
        {data.high_count > 0 && (
          <span className="text-orange-600 font-bold">{data.high_count} high</span>
        )}
        {(data.confirmed_count ?? 0) > 0 && (
          <span className="text-emerald-600 font-bold">
            {data.confirmed_count} confirmed
          </span>
        )}
        {data.has_security_txt && (
          <span className="text-emerald-600 inline-flex items-center gap-1"><Check className="w-3.5 h-3.5" /> {t('report.exposed.securityTxt')}</span>
        )}
      </div>

      {/* WAF / baseline warnings */}
      {wafNotice && (
        <div className="mb-3 rounded-lg px-3 py-2 text-xs bg-purple-50 border border-purple-200 text-purple-700 flex items-start gap-2">
          <ShieldCheck className="w-4 h-4 shrink-0 mt-px" />
          <span><strong>{t('report.exposed.wafDetected')}</strong> — {t('report.exposed.wafNotice')}</span>
        </div>
      )}
      {unreliable403 && (
        <div className="mb-3 rounded-lg px-3 py-2 text-xs bg-amber-50 border border-amber-200 text-amber-700 flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-px" />
          <span>{t('report.exposed.returns403a')} <strong>{t('report.exposed.returns403b')}</strong> {t('report.exposed.returns403c')}</span>
        </div>
      )}

      {data.total === 0 ? (
        <p className="text-emerald-600 text-sm text-center py-4 flex items-center justify-center gap-1.5">
          <Check className="w-4 h-4" /> {t('report.exposed.empty')}
        </p>
      ) : (
        <>
          <div className="space-y-1.5">
            {visible.map((f, i) => {
              const badge = CONF_BADGE[f.confidence ?? 'high']
              return (
                <div
                  key={i}
                  className={clsx('border rounded-lg px-3 py-2 text-xs', SEV_COLOR[f.severity])}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-start gap-2 flex-1 min-w-0">
                      {(() => { const SevIcon = SEV_ICON[f.severity] ?? Info; return <SevIcon className="w-3.5 h-3.5 mt-0.5 shrink-0" /> })()}
                      <div className="min-w-0">
                        <div className="flex items-center flex-wrap gap-2">
                          <a
                            href={f.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="font-mono font-semibold hover:underline hover:brightness-125 transition-all"
                            title={`Open ${f.url}`}
                          >
                            {f.path}
                          </a>
                          <ExternalLink className="w-3 h-3 text-dark-500 shrink-0" />
                          <span className="text-dark-500">HTTP {f.status}</span>
                          {f.size > 0 && (
                            <span className="text-dark-600">{(f.size / 1024).toFixed(1)} KB</span>
                          )}
                          {badge && (
                            <span className={clsx('rounded px-1.5 py-0.5 text-[10px] font-mono', badge.cls)}>
                              {badge.label}
                            </span>
                          )}
                        </div>
                        <p className="text-dark-400 mt-0.5 font-sans">{f.description}</p>
                        {f.snippet && (
                          <p className="text-dark-600 font-mono text-[10px] mt-1 truncate max-w-sm">
                            {f.snippet}
                          </p>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>

          {infoItems.length > 0 && (
            <button
              onClick={() => setShowAll(!showAll)}
              className="mt-3 text-xs text-cyber-700 hover:text-cyber-800 font-medium inline-flex items-center gap-1 transition-colors duration-150"
            >
              {showAll
                ? <>{t('report.exposed.hide', { count: infoItems.length })} <ChevronUp className="w-3.5 h-3.5" /></>
                : <>{t('report.exposed.showMore', { count: infoItems.length })} <ChevronDown className="w-3.5 h-3.5" /></>}
            </button>
          )}
        </>
      )}

      <FindingsList findings={data.findings ?? []} />
    </SectionCard>
  )
}

