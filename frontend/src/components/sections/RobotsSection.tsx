import { RobotsResult } from '../../types/report'
import { SectionCard, FindingsList } from '../ui'
import ModuleErrorNote, { isModuleError } from './ModuleErrorNote'
import clsx from 'clsx'
import { Check, ExternalLink, FileSearch } from 'lucide-react'
import { useTranslation } from 'react-i18next'

export default function RobotsSection({ data }: { data: RobotsResult }) {
  const { t } = useTranslation()
  if (!data) return null
  if (isModuleError(data)) {
    return (
      <SectionCard title={t('report.robots.title')} icon={<FileSearch />}>
        <ModuleErrorNote error={data.error} />
      </SectionCard>
    )
  }
  const sensitiveRobots = data.sensitive_in_robots ?? []
  const sensitiveSitemap = data.sensitive_in_sitemap ?? []
  const disallowed = data.robots_disallowed ?? []

  return (
    <SectionCard title={t('report.robots.title')} icon={<FileSearch />} risk={data.risk}>
      {/* Status badges */}
      <div className="flex flex-wrap gap-2 mb-4">
        <span className={clsx('text-[11px] font-semibold px-2 py-1 rounded border',
          data.robots_found
            ? 'text-emerald-600 bg-emerald-50 border-emerald-200'
            : 'text-dark-500 bg-dark-900 border-dark-800')}>
          {data.robots_found ? t('report.robots.robotsFound') : t('report.robots.noRobots')}
        </span>
        <span className={clsx('text-[11px] font-semibold px-2 py-1 rounded border',
          data.sitemap_found
            ? 'text-emerald-600 bg-emerald-50 border-emerald-200'
            : 'text-dark-500 bg-dark-900 border-dark-800')}>
          {data.sitemap_found ? t('report.robots.sitemapUrls', { count: data.sitemap_url_count }) : t('report.robots.noSitemap')}
        </span>
        {(data.robots_sitemaps ?? []).length > 0 && (
          <span className="text-[11px] text-dark-500 px-2 py-1 bg-dark-800/50 border border-dark-700 rounded">
            {t('report.robots.sitemapRefs', { count: data.robots_sitemaps.length })}
          </span>
        )}
      </div>

      {sensitiveRobots.length > 0 && (
        <div className="mb-3">
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-1.5">
            {t('report.withCount', { label: t('report.robots.sensitivePaths'), count: sensitiveRobots.length })}
          </h4>
          <div className="flex flex-wrap gap-1">
            {sensitiveRobots.map((p, i) => (
              <span key={i} className="text-[11px] font-mono text-orange-700 bg-orange-50 border border-orange-200 px-1.5 py-0.5 rounded">
                {p}
              </span>
            ))}
          </div>
        </div>
      )}

      {disallowed.length > 0 && sensitiveRobots.length === 0 && (
        <div className="mb-3">
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-1.5">
            {t('report.withCount', { label: t('report.robots.disallowed'), count: disallowed.length })}
          </h4>
          <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto">
            {disallowed.map((p, i) => (
              <span key={i} className="text-[10px] font-mono text-dark-400 bg-dark-800/50 border border-dark-700 px-1.5 py-0.5 rounded">
                {p}
              </span>
            ))}
          </div>
        </div>
      )}

      {sensitiveSitemap.length > 0 && (
        <div className="mb-3">
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-1.5">
            {t('report.withCount', { label: t('report.robots.sensitiveUrls'), count: sensitiveSitemap.length })}
          </h4>
          <div className="space-y-0.5 max-h-28 overflow-y-auto">
            {sensitiveSitemap.map((u, i) => (
              <a key={i} href={u} target="_blank" rel="noopener noreferrer"
                className="flex items-center gap-1 text-[10px] font-mono text-amber-700 hover:text-amber-800 hover:underline truncate">
                <span className="truncate">{u}</span> <ExternalLink className="w-3 h-3 shrink-0" />
              </a>
            ))}
          </div>
        </div>
      )}

      {!data.robots_found && !data.sitemap_found && (
        <p className="text-dark-500 text-sm text-center py-3">{t('report.robots.empty')}</p>
      )}

      <FindingsList findings={data.findings ?? []} />
    </SectionCard>
  )
}
