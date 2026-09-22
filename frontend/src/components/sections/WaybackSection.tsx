import { useState } from 'react'
import { WaybackSecretsResult } from '../../types/report'
import { SectionCard, FindingsList, Pager, PAGE_SIZE, downloadCsv } from '../ui'
import ModuleErrorNote, { isModuleError } from './ModuleErrorNote'
import clsx from 'clsx'
import { Check, ChevronDown, ChevronUp, Download, History } from 'lucide-react'
import { useTranslation } from 'react-i18next'

const SEV_STYLES: Record<string, string> = {
  critical: 'text-red-700 bg-red-50 border-red-200',
  high:     'text-orange-700 bg-orange-50 border-orange-200',
  medium:   'text-amber-700 bg-amber-50 border-amber-200',
  low:      'text-dark-300 bg-dark-900 border-dark-800',
}

export default function WaybackSection({ data }: { data: WaybackSecretsResult }) {
  const { t } = useTranslation()
  const [showUrls, setShowUrls] = useState(false)
  const [indexedPage, setIndexedPage] = useState(1)

  if (!data) return null
  if (isModuleError(data)) {
    return (
      <SectionCard title={t('report.wayback.title')} icon={<History />}>
        <ModuleErrorNote error={data.error} />
      </SectionCard>
    )
  }

  const sensitiveUrls = data.sensitive_urls ?? []
  const indexedUrls  = data.indexed_urls ?? []
  const secrets      = data.secrets_found ?? []
  const indexedPageRows = indexedUrls.slice((indexedPage - 1) * PAGE_SIZE, indexedPage * PAGE_SIZE)

  return (
    <SectionCard title={t('report.wayback.title')} icon={<History />} risk={data.risk}>
      {/* Stats */}
      <div className="grid grid-cols-4 gap-3 mb-4">
        <div className="rounded-lg border border-dark-700 bg-dark-800/50 p-3 text-center">
          <div className="text-xl font-bold text-dark-300">{data.urls_indexed ?? 0}</div>
          <div className="text-dark-500 text-[10px] mt-0.5">{t('report.wayback.indexed')}</div>
        </div>
        <div className="rounded-lg border border-dark-700 bg-dark-800/50 p-3 text-center">
          <div className="text-xl font-bold text-dark-400">{data.snapshots_fetched ?? 0}</div>
          <div className="text-dark-500 text-[10px] mt-0.5">{t('report.wayback.fetched')}</div>
        </div>
        <div className={clsx('rounded-lg border p-3 text-center',
          (data.sensitive_count ?? 0) > 0 ? 'bg-orange-50 border-orange-200' : 'bg-dark-900 border-dark-800')}>
          <div className={clsx('text-xl font-bold', (data.sensitive_count ?? 0) > 0 ? 'text-orange-600' : 'text-emerald-600')}>
            {data.sensitive_count ?? 0}
          </div>
          <div className="text-dark-500 text-[10px] mt-0.5">{t('report.wayback.sensitive')}</div>
        </div>
        <div className={clsx('rounded-lg border p-3 text-center',
          (data.secret_count ?? 0) > 0 ? 'bg-red-50 border-red-200' : 'bg-dark-900 border-dark-800')}>
          <div className={clsx('text-xl font-bold', (data.secret_count ?? 0) > 0 ? 'text-red-600' : 'text-emerald-600')}>
            {data.secret_count ?? 0}
          </div>
          <div className="text-dark-500 text-[10px] mt-0.5">{t('report.wayback.secrets')}</div>
        </div>
      </div>

      {/* Secrets found */}
      {secrets.length > 0 && (
        <div className="mb-4">
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-2">
            {t('report.withCount', { label: t('report.wayback.secretsDetected'), count: secrets.length })}
          </h4>
          <div className="space-y-1.5">
            {secrets.map((s, i) => (
              <div key={i} className={clsx('rounded border px-2.5 py-2 text-xs', SEV_STYLES[s.severity] ?? SEV_STYLES.low)}>
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-bold">{s.secret_type}</span>
                  <span className="text-[9px] uppercase font-bold opacity-60 ml-auto">{s.severity}</span>
                </div>
                <code className="block text-[10px] font-mono opacity-70 truncate">{s.snippet}</code>
                <a href={`https://web.archive.org/web/${s.url}`} target="_blank" rel="noopener noreferrer"
                  className="mt-1 block text-[10px] font-mono opacity-40 hover:opacity-80 truncate hover:underline">
                  {s.url}
                </a>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Sensitive URLs */}
      {sensitiveUrls.length > 0 && (
        <div>
          <button
            onClick={() => setShowUrls(!showUrls)}
            className="text-[10px] font-semibold text-dark-500 uppercase tracking-wider hover:text-dark-300 mb-2 flex items-center gap-1 transition-colors duration-150"
          >
            {t('report.withCount', { label: t('report.wayback.sensitivePaths'), count: sensitiveUrls.length })}
            {showUrls ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
          {showUrls && (
            <div className="space-y-1 max-h-48 overflow-y-auto">
              {sensitiveUrls.map((u, i) => (
                <div key={i} className={clsx('rounded border px-2.5 py-1.5 text-[11px] flex items-center gap-2', SEV_STYLES[u.severity] ?? SEV_STYLES.low)}>
                  <span className="text-[10px] opacity-60 shrink-0">{u.label}</span>
                  <a href={`https://web.archive.org/web/${u.timestamp}/${u.url}`} target="_blank" rel="noopener noreferrer"
                    className="font-mono truncate flex-1 hover:underline opacity-80">
                    {u.url}
                  </a>
                  <span className="text-[9px] opacity-50 shrink-0">{(u.timestamp ?? '').slice(0, 8)}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {secrets.length === 0 && sensitiveUrls.length === 0 && (
        <p className="text-emerald-600 text-sm text-center py-3 flex items-center justify-center gap-1.5"><Check className="w-4 h-4" /> {t('report.wayback.empty')}</p>
      )}

      {/* Indexed URLs sample — historical surface even when nothing sensitive */}
      {indexedUrls.length > 0 && (
        <div className="mt-3">
          <div className="flex items-center gap-2 mb-2">
            <h4 className="text-[10px] font-semibold text-dark-500 uppercase tracking-wider flex-1">
              {indexedUrls.length < (data.urls_indexed ?? 0)
                ? t('report.wayback.indexedHeaderPartial', { total: (data.urls_indexed ?? 0).toLocaleString(), count: indexedUrls.length })
                : t('report.wayback.indexedHeader', { total: (data.urls_indexed ?? 0).toLocaleString() })}
            </h4>
            <Pager page={indexedPage} total={indexedUrls.length} onPage={setIndexedPage} />
            <button
              onClick={() => downloadCsv(
                'wayback_indexed_urls.csv',
                ['url', 'timestamp'],
                indexedUrls.map((u) => [u.url, u.timestamp]),
              )}
              className="btn-secondary !py-1 !px-2 !text-[10px]"
              title={t('report.wayback.csvTitle')}
            >
              <Download className="w-3 h-3" />
              CSV
            </button>
          </div>
          <div className="space-y-1">
            {indexedPageRows.map((u, i) => (
              <a key={`${indexedPage}:${i}`} href={`https://web.archive.org/web/${u.timestamp}/${u.url}`} target="_blank" rel="noopener noreferrer"
                className="rounded border border-dark-700 bg-dark-800/50 px-2.5 py-1.5 text-[11px] flex items-center gap-2 hover:border-cyber-400 transition-colors duration-150">
                <span className="font-mono truncate flex-1 text-dark-300 hover:underline">{u.url}</span>
                <span className="text-[9px] text-dark-500 shrink-0">{(u.timestamp ?? '').slice(0, 8)}</span>
              </a>
            ))}
          </div>
        </div>
      )}

      <FindingsList findings={data.findings ?? []} />
    </SectionCard>
  )
}
