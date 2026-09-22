import { useState } from 'react'
import { SubdomainsResult } from '../../types/report'
import { SectionCard, FindingsList } from '../ui'
import ModuleErrorNote, { isModuleError } from './ModuleErrorNote'
import clsx from 'clsx'
import { AlertTriangle, ChevronDown, Search } from 'lucide-react'
import { useTranslation } from 'react-i18next'

export default function SubdomainsSection({ data }: { data: SubdomainsResult }) {
  const { t } = useTranslation()
  const [filter, setFilter] = useState<'all' | 'sensitive'>('all')
  const [search, setSearch] = useState('')
  const PAGE = 50
  const [showAll, setShowAll] = useState(false)
  const [page, setPage] = useState(1)

  if (!data) return null
  if (isModuleError(data)) {
    return (
      <SectionCard title={t('report.subdomains.title')} icon={<Search />}>
        <ModuleErrorNote error={data.error} />
      </SectionCard>
    )
  }

  const subdomains = data.subdomains ?? []
  const filtered = subdomains.filter(s => {
    if (filter === 'sensitive' && !s.sensitive) return false
    if (search && !(s.subdomain ?? '').includes(search)) return false
    return true
  })

  const paginated = showAll ? filtered : filtered.slice(0, page * PAGE)
  const sensitiveCount = subdomains.filter(s => s.sensitive).length

  return (
    <SectionCard title={t('report.subdomains.title')} icon={<Search />} risk={data.risk}>
      <div className="flex flex-wrap items-center gap-3 mb-4">
        <div className="flex gap-2 text-xs text-dark-400">
          <span>{t('report.subdomains.total')} <span className="text-dark-200 font-bold">{data.count}</span></span>
          <span>|</span>
          <span>CRT.sh: <span className="text-dark-200">{data.crt_sh_count}</span></span>
          <span>|</span>
          <span>HackerTarget: <span className="text-dark-200">{data.hackertarget_count ?? 0}</span></span>
          <span>|</span>
          <span className={clsx(sensitiveCount > 0 ? 'text-orange-600' : 'text-dark-400')}>
            {t('report.subdomains.sensitive')} <span className="font-bold">{sensitiveCount}</span>
          </span>
        </div>
        <div className="flex gap-2 ml-auto">
          <input
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(1) }}
            placeholder={t('report.subdomains.filterPlaceholder')}
            className="text-xs bg-white border border-dark-700 rounded-lg px-2 py-1 text-dark-200 w-36 focus:outline-none focus:border-cyber-500 transition-colors duration-150"
          />
          <button
            onClick={() => { setFilter(f => f === 'all' ? 'sensitive' : 'all'); setPage(1) }}
            className={clsx('text-xs px-2.5 py-1 rounded-lg border transition-colors duration-150',
              filter === 'sensitive'
                ? 'bg-orange-50 border-orange-300 text-orange-700 font-medium'
                : 'bg-white border-dark-700 text-dark-400 hover:text-dark-200'
            )}
          >
            {filter === 'sensitive' ? t('report.subdomains.filterSensitive') : t('report.subdomains.filterAll')}
          </button>
        </div>
      </div>

      {filtered.length === 0 ? (
        <p className="text-dark-500 text-sm">{t('report.subdomains.empty')}</p>
      ) : (
        <>
          <div className="space-y-1 max-h-96 overflow-y-auto pr-1">
            {paginated.map((s, i) => (
              <div
                key={i}
                className={clsx(
                  'flex items-center gap-3 px-3 py-1.5 rounded-lg text-xs border',
                  s.sensitive
                    ? 'bg-orange-50 border-orange-200'
                    : 'bg-dark-800/40 border-dark-800/60'
                )}
              >
                {s.sensitive && <AlertTriangle className="w-3.5 h-3.5 text-orange-500 shrink-0" />}
                <span className={clsx('font-mono flex-1', s.sensitive ? 'text-orange-700' : 'text-dark-200')}>
                  {s.subdomain}
                </span>
                <span className="text-dark-600 shrink-0">{(s.ips ?? []).join(', ')}</span>
              </div>
            ))}
          </div>
          {!showAll && paginated.length < filtered.length && (
            <div className="mt-3 flex gap-3 justify-center">
              <button
                onClick={() => setPage(p => p + 1)}
                className="text-xs text-cyber-700 hover:text-cyber-800 font-medium inline-flex items-center gap-1 transition-colors duration-150"
              >
                {t('report.subdomains.loadMore', { count: filtered.length - paginated.length })} <ChevronDown className="w-3.5 h-3.5" />
              </button>
              <span className="text-dark-700 text-xs">·</span>
              <button
                onClick={() => setShowAll(true)}
                className="text-xs text-dark-400 hover:text-dark-200"
              >
                {t('report.subdomains.showAll', { count: filtered.length })}
              </button>
            </div>
          )}
        </>
      )}
      <FindingsList findings={data.findings ?? []} />
    </SectionCard>
  )
}
