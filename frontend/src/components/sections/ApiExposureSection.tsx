import { ApiExposureResult } from '../../types/report'
import { SectionCard, FindingsList } from '../ui'
import ModuleErrorNote, { isModuleError } from './ModuleErrorNote'
import clsx from 'clsx'
import { Check, ExternalLink, Radio } from 'lucide-react'
import { useTranslation } from 'react-i18next'

const SEV_STYLES: Record<string, string> = {
  critical: 'text-red-700 bg-red-50 border-red-200',
  high:     'text-orange-700 bg-orange-50 border-orange-200',
  medium:   'text-amber-700 bg-amber-50 border-amber-200',
  low:      'text-dark-300 bg-dark-900 border-dark-800',
}

const STATUS_COLOR: Record<string, string> = {
  '200': 'text-red-600',
  '401': 'text-orange-600',
  '403': 'text-amber-600',
}

export default function ApiExposureSection({ data }: { data: ApiExposureResult }) {
  const { t } = useTranslation()
  if (!data) return null
  if (isModuleError(data)) {
    return (
      <SectionCard title={t('report.apiExposure.title')} icon={<Radio />}>
        <ModuleErrorNote error={data.error} />
      </SectionCard>
    )
  }
  const found = data.found ?? []
  const repos = data.github_repos ?? []
  const codeHits = data.github_code_hits ?? []
  const collections = data.postman_collections ?? []
  const workspaces = data.postman_workspaces ?? []

  return (
    <SectionCard title={t('report.apiExposure.title')} icon={<Radio />} risk={data.risk}>
      {/* Stats */}
      <div className="grid grid-cols-3 md:grid-cols-6 gap-3 mb-4">
        <div className="rounded-lg border border-dark-700 bg-dark-800/50 p-3 text-center">
          <div className="text-xl font-bold text-dark-300">{data.paths_checked ?? 0}</div>
          <div className="text-dark-500 text-[10px] mt-0.5">{t('report.apiExposure.probed')}</div>
        </div>
        <div className={clsx('rounded-lg border p-3 text-center',
          data.swagger_found ? 'bg-orange-50 border-orange-200' : 'bg-dark-900 border-dark-800')}>
          <div className={clsx('text-xl font-bold', data.swagger_found ? 'text-orange-600' : 'text-dark-500')}>
            {data.swagger_found ? <Check className="w-5 h-5 mx-auto" strokeWidth={2.5} /> : '—'}
          </div>
          <div className="text-dark-500 text-[10px] mt-0.5">Swagger</div>
        </div>
        <div className={clsx('rounded-lg border p-3 text-center',
          data.graphql_found ? 'bg-orange-50 border-orange-200' : 'bg-dark-900 border-dark-800')}>
          <div className={clsx('text-xl font-bold', data.graphql_found ? 'text-orange-600' : 'text-dark-500')}>
            {data.graphql_found ? <Check className="w-5 h-5 mx-auto" strokeWidth={2.5} /> : '—'}
          </div>
          <div className="text-dark-500 text-[10px] mt-0.5">GraphQL</div>
        </div>
        <div className={clsx('rounded-lg border p-3 text-center',
          data.has_graphql_introspection ? 'bg-red-50 border-red-200' : 'bg-dark-900 border-dark-800')}>
          <div className={clsx('text-xl font-bold', data.has_graphql_introspection ? 'text-red-600' : 'text-dark-500')}>
            {data.has_graphql_introspection ? <Check className="w-5 h-5 mx-auto" strokeWidth={2.5} /> : '—'}
          </div>
          <div className="text-dark-500 text-[10px] mt-0.5">{t('report.apiExposure.introspect')}</div>
        </div>
        <div className={clsx('rounded-lg border p-3 text-center',
          repos.length > 0 ? 'bg-purple-50 border-purple-200' : 'bg-dark-900 border-dark-800')}>
          <div className={clsx('text-xl font-bold', repos.length > 0 ? 'text-purple-600' : 'text-dark-500')}>
            {repos.length}
          </div>
          <div className="text-dark-500 text-[10px] mt-0.5">{t('report.apiExposure.githubRepos')}</div>
        </div>
        <div className={clsx('rounded-lg border p-3 text-center',
          (collections.length + workspaces.length) > 0 ? 'bg-orange-50 border-orange-200' : 'bg-dark-900 border-dark-800')}>
          <div className={clsx('text-xl font-bold', (collections.length + workspaces.length) > 0 ? 'text-orange-600' : 'text-dark-500')}>
            {collections.length + workspaces.length}
          </div>
          <div className="text-dark-500 text-[10px] mt-0.5">Postman</div>
        </div>
      </div>

      {found.length > 0 ? (
        <div>
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-2">
            {t('report.withCount', { label: t('report.apiExposure.endpointsFound'), count: found.length })}
          </h4>
          <div className="space-y-1">
            {found.map((f, i) => (
              <div key={i} className={clsx('rounded border px-2.5 py-1.5 text-xs flex items-center gap-2', SEV_STYLES[f.severity] ?? SEV_STYLES.low)}>
                <span className={clsx('font-bold w-8 text-center shrink-0', STATUS_COLOR[String(f.status)] ?? 'text-dark-400')}>
                  {f.status}
                </span>
                <span className="font-mono flex-1 truncate">{f.path}</span>
                <span className="text-[10px] opacity-60 shrink-0">{f.label}</span>
                <a href={f.url} target="_blank" rel="noopener noreferrer"
                  className="opacity-40 hover:opacity-80 shrink-0 transition-opacity"><ExternalLink className="w-3 h-3" /></a>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <p className="text-emerald-600 text-sm text-center py-3 flex items-center justify-center gap-1.5"><Check className="w-4 h-4" /> {t('report.apiExposure.empty')}</p>
      )}

      <FindingsList findings={data.findings ?? []} />
    </SectionCard>
  )
}
