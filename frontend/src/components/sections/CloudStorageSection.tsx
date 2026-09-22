import { useState } from 'react'
import { CloudMetadataResult } from '../../types/report'
import { SectionCard, FindingsList, Pager, PAGE_SIZE, downloadCsv } from '../ui'
import ModuleErrorNote, { isModuleError } from './ModuleErrorNote'
import clsx from 'clsx'
import { Check, Cloud, Download, Microscope, Search } from 'lucide-react'
import { useTranslation } from 'react-i18next'

const PROVIDER_COLORS: Record<string, string> = {
  aws:   'text-orange-600 bg-orange-50 border-orange-200',
  gcs:   'text-blue-600 bg-blue-50 border-blue-800/40',
  azure: 'text-cyan-700 bg-cyan-50 border-cyan-200',
}

const PROVIDER_LABEL: Record<string, string> = {
  aws:   'AWS S3',
  gcs:   'Google GCS',
  azure: 'Azure Blob',
}

const SEV_STYLES: Record<string, string> = {
  critical: 'text-red-700 bg-red-50 border-red-200',
  high:     'text-orange-700 bg-orange-50 border-orange-200',
  medium:   'text-amber-700 bg-amber-50 border-amber-200',
  low:      'text-dark-300 bg-dark-900 border-dark-800',
}

export default function CloudStorageSection({ data }: { data: CloudMetadataResult }) {
  const { t } = useTranslation()
  const [privatePage, setPrivatePage] = useState(1)

  if (!data) return null
  if (isModuleError(data)) {
    return (
      <SectionCard title={t('report.cloud.title')} icon={<Cloud />}>
        <ModuleErrorNote error={data.error} />
      </SectionCard>
    )
  }

  const exposed = data.exposed ?? []
  const privateList = data.existing_private_list ?? []
  const privatePageRows = privateList.slice((privatePage - 1) * PAGE_SIZE, privatePage * PAGE_SIZE)

  return (
    <SectionCard title={t('report.cloud.title')} icon={<Cloud />} risk={data.risk}>
      {/* Stats */}
      <div className="grid grid-cols-3 gap-3 mb-4">
        <div className="rounded-lg border border-dark-700 bg-dark-800/50 p-3 text-center">
          <div className="text-2xl font-bold text-dark-300">{data.candidates_checked ?? 0}</div>
          <div className="text-dark-500 text-[10px] mt-0.5">{t('report.cloud.candidates')}</div>
        </div>
        <div className={clsx('rounded-lg border p-3 text-center',
          exposed.length > 0 ? 'bg-red-50 border-red-200' : 'bg-dark-900 border-dark-800')}>
          <div className={clsx('text-2xl font-bold', exposed.length > 0 ? 'text-red-600' : 'text-emerald-600')}>
            {data.exposed_count ?? 0}
          </div>
          <div className="text-dark-500 text-[10px] mt-0.5">{t('report.cloud.exposed')}</div>
        </div>
        <div className="rounded-lg border border-dark-700 bg-dark-800/50 p-3 text-center">
          <div className="text-2xl font-bold text-dark-400">{data.existing_private ?? 0}</div>
          <div className="text-dark-500 text-[10px] mt-0.5">{t('report.cloud.private')}</div>
        </div>
      </div>
      {(data.s3scanner_used || data.grayhatwarfare_used) && (
        <div className="flex gap-3 mb-3 flex-wrap">
          {data.s3scanner_used && (
            <p className="text-[10px] text-emerald-600 inline-flex items-center gap-1"><Microscope className="w-3 h-3" /> {t('report.cloud.s3scanner')}</p>
          )}
          {data.grayhatwarfare_used && (
            <p className="text-[10px] text-cyber-600 inline-flex items-center gap-1"><Search className="w-3 h-3" /> {t('report.cloud.ghw')}</p>
          )}
        </div>
      )}

      {exposed.length > 0 ? (
        <div className="space-y-1.5">
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-2">
            {t('report.withCount', { label: t('report.cloud.exposedBuckets'), count: exposed.length })}
          </h4>
          {exposed.map((b, i) => (
            <div key={i} className={clsx('rounded border px-3 py-2 text-xs', SEV_STYLES[b.severity] ?? SEV_STYLES.low)}>
              <div className="flex items-center gap-2 flex-wrap">
                <span className={clsx('text-[9px] font-bold px-1.5 py-px rounded border uppercase', PROVIDER_COLORS[b.provider] ?? 'text-dark-400 bg-dark-800 border-dark-700')}>
                  {PROVIDER_LABEL[b.provider] ?? b.provider}
                </span>
                <span className="font-mono font-bold">{b.name}</span>
                <span className="text-[10px] opacity-60">HTTP {b.status}</span>
                <span className="ml-auto text-[9px] font-bold uppercase opacity-70">{b.severity}</span>
              </div>
              <a href={b.url} target="_blank" rel="noopener noreferrer"
                className="mt-1 block text-[10px] font-mono opacity-60 hover:opacity-100 hover:underline truncate">
                {b.url}
              </a>
            </div>
          ))}
        </div>
      ) : (
        <p className="text-emerald-600 text-sm text-center py-3 flex items-center justify-center gap-1.5"><Check className="w-4 h-4" /> {t('report.cloud.empty')}</p>
      )}

      {/* Existing but private buckets = confirmed cloud footprint */}
      {privateList.length > 0 && (
        <div className="mt-4">
          <div className="flex items-center gap-2 mb-1">
            <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider flex-1">
              {t('report.withCount', { label: t('report.cloud.existingPrivate'), count: data.existing_private })}
            </h4>
            <Pager page={privatePage} total={privateList.length} onPage={setPrivatePage} />
            <button
              onClick={() => downloadCsv(
                'private_buckets.csv',
                ['name', 'provider', 'url'],
                privateList.map((b) => [b.name, b.provider, b.url]),
              )}
              className="btn-secondary !py-1 !px-2 !text-[10px]"
              title={t('report.cloud.csvTitle')}
            >
              <Download className="w-3 h-3" />
              CSV
            </button>
          </div>
          <p className="text-[11px] text-dark-500 mb-2">
            {t('report.cloud.privateNote')}
          </p>
          <div className="flex flex-wrap gap-1.5">
            {privatePageRows.map((b, i) => (
              <span key={`${privatePage}:${i}`} className="inline-flex items-center gap-1.5 text-[10px] font-mono px-2 py-1 rounded border bg-dark-900 border-dark-700 text-dark-300" title={b.url}>
                <span className={clsx('text-[9px] font-bold px-1 py-px rounded border uppercase', PROVIDER_COLORS[b.provider] ?? 'text-dark-400 bg-dark-800 border-dark-700')}>
                  {PROVIDER_LABEL[b.provider] ?? b.provider}
                </span>
                {b.name}
              </span>
            ))}
          </div>
        </div>
      )}

      <FindingsList findings={data.findings ?? []} />
    </SectionCard>
  )
}
