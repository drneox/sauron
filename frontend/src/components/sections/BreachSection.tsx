import { useState } from 'react'
import { BreachResult } from '../../types/report'
import { SectionCard, FindingsList, Pager, PAGE_SIZE, downloadCsv } from '../ui'
import ModuleErrorNote, { isModuleError } from './ModuleErrorNote'
import clsx from 'clsx'
import { Download, Skull } from 'lucide-react'
import { useTranslation } from 'react-i18next'

function ConfidenceBadge({ score }: { score: number }) {
  const s = score ?? 0
  const color = s >= 80 ? 'text-red-600 border-red-200 bg-red-50'
    : s >= 50 ? 'text-orange-600 border-orange-200 bg-orange-50'
    : 'text-amber-600 border-amber-200 bg-amber-50'
  return (
    <span className={clsx('text-[10px] font-bold border rounded px-1 py-0.5', color)}>
      {s}%
    </span>
  )
}

export default function BreachSection({ data }: { data: BreachResult }) {
  const { t } = useTranslation()
  const [comboPage, setComboPage] = useState(1)

  if (!data) return null
  if (isModuleError(data)) {
    return (
      <SectionCard title={t('report.breach.title')} icon={<Skull />}>
        <ModuleErrorNote error={data.error} />
      </SectionCard>
    )
  }

  const hasBreaches = (data.breach_count ?? 0) > 0
  const hasCombos = (data.combo_count ?? 0) > 0
  const breaches = data.breaches ?? []
  const comboSamples = data.combo_samples ?? []
  const comboPageRows = comboSamples.slice((comboPage - 1) * PAGE_SIZE, comboPage * PAGE_SIZE)
  const allEmails = data.all_emails ?? data.exposed_emails ?? []
  const hunterEmails = data.hunter?.emails ?? []
  const leakcheck = data.leakcheck
  const hunterConfigured = data.hunter?.error !== 'no_api_key'
  // Total emails = max between what we actually have and what Hunter reports
  const totalEmailCount = Math.max(allEmails.length, data.hunter?.total ?? 0)

  return (
    <SectionCard title={t('report.breach.title')} icon={<Skull />} risk={data.risk}>
      {/* Summary row */}
      <div className="grid grid-cols-4 gap-3 mb-4">
        <div className={clsx(
          'rounded-lg border p-3 text-center',
          hasBreaches ? 'bg-red-50 border-red-200' : 'bg-dark-900 border-dark-800'
        )}>
          <div className={clsx('text-2xl font-bold', hasBreaches ? 'text-red-600' : 'text-emerald-600')}>
            {data.breach_count ?? 0}
          </div>
          <div className="text-dark-500 text-[10px] mt-0.5">{t('report.breach.knownBreaches')}</div>
        </div>
        <div className={clsx(
          'rounded-lg border p-3 text-center',
          (leakcheck?.found ?? 0) > 0 ? 'bg-orange-50 border-orange-200' : 'bg-dark-900 border-dark-800'
        )}>
          <div className={clsx('text-2xl font-bold', (leakcheck?.found ?? 0) > 0 ? 'text-orange-600' : 'text-emerald-600')}>
            {leakcheck?.found?.toLocaleString() ?? '--'}
          </div>
          <div className="text-dark-500 text-[10px] mt-0.5">{t('report.breach.leakcheckRecords')}</div>
        </div>
        <div className={clsx(
          'rounded-lg border p-3 text-center',
          hasCombos ? 'bg-orange-50 border-orange-200' : 'bg-dark-900 border-dark-800'
        )}>
          <div className={clsx('text-2xl font-bold', hasCombos ? 'text-orange-600' : 'text-emerald-600')}>
            {(data.combo_count ?? 0) > 0 ? (data.combo_count ?? 0).toLocaleString() : '0'}
          </div>
          <div className="text-dark-500 text-[10px] mt-0.5">{t('report.breach.comboHits')}</div>
        </div>
        <div className="rounded-lg border border-dark-700 bg-dark-800/50 p-3 text-center">
          <div className={clsx('text-2xl font-bold', totalEmailCount > 0 ? 'text-amber-600' : 'text-emerald-600')}>
            {totalEmailCount}
          </div>
          <div className="text-dark-500 text-[10px] mt-0.5">{t('report.breach.emailsFound')}</div>
        </div>
      </div>

      {/* LeakCheck */}
      {leakcheck?.checked && (leakcheck.found ?? 0) > 0 && (
        <div className="mb-4 rounded-lg border border-orange-200 bg-orange-50 px-3 py-2.5">
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-2 flex items-center gap-2">
            LeakCheck
            <span className="text-orange-600 normal-case font-normal">{t('report.breach.records', { count: leakcheck.found })}</span>
          </h4>
          {(leakcheck.sources ?? []).length > 0 && (
            <div className="flex flex-wrap gap-1 mb-1.5">
              {(leakcheck.sources ?? []).map((src, i) => (
                <span key={i} className="text-[10px] font-mono bg-dark-800 border border-dark-700 text-dark-400 px-1.5 py-0.5 rounded">
                  {typeof src === 'string' ? src : `${src.name}${src.date ? ` (${src.date})` : ''}`}
                </span>
              ))}
            </div>
          )}
          {(leakcheck.fields ?? []).length > 0 && (
            <p className="text-[10px] text-dark-500">
              {t('report.breach.exposedFields')} <span className="text-dark-400">{(leakcheck.fields ?? []).join(', ')}</span>
            </p>
          )}
        </div>
      )}

      {/* Breach records HIBP */}
      {breaches.length > 0 && (
        <div className="mb-4">
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-2">{t('report.breach.breachRecords')}</h4>
          <div className="space-y-2">
            {breaches.map((b, i) => (
              <div key={i} className="bg-red-50 border border-red-200 rounded-lg px-3 py-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-red-700">{b.title}</span>
                  <span className="text-[10px] text-dark-500">{b.breach_date}</span>
                </div>
                <div className="mt-1 text-[10px] text-dark-400">
                  {(b.pwn_count ?? 0) > 0 && (
                    <span className="text-orange-600 font-semibold mr-2">
                      {t('report.breach.records', { count: b.pwn_count ?? 0 })}
                    </span>
                  )}
                  {(b.data_classes ?? []).slice(0, 5).join(' . ')}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Hunter.io emails */}
      {!hunterConfigured ? (
        <div className="mb-4 rounded-lg border border-dark-700 bg-dark-800/30 px-3 py-2.5">
          <p className="text-[10px] text-dark-500">
            <span className="text-cyber-700 font-semibold">Hunter.io</span> {t('report.breach.hunterNotConfigured')}{' '}
            {t('report.breach.hunterAdd')} <span className="font-mono text-dark-400">HUNTER_API_KEY=xxx</span> {t('report.breach.hunterTo')}{' '}
            <span className="font-mono text-dark-400">backend/.env</span> {t('report.breach.hunterHint')}
          </p>
        </div>
      ) : hunterEmails.length > 0 ? (
        <div className="mb-4">
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-2 flex items-center gap-2">
            {t('report.breach.hunterEmails')}
            {data.hunter?.organization && (
              <span className="text-dark-400 normal-case font-normal">{data.hunter.organization}</span>
            )}
            {(data.hunter?.total ?? 0) > hunterEmails.length && (
              <span className="text-dark-600 normal-case font-normal">{t('report.breach.more', { count: (data.hunter?.total ?? 0) - hunterEmails.length })}</span>
            )}
          </h4>
          <div className="space-y-1">
            {hunterEmails.map((e, i) => (
              <div key={i} className="flex items-center gap-2 bg-dark-800/40 rounded px-2 py-1.5 text-xs">
                <a
                  href={`mailto:${e.email}`}
                  className="font-mono text-amber-700 hover:text-yellow-200 hover:underline flex-1 truncate"
                >
                  {e.email}
                </a>
                <ConfidenceBadge score={e.confidence} />
                {e.position && (
                  <span className="text-dark-500 text-[10px] truncate max-w-[120px]">{e.position}</span>
                )}
                {e.linkedin && (
                  <a href={e.linkedin} target="_blank" rel="noopener noreferrer"
                    className="text-blue-600 hover:text-blue-600 text-[10px]">in</a>
                )}
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {/* crt.sh emails */}
      {(data.exposed_emails ?? []).length > 0 && (
        <div className="mb-4">
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-2">
            {t('report.breach.crtEmails')}
          </h4>
          <div className="flex flex-wrap gap-1.5">
            {(data.exposed_emails ?? []).map((e, i) => (
              <span key={i} className="text-[11px] bg-amber-50 border border-amber-200 text-amber-700 px-2 py-0.5 rounded font-mono">
                {typeof e === 'string' ? e : `${e.name}${e.date ? ` (${String(e.date).slice(0, 10)})` : ''}`}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Combo samples */}
      {comboSamples.length > 0 && (
        <div className="mb-4">
          <div className="flex items-center gap-2 mb-2">
            <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider flex-1">
              {t('report.breach.comboSamples')}
            </h4>
            <Pager page={comboPage} total={comboSamples.length} onPage={setComboPage} />
            <button
              onClick={() => downloadCsv('combo_samples.csv', ['combo'], comboSamples.map((s) => [s]))}
              className="btn-secondary !py-1 !px-2 !text-[10px]"
              title={t('report.breach.csvTitle')}
            >
              <Download className="w-3 h-3" />
              CSV
            </button>
          </div>
          <div className="space-y-1 font-mono">
            {comboPageRows.map((s, i) => (
              <div key={`${comboPage}:${i}`} className="text-[11px] text-dark-400 bg-dark-800/50 px-2 py-1 rounded">{s}</div>
            ))}
          </div>
          {(data.combo_count ?? 0) > comboSamples.length && (
            <p className="text-[11px] text-dark-500 mt-2">
              {t('report.breach.showing', { shown: comboSamples.length, total: (data.combo_count ?? 0).toLocaleString() })}
            </p>
          )}
        </div>
      )}

      {(data.public_code_mentions ?? 0) > 0 && (
        <div className="text-xs text-dark-400 mt-2">
          <span className="text-amber-600 font-semibold">{(data.public_code_mentions ?? 0).toLocaleString()}</span>
          {' '}{t('report.breach.mentions')}
        </div>
      )}

      {!hasBreaches && !hasCombos && allEmails.length === 0 && !(leakcheck?.found) && (
        <p className="text-emerald-600 text-sm text-center py-4">{t('report.breach.empty')}</p>
      )}

      <FindingsList findings={data.findings ?? []} />
    </SectionCard>
  )
}
