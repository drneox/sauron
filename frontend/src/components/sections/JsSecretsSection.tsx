import { useState } from 'react'
import { JsSecretsResult } from '../../types/report'
import { SectionCard, FindingsList } from '../ui'
import ModuleErrorNote, { isModuleError } from './ModuleErrorNote'
import clsx from 'clsx'
import { AlertTriangle, Check, Eye, EyeOff, KeyRound } from 'lucide-react'
import { useTranslation } from 'react-i18next'

function SecretValue({ snippet, value }: { snippet: string; value?: string }) {
  const { t } = useTranslation()
  const [show, setShow] = useState(false)
  return (
    <div className="font-mono mt-0.5 opacity-80 flex items-center gap-1.5">
      <span className={show && value ? 'break-all' : 'truncate'}>{show && value ? value : snippet}</span>
      {value && (
        <button
          onClick={() => setShow(!show)}
          className="opacity-50 hover:opacity-100 shrink-0 transition-opacity"
          title={show ? t('report.jsSecrets.hideSecret') : t('report.jsSecrets.revealSecret')}
        >
          {show ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
        </button>
      )}
    </div>
  )
}

const SEV_COLOR: Record<string, string> = {
  critical: 'text-red-600 bg-red-50 border-red-200',
  high: 'text-orange-600 bg-orange-50 border-orange-200',
  medium: 'text-amber-600 bg-amber-50 border-amber-200',
  low: 'text-dark-400 bg-dark-900 border-dark-800',
}

const HOST_KIND_COLOR: Record<string, string> = {
  'internal-env': 'text-orange-600 bg-orange-50 border-orange-200',
  'cloud':        'text-amber-600 bg-amber-50 border-amber-200',
  'subdomain':    'text-cyber-400 bg-cyber-50 border-cyber-200',
  'third-party':  'text-dark-400 bg-dark-900 border-dark-800',
}

export default function JsSecretsSection({ data }: { data: JsSecretsResult }) {
  const { t } = useTranslation()
  if (!data) return null
  if (isModuleError(data)) {
    return (
      <SectionCard title={t('report.jsSecrets.title')} icon={<KeyRound />}>
        <ModuleErrorNote error={data.error} />
      </SectionCard>
    )
  }
  const secrets = data.secrets_found ?? []
  const bySev = data.by_severity ?? {}

  return (
    <SectionCard title={t('report.jsSecrets.title')} icon={<KeyRound />} risk={data.risk}>
      {/* Summary */}
      <div className="grid grid-cols-4 gap-2 mb-4">
        {(['critical', 'high', 'medium', 'low'] as const).map(sev => (
          <div key={sev} className={clsx('rounded-lg border p-2 text-center', SEV_COLOR[sev])}>
            <div className="text-xl font-bold">{bySev[sev] ?? 0}</div>
            <div className="text-[10px] mt-0.5 opacity-70 capitalize">{sev}</div>
          </div>
        ))}
      </div>

      {/* File list */}
      {(data.js_files_scanned ?? []).length > 0 && (
        <div className="mb-3">
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-1">
            {t('report.withCount', { label: t('report.jsSecrets.filesScanned'), count: (data.js_files_scanned ?? []).length })}
          </h4>
          <div className="space-y-0.5 max-h-24 overflow-y-auto pr-1">
            {(data.js_files_scanned ?? []).map((f, i) => (
              <a key={i} href={f} target="_blank" rel="noopener noreferrer"
                className="block text-[10px] font-mono text-dark-500 hover:text-dark-300 truncate">
                {f}
              </a>
            ))}
          </div>
        </div>
      )}

      {/* Secrets list */}
      {secrets.length > 0 && (
        <div>
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-2">
            {t('report.withCount', { label: t('report.jsSecrets.secretsFound'), count: secrets.length })}
          </h4>
          <div className="space-y-1">
            {secrets.map((s, i) => (
              <div key={i} className={clsx('rounded border px-2 py-1.5 text-[11px]', SEV_COLOR[s.severity] ?? SEV_COLOR.low)}>
                <div className="flex items-center gap-2">
                  <span className="font-semibold">{s.type}</span>
                  <span className="text-[10px] opacity-60">{t('report.jsSecrets.line', { n: s.line })}</span>
                </div>
                <SecretValue snippet={s.snippet} value={s.value} />
                <div className="text-[10px] opacity-50 truncate">{(s.file ?? '').split('/').pop()}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {secrets.length === 0 && (
        <p className="text-emerald-600 text-sm text-center py-3 flex items-center justify-center gap-1.5"><Check className="w-4 h-4" /> {t('report.jsSecrets.empty')}</p>
      )}

      {/* Extracted endpoints */}
      {(data.endpoints ?? []).length > 0 && (
        <div className="mt-3">
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-1">
            {t('report.withCount', { label: t('report.jsSecrets.endpoints'), count: (data.endpoints ?? []).length })}
          </h4>
          <div className="space-y-0.5 max-h-32 overflow-y-auto pr-1">
            {(data.endpoints ?? []).map((e, i) => (
              <div key={i} className="flex items-baseline gap-2 text-[11px]">
                <span className="font-mono text-dark-200 truncate">{e.path}</span>
                <span className="text-[10px] text-dark-600 truncate shrink-0 max-w-[40%]">{(e.source ?? '').split('/').pop()}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Extracted hosts */}
      {(data.hosts ?? []).length > 0 && (
        <div className="mt-3">
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-1">
            {t('report.withCount', { label: t('report.jsSecrets.hosts'), count: (data.hosts ?? []).length })}
          </h4>
          <div className="space-y-0.5 max-h-32 overflow-y-auto pr-1">
            {(data.hosts ?? []).map((h, i) => (
              <div key={i} className="flex items-center gap-2 text-[11px]">
                <span className={clsx('text-[9px] px-1.5 py-0.5 rounded border font-bold uppercase shrink-0',
                  HOST_KIND_COLOR[h.kind] ?? HOST_KIND_COLOR['third-party'])}>
                  {h.kind}
                </span>
                <span className="font-mono text-dark-200 truncate">{h.host}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* GUIDs */}
      {(data.guids ?? []).length > 0 && (
        <div className="mt-3">
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-1">
            {t('report.withCount', { label: t('report.jsSecrets.guids'), count: (data.guids ?? []).length })}
          </h4>
          <div className="space-y-0.5 max-h-24 overflow-y-auto pr-1">
            {(data.guids ?? []).map((g, i) => (
              <div key={i} className="text-[11px]">
                <span className="font-mono text-dark-300">{g.value}</span>
                <span className="text-[10px] text-dark-600 ml-2">{g.context}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Sourcemaps */}
      {(data.sourcemaps ?? []).length > 0 && (
        <div className="mt-3">
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-1">
            {t('report.withCount', { label: t('report.jsSecrets.sourcemaps'), count: (data.sourcemaps ?? []).length })}
          </h4>
          <div className="space-y-1">
            {(data.sourcemaps ?? []).map((m, i) => (
              <div key={i} className={clsx('rounded border px-2 py-1.5 text-[11px]',
                m.has_sources_content
                  ? 'text-red-600 bg-red-50 border-red-200'
                  : 'text-dark-400 bg-dark-900 border-dark-800')}>
                <a href={m.map} target="_blank" rel="noopener noreferrer"
                  className="font-mono truncate block hover:underline">
                  {m.map}
                </a>
                {m.has_sources_content && (
                  <div className="text-[10px] font-semibold mt-0.5 flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> {t('report.jsSecrets.fullSource')}</div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      <FindingsList findings={data.findings ?? []} />
    </SectionCard>
  )
}
