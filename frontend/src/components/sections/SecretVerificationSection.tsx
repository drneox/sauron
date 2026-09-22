import { SecretVerificationResult } from '../../types/report'
import { SectionCard, FindingsList } from '../ui'
import ModuleErrorNote from './ModuleErrorNote'
import clsx from 'clsx'
import { AlertOctagon, AlertTriangle, BadgeCheck } from 'lucide-react'
import { useTranslation } from 'react-i18next'

const VERDICT_STYLE: Record<string, { badge: string; row: string; label: string }> = {
  valid: {
    badge: 'bg-red-100 text-red-600 border-red-200',
    row: 'text-red-700 bg-red-50 border-red-200',
    label: 'VALID KEY',
  },
  invalid: {
    badge: 'bg-emerald-100 text-emerald-600 border-emerald-200',
    row: 'text-dark-300 bg-dark-900 border-dark-800',
    label: 'INVALID',
  },
  unknown: {
    badge: 'bg-amber-100 text-amber-600 border-amber-200',
    row: 'text-amber-700 bg-amber-50 border-amber-200',
    label: 'UNKNOWN',
  },
}

export default function SecretVerificationSection({ data }: { data: SecretVerificationResult }) {
  const { t } = useTranslation()
  if (!data) return null

  if (data.status === 'skipped') {
    return (
      <SectionCard title={t('report.secretVerification.title')} icon={<BadgeCheck />}>
        <p className="text-dark-400 text-sm text-center py-3">{t('report.secretVerification.skipped')}</p>
      </SectionCard>
    )
  }

  if (data.status === 'error') {
    return (
      <SectionCard title={t('report.secretVerification.title')} icon={<BadgeCheck />}>
        <ModuleErrorNote error={data.error} />
      </SectionCard>
    )
  }

  const verified = data.verified ?? []
  const jwts = data.jwt_analysis ?? []

  return (
    <SectionCard title={t('report.secretVerification.title')} icon={<BadgeCheck />} risk={data.risk}>
      {typeof data.valid_count === 'number' && (
        <p className={clsx('text-xs mb-3 flex items-center gap-1.5', data.valid_count > 0 ? 'text-red-600 font-semibold' : 'text-dark-400')}>
          {data.valid_count > 0 && <AlertOctagon className="w-4 h-4" />}
          {data.valid_count > 0
            ? t('report.secretVerification.validConfirmed', { count: data.valid_count })
            : t('report.secretVerification.noValid')}
        </p>
      )}

      {/* Verified keys */}
      {verified.length > 0 && (
        <div className="mb-3">
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-2">
            {t('report.withCount', { label: t('report.secretVerification.verifiedKeys'), count: verified.length })}
          </h4>
          <div className="space-y-1">
            {verified.map((v, i) => {
              const style = VERDICT_STYLE[v.verdict] ?? VERDICT_STYLE.unknown
              return (
                <div key={i} className={clsx('rounded border px-2 py-1.5 text-[11px]', style.row)}>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={clsx('text-[9px] px-1.5 py-0.5 rounded border font-bold uppercase shrink-0', style.badge)}>
                      {style.label}
                    </span>
                    <span className="font-semibold">{v.type}</span>
                    <span className="text-[10px] opacity-60">{v.host}</span>
                  </div>
                  <div className="font-mono mt-0.5 opacity-80 truncate">{v.key}</div>
                  {v.evidence && (
                    <div className="text-[10px] opacity-50 mt-0.5">{v.evidence}</div>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* JWT analysis */}
      {jwts.length > 0 && (
        <div>
          <h4 className="text-[10px] font-bold text-dark-500 uppercase tracking-wider mb-2">
            {t('report.withCount', { label: t('report.secretVerification.jwtAnalysis'), count: jwts.length })}
          </h4>
          <div className="space-y-1">
            {jwts.map((j, i) => (
              <div key={i} className="rounded border border-dark-700 bg-dark-800/50 px-2 py-1.5 text-[11px] text-dark-300">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-[10px] opacity-70 truncate">{j.source.split('/').pop()}</span>
                  <span className="text-[10px]">alg: <span className="font-semibold">{j.alg}</span></span>
                  {j.issuer && <span className="text-[10px] opacity-60">iss: {j.issuer}</span>}
                  {j.expires && <span className="text-[10px] opacity-60">exp: {j.expires}</span>}
                </div>
                {(j.issues ?? []).length > 0 && (
                  <ul className="mt-1 space-y-0.5">
                    {(j.issues ?? []).map((issue, k) => (
                      <li key={k} className="text-[10px] text-amber-700 flex items-start gap-1"><AlertTriangle className="w-3 h-3 mt-px shrink-0" /> {issue}</li>
                    ))}
                  </ul>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {verified.length === 0 && jwts.length === 0 && (
        <p className="text-dark-400 text-sm text-center py-3">{t('report.secretVerification.empty')}</p>
      )}

      <FindingsList findings={data.findings ?? []} />
    </SectionCard>
  )
}
