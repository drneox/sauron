import { useEffect, useState } from 'react'
import axios from 'axios'
import clsx from 'clsx'
import { useTranslation } from 'react-i18next'
import { ChevronDown, ChevronRight, Landmark } from 'lucide-react'
import { RiskBadge } from './ui'

interface FrameworkCell {
  framework: string
  open: { critical: number; high: number; medium: number; low: number; total: number }
  accepted: number
  fixed: number
  total: number
}

interface ComplianceResponse {
  company_id: number
  company_name: string
  generated_at: string
  frameworks: FrameworkCell[]
  untagged: { open: number; total: number }
}

const FRAMEWORK_LABEL: Record<string, string> = {
  'NIST-CSF': 'NIST CSF',
  'ISO-27001': 'ISO 27001',
  'PCI-DSS': 'PCI DSS',
  'CIS': 'CIS Controls',
}

// Collapsible compliance-coverage section for the company dashboard: one card
// per framework with open findings by severity and a fixed/total progress bar.
export default function ComplianceSection({ companyId }: { companyId: number }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [data, setData] = useState<ComplianceResponse | null>(null)
  const [error, setError] = useState(false)

  useEffect(() => {
    if (!open || data || error) return
    let cancelled = false
    axios.get<ComplianceResponse>(`/api/companies/${companyId}/compliance`)
      .then(({ data }) => { if (!cancelled) setData(data) })
      .catch(() => { if (!cancelled) setError(true) })
    return () => { cancelled = true }
  }, [open, companyId, data, error])

  return (
    <div className="card space-y-3">
      <button onClick={() => setOpen((o) => !o)} className="w-full flex items-center gap-2 text-left">
        {open ? <ChevronDown className="w-4 h-4 text-dark-500" /> : <ChevronRight className="w-4 h-4 text-dark-500" />}
        <Landmark className="w-4 h-4 text-cyber-600" />
        <h3 className="text-[15px] font-semibold tracking-tight text-dark-100 flex-1">
          {t('compliance.title')}
        </h3>
        {data && (
          <span className="text-xs text-dark-500">
            {t('compliance.openTotal', { count: data.frameworks.reduce((a, f) => a + f.open.total, 0) })}
          </span>
        )}
      </button>

      {open && error && (
        <p className="text-sm text-red-600">{t('compliance.loadError')}</p>
      )}
      {open && !data && !error && (
        <p className="text-sm text-dark-500 animate-pulse">{t('common.loading')}</p>
      )}

      {open && data && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {data.frameworks.map((fw) => {
            const progress = fw.total > 0 ? Math.round((fw.fixed / fw.total) * 100) : 100
            return (
              <div key={fw.framework} className="rounded-lg border border-dark-800 bg-dark-900/40 px-3 py-2.5 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-dark-100">{FRAMEWORK_LABEL[fw.framework] ?? fw.framework}</span>
                  <span className={clsx(
                    'text-[10px] px-1.5 py-0.5 rounded-full border font-semibold',
                    fw.open.total > 0 ? 'bg-red-50 text-red-700 border-red-200' : 'bg-emerald-50 text-emerald-700 border-emerald-200',
                  )}>
                    {t('compliance.openCount', { count: fw.open.total })}
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  {(['critical', 'high', 'medium', 'low'] as const).map((r) => (
                    fw.open[r] > 0 && (
                      <span key={r} className="inline-flex items-center gap-1 text-[10px]">
                        <RiskBadge risk={r} />
                        <span className="font-mono font-semibold text-dark-200">{fw.open[r]}</span>
                      </span>
                    )
                  ))}
                  {fw.open.total === 0 && <span className="text-[11px] text-dark-500">{t('compliance.noOpen')}</span>}
                </div>
                <div>
                  <div className="flex justify-between text-[10px] text-dark-500 mb-1">
                    <span>{t('compliance.progress')}</span>
                    <span className="font-mono">{fw.fixed}/{fw.total} · {progress}%</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-dark-800 overflow-hidden">
                    <div
                      className={clsx('h-full rounded-full transition-all duration-300', progress >= 80 ? 'bg-emerald-500' : progress >= 50 ? 'bg-amber-500' : 'bg-red-500')}
                      style={{ width: `${progress}%` }}
                    />
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
