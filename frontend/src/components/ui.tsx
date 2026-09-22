import { RiskLevel } from '../types/report'
import clsx from 'clsx'
import { useTranslation } from 'react-i18next'
import { AlertTriangle, Check, ChevronLeft, ChevronRight, X } from 'lucide-react'

export function RiskBadge({ risk }: { risk: RiskLevel }) {
  return (
    <span className={clsx(
      'text-[11px] px-2 py-0.5 rounded-full font-semibold uppercase tracking-wide border',
      risk === 'critical' && 'bg-red-50 text-red-700 border-red-200',
      risk === 'high' && 'bg-orange-50 text-orange-700 border-orange-200',
      risk === 'medium' && 'bg-amber-50 text-amber-700 border-amber-200',
      risk === 'low' && 'bg-emerald-50 text-emerald-700 border-emerald-200',
    )}>
      {risk}
    </span>
  )
}

export function CheckIcon({ ok }: { ok: boolean }) {
  return ok
    ? <Check className="w-4 h-4 text-emerald-500" strokeWidth={2.5} />
    : <X className="w-4 h-4 text-red-500" strokeWidth={2.5} />
}

export function SectionCard({ title, icon, risk, children }: {
  title: string
  icon: React.ReactNode
  risk?: RiskLevel
  children: React.ReactNode
}) {
  return (
    <div className="card">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-lg bg-cyber-50 border border-cyber-100 flex items-center justify-center text-cyber-600 shrink-0 [&>svg]:w-4 [&>svg]:h-4">
          {icon}
        </div>
        <h2 className="text-[15px] font-semibold tracking-tight text-dark-100 flex-1">{title}</h2>
        {risk && <RiskBadge risk={risk} />}
      </div>
      {children}
    </div>
  )
}

export function KeyValue({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex gap-2 text-sm py-1.5 border-b border-dark-800 last:border-0">
      <span className="text-dark-500 min-w-[160px] shrink-0">{label}</span>
      <span className="text-dark-100 break-all font-mono text-[13px]">{value ?? <span className="text-dark-600 font-sans">—</span>}</span>
    </div>
  )
}

export const PAGE_SIZE = 50

export function Pager({ page, total, onPage, pageSize = PAGE_SIZE }: {
  page: number
  total: number
  onPage: (page: number) => void
  pageSize?: number
}) {
  const { t } = useTranslation()
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  if (totalPages <= 1) return null
  const current = Math.min(Math.max(page, 1), totalPages)
  const btn = 'inline-flex items-center justify-center w-6 h-6 rounded-md border border-dark-700 bg-white text-dark-300 hover:bg-dark-900 disabled:opacity-40 disabled:cursor-not-allowed transition-colors duration-150'
  return (
    <div className="flex items-center gap-2 text-[11px] text-dark-500">
      <button onClick={() => onPage(current - 1)} disabled={current <= 1} className={btn} title={t('common.previousPage')}>
        <ChevronLeft className="w-3.5 h-3.5" />
      </button>
      <span className="font-mono whitespace-nowrap">{t('common.pageOf', { current, total: totalPages })}</span>
      <button onClick={() => onPage(current + 1)} disabled={current >= totalPages} className={btn} title={t('common.nextPage')}>
        <ChevronRight className="w-3.5 h-3.5" />
      </button>
    </div>
  )
}

export function downloadCsv(
  filename: string,
  headers: string[],
  rows: (string | number | null | undefined)[][],
) {
  const esc = (v: string | number | null | undefined): string => {
    if (v == null) return ''
    const s = String(v)
    return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
  }
  const csv = [headers, ...rows].map((r) => r.map(esc).join(',')).join('\r\n')
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

const URL_RE = /(https?:\/\/[^\s<>"'`]+)/g

/** Renders text with URLs turned into clickable links (opens in a new tab). */
export function LinkifyText({ text, className }: { text: string; className?: string }) {
  const parts = text.split(URL_RE)
  return (
    <span className={className}>
      {parts.map((p, i) =>
        /^https?:\/\//.test(p) ? (
          <a
            key={i}
            href={p}
            target="_blank"
            rel="noopener noreferrer"
            className="text-cyber-700 hover:text-cyber-500 hover:underline break-all"
            onClick={(e) => e.stopPropagation()}
          >
            {p}
          </a>
        ) : (
          <span key={i}>{p}</span>
        ),
      )}
    </span>
  )
}

export function FindingsList({ findings }: { findings: string[] }) {
  if (!findings.length) return null
  return (
    <ul className="mt-3 space-y-1.5">
      {findings.map((f, i) => (
        <li key={i} className="flex items-start gap-2 text-xs text-amber-700">
          <AlertTriangle className="w-3.5 h-3.5 mt-px shrink-0 text-amber-500" />
          <LinkifyText text={f} />
        </li>
      ))}
    </ul>
  )
}
