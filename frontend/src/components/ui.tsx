import { RiskLevel } from '../types/report'
import clsx from 'clsx'
import { useTranslation } from 'react-i18next'
import { AlertTriangle, Check, ChevronLeft, ChevronRight, X } from 'lucide-react'
import axios from 'axios'

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

// Plain `<a href="/api/...">` links can't carry the Bearer token the backend
// requires (AUTH_ENABLED=true rejects them with 401, which browsers surface
// as a generic "file not available" download failure) — so authenticated
// exports go through axios (its request interceptor attaches the token) and
// save the response blob manually instead of relying on browser navigation.
export async function downloadFromApi(url: string, filename: string): Promise<void> {
  const res = await axios.get(url, { responseType: 'blob' })
  const blobUrl = URL.createObjectURL(res.data)
  const a = document.createElement('a')
  a.href = blobUrl
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(blobUrl)
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
// A bare path ("/configuration.php") rather than a full URL — most finding
// strings only carry the path (e.g. "... → /configuration.php (medium
// confidence)"), never the scheme+host. Bounded by whitespace/punctuation on
// both sides (incl. the "→" arrow some modules use) so we don't swallow
// trailing sentence punctuation or grab a slash inside running prose.
const PATH_RE = /(?:(?<=[\s(:"'→])|^)(\/[A-Za-z0-9_][A-Za-z0-9_\-./]*)(?=[\s).,:;"']|$)/g

/**
 * Renders text with URLs turned into clickable links (opens in a new tab).
 * When `baseUrl` is given (a specific finding's own domain — only pass it
 * where that's unambiguous, e.g. a per-domain findings list), bare paths
 * like "/configuration.php" are ALSO linkified against that domain.
 */
export function LinkifyText({ text, className, baseUrl }: { text: string; className?: string; baseUrl?: string }) {
  const urlParts = text.split(URL_RE)
  return (
    <span className={className}>
      {urlParts.map((part, i) => {
        if (/^https?:\/\//.test(part)) {
          return (
            <a
              key={i}
              href={part}
              target="_blank"
              rel="noopener noreferrer"
              className="text-cyber-700 hover:text-cyber-500 hover:underline break-all"
              onClick={(e) => e.stopPropagation()}
            >
              {part}
            </a>
          )
        }
        if (!baseUrl) return <span key={i}>{part}</span>
        // Odd indices of a one-capture-group split() are always the matches.
        const pathParts = part.split(PATH_RE)
        return (
          <span key={i}>
            {pathParts.map((p, j) =>
              j % 2 === 1 ? (
                <a
                  key={j}
                  href={baseUrl.replace(/\/$/, '') + p}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-cyber-700 hover:text-cyber-500 hover:underline break-all"
                  onClick={(e) => e.stopPropagation()}
                >
                  {p}
                </a>
              ) : (
                <span key={j}>{p}</span>
              ),
            )}
          </span>
        )
      })}
    </span>
  )
}

export function FindingsList({ findings, baseUrl }: { findings: string[]; baseUrl?: string }) {
  if (!findings.length) return null
  return (
    <ul className="mt-3 space-y-1.5">
      {findings.map((f, i) => (
        <li key={i} className="flex items-start gap-2 text-xs text-amber-700">
          <AlertTriangle className="w-3.5 h-3.5 mt-px shrink-0 text-amber-500" />
          <LinkifyText text={f} baseUrl={baseUrl} />
        </li>
      ))}
    </ul>
  )
}
