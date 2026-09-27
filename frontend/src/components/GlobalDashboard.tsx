import { useState, useEffect, useCallback, useRef } from 'react'
import axios from 'axios'
import clsx from 'clsx'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import {
  Company,
  CompanyAssets,
  CompanyDomain,
  CompanyHosts,
  AssetSummary,
  ScanListItem,
  PeriodChanges,
  PeriodFinding,
  WithCompany,
  AssetsDiff,
  GlobalAssetsDiff,
  CompanyScoreChange,
  GlobalModifiedEntry,
} from '../types/report'
import {
  AssetTable,
  AssetCategory,
  AssetInventory,
  LinkValueCell,
  fmtShort,
  gradeChipColor,
  th,
  td,
} from './assetTable'
import { HostTable, HostFilter, TaggedHost } from './hostTable'
import { downloadFromApi, LinkifyText, RiskBadge } from './ui'
import AddAppModal from './AddAppModal'
import AttackSurfaceGraph, { type IpGroup } from './AttackSurfaceGraph'
import RatingTrendCard from './RatingTrend'
import DashboardAnalytics from './DashboardAnalytics'
import PortfolioSection from './PortfolioSection'
import ComplianceSection from './ComplianceSection'
import {
  ArrowLeft,
  ArrowLeftRight,
  ClipboardCheck,
  Download,
  Plus,
  FileText,
  FileWarning,
  Network,
  Pencil,
  RefreshCw,
  Smartphone,
  Trash2,
  TrendingDown,
  TrendingUp,
  X,
  type LucideIcon,
} from 'lucide-react'

interface Props {
  onGoToCompanies: () => void
  onOpenCompany: (company: Company) => void
  lockedCompany?: Company
  onOpenCompanyReport?: (company: Company) => void
  onOpenRemediation?: (company: Company) => void
  onBack?: () => void
  readOnly?: boolean
}

type GlobalCategory = AssetCategory | 'companies' | 'domains' | 'hosts'

// Card categories that filter the host-centric table; the rest keep their
// legacy per-asset listings (companies/domains/apps/neighbors have no host
// attribution).
const HOST_FILTERS = new Set<GlobalCategory>([
  'hosts', 'subdomains', 'ips', 'endpoints', 'technologies',
  'admin_panels', 'exposed_files', 'ports',
])

// Listing categories backed by a single scanner module → eligible for the
// per-module rescan button in the listing header.
const MODULE_RESCAN: Partial<Record<GlobalCategory, string>> = {
  subdomains: 'subdomains',
  technologies: 'tech',
  apps: 'mobile_apps',
  neighbors: 'reverse_ip',
  admin_panels: 'admin',
  exposed_files: 'exposed',
  ports: 'ports',
}

const MAX_COMPANIES = 20

const errorMessage = (err: unknown, fallback: string) =>
  axios.isAxiosError(err)
    ? err.response?.data?.detail || err.message || fallback
    : fallback

const SUMMARY_KEYS = [
  'domains', 'subdomains', 'ips', 'endpoints', 'technologies',
  'admin_panels', 'exposed_files', 'open_ports', 'apps', 'neighbors', 'new_last_cycle',
] as const

const emptyTotals = (): AssetSummary => ({
  domains: 0, subdomains: 0, ips: 0, endpoints: 0, technologies: 0,
  admin_panels: 0, exposed_files: 0, open_ports: 0, apps: 0, neighbors: 0,
  new_last_cycle: 0,
})

function mergeInventories(loaded: { company: Company; data: CompanyAssets }[]): AssetInventory {
  const tag = <T,>(rows: T[] | undefined, company: string): WithCompany<T>[] =>
    (rows ?? []).map((r) => ({ ...r, company }))
  const merged: AssetInventory = {
    subdomains: [], ips: [], endpoints: [], technologies: [],
    admin_panels: [], exposed_files: [], ports: [], apps: [], neighbors: [],
  }
  for (const { company, data } of loaded) {
    const a = data.assets
    merged.subdomains.push(...tag(a?.subdomains, company.name))
    merged.ips.push(...tag(a?.ips, company.name))
    merged.endpoints.push(...tag(a?.endpoints, company.name))
    merged.technologies.push(...tag(a?.technologies, company.name))
    merged.admin_panels.push(...tag(a?.admin_panels, company.name))
    merged.exposed_files.push(...tag(a?.exposed_files, company.name))
    merged.ports!.push(...tag(a?.ports, company.name))
    merged.apps!.push(...tag(a?.apps, company.name))
    merged.neighbors!.push(...tag(a?.neighbors, company.name))
  }
  return merged
}

function filterByCompany(assets: AssetInventory, companyName: string | null): AssetInventory {
  if (!companyName) return assets
  const pick = <T extends { company?: string }>(rows: T[] | undefined): T[] =>
    (rows ?? []).filter((r) => r.company === companyName)
  return {
    subdomains: pick(assets.subdomains),
    ips: pick(assets.ips),
    endpoints: pick(assets.endpoints),
    technologies: pick(assets.technologies),
    admin_panels: pick(assets.admin_panels),
    exposed_files: pick(assets.exposed_files),
    ports: pick(assets.ports),
    apps: pick(assets.apps),
    neighbors: pick(assets.neighbors),
  }
}

function filterByDomain(assets: AssetInventory, domain: string): AssetInventory {
  if (!domain) return assets
  const d = domain.toLowerCase()
  const byDomain = <T,>(rows: T[] | undefined): T[] =>
    (rows ?? []).filter((r) => String((r as { domain?: string }).domain ?? '').toLowerCase() === d)
  return {
    subdomains: byDomain(assets.subdomains),
    ips: (assets.ips ?? []).filter((r) => ((r as { domains?: string[] }).domains ?? []).some((x) => x.toLowerCase() === d)),
    endpoints: byDomain(assets.endpoints),
    technologies: byDomain(assets.technologies),
    admin_panels: byDomain(assets.admin_panels),
    exposed_files: byDomain(assets.exposed_files),
    ports: byDomain(assets.ports),
    apps: byDomain(assets.apps),
    neighbors: byDomain(assets.neighbors),
  }
}

function filterHostsByDomain(hosts: TaggedHost[], domain: string): TaggedHost[] {
  const d = domain.toLowerCase()
  const named = hosts.filter((h) => h.kind !== 'ip' && (h.domain.toLowerCase() === d || h.value.toLowerCase() === d))
  const ips = new Set(named.flatMap((h) => h.ips ?? []))
  return hosts.filter((h) => named.includes(h) || (h.kind === 'ip' && ips.has(h.value)))
}

const recurrenceLabel = (d: CompanyDomain, offLabel: string) => {
  const s = d.schedule
  if (!s || !s.enabled) return offLabel
  if (s.interval_hours === 24) return '24h'
  if (s.interval_hours === 168) return '7d'
  return `${s.interval_hours}h`
}

function GradeBadge({ grade }: { grade: string | null }) {
  return (
    <span className={clsx(
      'text-xs px-2 py-0.5 rounded-full font-semibold border inline-block w-8 text-center',
      gradeChipColor(grade),
    )}>
      {grade ?? '—'}
    </span>
  )
}

function CompaniesTable({ companies, search, onOpenCompany }: {
  companies: Company[]
  search: string
  onOpenCompany: (company: Company) => void
}) {
  const { t } = useTranslation()
  const q = search.trim().toLowerCase()
  const rows = companies.filter((c) => !q || c.name.toLowerCase().includes(q))
  return (
    <table className="w-full">
      <thead>
        <tr>
          <th className={th}>{t('dashboard.table.company')}</th>
          <th className={th}>{t('dashboard.table.domains')}</th>
          <th className={th}>{t('dashboard.table.lastGrade')}</th>
          <th className={th}>{t('dashboard.table.lastScan')}</th>
        </tr>
      </thead>
      <tbody className="divide-y divide-dark-800">
        {rows.length === 0 ? (
          <tr>
            <td colSpan={4} className="px-3 py-8 text-center text-dark-500 text-sm">
              {q ? t('dashboard.noResults') : t('dashboard.noCompaniesYet')}
            </td>
          </tr>
        ) : rows.map((c) => {
          const lastScanned = c.domains
            .filter((d) => d.last_scan_at)
            .sort((a, b) => (b.last_scan_at ?? '').localeCompare(a.last_scan_at ?? ''))[0]
          return (
            <tr
              key={c.id}
              onClick={() => onOpenCompany(c)}
              className="hover:bg-dark-800/40 cursor-pointer"
              title={t('dashboard.openDashboardTitle', { name: c.name })}
            >
              <td className="px-3 py-2">
                <span className="text-cyber-700 font-semibold break-all">{c.name}</span>
              </td>
              <td className={td}>{c.domains.length}</td>
              <td className={td}><GradeBadge grade={lastScanned?.last_grade ?? null} /></td>
              <td className={clsx(td, 'whitespace-nowrap')} title={lastScanned?.last_scan_at ?? undefined}>
                {lastScanned?.last_scan_at ? fmtShort(lastScanned.last_scan_at) : '—'}
              </td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}

function DomainsTable({ companies, search, showCompany, activeDomain, onSelectDomain }: {
  companies: Company[]
  search: string
  showCompany: boolean
  activeDomain: string
  onSelectDomain: (companyName: string, domain: string) => void
}) {
  const { t } = useTranslation()
  const q = search.trim().toLowerCase()
  const rows = companies
    .flatMap((c) => c.domains.map((d) => ({ ...d, company: c.name })))
    .filter((d) => !q || d.domain.toLowerCase().includes(q))
  return (
    <table className="w-full">
      <thead>
        <tr>
          <th className={th}>{t('dashboard.table.domain')}</th>
          {showCompany && <th className={th}>{t('dashboard.table.company')}</th>}
          <th className={th}>{t('dashboard.table.grade')}</th>
          <th className={th}>{t('dashboard.table.lastScan')}</th>
          <th className={th}>{t('dashboard.table.recurrence')}</th>
        </tr>
      </thead>
      <tbody className="divide-y divide-dark-800">
        {rows.length === 0 ? (
          <tr>
            <td colSpan={showCompany ? 5 : 4} className="px-3 py-8 text-center text-dark-500 text-sm">
              {q ? t('dashboard.noResults') : t('dashboard.noDomainsYet')}
            </td>
          </tr>
        ) : rows.map((d) => (
          <tr
            key={`${d.company}:${d.id}`}
            onClick={(e) => {
              if ((e.target as HTMLElement).closest('a')) return
              onSelectDomain(d.company, d.domain)
            }}
            title={t('dashboard.filterToDomainTitle', { name: d.domain })}
            className={clsx('cursor-pointer', activeDomain === d.domain ? 'bg-cyber-50' : 'hover:bg-dark-800/40')}
          >
            <LinkValueCell
              asset={{ value: d.domain, first_seen: d.created_at, last_seen: d.last_scan_at ?? d.created_at, is_new: false }}
              href={`https://${d.domain}`}
            />
            {showCompany && <td className={clsx(td, 'whitespace-nowrap')}>{d.company}</td>}
            <td className={td}><GradeBadge grade={d.last_grade} /></td>
            <td className={clsx(td, 'whitespace-nowrap')} title={d.last_scan_at ?? undefined}>
              {d.last_scan_at ? fmtShort(d.last_scan_at) : t('common.neverScanned')}
            </td>
            <td className={td}>
              <span className={clsx(
                'text-[10px] px-1.5 py-0.5 rounded-full font-semibold border whitespace-nowrap',
                d.schedule?.enabled
                  ? 'bg-cyan-50 text-cyan-700 border-cyan-200'
                  : 'bg-dark-900 text-dark-500 border-dark-800',
              )}>
                {recurrenceLabel(d, t('dashboard.recurrenceOff'))}
              </span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

const DIFF_ORDER: AssetCategory[] = [
  'subdomains', 'ips', 'ports', 'endpoints', 'technologies', 'admin_panels', 'exposed_files',
  'apps', 'neighbors',
]

const fmtDiffValue = (v: unknown): string => {
  if (v == null) return '—'
  if (typeof v === 'string') return v
  return JSON.stringify(v)
}

function CompanyTag({ name }: { name: string }) {
  return (
    <span className="ml-1.5 text-[10px] px-1.5 py-0.5 rounded-full font-semibold font-sans border bg-cyan-50 text-cyan-700 border-cyan-200 whitespace-nowrap">
      {name}
    </span>
  )
}

function GlobalDiffValueList({ entries, kind, showCompany = true }: {
  entries: { value: string; company: string }[]
  kind: 'added' | 'removed'
  showCompany?: boolean
}) {
  const { t } = useTranslation()
  if (entries.length === 0) {
    return <p className="text-xs text-dark-600 italic">{t('dashboard.none')}</p>
  }
  return (
    <ul className="space-y-1">
      {entries.map((e, i) => (
        <li
          key={`${e.company}:${e.value}:${i}`}
          className={clsx(
            'text-xs break-all px-2 py-1.5 rounded-lg border font-mono',
            kind === 'added'
              ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
              : 'bg-red-50 border-red-200 text-red-800',
          )}
        >
          {kind === 'added' ? '+ ' : '− '}{e.value}
          {showCompany && <CompanyTag name={e.company} />}
        </li>
      ))}
    </ul>
  )
}

function GlobalDiffModifiedList({ entries, showCompany = true }: { entries: GlobalModifiedEntry[]; showCompany?: boolean }) {
  const { t } = useTranslation()
  if (entries.length === 0) {
    return <p className="text-xs text-dark-600 italic">{t('dashboard.none')}</p>
  }
  return (
    <ul className="space-y-1">
      {entries.map((e, i) => (
        <li
          key={`${e.company}:${e.value}:${e.field}:${i}`}
          className="text-xs break-all px-2 py-1.5 rounded-lg border bg-amber-50 border-amber-200 text-amber-800 font-mono"
        >
          {e.value} — {e.field}: {fmtDiffValue(e.old)} → {fmtDiffValue(e.new)}
          {showCompany && <CompanyTag name={e.company} />}
        </li>
      ))}
    </ul>
  )
}

function ScoreChangeList({ changes }: { changes: CompanyScoreChange[] }) {
  const { t } = useTranslation()
  if (changes.length === 0) {
    return <span className="text-dark-500 text-xs">{t('dashboard.noScoreData')}</span>
  }
  return (
    <ul className="flex flex-wrap items-center gap-x-4 gap-y-2">
      {changes.map((sc) => {
        const delta = sc.delta ?? null
        return (
          <li key={sc.company} className="flex items-center gap-2 text-sm">
            <span className="text-xs font-semibold text-dark-200">{sc.company}</span>
            <span className={clsx('px-2 py-0.5 rounded-full border text-xs', gradeChipColor(sc.from_grade))}>
              {sc.from_grade ?? '—'}
            </span>
            <span className="text-dark-500">→</span>
            <span className={clsx('px-2 py-0.5 rounded-full border text-xs', gradeChipColor(sc.to_grade))}>
              {sc.to_grade ?? '—'}
            </span>
            {delta != null && (
              <span className={clsx(
                'text-xs font-semibold inline-flex items-center gap-1 font-mono',
                delta > 0 ? 'text-emerald-600' : delta < 0 ? 'text-red-600' : 'text-dark-400',
              )}>
                {delta > 0 ? <TrendingUp className="w-3.5 h-3.5" /> : delta < 0 ? <TrendingDown className="w-3.5 h-3.5" /> : null}
                {delta > 0 ? `+${delta}` : delta < 0 ? `${delta}` : '± 0'}
              </span>
            )}
          </li>
        )
      })}
    </ul>
  )
}

function PeriodFindingList({ items, total, showCompany }: { items: PeriodFinding[]; total: number; showCompany: boolean }) {
  const { t } = useTranslation()
  const [showAll, setShowAll] = useState(false)
  const shown = showAll ? items : items.slice(0, 25)
  return (
    <div className="space-y-1.5">
      <ul className="divide-y divide-dark-800">
        {shown.map((f, i) => (
          <li key={`${f.company}:${f.domain}:${f.module}:${i}`} className="py-1.5 flex items-start gap-2">
            <RiskBadge risk={(['critical', 'high', 'medium', 'low', 'info'].includes(f.risk) ? f.risk : 'low') as 'critical' | 'high' | 'medium' | 'low' | 'info'} />
            <span className="text-[10px] px-1.5 py-0.5 rounded-full border bg-dark-900 text-dark-500 border-dark-700 font-mono whitespace-nowrap">{f.module}</span>
            <span className="text-xs text-dark-200 flex-1 min-w-0 break-words">
              <LinkifyText text={f.text} baseUrl={`https://${f.domain}`} />
              <span className="text-dark-500"> — {showCompany && f.company ? `${f.company} · ` : ''}{f.domain}</span>
            </span>
          </li>
        ))}
      </ul>
      {(items.length > 25 || total > items.length) && (
        <div className="flex items-center gap-3 text-[11px] text-dark-500">
          <span>{t('dashboard.showingOf', { shown: shown.length, total })}</span>
          {items.length > 25 && (
            <button onClick={() => setShowAll((o) => !o)} className="text-cyber-700 hover:underline">
              {showAll ? '−' : '+'}
            </button>
          )}
        </div>
      )}
    </div>
  )
}

function PeriodFindingsSection({ diff, showCompany }: { diff: GlobalAssetsDiff; showCompany: boolean }) {
  const { t } = useTranslation()
  const fresh = diff.findings_new ?? []
  const resolved = diff.findings_resolved ?? []
  if (fresh.length === 0 && resolved.length === 0) {
    return <p className="text-xs text-dark-500">{t('dashboard.noFindingChanges')}</p>
  }
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <div className="space-y-1">
        <div className="text-xs font-semibold text-red-700">{t('dashboard.newFindings', { count: diff.findings_new_total ?? fresh.length })}</div>
        <PeriodFindingList items={fresh} total={diff.findings_new_total ?? fresh.length} showCompany={showCompany} />
      </div>
      <div className="space-y-1">
        <div className="text-xs font-semibold text-emerald-700">{t('dashboard.resolvedFindings', { count: diff.findings_resolved_total ?? resolved.length })}</div>
        <PeriodFindingList items={resolved} total={diff.findings_resolved_total ?? resolved.length} showCompany={showCompany} />
      </div>
    </div>
  )
}

function GlobalDiffResult({ diff, showCompany = true }: { diff: GlobalAssetsDiff; showCompany?: boolean }) {
  const { t } = useTranslation()
  const categories = DIFF_ORDER.filter(
    (c) => (diff.added?.[c]?.length ?? 0) > 0
      || (diff.removed?.[c]?.length ?? 0) > 0
      || (diff.modified?.[c]?.length ?? 0) > 0,
  )
  const totals = DIFF_ORDER.reduce(
    (acc, c) => ({
      added: acc.added + (diff.added?.[c]?.length ?? 0),
      removed: acc.removed + (diff.removed?.[c]?.length ?? 0),
      modified: acc.modified + (diff.modified?.[c]?.length ?? 0),
    }),
    { added: 0, removed: 0, modified: 0 },
  )

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <span className="text-xs text-dark-500 uppercase tracking-wider font-semibold">{t('dashboard.scoreChangeByCompany')}</span>
        <ScoreChangeList changes={diff.score_changes} />
      </div>

      {/* Asset delta summary — discovered/removed/modified totals per category */}
      <div className="space-y-2">
        <span className="text-xs text-dark-500 uppercase tracking-wider font-semibold">{t('dashboard.assetDeltaSummary')}</span>
        <div className="flex flex-wrap items-center gap-2">
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full border bg-emerald-50 border-emerald-200 text-emerald-700 text-xs font-semibold font-mono">
            +{totals.added} {t('dashboard.deltaDiscovered')}
          </span>
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full border bg-red-50 border-red-200 text-red-700 text-xs font-semibold font-mono">
            −{totals.removed} {t('dashboard.deltaRemoved')}
          </span>
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full border bg-amber-50 border-amber-200 text-amber-700 text-xs font-semibold font-mono">
            ~{totals.modified} {t('dashboard.deltaModified')}
          </span>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {categories.map((c) => {
            const a = diff.added?.[c]?.length ?? 0
            const r = diff.removed?.[c]?.length ?? 0
            const m = diff.modified?.[c]?.length ?? 0
            return (
              <span key={c} className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-dark-900 text-[11px] text-dark-300">
                {t(`dashboard.categories.${c}`)}
                <span className="font-mono">
                  {a > 0 && <span className="text-emerald-600">+{a}</span>}
                  {a > 0 && (r > 0 || m > 0) && ' '}
                  {r > 0 && <span className="text-red-600">−{r}</span>}
                  {r > 0 && m > 0 && ' '}
                  {m > 0 && <span className="text-amber-600">~{m}</span>}
                </span>
              </span>
            )
          })}
        </div>
      </div>

      <PeriodFindingsSection diff={diff} showCompany={showCompany} />

      {diff.skipped_companies.length > 0 && (
        <p className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">
          {t('dashboard.skipped', { names: diff.skipped_companies.join(', ') })}
        </p>
      )}

      {categories.length === 0 ? (
        <p className="text-sm text-dark-500 text-center py-6">
          {t('dashboard.noChanges')}
        </p>
      ) : (
        categories.map((c) => (
          <div key={c}>
            <h4 className="text-xs font-semibold text-dark-500 uppercase tracking-wider mb-2">
              {t(`dashboard.categories.${c}`)}
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="space-y-1">
                <div className="text-xs font-semibold text-emerald-700">
                  {t('dashboard.added', { count: diff.added?.[c]?.length ?? 0 })}
                </div>
                <GlobalDiffValueList entries={diff.added?.[c] ?? []} kind="added" showCompany={showCompany} />
              </div>
              <div className="space-y-1">
                <div className="text-xs font-semibold text-red-700">
                  {t('dashboard.removed', { count: diff.removed?.[c]?.length ?? 0 })}
                </div>
                <GlobalDiffValueList entries={diff.removed?.[c] ?? []} kind="removed" showCompany={showCompany} />
              </div>
              <div className="space-y-1">
                <div className="text-xs font-semibold text-amber-700 inline-flex items-center gap-1">
                  <Pencil className="w-3 h-3" /> {t('dashboard.modified', { count: diff.modified?.[c]?.length ?? 0 })}
                </div>
                <GlobalDiffModifiedList entries={diff.modified?.[c] ?? []} showCompany={showCompany} />
              </div>
            </div>
          </div>
        ))
      )}
    </div>
  )
}

export default function GlobalDashboard({ onGoToCompanies, onOpenCompany, lockedCompany, onOpenCompanyReport, onOpenRemediation, onBack, readOnly = false }: Props) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const locked = lockedCompany ?? null
  const [companies, setCompanies] = useState<Company[]>([])
  const [loaded, setLoaded] = useState<{ company: Company; data: CompanyAssets }[]>([])
  const [loadedHosts, setLoadedHosts] = useState<{ company: Company; data: CompanyHosts }[]>([])
  const [failedCompanies, setFailedCompanies] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [partialErrorDismissed, setPartialErrorDismissed] = useState(false)
  const [category, setCategory] = useState<GlobalCategory>('hosts')
  const [search, setSearch] = useState('')
  const [companyFilter, setCompanyFilter] = useState(locked ? String(locked.id) : '')
  const [scanInProgress, setScanInProgress] = useState(false)
  // Domain filter: scoped to the company it was picked in, so switching company drops it
  const [domainSel, setDomainSel] = useState<{ companyId: number; domain: string } | null>(null)
  // Node picked on the node map: narrows the host list to that host, or to every
  // host resolving to that IP (across companies when none is filtered — the shared-IP case)
  const [nodeFocus, setNodeFocus] = useState<{ kind: 'host' | 'ip' | 'ipset'; value: string; company?: string; values?: string[] } | null>(null)

  // Compare mode (aggregated across companies)
  const [compareMode, setCompareMode] = useState(false)
  const isoDay = (d: Date) => d.toISOString().slice(0, 10)
  const daysAgo = (n: number) => isoDay(new Date(Date.now() - n * 86_400_000))
  const [fromDate, setFromDate] = useState(daysAgo(7))
  const [toDate, setToDate] = useState(isoDay(new Date()))
  const [diff, setDiff] = useState<GlobalAssetsDiff | null>(null)
  const [diffLoading, setDiffLoading] = useState(false)
  const [diffError, setDiffError] = useState('')
  const [addAppOpen, setAddAppOpen] = useState(false)
  // Optional visualization, toggled in Settings
  const [constellationOn, setConstellationOn] = useState(false)
  useEffect(() => {
    axios.get<{ constellation_enabled?: boolean }>('/api/settings')
      .then(({ data }) => setConstellationOn(data.constellation_enabled === true))
      .catch(() => setConstellationOn(false))
  }, [])

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    try {
      const limited = locked
        ? [locked]
        : (await axios.get<Company[]>('/api/companies')).data.slice(0, MAX_COMPANIES)
      setCompanies(limited)
      setError('')

      const results = await Promise.allSettled(
        limited.map(async (company) => {
          const { data } = await axios.get<CompanyAssets>(`/api/companies/${company.id}/assets`)
          return { company, data }
        }),
      )
      const ok: { company: Company; data: CompanyAssets }[] = []
      const failed: string[] = []
      results.forEach((r, i) => {
        if (r.status === 'fulfilled') ok.push(r.value)
        else failed.push(limited[i].name)
      })
      setLoaded(ok)
      setFailedCompanies(failed)
      if (failed.length > 0) setPartialErrorDismissed(false)

      // Host-centric view — independent failure path: a /hosts outage must not
      // blank the legacy inventory above (the table just falls back to empty).
      const hostResults = await Promise.allSettled(
        limited.map(async (company) => {
          const { data } = await axios.get<CompanyHosts>(`/api/companies/${company.id}/hosts`)
          return { company, data }
        }),
      )
      setLoadedHosts(hostResults
        .filter((r): r is PromiseFulfilledResult<{ company: Company; data: CompanyHosts }> => r.status === 'fulfilled')
        .map((r) => r.value))
    } catch (err) {
      setError(errorMessage(err, t('dashboard.loadError')))
    } finally {
      if (!silent) setLoading(false)
    }
    // locked identity is stable for the lifetime of this mounted view
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [locked?.id])

  useEffect(() => { load() }, [load])

  // Live refresh: while any known domain has a queued/running scan,
  // reload all inventories every 10s. No polling when nothing is active.
  useEffect(() => {
    const domainNames = new Set(companies.flatMap((c) => c.domains.map((d) => d.domain)))
    if (domainNames.size === 0) return
    let timer: ReturnType<typeof setInterval> | null = null
    let cancelled = false

    const checkActiveScans = async (): Promise<boolean> => {
      try {
        const { data: scans } = await axios.get<ScanListItem[]>('/api/scans')
        if (cancelled) return false
        const active = scans.some(
          (s) => domainNames.has(s.domain) && (s.status === 'running' || s.status === 'queued'),
        )
        setScanInProgress(active)
        return active
      } catch {
        return false
      }
    }

    const tick = async () => {
      const active = await checkActiveScans()
      if (cancelled) return
      if (active) {
        load(true)
      } else if (timer) {
        clearInterval(timer)
        timer = null
        load(true) // final refresh to pick up the completed scan's assets
      }
    }

    checkActiveScans().then((active) => {
      if (cancelled || !active) return
      timer = setInterval(tick, 10000)
    })

    return () => {
      cancelled = true
      if (timer) clearInterval(timer)
    }
  }, [companies, load])

  const totals = emptyTotals()
  for (const { data } of loaded) {
    for (const key of SUMMARY_KEYS) {
      totals[key] = (totals[key] ?? 0) + (data.summary?.[key] ?? 0)
    }
  }

  const assets = mergeInventories(loaded)
  const allHosts: TaggedHost[] = loadedHosts.flatMap(({ company, data }) =>
    (data.hosts ?? []).map((h) => ({ ...h, company: company.name, companyId: company.id })),
  )
  const selectedCompany = companies.find((c) => String(c.id) === companyFilter) ?? null
  // Single-company context: locked (from Companies view) or selected via dropdown
  const activeCompany = locked ?? selectedCompany
  const activeDomain = domainSel && String(domainSel.companyId) === companyFilter ? domainSel.domain : ''
  const visibleAssets = filterByDomain(filterByCompany(assets, selectedCompany?.name ?? null), activeDomain)
  const companyHosts = selectedCompany
    ? allHosts.filter((h) => h.company === selectedCompany.name)
    : allHosts
  const scopedHosts = activeDomain ? filterHostsByDomain(companyHosts, activeDomain) : companyHosts
  // A node belongs to the scope it was picked in: changing company/domain drops it
  useEffect(() => { setNodeFocus(null) }, [companyFilter, activeDomain])
  // The map keeps drawing the scope (not the focused subset), so other nodes stay clickable
  const visibleHosts = nodeFocus
    ? scopedHosts.filter((h) => {
        if (nodeFocus.kind === 'host') return h.value === nodeFocus.value && h.company === nodeFocus.company
        const wanted = nodeFocus.kind === 'ipset' ? nodeFocus.values ?? [] : [nodeFocus.value]
        return h.kind === 'ip' ? wanted.includes(h.value) : (h.ips ?? []).some((ip) => wanted.includes(ip))
      })
    : scopedHosts
  // The host table sits below the map, often off-screen: bring it into view after a node click
  const hostsCardRef = useRef<HTMLDivElement | null>(null)
  const revealHosts = () => {
    setTimeout(() => hostsCardRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 60)
  }
  const selectDomain = (companyName: string, domain: string) => {
    const c = companies.find((x) => x.name === companyName)
    if (!c) return
    setCompanyFilter(String(c.id))
    setDomainSel({ companyId: c.id, domain })
    setNodeFocus(null)
    revealHosts()
  }
  const selectCompanyByName = (companyName: string) => {
    const c = companies.find((x) => x.name === companyName)
    if (!c) return
    setCompanyFilter(String(c.id))
    setDomainSel(null)
    setNodeFocus(null)
    revealHosts()
  }
  const showHostList = () => { if (!HOST_FILTERS.has(category)) setCategory('hosts') }
  const selectHostNode = (host: string, companyName: string) => {
    setNodeFocus({ kind: 'host', value: host, company: companyName })
    showHostList()
    revealHosts()
  }
  // Header chips toggle: a second click on the active one clears it
  const selectIpGroup = (group: IpGroup, ips: string[]) => {
    if (nodeFocus?.kind === 'ipset' && nodeFocus.value === group) {
      setNodeFocus(null)
      return
    }
    setNodeFocus({ kind: 'ipset', value: group, values: ips })
    showHostList()
    revealHosts()
  }
  // "Clear filters" on the map: everything a node click can have set
  const clearFilters = () => {
    setNodeFocus(null)
    setDomainSel(null)
    if (!locked) setCompanyFilter('')
  }
  const selectIpNode = (ip: string) => {
    setNodeFocus({ kind: 'ip', value: ip })
    showHostList()
    revealHosts()
  }
  const isHostView = HOST_FILTERS.has(category)
  const filteredCompanies = selectedCompany ? [selectedCompany] : companies

  const visibleTotal =
    visibleAssets.subdomains.length + visibleAssets.ips.length + visibleAssets.endpoints.length
    + visibleAssets.technologies.length + visibleAssets.admin_panels.length + visibleAssets.exposed_files.length
    + (visibleAssets.apps?.length ?? 0) + (visibleAssets.neighbors?.length ?? 0)
    + (visibleAssets.ports?.length ?? 0)

  const totalAssets =
    assets.subdomains.length + assets.ips.length + assets.endpoints.length
    + assets.technologies.length + assets.admin_panels.length + assets.exposed_files.length
    + (assets.apps?.length ?? 0) + (assets.neighbors?.length ?? 0)

  // Real per-category "new" counts, derived from the is_new flags of the
  // actual rows shown in the tables (the badge must match what you see).
  const countNew = (rows?: { is_new?: boolean }[]) => (rows ?? []).filter((r) => r.is_new).length
  const newByCategory: Record<string, number> = {
    hosts: countNew(visibleHosts),
    subdomains: countNew(visibleAssets.subdomains),
    ips: countNew(visibleAssets.ips),
    endpoints: countNew(visibleAssets.endpoints),
    technologies: countNew(visibleAssets.technologies),
    admin_panels: countNew(visibleAssets.admin_panels),
    exposed_files: countNew(visibleAssets.exposed_files),
    apps: countNew(visibleAssets.apps),
    neighbors: countNew(visibleAssets.neighbors),
    ports: countNew(visibleAssets.ports),
  }

  // Suspicious apps pending review, per company in scope (drives the bulk
  // "reject all suspicious" action in the Apps section header)
  const bulkReviewTargets = loaded
    .filter(({ company }) => !selectedCompany || company.id === selectedCompany.id)
    .map(({ company, data }) => ({
      company,
      suspicious: (data.assets?.apps ?? []).filter((a) => a.suspicious).length,
    }))
    .filter((x) => x.suspicious > 0)
  // The button count must match the rows on screen: the Apps table dedupes by
  // store:value (same app discovered under several domains/companies shows
  // once), so count suspicious among the SAME deduped row set. Derived from
  // visibleAssets → recomputed from live data after every load/reject.
  const seenAppKeys = new Set<string>()
  const suspiciousAppCount = (visibleAssets.apps ?? []).filter((a) => {
    const key = `${a.store}:${a.value}`
    if (seenAppKeys.has(key)) return false
    seenAppKeys.add(key)
    return true
  }).filter((a) => a.suspicious).length

  const rejectAllSuspicious = async () => {
    if (!confirm(t('assets.rejectAllSuspiciousConfirm', { count: suspiciousAppCount }))) return
    try {
      let deleted = 0
      for (const { company } of bulkReviewTargets) {
        const { data } = await axios.post<{ deleted: number }>(
          `/api/companies/${company.id}/assets/review-bulk`,
          { type: 'app', action: 'reject', only_suspicious: true },
        )
        deleted += data.deleted
      }
      alert(t('assets.rejectAllSuspiciousDone', { count: deleted }))
      load(true)
    } catch (err) {
      alert(t('assets.reviewError', { msg: errorMessage(err, t('common.unknownError')) }))
    }
  }

  // Per-module rescan: one module scan per domain in scope (the queue
  // serializes them). Single domain → straight to the progress page;
  // several → confirm, enqueue each, land on History.
  const [rescanning, setRescanning] = useState(false)
  const scopeDomains = filteredCompanies.flatMap((c) => c.domains)

  const rescanModule = async (module: string) => {
    const targets = scopeDomains.map((d) => d.domain)
    if (!targets.length || rescanning) return
    if (targets.length > 1 && !window.confirm(t('dashboard.rescanModuleConfirmMulti', { count: targets.length }))) return
    setRescanning(true)
    try {
      let firstId: string | null = null
      for (const domain of targets) {
        const { data } = await axios.post('/api/scan', { domain, modules: [module] })
        firstId = firstId ?? data.scan_id
      }
      navigate(targets.length === 1 && firstId ? `/scanning/${firstId}` : '/history')
    } catch (err) {
      setError(errorMessage(err, t('dashboard.rescanModuleError')))
      setRescanning(false)
    }
  }

  // Cards reflect the selected company when filtered, global totals otherwise
  const cardTotals = selectedCompany || activeDomain
    ? {
        domains: activeDomain ? 1 : filteredCompanies.flatMap((c) => c.domains).length,
        subdomains: visibleAssets.subdomains.length,
        ips: visibleAssets.ips.length,
        endpoints: visibleAssets.endpoints.length,
        technologies: visibleAssets.technologies.length,
        admin_panels: visibleAssets.admin_panels.length,
        exposed_files: visibleAssets.exposed_files.length,
        apps: visibleAssets.apps?.length ?? 0,
        neighbors: visibleAssets.neighbors?.length ?? 0,
        open_ports: visibleAssets.ports?.length ?? 0,
      }
    : totals

  const toggleCompareMode = () => {
    setCompareMode((prev) => !prev)
    setDiff(null)
    setDiffError('')
  }

  // Keep the compare scan list in sync with the company filter
  useEffect(() => {
    if (compareMode) {
      setDiff(null)
      setDiffError('')
    }
  }, [companyFilter]) // eslint-disable-line react-hooks/exhaustive-deps

  const applyPreset = (days: number) => {
    setFromDate(daysAgo(days))
    setToDate(isoDay(new Date()))
  }

  const handleCompare = async () => {
    if (!fromDate || !toDate) return
    if (fromDate > toDate) {
      setDiffError(t('dashboard.dateRangeInvalid'))
      return
    }
    setDiffLoading(true)
    setDiff(null)
    setDiffError('')
    const targets = selectedCompany ? [selectedCompany] : companies
    const results = await Promise.allSettled(
      targets.map(async (c) => {
        const { data } = await axios.get<PeriodChanges>(`/api/companies/${c.id}/changes`, {
          params: { from: fromDate, to: toDate },
        })
        return { company: c.name, data }
      }),
    )
    const merged: GlobalAssetsDiff = {
      from_scan_at: null,
      to_scan_at: null,
      scans_in_period: 0,
      findings_new: [],
      findings_resolved: [],
      findings_new_total: 0,
      findings_resolved_total: 0,
      added: {},
      removed: {},
      modified: {},
      score_changes: [],
      skipped_companies: [],
    }
    for (const r of results) {
      if (r.status === 'rejected') continue
      const { company, data: d } = r.value
      merged.from_scan_at = merged.from_scan_at ?? d.from_scan_at ?? null
      merged.to_scan_at = merged.to_scan_at ?? d.to_scan_at ?? null
      merged.scans_in_period = (merged.scans_in_period ?? 0) + (d.scans_in_period?.count ?? 0)
      for (const f of d.findings?.new ?? []) merged.findings_new!.push({ ...f, company })
      for (const f of d.findings?.resolved ?? []) merged.findings_resolved!.push({ ...f, company })
      merged.findings_new_total! += d.findings?.new_total ?? 0
      merged.findings_resolved_total! += d.findings?.resolved_total ?? 0
      for (const cat of DIFF_ORDER) {
        for (const v of d.added?.[cat] ?? []) {
          (merged.added[cat] ??= []).push({ value: v, company })
        }
        for (const v of d.removed?.[cat] ?? []) {
          (merged.removed[cat] ??= []).push({ value: v, company })
        }
        for (const e of d.modified?.[cat] ?? []) {
          (merged.modified[cat] ??= []).push({ ...e, company })
        }
      }
      merged.score_changes.push({
        company,
        from_grade: d.score_change?.from_grade ?? null,
        to_grade: d.score_change?.to_grade ?? null,
        delta: d.score_change?.delta ?? null,
      })
    }
    merged.skipped_companies = results
      .map((r, i) => (r.status === 'rejected' ? targets[i].name : null))
      .filter((n): n is string => n != null)
    setDiffLoading(false)
    if (merged.score_changes.length === 0) {
      const rejected = results.find((r) => r.status === 'rejected')
      const detail = rejected && axios.isAxiosError(rejected.reason) && [400, 409].includes(rejected.reason.response?.status ?? 0)
        ? rejected.reason.response?.data?.detail
        : null
      setDiffError(detail || t('dashboard.diffError'))
      return
    }
    setDiff(merged)
  }

  const allCards: {
    key: string
    label: string
    icon: LucideIcon | null
    count: number
    selectable: GlobalCategory | null
  }[] = [
    { key: 'hosts', label: t('dashboard.categories.hosts'), icon: null, count: visibleHosts.length, selectable: 'hosts' },
    { key: 'companies', label: t('dashboard.categories.companies'), icon: null, count: filteredCompanies.length, selectable: 'companies' },
    { key: 'domains', label: t('dashboard.categories.domains'), icon: null, count: cardTotals.domains, selectable: 'domains' },
    { key: 'subdomains', label: t('dashboard.categories.subdomains'), icon: null, count: cardTotals.subdomains, selectable: 'subdomains' },
    { key: 'ips', label: t('dashboard.categories.ips'), icon: null, count: cardTotals.ips, selectable: 'ips' },
    { key: 'endpoints', label: t('dashboard.categories.endpoints'), icon: null, count: cardTotals.endpoints, selectable: 'endpoints' },
    { key: 'technologies', label: t('dashboard.categories.technologies'), icon: null, count: cardTotals.technologies, selectable: 'technologies' },
    { key: 'apps', label: t('dashboard.categories.apps'), icon: Smartphone, count: cardTotals.apps ?? 0, selectable: 'apps' },
    { key: 'neighbors', label: t('dashboard.categories.neighbors'), icon: Network, count: cardTotals.neighbors ?? 0, selectable: 'neighbors' },
    { key: 'admin_panels', label: t('dashboard.categories.admin_panels'), icon: null, count: cardTotals.admin_panels, selectable: 'admin_panels' },
    { key: 'exposed_files', label: t('dashboard.categories.exposed_files'), icon: null, count: cardTotals.exposed_files, selectable: 'exposed_files' },
    { key: 'open_ports', label: t('dashboard.categories.ports'), icon: null, count: cardTotals.open_ports, selectable: 'ports' },
  ]
  const cards = allCards.filter((c) => !locked || (c.key !== 'companies' && c.key !== 'domains'))

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-3">
        {locked && onBack && (
          <button onClick={onBack} className="btn-secondary">
            <ArrowLeft className="w-3.5 h-3.5" />
            {t('nav.companies')}
          </button>
        )}
        <div className="flex-1 min-w-[200px]">
          <h2 className="text-xl font-semibold tracking-tight text-dark-100">
            {locked ? t('dashboard.lockedTitle', { name: locked.name }) : t('dashboard.globalTitle')}
          </h2>
          <div className="text-xs text-dark-500">
            {locked
              ? t('dashboard.domainsTracked', { count: locked.domains.length })
              : t('dashboard.aggregated', { count: companies.length })}
            {' · '}
            {t('dashboard.assetsCount', { count: visibleTotal })}
          </div>
          {scanInProgress && (
            <div className="flex items-center gap-2 text-xs text-red-600 mt-0.5 font-medium">
              <span className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />
              {t('dashboard.live')}
            </div>
          )}
        </div>
        {/* Company actions: available when a single company is in context
            (locked from Companies view OR selected in the dropdown) */}
        {activeCompany && onOpenCompanyReport && (
          <button onClick={() => onOpenCompanyReport(activeCompany)} className="btn-secondary">
            <FileText className="w-3.5 h-3.5" />
            {t('dashboard.report')}
          </button>
        )}
        {activeCompany && onOpenRemediation && (
          <button onClick={() => onOpenRemediation(activeCompany)} className="btn-secondary">
            <ClipboardCheck className="w-3.5 h-3.5" />
            {t('dashboard.remediation')}
          </button>
        )}
        <button
          onClick={() => downloadFromApi('/api/companies/assets/export/all?format=csv', 'all_assets.csv')}
          className="btn-secondary"
          title={t('dashboard.exportAllCsv')}
        >
          <Download className="w-3.5 h-3.5" />
          {t('dashboard.exportAllCsv')}
        </button>
        <button
          onClick={toggleCompareMode}
          className={clsx(
            'text-xs px-3 py-1.5 border rounded-lg transition-colors duration-150 inline-flex items-center gap-1.5',
            compareMode
              ? 'bg-cyber-50 border-cyber-400 text-cyber-700 font-medium'
              : 'bg-white hover:bg-dark-900 border-dark-700 text-dark-200',
          )}
        >
          <ArrowLeftRight className="w-3.5 h-3.5" />
          {t('dashboard.compare')}
        </button>
        {activeCompany && (
          <>
            <button
              onClick={() => downloadFromApi(`/api/companies/${activeCompany.id}/assets/export?format=csv`, `${activeCompany.name}_assets.csv`)}
              className="btn-secondary"
            >
              <Download className="w-3.5 h-3.5" />
              CSV
            </button>
            <button
              onClick={() => downloadFromApi(`/api/companies/${activeCompany.id}/assets/export?format=json`, `${activeCompany.name}_assets.json`)}
              className="btn-secondary"
            >
              <Download className="w-3.5 h-3.5" />
              JSON
            </button>
          </>
        )}
        <button
          onClick={() => load()}
          disabled={loading}
          className="btn-secondary disabled:cursor-wait"
        >
          <RefreshCw className={clsx('w-3.5 h-3.5', loading && 'animate-spin')} />
          {loading ? t('dashboard.refreshing') : t('dashboard.refresh')}
        </button>
      </div>

      {/* Filters — always visible under the header */}
      {companies.length > 0 && (
        <div className="card flex flex-wrap items-center gap-3 py-3">
          {locked ? (
            <span className="chip bg-cyan-50 text-cyan-700 border-cyan-200">{locked.name}</span>
          ) : selectedCompany ? (
            <span className="chip bg-cyan-50 text-cyan-700 border-cyan-200 inline-flex items-center gap-1.5">
              {selectedCompany.name}
              <button
                onClick={() => setCompanyFilter('')}
                className="hover:text-cyan-900 transition-colors"
                title={t('dashboard.clearCompanyFilter')}
              >
                <X className="w-3 h-3" />
              </button>
            </span>
          ) : null}
          {activeDomain && (
            <span className="chip bg-violet-50 text-violet-700 border-violet-200 inline-flex items-center gap-1.5 font-mono">
              {activeDomain}
              <button
                onClick={() => setDomainSel(null)}
                className="hover:text-violet-900 transition-colors"
                title={t('dashboard.clearDomainFilter')}
              >
                <X className="w-3 h-3" />
              </button>
            </span>
          )}
          {nodeFocus && (
            <span className="chip bg-fuchsia-50 text-fuchsia-700 border-fuchsia-200 inline-flex items-center gap-1.5 font-mono">
              {nodeFocus.kind === 'ip' ? t('dashboard.nodeFilterIp', { value: nodeFocus.value })
                : nodeFocus.kind === 'ipset'
                  ? t(`nodeMap.${nodeFocus.value === 'cross' ? 'crossIps' : nodeFocus.value === 'shared' ? 'sharedIps' : 'providerIps'}`, { count: nodeFocus.values?.length ?? 0 })
                  : nodeFocus.value}
              <button
                onClick={() => setNodeFocus(null)}
                className="hover:text-fuchsia-900 transition-colors"
                title={t('dashboard.clearNodeFilter')}
              >
                <X className="w-3 h-3" />
              </button>
            </span>
          )}
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t('dashboard.filterPlaceholder', { category: t(`dashboard.categories.${category}`).toLowerCase() })}
            spellCheck={false}
            className="bg-white border border-dark-700 rounded-lg px-3 py-1.5 text-xs text-dark-100 placeholder:text-dark-600 focus:outline-none focus:border-cyber-500 focus:ring-2 focus:ring-cyber-500/20 transition-colors duration-150 w-64"
          />
        </div>
      )}

      {/* Compliance coverage — only in single-company context */}
      {activeCompany && <ComplianceSection companyId={activeCompany.id} />}

      {addAppOpen && (
        <AddAppModal
          domains={activeCompany?.domains ?? companies.flatMap((c) => c.domains)}
          defaultDomain={activeCompany?.domains[0]?.domain}
          onClose={() => setAddAppOpen(false)}
          onAdded={() => load(true)}
        />
      )}

      {compareMode && (
        <div className="card space-y-4">
          <div className="flex flex-wrap items-end gap-3">  <h3 className="text-[15px] font-semibold tracking-tight text-dark-100 flex-1 min-w-[120px]">
              {t('dashboard.compareTitle')}{selectedCompany ? ` — ${selectedCompany.name}` : ` — ${t('dashboard.compareAll')}`}
            </h3>
            <label className="space-y-1">
              <span className="block text-[10px] font-semibold text-dark-500 uppercase tracking-wider">{t('dashboard.from')}</span>
              <input
                type="date"
                value={fromDate}
                max={toDate || undefined}
                onChange={(e) => setFromDate(e.target.value)}
                className="bg-white border border-dark-700 rounded-lg px-2 py-1.5 text-xs text-dark-200 focus:outline-none focus:border-cyber-500 transition-colors duration-150"
              />
            </label>
            <label className="space-y-1">
              <span className="block text-[10px] font-semibold text-dark-500 uppercase tracking-wider">{t('dashboard.to')}</span>
              <input
                type="date"
                value={toDate}
                min={fromDate || undefined}
                onChange={(e) => setToDate(e.target.value)}
                className="bg-white border border-dark-700 rounded-lg px-2 py-1.5 text-xs text-dark-200 focus:outline-none focus:border-cyber-500 transition-colors duration-150"
              />
            </label>
            <div className="flex items-center gap-1">
              {([['presetDay', 1], ['presetWeek', 7], ['presetMonth', 30]] as const).map(([key, days]) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => applyPreset(days)}
                  className="text-[11px] px-2 py-1.5 rounded-lg border border-dark-700 bg-white hover:bg-dark-900 text-dark-300 transition-colors duration-150"
                >
                  {t(`dashboard.${key}`)}
                </button>
              ))}
            </div>
            <button
              onClick={handleCompare}
              disabled={diffLoading || !fromDate || !toDate}
              className="text-xs px-4 py-1.5 bg-cyber-600 hover:bg-cyber-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition-colors duration-150"
            >
              {diffLoading ? t('dashboard.comparing') : t('dashboard.compare')}
            </button>
          </div>

          {diffError && (
            <div className="px-3 py-2 rounded-lg border border-amber-200 bg-amber-50 text-amber-700 text-sm">
              {diffError}
            </div>
          )}

          {diff && !diffError && (
            <>
              <div className="text-xs text-dark-500">
                {fromDate} → {toDate}
                {' · '}
                {(diff.scans_in_period ?? 0) > 0
                  ? t('dashboard.scansInPeriod', { count: diff.scans_in_period })
                  : t('dashboard.noScansInPeriod')}
              </div>
              <GlobalDiffResult diff={diff} showCompany={!locked} />
            </>
          )}
        </div>
      )}

      {error && (
        <div className="card border-red-200 bg-red-50 text-red-700 text-sm flex items-center justify-between gap-4">
          <span>{error}</span>
          <button
            onClick={() => setError('')}
            className="text-red-400 hover:text-red-600 shrink-0 transition-colors"
            title={t('common.dismiss')}
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {!error && failedCompanies.length > 0 && !partialErrorDismissed && (
        <div className="card border-amber-200 bg-amber-50 text-amber-700 text-sm flex items-center justify-between gap-4">
          <span>
            {t('dashboard.partialError', { names: failedCompanies.join(', ') })}
          </span>
          <button
            onClick={() => setPartialErrorDismissed(true)}
            className="text-amber-500 hover:text-amber-700 shrink-0 transition-colors"
            title={t('common.dismiss')}
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {loading && loaded.length === 0 && companies.length === 0 ? (
        <div className="card text-center text-dark-500 py-12 text-sm animate-pulse">
          {t('dashboard.loadingGlobal')}
        </div>
      ) : companies.length === 0 && !error ? (
        <div className="card text-center text-dark-500 py-12 text-sm space-y-3">
          <p>{t('dashboard.noCompanies')}</p>
          <button
            onClick={onGoToCompanies}
            className="btn-secondary"
          >
            {t('dashboard.goToCompanies')}
          </button>
        </div>
      ) : (
        <>
          {/* Rating trend for the active company (locked, or picked from the
              filter dropdown) / Portfolio across every company otherwise —
              this must track the same selection the dropdown drives, or the
              two controls look disconnected. */}
          {activeCompany && <RatingTrendCard companyId={activeCompany.id} />}
          {!activeCompany && (
            <PortfolioSection
              companies={companies}
              onOpenCompany={(c) => setCompanyFilter(String(c.id))}
            />
          )}

          {/* Summary cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {cards.map((c) => {
              const active = c.selectable != null && c.selectable === category
              return (
                <button
                  key={c.key}
                  onClick={() => c.selectable && setCategory(c.selectable)}
                  disabled={c.selectable == null}
                  title={c.selectable == null ? t('dashboard.noListingTitle') : t('dashboard.showCategory', { category: c.label.toLowerCase() })}
                  className={clsx(
                    'card text-left transition-all duration-150',
                    c.selectable != null && 'hover:border-cyber-400 hover:shadow-md hover:shadow-cyber-900/5 cursor-pointer',
                    c.selectable == null && 'cursor-default opacity-80',
                    active && 'border-cyber-500 ring-1 ring-cyber-500/30',
                  )}
                >
                  <div className="flex items-center gap-2">
                    <div className="text-2xl font-bold tracking-tight text-dark-100 font-mono">{c.count}</div>
                    {c.selectable != null && (newByCategory[c.selectable] ?? 0) > 0 && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded-full font-semibold border bg-emerald-50 text-emerald-700 border-emerald-200">
                        {t('common.newItems', { count: newByCategory[c.selectable] ?? 0 })}
                      </span>
                    )}
                  </div>
                  <div className={clsx('text-xs mt-1 inline-flex items-center gap-1.5', active ? 'text-cyber-700 font-medium' : 'text-dark-500')}>
                    {c.icon && <c.icon className="w-3.5 h-3.5" />}
                    {c.label}
                  </div>
                </button>
              )
            })}
          </div>

          {/* Analytics charts — same scope as the cards (global or filtered company) */}
          <DashboardAnalytics companyId={selectedCompany?.id ?? null} domain={activeDomain || null} />

          {constellationOn && (
            <AttackSurfaceGraph
              hosts={scopedHosts}
              drawHosts={visibleHosts}
              companies={filteredCompanies}
              focusDomain={activeDomain || null}
              selected={nodeFocus}
              onSelectCompany={selectCompanyByName}
              onSelectDomain={selectDomain}
              onSelectHost={selectHostNode}
              onSelectIp={selectIpNode}
              onSelectIpGroup={selectIpGroup}
              filtered={Boolean(nodeFocus || activeDomain || (selectedCompany && !locked))}
              onClearFilters={clearFilters}
            />
          )}

          {totalAssets === 0 && visibleHosts.length === 0 && category !== 'companies' && category !== 'domains' ? (
            <div className="card text-center text-dark-500 py-12 text-sm">
              {t('dashboard.noAssets')}
            </div>
          ) : (
            <div className="card scroll-mt-4" ref={hostsCardRef}>
              <div className="flex flex-wrap items-center gap-3 mb-3">
                <h3 className="text-[15px] font-semibold tracking-tight text-dark-100 flex-1">
                  {isHostView && category !== 'hosts'
                    ? `${t('dashboard.categories.hosts')} · ${t(`dashboard.categories.${category}`)}`
                    : t(`dashboard.categories.${category}`)}
                </h3>
                {!readOnly && MODULE_RESCAN[category] && (
                  <button
                    onClick={() => rescanModule(MODULE_RESCAN[category]!)}
                    disabled={!scopeDomains.length || rescanning}
                    title={scopeDomains.length === 1
                      ? t('dashboard.rescanModuleTitle', { domain: scopeDomains[0].domain })
                      : t('dashboard.rescanModuleMulti', { count: scopeDomains.length })}
                    className="btn-secondary disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <RefreshCw className={clsx('w-3.5 h-3.5', rescanning && 'animate-spin')} />
                    {t('dashboard.rescanModule')}
                  </button>
                )}
                {category === 'apps' && !readOnly && (
                  <button onClick={() => setAddAppOpen(true)} className="btn-secondary">
                    <Plus className="w-3.5 h-3.5" />
                    {t('assets.addApp.button')}
                  </button>
                )}
                {category === 'apps' && suspiciousAppCount > 0 && (
                  <button
                    onClick={rejectAllSuspicious}
                    className="btn-secondary text-red-700 border-red-200 hover:bg-red-50"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    {t('assets.rejectAllSuspicious', { count: suspiciousAppCount })}
                  </button>
                )}
              </div>
              <div className="overflow-x-auto -mx-4 px-4">
                {category === 'companies' ? (
                  <CompaniesTable companies={filteredCompanies} search={search} onOpenCompany={onOpenCompany} />
                ) : category === 'domains' ? (
                  <DomainsTable companies={filteredCompanies} search={search} showCompany={!selectedCompany} activeDomain={activeDomain} onSelectDomain={selectDomain} />
                ) : isHostView ? (
                  <HostTable
                    hosts={visibleHosts}
                    filter={category as HostFilter}
                    search={search}
                    showCompany={!selectedCompany}
                  />
                ) : (
                  <AssetTable
                    category={category as AssetCategory}
                    assets={visibleAssets}
                    search={search}
                    showCompany={!selectedCompany}
                    domains={activeCompany?.domains ?? companies.flatMap((c) => c.domains)}
                    onChanged={() => load(true)}
                  />
                )}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
