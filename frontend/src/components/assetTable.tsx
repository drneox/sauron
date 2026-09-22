import { useState } from 'react'
import axios from 'axios'
import clsx from 'clsx'
import { useTranslation } from 'react-i18next'
import {
  AssetBase,
  SubdomainAsset,
  IpAsset,
  EndpointAsset,
  TechnologyAsset,
  AdminPanelAsset,
  ExposedFileAsset,
  PortAsset,
  AppAsset,
  NeighborAsset,
  AssetCategoryKey,
  CompanyDomain,
  LlmVerdict,
  WithCompany,
} from '../types/report'
import { RiskBadge } from './ui'
import { BadgeCheck, Check, ExternalLink, Trash2 } from 'lucide-react'

export type AssetCategory = AssetCategoryKey

export const CATEGORY_LABELS: Record<AssetCategory, string> = {
  subdomains: 'Subdomains',
  ips: 'IPs',
  endpoints: 'Endpoints',
  technologies: 'Technologies',
  admin_panels: 'Admin Panels',
  exposed_files: 'Exposed Files',
  ports: 'Open Ports',
  apps: 'Apps',
  neighbors: 'Neighbors',
}

export const fmtShort = (iso: string) => {
  const d = new Date(iso)
  if (isNaN(d.getTime())) return '—'
  const date = d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })
  const time = d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
  return `${date} ${time}`
}

const httpStatusColor = (status: number | null) => {
  if (status == null) return 'text-dark-500'
  if (status < 300) return 'text-emerald-600'
  if (status < 400) return 'text-cyan-700'
  if (status < 500) return 'text-amber-600'
  return 'text-red-600'
}

export const gradeChipColor = (g: string | null | undefined) => {
  if (g === 'A') return 'bg-emerald-50 text-emerald-700 border-emerald-200'
  if (g === 'B') return 'bg-cyan-50 text-cyan-700 border-cyan-200'
  if (g === 'C') return 'bg-amber-50 text-amber-700 border-amber-200'
  if (g === 'D') return 'bg-orange-50 text-orange-700 border-orange-200'
  if (g === 'F') return 'bg-red-50 text-red-700 border-red-200'
  return 'bg-dark-900 text-dark-500 border-dark-800'
}

export type AssetRow = Pick<AssetBase, 'value' | 'first_seen' | 'last_seen' | 'is_new'>

// Asset inventory whose rows may carry the origin company (global dashboard)
export interface AssetInventory {
  subdomains: WithCompany<SubdomainAsset>[]
  ips: WithCompany<IpAsset>[]
  endpoints: WithCompany<EndpointAsset>[]
  technologies: WithCompany<TechnologyAsset>[]
  admin_panels: WithCompany<AdminPanelAsset>[]
  exposed_files: WithCompany<ExposedFileAsset>[]
  ports?: WithCompany<PortAsset>[]
  apps?: WithCompany<AppAsset>[]
  neighbors?: WithCompany<NeighborAsset>[]
}

function NewBadge() {
  return (
    <span className="text-[10px] px-1.5 py-0.5 rounded-full font-semibold border bg-mint-300/20 text-emerald-700 border-mint-400/40">
      NEW
    </span>
  )
}

function ValueCell({ asset, nowrap = false }: { asset: AssetRow; nowrap?: boolean }) {
  return (
    <td className="px-3 py-2">
      <div className="flex items-center gap-2">
        <span className={clsx('text-dark-100 font-medium font-mono text-xs', nowrap ? 'whitespace-nowrap' : 'break-all')}>{asset.value}</span>
        {asset.is_new && <NewBadge />}
      </div>
    </td>
  )
}

function SeenCells({ asset }: { asset: AssetRow }) {
  return (
    <>
      <td className="px-3 py-2 text-xs text-dark-400 whitespace-nowrap" title={asset.first_seen}>
        {fmtShort(asset.first_seen)}
      </td>
      <td className="px-3 py-2 text-xs text-dark-400 whitespace-nowrap" title={asset.last_seen}>
        {fmtShort(asset.last_seen)}
      </td>
    </>
  )
}

export function LinkValueCell({ asset, href, extra }: { asset: AssetRow; href?: string | null; extra?: React.ReactNode }) {
  return (
    <td className="px-3 py-2">
      <div className="flex items-center gap-2 flex-wrap">
        {href ? (
          <a
            href={href}
            target="_blank"
            rel="noopener noreferrer"
            className="text-cyber-700 hover:text-cyber-800 font-medium font-mono text-xs hover:underline underline-offset-2 break-all inline-flex items-center gap-1 group"
          >
            {asset.value}
            <ExternalLink className="w-3 h-3 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity duration-150" />
          </a>
        ) : (
          <span className="text-dark-100 font-medium font-mono text-xs break-all">{asset.value}</span>
        )}
        {asset.is_new && <NewBadge />}
        {extra}
      </div>
    </td>
  )
}

function VerdictBadge({ verdict }: { verdict?: LlmVerdict | null }) {
  const { t } = useTranslation()
  if (!verdict) return null
  return (
    <span className={clsx(
      'text-[10px] px-1.5 py-0.5 rounded-full font-semibold border whitespace-nowrap',
      verdict === 'official' && 'bg-mint-300/20 text-emerald-700 border-mint-400/40',
      verdict === 'suspicious' && 'bg-red-50 text-red-700 border-red-200',
      verdict === 'unrelated' && 'bg-dark-900 text-dark-500 border-dark-800',
    )}>
      {verdict === 'official' ? t('assets.verdict.official') : verdict === 'suspicious' ? t('assets.verdict.suspicious') : t('assets.verdict.unrelated')}
    </span>
  )
}

export const th = 'px-3 py-2 text-left text-[11px] uppercase tracking-wider font-semibold text-dark-500 border-b border-dark-800'
export const td = 'px-3 py-2 text-xs text-dark-300 font-mono'

function CompanyTh({ show }: { show: boolean }) {
  const { t } = useTranslation()
  return show ? <th className={th}>{t('assets.col.company')}</th> : null
}

function CompanyCell({ asset, show }: { asset: { company?: string }; show: boolean }) {
  if (!show) return null
  return <td className={clsx(td, 'whitespace-nowrap')}>{asset.company ?? '—'}</td>
}

export function AssetTable({ category, assets, search, showCompany = false, domains, onChanged }: {
  category: AssetCategory
  assets: AssetInventory | undefined
  search: string
  showCompany?: boolean
  domains?: CompanyDomain[]
  onChanged?: () => void
}) {
  const { t } = useTranslation()
  const q = search.trim().toLowerCase()
  const match = (a: AssetRow) => !q || a.value.toLowerCase().includes(q)
  const extraCol = showCompany ? 1 : 0

  // Optimistic confirmations of official app developers (per domain id)
  const [confirmedDevs, setConfirmedDevs] = useState<Set<string>>(new Set())

  const devKey = (domainId: number, a: WithCompany<AppAsset>) =>
    `${domainId}:${a.store ?? ''}:${a.developer ?? ''}`

  const isDevConfirmed = (a: WithCompany<AppAsset>, domain?: CompanyDomain) => {
    if (!a.developer) return false
    if (a.official_developer === true) return true
    if (domain && confirmedDevs.has(devKey(domain.id, a))) return true
    return (domain?.app_developers ?? []).some(
      (d) => d.name === a.developer && d.store === a.store,
    )
  }

  const confirmDeveloper = async (a: WithCompany<AppAsset>, domain: CompanyDomain) => {
    if (!a.developer || !a.store) return
    if (!confirm(t('assets.monitorConfirm', { developer: a.developer }))) return
    const entry = { store: a.store, name: a.developer }
    const existing = (domain.app_developers ?? []).filter(
      (d) => !(d.store === entry.store && d.name === entry.name),
    )
    try {
      await axios.put(`/api/domains/${domain.id}/app-developers`, {
        app_developers: [...existing, entry],
      })
      setConfirmedDevs((prev) => new Set(prev).add(devKey(domain.id, a)))
    } catch (err: unknown) {
      const msg = axios.isAxiosError(err)
        ? err.response?.data?.detail || err.message
        : t('common.unknownError')
      alert(t('assets.confirmError', { msg }))
    }
  }

  const reviewApp = async (a: WithCompany<AppAsset>, action: 'approve' | 'reject') => {
    if (a.id == null) return
    if (action === 'reject' && !confirm(t('assets.rejectAppConfirm', { name: a.value }))) return
    try {
      await axios.post(`/api/assets/${a.id}/review`, { action })
      onChanged?.()
    } catch (err: unknown) {
      const msg = axios.isAxiosError(err)
        ? err.response?.data?.detail || err.message
        : t('common.unknownError')
      alert(t('assets.reviewError', { msg }))
    }
  }

  const emptyRow = (cols: number) => (
    <tr>
      <td colSpan={cols} className="px-3 py-8 text-center text-dark-500 text-sm">
        {q ? t('assets.emptyFiltered') : t('assets.emptyInventory', { category: t(`dashboard.categories.${category}`).toLowerCase() })}
      </td>
    </tr>
  )

  if (category === 'subdomains') {
    const rows = (assets?.subdomains ?? []).filter(match)
    return (
      <table className="w-full">
        <thead>
          <tr>
            <th className={th}>{t('assets.col.subdomain')}</th>
            <CompanyTh show={showCompany} />
            <th className={th}>{t('assets.col.domain')}</th>
            <th className={th}>{t('assets.col.ips')}</th>
            <th className={th}>{t('assets.col.http')}</th>
            <th className={th}>{t('assets.col.firstSeen')}</th>
            <th className={th}>{t('assets.col.lastSeen')}</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-dark-800">
          {rows.length === 0 ? emptyRow(6 + extraCol) : rows.map((a) => (
            <tr key={`${a.company ?? ''}:${a.value}`} className="hover:bg-dark-800/40">
              <LinkValueCell asset={a} href={`https://${a.value}`} />
              <CompanyCell asset={a} show={showCompany} />
              <td className={td}>{a.domain}</td>
              <td className={td}>{(a.ips ?? []).join(', ') || '—'}</td>
              <td className={clsx(td, httpStatusColor(a.http_status))}>{a.http_status ?? '—'}</td>
              <SeenCells asset={a} />
            </tr>
          ))}
        </tbody>
      </table>
    )
  }

  if (category === 'ports') {
    const rows = (assets?.ports ?? []).filter(match).sort((a, b) => a.port - b.port)
    return (
      <table className="w-full">
        <thead>
          <tr>
            <th className={th}>{t('assets.col.port')}</th>
            <th className={th}>{t('assets.col.service')}</th>
            <th className={th}>{t('assets.col.ip')}</th>
            <CompanyTh show={showCompany} />
            <th className={th}>{t('assets.col.domain')}</th>
            <th className={th}>{t('assets.col.firstSeen')}</th>
            <th className={th}>{t('assets.col.lastSeen')}</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-dark-800">
          {rows.length === 0 ? emptyRow(6 + extraCol) : rows.map((a) => (
            <tr key={`${a.company ?? ''}:${a.value}`} className="hover:bg-dark-800/40">
              <td className={td}>
                <span className="text-dark-100 font-medium font-mono whitespace-nowrap">{a.port}</span>
                {a.is_new && <span className="ml-2"><NewBadge /></span>}
              </td>
              <td className={td}>
                <span className="text-[10px] px-1.5 py-0.5 rounded-full font-semibold border bg-cyan-50 text-cyan-700 border-cyan-200">
                  {a.service}
                </span>
              </td>
              <td className={clsx(td, 'whitespace-nowrap')}>{a.ip}</td>
              <CompanyCell asset={a} show={showCompany} />
              <td className={td}>{a.domain}</td>
              <SeenCells asset={a} />
            </tr>
          ))}
        </tbody>
      </table>
    )
  }

  if (category === 'ips') {
    const rows = (assets?.ips ?? []).filter(match)
    return (
      <table className="w-full">
        <thead>
          <tr>
            <th className={th}>{t('assets.col.ip')}</th>
            <CompanyTh show={showCompany} />
            <th className={th}>{t('assets.col.domains')}</th>
            <th className={th}>{t('assets.col.openPorts')}</th>
            <th className={th}>{t('assets.col.firstSeen')}</th>
            <th className={th}>{t('assets.col.lastSeen')}</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-dark-800">
          {rows.length === 0 ? emptyRow(5 + extraCol) : rows.map((a) => (
            <tr key={`${a.company ?? ''}:${a.value}`} className="hover:bg-dark-800/40">
              <ValueCell asset={a} nowrap />
              <CompanyCell asset={a} show={showCompany} />
              <td className={td}>{(a.domains ?? []).join(', ') || '—'}</td>
              <td className={td}>
                {(a.open_ports ?? []).length
                  ? a.open_ports.map((p) => `${p.port}/${p.service}`).join(', ')
                  : '—'}
              </td>
              <SeenCells asset={a} />
            </tr>
          ))}
        </tbody>
      </table>
    )
  }

  if (category === 'endpoints') {
    const rows = (assets?.endpoints ?? []).filter(match)
    return (
      <table className="w-full">
        <thead>
          <tr>
            <th className={th}>{t('assets.col.path')}</th>
            <CompanyTh show={showCompany} />
            <th className={th}>{t('assets.col.domain')}</th>
            <th className={th}>{t('assets.col.source')}</th>
            <th className={th}>{t('assets.col.firstSeen')}</th>
            <th className={th}>{t('assets.col.lastSeen')}</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-dark-800">
          {rows.length === 0 ? emptyRow(5 + extraCol) : rows.map((a) => (
            <tr key={`${a.company ?? ''}:${a.domain}${a.value}`} className="hover:bg-dark-800/40">
              <ValueCell asset={a} />
              <CompanyCell asset={a} show={showCompany} />
              <td className={td}>{a.domain}</td>
              <td className={td}>
                <span className="text-[11px] px-2 py-0.5 rounded-full font-medium border bg-purple-50 text-purple-700 border-purple-200">
                  {a.source}
                </span>
              </td>
              <SeenCells asset={a} />
            </tr>
          ))}
        </tbody>
      </table>
    )
  }

  if (category === 'technologies') {
    const rows = (assets?.technologies ?? []).filter(match)
    return (
      <table className="w-full">
        <thead>
          <tr>
            <th className={th}>{t('assets.col.technology')}</th>
            <th className={th}>{t('assets.col.category')}</th>
            <CompanyTh show={showCompany} />
            <th className={th}>{t('assets.col.domain')}</th>
            <th className={th}>{t('assets.col.firstSeen')}</th>
            <th className={th}>{t('assets.col.lastSeen')}</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-dark-800">
          {rows.length === 0 ? emptyRow(5 + extraCol) : rows.map((a) => (
            <tr key={`${a.company ?? ''}:${a.domain}:${a.value}`} className="hover:bg-dark-800/40">
              <ValueCell asset={a} />
              <td className={td}>
                <span className="text-[11px] px-2 py-0.5 rounded-full font-medium border bg-cyan-50 text-cyan-700 border-cyan-200">
                  {a.category}
                </span>
              </td>
              <CompanyCell asset={a} show={showCompany} />
              <td className={td}>{a.domain}</td>
              <SeenCells asset={a} />
            </tr>
          ))}
        </tbody>
      </table>
    )
  }

  if (category === 'admin_panels') {
    const rows = (assets?.admin_panels ?? []).filter(match)
    return (
      <table className="w-full">
        <thead>
          <tr>
            <th className={th}>{t('assets.col.url')}</th>
            <CompanyTh show={showCompany} />
            <th className={th}>{t('assets.col.domain')}</th>
            <th className={th}>{t('assets.col.http')}</th>
            <th className={th}>{t('assets.col.firstSeen')}</th>
            <th className={th}>{t('assets.col.lastSeen')}</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-dark-800">
          {rows.length === 0 ? emptyRow(5 + extraCol) : rows.map((a) => (
            <tr key={`${a.company ?? ''}:${a.value}`} className="hover:bg-dark-800/40">
              <LinkValueCell asset={a} href={a.value} />
              <CompanyCell asset={a} show={showCompany} />
              <td className={td}>{a.domain}</td>
              <td className={clsx(td, httpStatusColor(a.http_status))}>{a.http_status ?? '—'}</td>
              <SeenCells asset={a} />
            </tr>
          ))}
        </tbody>
      </table>
    )
  }

  if (category === 'apps') {
    // Same app discovered under several domains of the company → show once
    const seenApps = new Set<string>()
    const rows = (assets?.apps ?? []).filter(match).filter((a) => {
      const key = `${a.store}:${a.value}`
      if (seenApps.has(key)) return false
      seenApps.add(key)
      return true
    })
    return (
      <table className="w-full">
        <thead>
          <tr>
            <th className={th}>{t('assets.col.app')}</th>
            <CompanyTh show={showCompany} />
            <th className={th}>{t('assets.col.store')}</th>
            <th className={th}>{t('assets.col.os')}</th>
            <th className={th}>{t('assets.col.version')}</th>
            <th className={th}>{t('assets.col.developer')}</th>
            <th className={th}>{t('assets.col.updated')}</th>
            <th className={th}>{t('assets.col.firstSeen')}</th>
            <th className={th}>{t('assets.col.lastSeen')}</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-dark-800">
          {rows.length === 0 ? emptyRow(8 + extraCol) : rows.map((a) => {
            const domain = domains?.find((d) => d.domain === a.domain)
            const confirmed = isDevConfirmed(a, domain)
            const canConfirm = !confirmed && !!domain && !!a.store && !!a.developer
            return (
            <tr key={`${a.company ?? ''}:${a.store ?? ''}:${a.value}`} className="hover:bg-dark-800/40">
              <LinkValueCell asset={a} href={a.url} extra={
                <>
                  <VerdictBadge verdict={a.llm_verdict} />
                  {a.suspicious && a.id != null && (
                    <>
                      <button
                        onClick={() => reviewApp(a, 'approve')}
                        title={t('assets.approveAppTitle')}
                        className="p-0.5 text-dark-500 hover:text-mint-600 hover:bg-mint-300/20 rounded transition-colors duration-150"
                      >
                        <Check className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => reviewApp(a, 'reject')}
                        title={t('assets.rejectAppTitle')}
                        className="p-0.5 text-dark-500 hover:text-red-600 hover:bg-red-50 rounded transition-colors duration-150"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </>
                  )}
                </>
              } />
              <CompanyCell asset={a} show={showCompany} />
              <td className={td}>
                {a.store ? (
                  <span className={clsx(
                    'text-[10px] px-1.5 py-0.5 rounded-full font-semibold border whitespace-nowrap',
                    a.store === 'app_store'
                      ? 'bg-blue-50 text-blue-700 border-blue-200'
                      : 'bg-emerald-50 text-emerald-700 border-emerald-200',
                  )}>
                    {a.store === 'app_store' ? 'App Store' : 'Google Play'}
                  </span>
                ) : '—'}
              </td>
              <td className={td}>
                {a.os ? (
                  <span className="text-[10px] px-1.5 py-0.5 rounded-full font-semibold border bg-dark-900 text-dark-300 border-dark-800 uppercase">
                    {a.os}
                  </span>
                ) : '—'}
              </td>
              <td className={clsx(td, 'font-mono whitespace-nowrap')}>{a.version ?? '—'}</td>
              <td className={td}>
                {a.developer ? (
                  <div className="flex items-center gap-1.5">
                    <span>{a.developer}</span>
                    {confirmed ? (
                      <span title={t('assets.officialDev')}>
                        <BadgeCheck className="w-3.5 h-3.5 text-mint-600 shrink-0" />
                      </span>
                    ) : canConfirm && domain ? (
                      <button
                        onClick={() => confirmDeveloper(a, domain)}
                        title={t('assets.confirmDevTitle', { developer: a.developer, domain: domain.domain })}
                        className="p-0.5 text-dark-500 hover:text-mint-600 hover:bg-mint-300/20 rounded transition-colors duration-150"
                      >
                        <Check className="w-3.5 h-3.5" />
                      </button>
                    ) : null}
                  </div>
                ) : '—'}
              </td>
              <td className={clsx(td, 'whitespace-nowrap')} title={a.updated ?? undefined}>
                {a.updated ? fmtShort(a.updated) : '—'}
              </td>
              <SeenCells asset={a} />
            </tr>
            )
          })}
        </tbody>
      </table>
    )
  }

  if (category === 'neighbors') {
    const rows = (assets?.neighbors ?? []).filter(match)
    return (
      <div>
        <p className="px-3 py-2 text-xs text-dark-500 italic">
          {t('assets.neighborsNote')}
        </p>
        <table className="w-full">
          <thead>
            <tr>
              <th className={th}>{t('assets.col.neighborDomain')}</th>
              <CompanyTh show={showCompany} />
              <th className={th}>{t('assets.col.sharedIp')}</th>
              <th className={th}>{t('assets.col.neighborOf')}</th>
              <th className={th}>{t('assets.col.firstSeen')}</th>
              <th className={th}>{t('assets.col.lastSeen')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-dark-800">
            {rows.length === 0 ? emptyRow(5 + extraCol) : rows.map((a) => (
              <tr key={`${a.company ?? ''}:${a.ip ?? ''}:${a.value}`} className="hover:bg-dark-800/40">
                <LinkValueCell asset={a} href={`https://${a.value}`} />
                <CompanyCell asset={a} show={showCompany} />
                <td className={clsx(td, 'font-mono whitespace-nowrap')}>{a.ip ?? '—'}</td>
                <td className={td}>{a.neighbor_of ?? a.domain ?? '—'}</td>
                <SeenCells asset={a} />
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )
  }

  const rows = (assets?.exposed_files ?? []).filter(match)
  return (
    <table className="w-full">
      <thead>
        <tr>
          <th className={th}>{t('assets.col.path')}</th>
          <CompanyTh show={showCompany} />
          <th className={th}>{t('assets.col.domain')}</th>
          <th className={th}>{t('assets.col.risk')}</th>
          <th className={th}>{t('assets.col.firstSeen')}</th>
          <th className={th}>{t('assets.col.lastSeen')}</th>
        </tr>
      </thead>
      <tbody className="divide-y divide-dark-800">
        {rows.length === 0 ? emptyRow(5 + extraCol) : rows.map((a) => (
          <tr key={`${a.company ?? ''}:${a.domain}${a.value}`} className="hover:bg-dark-800/40">
            <ValueCell asset={a} />
            <CompanyCell asset={a} show={showCompany} />
            <td className={td}>{a.domain}</td>
            <td className={td}><RiskBadge risk={a.risk} /></td>
            <SeenCells asset={a} />
          </tr>
        ))}
      </tbody>
    </table>
  )
}
