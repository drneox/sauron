import { Fragment, useState } from 'react'
import { Link } from 'react-router-dom'
import clsx from 'clsx'
import { useTranslation } from 'react-i18next'
import { HostAsset, HostKind, WithCompany } from '../types/report'
import { RiskBadge } from './ui'
import { fmtShort, td, th } from './assetTable'
import { ChevronDown } from 'lucide-react'

// Host row merged across companies (global dashboard) — carries its origin
// company name (display) and id (link to the host detail route).
export type TaggedHost = WithCompany<HostAsset> & { companyId?: number }

// Card categories that act as filters over the host table ('hosts' = no filter)
export type HostFilter =
  | 'hosts'
  | 'subdomains'
  | 'ips'
  | 'endpoints'
  | 'technologies'
  | 'admin_panels'
  | 'exposed_files'
  | 'ports'

export function hostMatchesFilter(host: HostAsset, filter: HostFilter): boolean {
  switch (filter) {
    case 'subdomains': return host.kind === 'subdomain'
    case 'ips': return host.kind === 'ip'
    case 'endpoints': return (host.endpoints ?? []).length > 0
    case 'technologies': return (host.technologies ?? []).length > 0
    case 'admin_panels': return (host.admin_panels ?? []).length > 0
    case 'exposed_files': return (host.exposed_files ?? []).length > 0
    case 'ports': return (host.open_ports ?? []).length > 0
    default: return true
  }
}

const KIND_CHIP: Record<HostKind, string> = {
  domain: 'bg-cyber-50 text-cyber-700 border-cyber-200',
  subdomain: 'bg-purple-50 text-purple-700 border-purple-200',
  ip: 'bg-dark-900 text-dark-300 border-dark-800',
}

export function KindChip({ kind }: { kind: HostKind }) {
  const { t } = useTranslation()
  return (
    <span className={clsx('text-[10px] px-1.5 py-0.5 rounded-full font-semibold border whitespace-nowrap', KIND_CHIP[kind])}>
      {t(`hosts.kind.${kind}`)}
    </span>
  )
}

const httpStatusColor = (status: number | null) => {
  if (status == null) return 'text-dark-500'
  if (status < 300) return 'text-emerald-600'
  if (status < 400) return 'text-cyan-700'
  if (status < 500) return 'text-amber-600'
  return 'text-red-600'
}

function CountBadge({ n, warn = false }: { n: number; warn?: boolean }) {
  if (!n) return <span className="text-dark-600">—</span>
  return (
    <span className={clsx(
      'text-[10px] px-1.5 py-0.5 rounded-full font-semibold border whitespace-nowrap font-mono',
      warn ? 'bg-amber-50 text-amber-700 border-amber-200' : 'bg-dark-900 text-dark-300 border-dark-800',
    )}>
      {n}
    </span>
  )
}

function TechChips({ host, limit }: { host: HostAsset; limit?: number }) {
  const techs = host.technologies ?? []
  const shown = limit ? techs.slice(0, limit) : techs
  return (
    <div className="flex flex-wrap gap-1">
      {shown.map((tech) => (
        <span
          key={tech.name}
          title={tech.category}
          className="text-[10px] px-1.5 py-0.5 rounded-full font-medium border bg-cyan-50 text-cyan-700 border-cyan-200 whitespace-nowrap"
        >
          {tech.name}
        </span>
      ))}
      {limit != null && techs.length > limit && (
        <span className="text-[10px] px-1.5 py-0.5 rounded-full border bg-dark-900 text-dark-400 border-dark-800">
          +{techs.length - limit}
        </span>
      )}
      {techs.length === 0 && <span className="text-dark-600 text-xs">—</span>}
    </div>
  )
}

function PortChips({ host, limit }: { host: HostAsset; limit?: number }) {
  const ports = host.open_ports ?? []
  const shown = limit ? ports.slice(0, limit) : ports
  return (
    <div className="flex flex-wrap gap-1">
      {shown.map((p) => (
        <span
          key={p.port}
          title={p.service ?? undefined}
          className="text-[10px] px-1.5 py-0.5 rounded-full font-semibold border bg-emerald-50 text-emerald-700 border-emerald-200 whitespace-nowrap font-mono"
        >
          {p.port}{p.service ? `/${p.service}` : ''}
        </span>
      ))}
      {limit != null && ports.length > limit && (
        <span className="text-[10px] px-1.5 py-0.5 rounded-full border bg-dark-900 text-dark-400 border-dark-800">
          +{ports.length - limit}
        </span>
      )}
      {ports.length === 0 && <span className="text-dark-600 text-xs">—</span>}
    </div>
  )
}

export function ExpandedHost({ host }: { host: HostAsset }) {
  const { t } = useTranslation()
  const sections: { label: string; content: React.ReactNode }[] = []

  if ((host.ips ?? []).length > 0 && host.kind !== 'ip') {
    sections.push({
      label: t('hosts.detail.ips'),
      content: <span className="font-mono text-xs text-dark-200 break-all">{host.ips.join(', ')}</span>,
    })
  }
  if ((host.technologies ?? []).length > 0) {
    sections.push({ label: t('hosts.detail.technologies'), content: <TechChips host={host} /> })
  }
  if ((host.open_ports ?? []).length > 0) {
    sections.push({ label: t('hosts.detail.openPorts'), content: <PortChips host={host} /> })
  }
  if ((host.endpoints ?? []).length > 0) {
    sections.push({
      label: t('hosts.detail.endpoints'),
      content: (
        <ul className="space-y-1">
          {host.endpoints.map((e) => (
            <li key={e.path} className="flex items-center gap-2 text-xs font-mono text-dark-200 break-all">
              {e.path}
              <span className="text-[10px] px-1.5 py-0.5 rounded-full border bg-purple-50 text-purple-700 border-purple-200 font-sans whitespace-nowrap">{e.source}</span>
            </li>
          ))}
        </ul>
      ),
    })
  }
  if ((host.admin_panels ?? []).length > 0) {
    sections.push({
      label: t('hosts.detail.adminPanels'),
      content: (
        <ul className="space-y-1">
          {host.admin_panels.map((p) => (
            <li key={p.url} className="flex flex-wrap items-center gap-2 text-xs">
              <a href={p.url} target="_blank" rel="noopener noreferrer" className="font-mono text-cyber-700 hover:underline break-all">{p.url}</a>
              {p.http_status != null && <span className={clsx('font-mono', httpStatusColor(p.http_status))}>{p.http_status}</span>}
              {p.severity && <RiskBadge risk={(p.severity === 'info' ? 'low' : p.severity) as HostAsset['risk']} />}
            </li>
          ))}
        </ul>
      ),
    })
  }
  if ((host.exposed_files ?? []).length > 0) {
    sections.push({
      label: t('hosts.detail.exposedFiles'),
      content: (
        <ul className="space-y-1">
          {host.exposed_files.map((f) => (
            <li key={f.path} className="flex flex-wrap items-center gap-2 text-xs">
              {f.url ? (
                <a href={f.url} target="_blank" rel="noopener noreferrer" className="font-mono text-cyber-700 hover:underline break-all">{f.path}</a>
              ) : (
                <span className="font-mono text-dark-200 break-all">{f.path}</span>
              )}
              <RiskBadge risk={f.risk} />
              {f.description && <span className="text-dark-500">{f.description}</span>}
            </li>
          ))}
        </ul>
      ),
    })
  }
  if ((host.neighbors ?? []).length > 0) {
    sections.push({
      label: t('hosts.detail.neighbors'),
      content: (
        <ul className="space-y-1">
          {host.neighbors.map((n) => (
            <li key={n.domain} className="text-xs font-mono text-dark-200 break-all">{n.domain}</li>
          ))}
        </ul>
      ),
    })
  }

  if (sections.length === 0) {
    return <p className="text-xs text-dark-500 italic">{t('hosts.detail.none')}</p>
  }
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-3 py-1">
      {sections.map((s) => (
        <div key={s.label}>
          <div className="text-[10px] font-semibold text-dark-500 uppercase tracking-wider mb-1">{s.label}</div>
          {s.content}
        </div>
      ))}
    </div>
  )
}

export function HostTable({ hosts, filter, search, showCompany = false }: {
  hosts: TaggedHost[]
  filter: HostFilter
  search: string
  showCompany?: boolean
}) {
  const { t } = useTranslation()
  const [expanded, setExpanded] = useState<string | null>(null)
  const q = search.trim().toLowerCase()
  const rows = hosts
    .filter((h) => hostMatchesFilter(h, filter))
    .filter((h) => !q || h.value.toLowerCase().includes(q)
      || (h.ips ?? []).some((ip) => ip.includes(q))
      || (h.technologies ?? []).some((tech) => tech.name.toLowerCase().includes(q)))
  const cols = showCompany ? 9 : 8

  return (
    <table className="w-full">
      <thead>
        <tr>
          <th className={th}>{t('hosts.col.host')}</th>
          {showCompany && <th className={th}>{t('assets.col.company')}</th>}
          <th className={th}>{t('hosts.col.ips')}</th>
          <th className={th}>{t('hosts.col.http')}</th>
          <th className={th}>{t('hosts.col.technologies')}</th>
          <th className={th}>{t('hosts.col.ports')}</th>
          <th className={th} title={t('hosts.col.endpoints')}>{t('hosts.col.endpointsShort')}</th>
          <th className={th} title={t('hosts.col.panelsFiles')}>{t('hosts.col.panelsFilesShort')}</th>
          <th className={th}>{t('hosts.col.risk')}</th>
        </tr>
      </thead>
      <tbody className="divide-y divide-dark-800">
        {rows.length === 0 ? (
          <tr>
            <td colSpan={cols} className="px-3 py-8 text-center text-dark-500 text-sm">
              {q ? t('hosts.emptyFiltered') : t('hosts.empty')}
            </td>
          </tr>
        ) : rows.map((h) => {
          const key = `${h.company ?? ''}:${h.value}`
          const open = expanded === key
          const detailTo = h.companyId != null
            ? `/companies/${h.companyId}/assets/${encodeURIComponent(h.value)}`
            : null
          return (
            <Fragment key={key}>
              <tr
                onClick={() => setExpanded(open ? null : key)}
                className="hover:bg-dark-800/40 cursor-pointer"
                title={t(open ? 'dashboard.collapse' : 'dashboard.expand')}
              >
                <td className="px-3 py-2">
                  <div className="flex items-center gap-2">
                    <ChevronDown className={clsx('w-3.5 h-3.5 text-dark-500 shrink-0 transition-transform duration-150', !open && '-rotate-90')} />
                    {detailTo ? (
                      <Link
                        to={detailTo}
                        onClick={(e) => e.stopPropagation()}
                        className="text-cyber-700 hover:text-cyber-800 font-medium font-mono text-xs hover:underline underline-offset-2 break-all"
                      >
                        {h.value}
                      </Link>
                    ) : (
                      <span className="text-dark-100 font-medium font-mono text-xs break-all">{h.value}</span>
                    )}
                    <KindChip kind={h.kind} />
                    {h.is_new && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded-full font-semibold border bg-mint-300/20 text-emerald-700 border-mint-400/40">
                        NEW
                      </span>
                    )}
                  </div>
                </td>
                {showCompany && <td className={clsx(td, 'whitespace-nowrap')}>{h.company ?? '—'}</td>}
                <td className={td}>
                  {h.kind === 'ip' ? <span className="text-dark-600">—</span> : <CountBadge n={(h.ips ?? []).length} />}
                </td>
                <td className={clsx(td, httpStatusColor(h.http_status))}>{h.http_status ?? '—'}</td>
                <td className={td}><TechChips host={h} limit={3} /></td>
                <td className={td}><PortChips host={h} limit={4} /></td>
                <td className={td}><CountBadge n={(h.endpoints ?? []).length} /></td>
                <td className={td}>
                  <div className="flex items-center gap-1">
                    <CountBadge n={(h.admin_panels ?? []).length} warn />
                    <span className="text-dark-600">/</span>
                    <CountBadge n={(h.exposed_files ?? []).length} warn />
                  </div>
                </td>
                <td className={td}><RiskBadge risk={h.risk} /></td>
              </tr>
              {open && (
                <tr key={`${key}:detail`} className="bg-dark-900/40">
                  <td colSpan={cols} className="px-8 py-3">
                    <ExpandedHost host={h} />
                  </td>
                </tr>
              )}
            </Fragment>
          )
        })}
      </tbody>
    </table>
  )
}
