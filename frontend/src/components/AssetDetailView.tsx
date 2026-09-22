import { useEffect, useState } from 'react'
import axios from 'axios'
import clsx from 'clsx'
import { useTranslation } from 'react-i18next'
import { Link, useNavigate } from 'react-router-dom'
import { Company, HostDetail, ScanListItem } from '../types/report'
import { ExpandedHost, KindChip } from './hostTable'
import { fmtShort, gradeChipColor, td, th } from './assetTable'
import { KeyValue, LinkifyText, RiskBadge, SectionCard } from './ui'
import {
  ArrowLeft,
  Fingerprint,
  History,
  Play,
  ScanSearch,
  ShieldAlert,
  Siren,
} from 'lucide-react'

const fmtVal = (v: unknown): string => {
  if (v == null) return '—'
  if (typeof v === 'string') return v
  return JSON.stringify(v)
}

interface Props {
  company: Company
  hostValue: string
  readOnly?: boolean
  onBack: () => void
}

export default function AssetDetailView({ company, hostValue, readOnly = false, onBack }: Props) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [detail, setDetail] = useState<HostDetail | null>(null)
  const [error, setError] = useState('')
  const [hostScans, setHostScans] = useState<ScanListItem[]>([])
  const [launching, setLaunching] = useState(false)

  useEffect(() => {
    let cancelled = false
    setDetail(null)
    setError('')
    axios.get<HostDetail>(`/api/companies/${company.id}/hosts/${encodeURIComponent(hostValue)}`)
      .then(({ data }) => { if (!cancelled) setDetail(data) })
      .catch((err) => {
        if (cancelled) return
        setError(axios.isAxiosError(err) && err.response?.status === 404
          ? t('hosts.detail.notFound')
          : t('hosts.detail.loadError'))
      })
    return () => { cancelled = true }
  }, [company.id, hostValue, t])

  useEffect(() => {
    let cancelled = false
    const load = () => {
      axios.get<ScanListItem[]>(`/api/scans`, { params: { domain: hostValue } })
        .then(({ data }) => { if (!cancelled) setHostScans(data) })
        .catch(() => { /* leave the section empty */ })
    }
    load()
    const timer = setInterval(load, 5000)  // refresh while a host scan may be running
    return () => { cancelled = true; clearInterval(timer) }
  }, [hostValue])

  const scanHost = async () => {
    if (launching) return
    setLaunching(true)
    try {
      const { data } = await axios.post('/api/host-scan', { host: hostValue })
      navigate(`/scanning/${data.scan_id}`)
    } catch (err: unknown) {
      const msg = axios.isAxiosError(err)
        ? (err.response?.data as { detail?: string } | undefined)?.detail || err.message
        : 'Unknown error'
      setError(msg)
      setLaunching(false)
    }
  }

  const host = detail?.host

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <button onClick={onBack} className="btn-secondary">
          <ArrowLeft className="w-3.5 h-3.5" />
          {t('hosts.detail.back')}
        </button>
        <div className="flex-1 min-w-[200px]">
          <h2 className="text-xl font-semibold tracking-tight text-dark-100 font-mono break-all">{hostValue}</h2>
          <div className="text-xs text-dark-500">{company.name}</div>
        </div>
        {host && (
          <div className="flex items-center gap-2">
            <KindChip kind={host.kind} />
            <RiskBadge risk={host.risk} />
            {host.is_new && (
              <span className="text-[10px] px-1.5 py-0.5 rounded-full font-semibold border bg-mint-300/20 text-emerald-700 border-mint-400/40">
                NEW
              </span>
            )}
          </div>
        )}
        {!readOnly && (
          <button
            onClick={scanHost}
            disabled={launching}
            className="px-4 py-1.5 bg-cyber-600 hover:bg-cyber-700 active:bg-cyber-800 text-white text-xs font-semibold rounded-lg transition-colors duration-150 inline-flex items-center gap-1.5 disabled:opacity-50"
            title={t('hosts.detail.scanHostTitle')}
          >
            <ScanSearch className="w-3.5 h-3.5" />
            {launching ? t('hosts.detail.scanHostLaunching') : t('hosts.detail.scanHost')}
          </button>
        )}
      </div>

      {error ? (
        <div className="card text-center text-dark-500 py-12 text-sm">{error}</div>
      ) : !detail || !host ? (
        <div className="card text-center text-dark-500 py-12 text-sm animate-pulse">
          {t('hosts.detail.loading')}
        </div>
      ) : (
        <>
          <SectionCard title={t('hosts.detail.identity')} icon={<Fingerprint />} risk={host.risk}>
            <KeyValue label={t('hosts.detail.kind')} value={t(`hosts.kind.${host.kind}`)} />
            <KeyValue label={t('hosts.detail.domain')} value={host.domain} />
            <KeyValue label={t('hosts.detail.ips')} value={(host.ips ?? []).join(', ') || null} />
            <KeyValue label={t('hosts.detail.http')} value={host.http_status != null ? String(host.http_status) : null} />
            <KeyValue
              label={t('hosts.detail.firstSeen')}
              value={host.first_seen ? fmtShort(host.first_seen) : null}
            />
            <KeyValue
              label={t('hosts.detail.lastSeen')}
              value={host.last_seen ? fmtShort(host.last_seen) : null}
            />
          </SectionCard>

          <SectionCard title={t('hosts.detail.attributes')} icon={<ScanSearch />}>
            <ExpandedHost host={host} />
          </SectionCard>

          <SectionCard title={t('hosts.detail.findings')} icon={<Siren />}>
            {(detail.related_findings ?? []).length === 0 ? (
              <p className="text-xs text-dark-500 italic">{t('hosts.detail.noFindings')}</p>
            ) : (
              <ul className="space-y-1.5">
                {detail.related_findings.map((f, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs">
                    <ShieldAlert className="w-3.5 h-3.5 mt-px shrink-0 text-amber-500" />
                    <span className="flex-1 break-all text-dark-200">
                      <LinkifyText text={f.finding} />
                      {f.module && <span className="text-dark-500"> — {f.module}</span>}
                    </span>
                    {f.risk && <RiskBadge risk={f.risk} />}
                  </li>
                ))}
              </ul>
            )}
          </SectionCard>

          <SectionCard title={t('hosts.detail.history')} icon={<History />}>
            {(detail.history ?? []).length === 0 ? (
              <p className="text-xs text-dark-500 italic">{t('hosts.detail.noHistory')}</p>
            ) : (
              <div className="overflow-x-auto -mx-4 px-4">
                <table className="w-full">
                  <thead>
                    <tr>
                      <th className={th}>{t('hosts.detail.historyCol.when')}</th>
                      <th className={th}>{t('hosts.detail.historyCol.asset')}</th>
                      <th className={th}>{t('hosts.detail.historyCol.field')}</th>
                      <th className={th}>{t('hosts.detail.historyCol.change')}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-dark-800">
                    {detail.history.map((h, i) => (
                      <tr key={`${h.changed_at}:${h.asset_value}:${h.field}:${i}`} className="hover:bg-dark-800/40">
                        <td className={clsx(td, 'whitespace-nowrap')} title={h.changed_at ?? undefined}>
                          {h.changed_at ? fmtShort(h.changed_at) : '—'}
                        </td>
                        <td className={td}>
                          <span className="break-all">{h.asset_value}</span>
                          <span className="ml-1.5 text-[10px] px-1.5 py-0.5 rounded-full border bg-dark-900 text-dark-400 border-dark-800 whitespace-nowrap">
                            {h.asset_type}
                          </span>
                        </td>
                        <td className={clsx(td, 'whitespace-nowrap')}>{h.field}</td>
                        <td className={td}>
                          <span className="break-all text-red-700/80 line-through decoration-red-300">{fmtVal(h.old)}</span>
                          <span className="text-dark-500"> → </span>
                          <span className="break-all text-emerald-700">{fmtVal(h.new)}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </SectionCard>

          <SectionCard title={t('hosts.detail.hostScans')} icon={<ScanSearch />}>
            {hostScans.length === 0 ? (
              <p className="text-xs text-dark-500 italic">{t('hosts.detail.noHostScans')}</p>
            ) : (
              <div className="overflow-x-auto -mx-4 px-4">
                <table className="w-full">
                  <thead>
                    <tr>
                      <th className={th}>{t('hosts.detail.hostScansCol.status')}</th>
                      <th className={th}>{t('hosts.detail.hostScansCol.started')}</th>
                      <th className={th}>{t('hosts.detail.hostScansCol.grade')}</th>
                      <th className={th}>{t('hosts.detail.hostScansCol.actions')}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-dark-800">
                    {hostScans.map((s) => {
                      const inFlight = s.status === 'running' || s.status === 'queued'
                      return (
                        <tr key={s.scan_id} className="hover:bg-dark-800/40">
                          <td className={clsx(td, 'whitespace-nowrap')}>
                            {t(`history.status.${s.status}`, s.status)}
                            {inFlight && (
                              <span className="ml-2 text-cyber-700 animate-pulse font-mono text-[11px]">{s.progress}%</span>
                            )}
                          </td>
                          <td className={clsx(td, 'whitespace-nowrap')} title={s.started_at ?? undefined}>
                            {s.started_at ? fmtShort(s.started_at) : '—'}
                          </td>
                          <td className={td}>
                            <span
                              className={clsx(
                                'text-xs px-2 py-0.5 rounded-full font-semibold border inline-block w-8 text-center',
                                gradeChipColor(s.grade),
                              )}
                            >
                              {s.grade ?? '—'}
                            </span>
                          </td>
                          <td className={clsx(td, 'whitespace-nowrap')}>
                            {inFlight ? (
                              <Link
                                to={`/scanning/${s.scan_id}`}
                                className="text-cyber-700 hover:underline font-medium inline-flex items-center gap-1"
                              >
                                <Play className="w-3 h-3" />
                                {t('hosts.detail.watchScan')}
                              </Link>
                            ) : s.status === 'completed' ? (
                              <Link to={`/report/${s.scan_id}`} className="text-cyber-700 hover:underline font-medium">
                                {t('hosts.detail.openReport')}
                              </Link>
                            ) : (
                              '—'
                            )}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </SectionCard>

          <SectionCard title={t('hosts.detail.recentScans')} icon={<ScanSearch />}>
            {(detail.recent_scans ?? []).length === 0 ? (
              <p className="text-xs text-dark-500 italic">{t('hosts.detail.noScans')}</p>
            ) : (
              <ul className="space-y-1.5">
                {detail.recent_scans.map((s) => (
                  <li key={s.id} className="flex items-center gap-3 text-xs">
                    <span
                      className={clsx(
                        'text-xs px-2 py-0.5 rounded-full font-semibold border inline-block w-8 text-center',
                        gradeChipColor(s.grade),
                      )}
                    >
                      {s.grade ?? '—'}
                    </span>
                    <span className="text-dark-400 font-mono whitespace-nowrap">
                      {s.completed_at ? fmtShort(s.completed_at) : '—'}
                    </span>
                    <Link to={`/report/${s.id}`} className="text-cyber-700 hover:underline font-medium">
                      {t('hosts.detail.openReport')}
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </SectionCard>
        </>
      )}
    </div>
  )
}
