import { useState } from 'react'
import { PortsResult } from '../../types/report'
import { SectionCard, FindingsList } from '../ui'
import ModuleErrorNote, { isModuleError } from './ModuleErrorNote'
import clsx from 'clsx'
import { AlertTriangle, ChevronDown, ChevronUp, LockOpen, Plug } from 'lucide-react'
import { useTranslation } from 'react-i18next'

export default function PortsSection({ data }: { data: PortsResult }) {
  const { t } = useTranslation()
  const [showAll, setShowAll] = useState(false)

  if (!data) return null
  if (isModuleError(data)) {
    return (
      <SectionCard title={t('report.ports.title')} icon={<Plug />}>
        <ModuleErrorNote error={data.error} />
      </SectionCard>
    )
  }

  const openPorts = data.open_ports ?? []
  const ports = showAll ? openPorts : openPorts.slice(0, 15)
  const unauth = data.unauthenticated_services ?? []

  return (
    <SectionCard title={t('report.ports.title')} icon={<Plug />} risk={data.risk}>
      <div className="flex gap-4 text-xs text-dark-400 mb-4">
        <span>IP: <span className="text-dark-200 font-mono">{data.ip ?? '—'}</span></span>
        <span>{t('report.ports.open')} <span className="text-dark-200 font-bold">{data.total_open}</span></span>
        {data.risky_ports > 0 && (
          <span className="text-orange-600">{t('report.ports.risky')} <span className="font-bold">{data.risky_ports}</span></span>
        )}
        {unauth.length > 0 && (
          <span className="text-red-600 font-bold">{t('report.ports.unauthenticated')} <span>{unauth.length}</span></span>
        )}
      </div>

      {unauth.length > 0 && (
        <div className="mb-4 p-3 rounded-lg border border-red-200 bg-red-50">
          <p className="text-[10px] font-semibold text-red-600 uppercase tracking-wider mb-2 flex items-center gap-1.5"><AlertTriangle className="w-3.5 h-3.5" /> {t('report.ports.unauthHeader')}</p>
          <div className="space-y-1">
            {unauth.map((s) => (
              <div key={s.port} className="flex items-center gap-2 text-xs text-red-700">
                <span className="font-mono font-bold w-12 shrink-0">{s.port}</span>
                <span className="font-medium">{s.service}</span>
                {s.banner && <span className="text-[10px] font-mono opacity-50 truncate">{s.banner.slice(0, 60)}</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {openPorts.length === 0 ? (
        <p className="text-dark-500 text-sm">{t('report.ports.empty')}</p>
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-dark-500 border-b border-dark-800">
                  <th className="text-left py-2 pr-4 font-semibold">{t('report.ports.colPort')}</th>
                  <th className="text-left py-2 pr-4 font-semibold">{t('report.ports.colService')}</th>
                  <th className="text-left py-2 font-semibold">{t('report.ports.colBanner')}</th>
                </tr>
              </thead>
              <tbody>
                {ports.map((p) => (
                  <tr key={p.port} className={clsx(
                    'border-b border-dark-800/50 hover:bg-dark-800/30 transition-colors',
                    p.risky && 'bg-orange-50'
                  )}>
                    <td className="py-1.5 pr-4">
                      <span className={clsx('font-mono font-bold',
                        p.unauthenticated ? 'text-red-600' : p.risky ? 'text-orange-600' : 'text-dark-200')}>
                        {p.port}
                      </span>
                    </td>
                    <td className="py-1.5 pr-4">
                      <span className="text-dark-300">{p.service}</span>
                      {p.unauthenticated && <LockOpen className="ml-1 w-3.5 h-3.5 inline text-red-500" /> }
                      {!p.unauthenticated && p.risky && <AlertTriangle className="ml-1 w-3.5 h-3.5 inline text-orange-500" />}
                    </td>
                    <td className="py-1.5 text-dark-500 font-mono truncate max-w-xs">
                      {p.banner ? p.banner.slice(0, 80) : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {openPorts.length > 15 && (
            <button
              onClick={() => setShowAll(!showAll)}
              className="mt-3 text-xs text-cyber-700 hover:text-cyber-800 font-medium inline-flex items-center gap-1 transition-colors duration-150"
            >
              {showAll ? <>{t('report.ports.showLess')} <ChevronUp className="w-3.5 h-3.5" /></> : <>{t('report.ports.showAll', { count: openPorts.length })} <ChevronDown className="w-3.5 h-3.5" /></>}
            </button>
          )}
        </>
      )}
      <FindingsList findings={data.findings ?? []} />
    </SectionCard>
  )
}
