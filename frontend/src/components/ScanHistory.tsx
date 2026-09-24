import { useState, useEffect, useCallback } from 'react'
import axios from 'axios'
import { useTranslation } from 'react-i18next'
import { ScanReport, ScanKind } from '../types/report'
import { Radar, Play, Square, RotateCcw } from 'lucide-react'

interface ScanSummary {
  scan_id: string
  domain: string
  target?: string
  status: string
  progress: number
  started_at: string
  completed_at: string | null
  grade: string | null
  kind?: ScanKind
}

interface Props {
  onViewReport: (report: ScanReport) => void
  onScanStarted?: (scanId: string) => void
  readOnly?: boolean
}

const STATUS_KEYS = ['completed', 'running', 'queued', 'interrupted', 'failed'] as const

export default function ScanHistory({ onViewReport, onScanStarted, readOnly = false }: Props) {
  const { t } = useTranslation()
  const [scans, setScans] = useState<ScanSummary[]>([])
  const [busyId, setBusyId] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      // backend returns newest first already
      const { data } = await axios.get('/api/scans')
      setScans(data)
    } catch { /* ignore */ }
  }, [])

  useEffect(() => {
    load()
    const timer = setInterval(load, 5000)  // refresh while scans may be running
    return () => clearInterval(timer)
  }, [load])

  const loadReport = async (scanId: string) => {
    const { data } = await axios.get(`/api/scan/${scanId}`)
    onViewReport(data)
  }

  const stopScan = async (scanId: string) => {
    setBusyId(scanId)
    try {
      await axios.post(`/api/scan/${scanId}/stop`)
      await load()
    } catch { /* ignore */ } finally {
      setBusyId(null)
    }
  }

  const restartScan = async (scanId: string) => {
    setBusyId(scanId)
    try {
      const { data } = await axios.post(`/api/scan/${scanId}/restart`)
      if (onScanStarted) {
        onScanStarted(data.scan_id)
      } else {
        await load()
      }
    } catch { /* ignore */ } finally {
      setBusyId(null)
    }
  }

  const gradeColor = (g: string | null) => {
    if (g === 'A') return 'text-emerald-600'
    if (g === 'B') return 'text-cyan-700'
    if (g === 'C') return 'text-amber-600'
    if (g === 'D') return 'text-orange-600'
    if (g === 'F') return 'text-red-600'
    return 'text-dark-500'
  }

  return (
    <div className="max-w-4xl mx-auto space-y-4">
      <h2 className="text-xl font-semibold tracking-tight text-dark-100">{t('history.title')}</h2>
      {scans.length === 0 ? (
        <div className="card text-center text-dark-500 py-12">{t('history.empty')}</div>
      ) : (
        <div className="space-y-2">
          {scans.map((s) => {
            const inFlight = s.status === 'running' || s.status === 'queued'
            return (
              <div key={s.scan_id} className="card card-hover flex items-center gap-4">
                <div className={`text-2xl font-bold w-10 text-center font-mono ${gradeColor(s.grade)}`}>
                  {s.grade ?? '—'}
                </div>
                <div className="flex-1">
                  <div className="font-medium text-dark-100 text-sm font-mono flex items-center gap-2">
                    {(s.kind === 'host' || s.kind === 'module') && s.target ? s.target : s.domain}
                    {s.kind === 'discover' && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded-full font-semibold border bg-cyan-50 text-cyan-700 border-cyan-200 inline-flex items-center gap-1 font-sans">
                        <Radar className="w-3 h-3" /> {t('history.discoveryBadge')}
                      </span>
                    )}
                    {s.kind === 'host' && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded-full font-semibold border bg-violet-50 text-violet-700 border-violet-200 inline-flex items-center gap-1 font-sans">
                        {t('history.hostBadge')}
                      </span>
                    )}
                    {s.kind === 'module' && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded-full font-semibold border bg-amber-50 text-amber-700 border-amber-200 inline-flex items-center gap-1 font-sans">
                        {t('history.moduleBadge')}
                      </span>
                    )}
                    {s.kind === 'agent' && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded-full font-semibold border bg-purple-50 text-purple-700 border-purple-200 inline-flex items-center gap-1 font-sans">
                        {t('history.agentBadge')}
                      </span>
                    )}
                  </div>
                  <div className="text-dark-500 text-xs">
                    {new Date(s.started_at).toLocaleString()} · {(STATUS_KEYS as readonly string[]).includes(s.status) ? t(`history.status.${s.status}`) : s.status}
                  </div>
                </div>
                {inFlight && (
                  <div className="text-xs text-cyber-700 animate-pulse font-mono">{s.progress}%</div>
                )}
                {!readOnly && inFlight && (
                  <button
                    onClick={() => stopScan(s.scan_id)}
                    disabled={busyId === s.scan_id}
                    className="btn-secondary inline-flex items-center gap-1.5 text-red-600 hover:bg-red-50 hover:border-red-300 disabled:opacity-50"
                    title={t('history.stopTitle')}
                  >
                    <Square className="w-3.5 h-3.5" /> {t('history.stop')}
                  </button>
                )}
                {inFlight && onScanStarted && (
                  <button onClick={() => onScanStarted(s.scan_id)} className="btn-secondary inline-flex items-center gap-1.5">
                    <Play className="w-3.5 h-3.5" /> {t('history.watch')}
                  </button>
                )}
                {!readOnly && !inFlight && s.kind !== 'host' && s.kind !== 'module' && (
                  <button
                    onClick={() => restartScan(s.scan_id)}
                    disabled={busyId === s.scan_id}
                    className="btn-secondary inline-flex items-center gap-1.5 disabled:opacity-50"
                    title={t('history.rescanTitle')}
                  >
                    <RotateCcw className="w-3.5 h-3.5" /> {t('history.rescan')}
                  </button>
                )}
                {s.status === 'completed' && (
                  <button onClick={() => loadReport(s.scan_id)} className="btn-secondary">
                    {t('history.viewReport')}
                  </button>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
