import { useCallback, useEffect, useState } from 'react'
import axios from 'axios'
import { useTranslation } from 'react-i18next'
import { Check, RotateCcw, X } from 'lucide-react'

interface LearnedPath {
  id: number
  path: string
  status: 'seen' | 'approved' | 'rejected'
  hosts: number
  hits: number
  last_status: number | null
  ai_verdict: string | null
  decided_by: string | null
}

interface LearnedPathsData {
  candidates: LearnedPath[]
  approved: LearnedPath[]
  rejected: LearnedPath[]
  seen: number
}

type Action = 'approve' | 'reject' | 'reset'

const btn = 'inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs transition-colors duration-150 disabled:opacity-50'

export default function LearnedPathsPanel() {
  const { t } = useTranslation()
  const [data, setData] = useState<LearnedPathsData | null>(null)
  const [busy, setBusy] = useState<number | null>(null)
  const [error, setError] = useState('')

  const load = useCallback(() => {
    axios.get<LearnedPathsData>('/api/learned-paths')
      .then(({ data }) => { setData(data); setError('') })
      .catch((err) => setError(axios.isAxiosError(err) ? err.response?.data?.detail || err.message : String(err)))
  }, [])

  useEffect(() => { load() }, [load])

  const decide = async (row: LearnedPath, action: Action) => {
    setBusy(row.id)
    try {
      await axios.post(`/api/learned-paths/${row.id}/${action}`)
      load()
    } catch (err) {
      setError(axios.isAxiosError(err) ? err.response?.data?.detail || err.message : String(err))
    } finally {
      setBusy(null)
    }
  }

  const row = (r: LearnedPath, actions: { action: Action; label: string; icon: React.ReactNode; tone: string }[]) => (
    <li key={r.id} className="flex flex-wrap items-center gap-3 py-2">
      <code className="text-sm text-dark-200 break-all">{r.path}</code>
      <span className="text-xs text-dark-500">
        {t('settings.learned.stats', { hosts: r.hosts, hits: r.hits, status: r.last_status ?? '—' })}
        {r.ai_verdict && ` · IA: ${r.ai_verdict}`}
      </span>
      <span className="ml-auto flex gap-2">
        {actions.map((a) => (
          <button key={a.action} disabled={busy === r.id} onClick={() => decide(r, a.action)} className={`${btn} ${a.tone}`}>
            {a.icon}{a.label}
          </button>
        ))}
      </span>
    </li>
  )

  const approve = { action: 'approve' as const, label: t('settings.learned.approve'), icon: <Check size={12} />, tone: 'border-emerald-300 text-emerald-700 hover:bg-emerald-50' }
  const reject = { action: 'reject' as const, label: t('settings.learned.reject'), icon: <X size={12} />, tone: 'border-dark-700 text-dark-400 hover:bg-dark-900' }
  const retire = { action: 'reset' as const, label: t('settings.learned.retire'), icon: <RotateCcw size={12} />, tone: 'border-dark-700 text-dark-400 hover:bg-dark-900' }

  return (
    <div className="space-y-3">
      <p className="text-xs text-dark-500 leading-relaxed">{t('settings.learned.desc')}</p>
      {error && <p className="text-xs text-red-600">{error}</p>}
      {data && (
        <>
          <div>
            <h4 className="text-sm font-medium text-dark-200">{t('settings.learned.candidates', { n: data.candidates.length })}</h4>
            {data.candidates.length === 0
              ? <p className="text-xs text-dark-500">{t('settings.learned.noCandidates', { n: data.seen })}</p>
              : <ul className="divide-y divide-dark-800">{data.candidates.map((r) => row(r, [approve, reject]))}</ul>}
          </div>
          {data.approved.length > 0 && (
            <div>
              <h4 className="text-sm font-medium text-dark-200">{t('settings.learned.approved', { n: data.approved.length })}</h4>
              <ul className="divide-y divide-dark-800">{data.approved.map((r) => row(r, [retire]))}</ul>
            </div>
          )}
          {data.rejected.length > 0 && (
            <div>
              <h4 className="text-sm font-medium text-dark-200">{t('settings.learned.rejected', { n: data.rejected.length })}</h4>
              <ul className="divide-y divide-dark-800">{data.rejected.map((r) => row(r, [retire]))}</ul>
            </div>
          )}
        </>
      )}
    </div>
  )
}
