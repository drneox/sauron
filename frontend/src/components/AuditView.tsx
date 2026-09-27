import { Fragment, useEffect, useState } from 'react'
import axios from 'axios'
import clsx from 'clsx'
import { useTranslation } from 'react-i18next'
import { ChevronRight, X } from 'lucide-react'
import { Pager } from './ui'

interface AuditEvent {
  id: number
  created_at: string
  user_email: string | null
  action: string
  target: string | null
  detail: Record<string, unknown> | null
  ip: string | null
}

interface AuditResponse {
  total: number
  actions: string[]
  events: AuditEvent[]
}

const LIMIT = 50

const errorMessage = (err: unknown, fallback: string) =>
  axios.isAxiosError(err)
    ? err.response?.data?.detail || err.message || fallback
    : fallback

const detailValue = (value: unknown): string => {
  if (value == null) return '—'
  if (typeof value === 'string') return value
  return JSON.stringify(value)
}

export default function AuditView() {
  const { t } = useTranslation()
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [total, setTotal] = useState(0)
  const [actions, setActions] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [actionFilter, setActionFilter] = useState('')
  const [emailInput, setEmailInput] = useState('')
  const [emailFilter, setEmailFilter] = useState('')
  const [offset, setOffset] = useState(0)
  const [expanded, setExpanded] = useState<number | null>(null)

  // Debounce the free-text email filter so typing doesn't fire a request per keystroke.
  useEffect(() => {
    const timer = setTimeout(() => {
      setEmailFilter(emailInput.trim())
      setOffset(0)
    }, 400)
    return () => clearTimeout(timer)
  }, [emailInput])

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    axios.get<AuditResponse>('/api/audit', {
      params: {
        ...(actionFilter ? { action: actionFilter } : {}),
        ...(emailFilter ? { user_email: emailFilter } : {}),
        limit: LIMIT,
        offset,
      },
    })
      .then(({ data }) => {
        if (cancelled) return
        setEvents(data.events)
        setTotal(data.total)
        setActions(data.actions)
        setError('')
      })
      .catch((err) => {
        if (!cancelled) setError(errorMessage(err, t('audit.loadError')))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => { cancelled = true }
  }, [actionFilter, emailFilter, offset])

  const page = Math.floor(offset / LIMIT) + 1

  return (
    <div className="max-w-5xl mx-auto space-y-4">
      <h2 className="text-xl font-semibold tracking-tight text-dark-100">{t('audit.title')}</h2>

      <div className="card flex flex-wrap gap-2">
        <select
          value={actionFilter}
          onChange={(e) => { setActionFilter(e.target.value); setOffset(0) }}
          className="bg-white border border-dark-700 rounded-lg px-3 py-2 text-sm text-dark-200 focus:outline-none focus:border-cyber-500 transition-colors duration-150"
        >
          <option value="">{t('audit.allActions')}</option>
          {actions.map((a) => (
            <option key={a} value={a}>{a}</option>
          ))}
        </select>
        <input
          type="text"
          value={emailInput}
          onChange={(e) => setEmailInput(e.target.value)}
          placeholder={t('audit.userPlaceholder')}
          autoComplete="off"
          spellCheck={false}
          className="flex-1 min-w-[180px] bg-white border border-dark-700 rounded-lg px-3 py-2 text-sm text-dark-100 placeholder:text-dark-600 focus:outline-none focus:border-cyber-500 focus:ring-2 focus:ring-cyber-500/20 transition-colors duration-150"
        />
      </div>

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

      {loading ? (
        <div className="card text-center text-dark-500 py-12 text-sm animate-pulse">
          {t('audit.loading')}
        </div>
      ) : events.length === 0 && !error ? (
        <div className="card text-center text-dark-500 py-12 text-sm">
          {t('audit.empty')}
        </div>
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-dark-500 uppercase tracking-wide border-b border-dark-800">
                <th className="py-2 pr-2 font-semibold w-6" />
                <th className="py-2 pr-4 font-semibold">{t('audit.col.time')}</th>
                <th className="py-2 pr-4 font-semibold">{t('audit.col.user')}</th>
                <th className="py-2 pr-4 font-semibold">{t('audit.col.action')}</th>
                <th className="py-2 pr-4 font-semibold">{t('audit.col.target')}</th>
                <th className="py-2 font-semibold">{t('audit.col.ip')}</th>
              </tr>
            </thead>
            <tbody>
              {events.map((ev) => {
                const hasDetail = !!ev.detail && Object.keys(ev.detail).length > 0
                return (
                  <Fragment key={ev.id}>
                    <tr
                      onClick={() => hasDetail && setExpanded(expanded === ev.id ? null : ev.id)}
                      className={clsx(
                        'border-b border-dark-800 last:border-0',
                        hasDetail && 'cursor-pointer hover:bg-dark-900/40',
                      )}
                    >
                      <td className="py-2.5 pr-2 text-dark-500">
                        {hasDetail && (
                          <ChevronRight className={clsx('w-3.5 h-3.5 transition-transform duration-150', expanded === ev.id && 'rotate-90')} />
                        )}
                      </td>
                      <td className="py-2.5 pr-4 text-dark-400 text-xs whitespace-nowrap">
                        {new Date(ev.created_at).toLocaleString()}
                      </td>
                      <td className="py-2.5 pr-4 text-dark-100 break-all">
                        {ev.user_email ?? (
                          <span className="text-dark-500 italic">{t('audit.system')}</span>
                        )}
                      </td>
                      <td className="py-2.5 pr-4 font-mono text-xs text-dark-200">{ev.action}</td>
                      <td className="py-2.5 pr-4 font-mono text-xs text-dark-300 break-all">
                        {ev.target ?? '—'}
                      </td>
                      <td className="py-2.5 font-mono text-xs text-dark-500 whitespace-nowrap">
                        {ev.ip ?? '—'}
                      </td>
                    </tr>
                    {expanded === ev.id && hasDetail && (
                      <tr className="bg-dark-900/30">
                        <td colSpan={6} className="px-6 py-3">
                          <div className="text-xs">
                            <div className="text-[11px] font-semibold uppercase tracking-wider text-dark-500 mb-1">
                              {t('audit.detail')}
                            </div>
                            <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-0.5 rounded-md bg-dark-900/50 border border-dark-800 px-3 py-2 mt-1">
                              {Object.entries(ev.detail!).map(([key, value]) => (
                                <Fragment key={key}>
                                  <dt className="text-dark-500 whitespace-nowrap">{key}</dt>
                                  <dd className="text-dark-200 font-mono break-all">{detailValue(value)}</dd>
                                </Fragment>
                              ))}
                            </dl>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
          <div className="pt-3 flex justify-end">
            <Pager
              page={page}
              total={total}
              pageSize={LIMIT}
              onPage={(p) => setOffset((p - 1) * LIMIT)}
            />
          </div>
        </div>
      )}
    </div>
  )
}
