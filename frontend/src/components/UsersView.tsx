import { useEffect, useState } from 'react'
import axios from 'axios'
import clsx from 'clsx'
import { useTranslation } from 'react-i18next'
import { AuthUser, UserRole, UserRow } from '../auth'
import { Trash2, X } from 'lucide-react'

interface Props {
  currentUser: AuthUser
}

const roleColor = (r: UserRole) => {
  if (r === 'admin') return 'bg-purple-50 text-purple-700 border-purple-200'
  if (r === 'operator') return 'bg-cyan-50 text-cyan-700 border-cyan-200'
  return 'bg-dark-900 text-dark-500 border-dark-800'
}

const errorMessage = (err: unknown, fallback: string) =>
  axios.isAxiosError(err)
    ? err.response?.data?.detail || err.message || fallback
    : fallback

const formatDate = (iso: string | null) =>
  iso ? new Date(iso).toLocaleString() : '—'

export default function UsersView({ currentUser }: Props) {
  const { t } = useTranslation()
  const [users, setUsers] = useState<UserRow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<UserRole>('viewer')
  const [creating, setCreating] = useState(false)
  const [busyId, setBusyId] = useState<number | null>(null)

  const load = async () => {
    try {
      const { data } = await axios.get<UserRow[]>('/api/users')
      setUsers(data)
      setError('')
    } catch (err) {
      setError(errorMessage(err, t('users.loadError')))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    setLoading(true)
    load()
  }, [])

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    const cleanEmail = email.trim().toLowerCase()
    if (!cleanEmail || !password) return
    setCreating(true)
    try {
      await axios.post('/api/users', { email: cleanEmail, password, role })
      setEmail('')
      setPassword('')
      setRole('viewer')
      await load()
    } catch (err) {
      setError(errorMessage(err, t('users.createError', { email: cleanEmail })))
    } finally {
      setCreating(false)
    }
  }

  const handleRoleChange = async (u: UserRow, newRole: UserRole) => {
    setBusyId(u.id)
    try {
      await axios.patch(`/api/users/${u.id}`, { role: newRole })
      await load()
    } catch (err) {
      setError(errorMessage(err, t('users.roleError', { email: u.email })))
    } finally {
      setBusyId(null)
    }
  }

  const handleToggleActive = async (u: UserRow) => {
    setBusyId(u.id)
    try {
      await axios.patch(`/api/users/${u.id}`, { active: !u.active })
      await load()
    } catch (err) {
      setError(errorMessage(err, t('users.updateError', { email: u.email })))
    } finally {
      setBusyId(null)
    }
  }

  const handleDelete = async (u: UserRow) => {
    if (!confirm(t('users.confirmDelete', { email: u.email }))) return
    setBusyId(u.id)
    try {
      await axios.delete(`/api/users/${u.id}`)
      await load()
    } catch (err) {
      setError(errorMessage(err, t('users.deleteError', { email: u.email })))
    } finally {
      setBusyId(null)
    }
  }

  return (
    <div className="max-w-4xl mx-auto space-y-4">
      <h2 className="text-xl font-semibold tracking-tight text-dark-100">{t('users.title')}</h2>

      <form onSubmit={handleCreate} className="card flex flex-wrap gap-2">
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="user@example.com"
          autoComplete="off"
          spellCheck={false}
          className="flex-1 min-w-[180px] bg-white border border-dark-700 rounded-lg px-3 py-2 text-sm text-dark-100 placeholder:text-dark-600 focus:outline-none focus:border-cyber-500 focus:ring-2 focus:ring-cyber-500/20 transition-colors duration-150"
        />
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder={t('users.passwordPlaceholder')}
          autoComplete="new-password"
          className="flex-1 min-w-[140px] bg-white border border-dark-700 rounded-lg px-3 py-2 text-sm text-dark-100 placeholder:text-dark-600 focus:outline-none focus:border-cyber-500 focus:ring-2 focus:ring-cyber-500/20 transition-colors duration-150"
        />
        <select
          value={role}
          onChange={(e) => setRole(e.target.value as UserRole)}
          className="bg-white border border-dark-700 rounded-lg px-3 py-2 text-sm text-dark-200 focus:outline-none focus:border-cyber-500 transition-colors duration-150"
        >
          <option value="viewer">viewer</option>
          <option value="operator">operator</option>
          <option value="admin">admin</option>
        </select>
        <button
          type="submit"
          disabled={creating || !email.trim() || !password}
          className="px-4 py-2 bg-cyber-600 hover:bg-cyber-700 disabled:opacity-50 text-white font-semibold rounded-lg transition-colors duration-150 text-sm"
        >
          {creating ? t('users.creating') : t('users.createUser')}
        </button>
      </form>

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
          {t('users.loading')}
        </div>
      ) : users.length === 0 && !error ? (
        <div className="card text-center text-dark-500 py-12 text-sm">
          {t('users.empty')}
        </div>
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-dark-500 uppercase tracking-wide border-b border-dark-800">
                <th className="py-2 pr-4 font-semibold">{t('users.email')}</th>
                <th className="py-2 pr-4 font-semibold">{t('users.role')}</th>
                <th className="py-2 pr-4 font-semibold">{t('users.status')}</th>
                <th className="py-2 pr-4 font-semibold">{t('users.lastLogin')}</th>
                <th className="py-2 pr-4 font-semibold">{t('users.created')}</th>
                <th className="py-2 font-semibold text-right">{t('users.actions')}</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => {
                const isSelf = u.id === currentUser.id
                const busy = busyId === u.id
                return (
                  <tr key={u.id} className="border-b border-dark-800 last:border-0">
                    <td className="py-2.5 pr-4 text-dark-100 break-all">
                      {u.email}
                      {isSelf && <span className="text-dark-500 text-xs ml-2">{t('users.you')}</span>}
                    </td>
                    <td className="py-2.5 pr-4">
                      <div className="flex items-center gap-2">
                        <span className={clsx('text-[11px] px-2 py-0.5 rounded-full font-semibold border uppercase tracking-wide', roleColor(u.role))}>
                          {u.role}
                        </span>
                        {!isSelf && (
                          <select
                            value={u.role}
                            disabled={busy}
                            onChange={(e) => handleRoleChange(u, e.target.value as UserRole)}
                            className="bg-white border border-dark-700 rounded-lg px-2 py-1 text-xs text-dark-200 focus:outline-none focus:border-cyber-500 disabled:opacity-50 transition-colors duration-150"
                          >
                            <option value="viewer">viewer</option>
                            <option value="operator">operator</option>
                            <option value="admin">admin</option>
                          </select>
                        )}
                      </div>
                    </td>
                    <td className="py-2.5 pr-4">
                      <button
                        onClick={() => handleToggleActive(u)}
                        disabled={busy || isSelf}
                        title={isSelf ? t('users.cannotDeactivate') : (u.active ? t('users.deactivate') : t('users.activate'))}
                        className={clsx(
                          'text-[11px] px-2 py-0.5 rounded-full font-semibold border transition-colors duration-150 disabled:opacity-50 disabled:cursor-not-allowed',
                          u.active
                            ? 'bg-emerald-50 text-emerald-700 border-emerald-200 hover:bg-emerald-100'
                            : 'bg-dark-900 text-dark-500 border-dark-800 hover:text-dark-300',
                        )}
                      >
                        {u.active ? t('users.active') : t('users.disabled')}
                      </button>
                    </td>
                    <td className="py-2.5 pr-4 text-dark-400 text-xs whitespace-nowrap">
                      {formatDate(u.last_login_at)}
                    </td>
                    <td className="py-2.5 pr-4 text-dark-500 text-xs whitespace-nowrap">
                      {formatDate(u.created_at)}
                    </td>
                    <td className="py-2.5 text-right">
                      <button
                        onClick={() => handleDelete(u)}
                        disabled={busy || isSelf}
                        title={isSelf ? t('users.cannotDelete') : t('users.deleteUser')}
                        className="p-1.5 text-dark-500 hover:text-red-600 hover:bg-red-50 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg transition-colors duration-150"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
