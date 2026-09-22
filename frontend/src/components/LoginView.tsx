import { useEffect, useState } from 'react'
import axios from 'axios'
import { useTranslation } from 'react-i18next'
import { LoginResponse } from '../auth'
import { Radar, ShieldCheck, Bot, Lock, Mail } from 'lucide-react'

interface Props {
  onLogin: (resp: LoginResponse) => void
}

function Spinner() {
  return (
    <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-90" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
    </svg>
  )
}

export default function LoginView({ onLogin }: Props) {
  const { t } = useTranslation()
  const [mode, setMode] = useState<'login' | 'bootstrap'>('login')
  const [checking, setChecking] = useState(true)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let cancelled = false
    axios
      .get<{ needed: boolean }>('/api/auth/bootstrap')
      .then(({ data }) => {
        if (!cancelled && data?.needed) setMode('bootstrap')
      })
      .catch(() => {
        // Backend without auth endpoints or unreachable — stay in login mode
      })
      .finally(() => {
        if (!cancelled) setChecking(false)
      })
    return () => { cancelled = true }
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    const cleanEmail = email.trim().toLowerCase()
    if (!cleanEmail || !password) return
    setBusy(true)
    setError('')
    try {
      const url = mode === 'bootstrap' ? '/api/auth/bootstrap' : '/api/auth/login'
      const { data } = await axios.post<LoginResponse>(url, { email: cleanEmail, password })
      onLogin(data)
    } catch (err) {
      if (axios.isAxiosError(err)) {
        if (err.response?.status === 401) {
          setError(t('login.invalidCredentials'))
        } else {
          setError(err.response?.data?.detail || err.message || t('login.loginFailed'))
        }
      } else {
        setError(t('login.loginFailed'))
      }
      setBusy(false)
    }
  }

  const isBootstrap = mode === 'bootstrap'

  return (
    <div className="min-h-screen bg-dark-950 text-dark-200 flex">
      {/* Brand panel */}
      <div className="hidden lg:flex flex-col justify-between w-[46%] relative overflow-hidden bg-gradient-to-br from-cyber-50 via-white to-mint-300/20 border-r border-dark-800 px-12 py-10">
        <div className="absolute inset-0 bg-dots-cyber opacity-60" />
        <div className="relative flex items-center gap-2.5">
          <img src="/logo.svg" alt="Sauron logo" className="w-8 h-8" />
          <span className="text-lg tracking-tight">
            <span className="font-bold text-dark-100">SAURON</span>
            <span className="font-light text-dark-500 ml-1">ASM</span>
          </span>
        </div>
        <div className="relative space-y-6 max-w-md">
          <h1 className="text-4xl font-bold tracking-tight text-dark-100 leading-[1.15]">
            {t('login.heroTitle1')}<br />
            <span className="text-cyber-600">{t('login.heroTitle2')}</span>
          </h1>
          <p className="text-dark-500 text-[15px] leading-relaxed">
            {t('login.heroSub')}
          </p>
          <ul className="space-y-3 text-sm text-dark-300">
            <li className="flex items-center gap-3">
              <span className="w-8 h-8 rounded-lg bg-white border border-dark-800 flex items-center justify-center text-cyber-600 shadow-sm">
                <Radar className="w-4 h-4" />
              </span>
              {t('login.feat1')}
            </li>
            <li className="flex items-center gap-3">
              <span className="w-8 h-8 rounded-lg bg-white border border-dark-800 flex items-center justify-center text-cyber-600 shadow-sm">
                <Bot className="w-4 h-4" />
              </span>
              {t('login.feat2')}
            </li>
            <li className="flex items-center gap-3">
              <span className="w-8 h-8 rounded-lg bg-white border border-dark-800 flex items-center justify-center text-mint-500 shadow-sm">
                <ShieldCheck className="w-4 h-4" />
              </span>
              {t('login.feat3')}
            </li>
          </ul>
        </div>
        <p className="relative text-xs text-dark-500 font-mono">
          {t('login.tagline')}
        </p>
      </div>

      {/* Form panel */}
      <div className="flex-1 flex items-center justify-center px-6 py-12">
        <div className="w-full max-w-sm space-y-8">
          <div className="space-y-2">
            <div className="lg:hidden flex items-center gap-2.5 mb-6">
              <img src="/logo.svg" alt="Sauron logo" className="w-8 h-8" />
              <span className="text-lg tracking-tight">
                <span className="font-bold text-dark-100">SAURON</span>
                <span className="font-light text-dark-500 ml-1">ASM</span>
              </span>
            </div>
            <h2 className="text-2xl font-semibold tracking-tight text-dark-100">
              {isBootstrap ? t('login.createAdmin') : t('login.welcomeBack')}
            </h2>
            <p className="text-dark-500 text-sm">
              {checking
                ? t('common.loading')
                : isBootstrap
                  ? t('login.setupAdmin')
                  : t('login.signInContinue')}
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label htmlFor="login-email" className="text-xs font-semibold text-dark-300 uppercase tracking-wider">
                {t('login.email')}
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-dark-600 pointer-events-none" />
                <input
                  id="login-email"
                  type="email"
                  value={email}
                  onChange={(e) => { setEmail(e.target.value); setError('') }}
                  placeholder={t('login.emailPlaceholder')}
                  autoFocus
                  autoComplete="email"
                  spellCheck={false}
                  disabled={checking || busy}
                  className="w-full bg-white border border-dark-700 rounded-lg pl-9 pr-3 py-2.5 text-sm text-dark-100 placeholder:text-dark-600 focus:outline-none focus:border-cyber-500 focus:ring-2 focus:ring-cyber-500/20 disabled:opacity-50 transition-colors duration-150"
                />
              </div>
            </div>
            <div className="space-y-1.5">
              <label htmlFor="login-password" className="text-xs font-semibold text-dark-300 uppercase tracking-wider">
                {t('login.password')}
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-dark-600 pointer-events-none" />
                <input
                  id="login-password"
                  type="password"
                  value={password}
                  onChange={(e) => { setPassword(e.target.value); setError('') }}
                  placeholder="••••••••"
                  autoComplete={isBootstrap ? 'new-password' : 'current-password'}
                  disabled={checking || busy}
                  className="w-full bg-white border border-dark-700 rounded-lg pl-9 pr-3 py-2.5 text-sm text-dark-100 placeholder:text-dark-600 focus:outline-none focus:border-cyber-500 focus:ring-2 focus:ring-cyber-500/20 disabled:opacity-50 transition-colors duration-150"
                />
              </div>
            </div>
            {error && (
              <p className="text-red-600 text-xs bg-red-50 border border-red-200 rounded-lg px-3 py-2">{error}</p>
            )}
            <button
              type="submit"
              disabled={checking || busy || !email.trim() || !password}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-cyber-600 hover:bg-cyber-700 active:bg-cyber-800 disabled:opacity-50 text-white font-semibold rounded-lg transition-colors duration-150 text-sm shadow-sm shadow-cyber-600/20"
            >
              {busy && <Spinner />}
              {busy
                ? (isBootstrap ? t('login.creating') : t('login.signingIn'))
                : (isBootstrap ? t('login.createAdminAccount') : t('login.signIn'))}
            </button>
          </form>

          <p className="text-center text-xs text-dark-600">
            {t('login.protected')}
          </p>
          <p className="text-center text-xs text-dark-600">
            by Carlos Ganoza
          </p>
        </div>
      </div>
    </div>
  )
}
