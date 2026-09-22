// Copyright 2026 Carlos Ganoza
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState, type ComponentType } from 'react'
import { useTranslation } from 'react-i18next'
import { Navigate, NavLink, Route, Routes, useLocation, useNavigate, useParams } from 'react-router-dom'
import { ScanReport, Company, ScanRequestPayload } from './types/report'
import { AuthUser, LoginResponse, clearToken, setToken, setUnauthorizedHandler } from './auth'
import DomainInput from './components/DomainInput'
import ScanProgress from './components/ScanProgress'
import ReportView from './components/ReportView'
import ScanHistory from './components/ScanHistory'
import CompaniesView from './components/CompaniesView'
import CompanyReportView from './components/CompanyReportView'
import RemediationView from './components/RemediationView'
import GlobalDashboard from './components/GlobalDashboard'
import AssetDetailView from './components/AssetDetailView'
import AgentScanView from './components/AgentScanView'
import ChatView from './components/ChatView'
import LoginView from './components/LoginView'
import UsersView from './components/UsersView'
import SettingsView from './components/SettingsView'
import ErrorBoundary from './components/ErrorBoundary'
import axios from 'axios'
import clsx from 'clsx'
import {
  Bot,
  Building2,
  ChevronDown,
  History,
  Languages,
  LayoutDashboard,
  LogOut,
  ScanSearch,
  Settings,
  Users,
} from 'lucide-react'

interface NavItem {
  to: string
  label: string
  icon: ComponentType<{ className?: string }>
}

type CompanyState =
  | { status: 'loading' }
  | { status: 'error' }
  | { status: 'ok'; company: Company }

// Resolve a company by route id from /api/companies (first load shows a
// "resolving…" state; unknown ids get a friendly 404).
function useCompany(companyId: string | undefined): CompanyState {
  const [state, setState] = useState<CompanyState>({ status: 'loading' })
  useEffect(() => {
    let cancelled = false
    setState({ status: 'loading' })
    axios.get<Company[]>('/api/companies')
      .then(({ data }) => {
        if (cancelled) return
        const company = data.find((c) => String(c.id) === companyId)
        setState(company ? { status: 'ok', company } : { status: 'error' })
      })
      .catch(() => {
        if (!cancelled) setState({ status: 'error' })
      })
    return () => { cancelled = true }
  }, [companyId])
  return state
}

function ResolvingCompany() {
  const { t } = useTranslation()
  return (
    <div className="flex items-center justify-center py-24 text-sm text-dark-500 animate-pulse">
      {t('nav.resolvingCompany')}
    </div>
  )
}

function CompanyNotFound() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  return (
    <div className="max-w-md mx-auto card text-center space-y-3 mt-16">
      <h2 className="text-base font-semibold tracking-tight text-dark-100">{t('nav.companyNotFoundTitle')}</h2>
      <p className="text-dark-500 text-sm leading-relaxed">{t('nav.companyNotFoundBody')}</p>
      <div className="flex justify-center gap-2">
        <button onClick={() => navigate('/companies')} className="btn-secondary">
          {t('nav.companies')}
        </button>
      </div>
    </div>
  )
}

function HomePage({ readOnly, onScan }: { readOnly: boolean; onScan: (domain: string, agentMode: boolean) => void }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  if (readOnly) {
    return (
      <div className="max-w-md mx-auto card text-center space-y-3 mt-16">
        <h2 className="text-base font-semibold tracking-tight text-dark-100">{t('nav.readOnlyTitle')}</h2>
        <p className="text-dark-500 text-sm leading-relaxed">
          {t('nav.readOnlyBody')}
        </p>
        <div className="flex justify-center gap-2">
          <button onClick={() => navigate('/history')} className="btn-secondary">
            {t('nav.history')}
          </button>
          <button onClick={() => navigate('/companies')} className="btn-secondary">
            {t('nav.companies')}
          </button>
        </div>
      </div>
    )
  }
  return <DomainInput onScan={onScan} />
}

function ScanningPage() {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate = useNavigate()
  if (!scanId) return <Navigate to="/" replace />
  return (
    <ScanProgress
      scanId={scanId}
      onComplete={(report) => navigate(`/report/${report.scan_id}`, { replace: true })}
    />
  )
}

function ReportPage() {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate = useNavigate()
  const { t } = useTranslation()
  const [report, setReport] = useState<ScanReport | null>(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    let cancelled = false
    setReport(null)
    setFailed(false)
    axios.get<ScanReport>(`/api/scan/${scanId}`)
      .then(({ data }) => { if (!cancelled) setReport(data) })
      .catch(() => { if (!cancelled) setFailed(true) })
    return () => { cancelled = true }
  }, [scanId])

  if (failed) {
    return (
      <div className="max-w-md mx-auto card text-center space-y-3 mt-16">
        <h2 className="text-base font-semibold tracking-tight text-dark-100">{t('nav.reportNotFoundTitle')}</h2>
        <p className="text-dark-500 text-sm leading-relaxed">{t('nav.reportNotFoundBody')}</p>
        <div className="flex justify-center gap-2">
          <button onClick={() => navigate('/history')} className="btn-secondary">
            {t('nav.history')}
          </button>
          <button onClick={() => navigate('/')} className="btn-secondary">
            {t('nav.newScan')}
          </button>
        </div>
      </div>
    )
  }
  if (!report) {
    return (
      <div className="flex items-center justify-center py-24 text-sm text-dark-500 animate-pulse">
        {t('nav.reportLoading')}
      </div>
    )
  }
  return (
    <ErrorBoundary>
      <ReportView report={report} onNewScan={() => navigate('/scan')} />
    </ErrorBoundary>
  )
}

function DashboardPage({ readOnly }: { readOnly: boolean }) {
  const navigate = useNavigate()
  return (
    <ErrorBoundary>
      <GlobalDashboard
        readOnly={readOnly}
        onGoToCompanies={() => navigate('/companies')}
        onOpenCompany={(c) => navigate(`/companies/${c.id}`)}
        onOpenCompanyReport={(c) => navigate(`/companies/${c.id}/report`)}
        onOpenRemediation={(c) => navigate(`/companies/${c.id}/remediations`)}
      />
    </ErrorBoundary>
  )
}

function CompaniesPage({ readOnly, isAdmin }: { readOnly: boolean; isAdmin: boolean }) {
  const navigate = useNavigate()
  return (
    <CompaniesView
      readOnly={readOnly}
      isAdmin={isAdmin}
      onScanStarted={(id) => navigate(`/scanning/${id}`)}
      onOpenDashboard={(c) => navigate(`/companies/${c.id}`)}
    />
  )
}

function CompanyDashboardPage({ readOnly }: { readOnly: boolean }) {
  const { companyId } = useParams<{ companyId: string }>()
  const navigate = useNavigate()
  const state = useCompany(companyId)
  if (state.status === 'loading') return <ResolvingCompany />
  if (state.status === 'error') return <CompanyNotFound />
  return (
    <ErrorBoundary>
      <GlobalDashboard
        readOnly={readOnly}
        onGoToCompanies={() => navigate('/companies')}
        onOpenCompany={(c) => navigate(`/companies/${c.id}`)}
        lockedCompany={state.company}
        onOpenCompanyReport={(c) => navigate(`/companies/${c.id}/report`)}
        onOpenRemediation={(c) => navigate(`/companies/${c.id}/remediations`)}
        onBack={() => navigate('/companies')}
      />
    </ErrorBoundary>
  )
}

function AssetDetailPage({ readOnly }: { readOnly: boolean }) {
  const { companyId, hostValue } = useParams<{ companyId: string; hostValue: string }>()
  const navigate = useNavigate()
  const state = useCompany(companyId)
  if (state.status === 'loading') return <ResolvingCompany />
  if (state.status === 'error') return <CompanyNotFound />
  return (
    <ErrorBoundary>
      <AssetDetailView
        company={state.company}
        hostValue={hostValue ?? ''}
        readOnly={readOnly}
        onBack={() => navigate(`/companies/${state.company.id}`)}
      />
    </ErrorBoundary>
  )
}

function CompanyReportPage() {
  const { companyId } = useParams<{ companyId: string }>()
  const navigate = useNavigate()
  const state = useCompany(companyId)
  if (state.status === 'loading') return <ResolvingCompany />
  if (state.status === 'error') return <CompanyNotFound />
  return (
    <ErrorBoundary>
      <CompanyReportView
        company={state.company}
        onBack={() => navigate(`/companies/${state.company.id}`)}
        onOpenReport={(scanId) => navigate(`/report/${scanId}`)}
      />
    </ErrorBoundary>
  )
}

function AgentPage() {
  const navigate = useNavigate()
  const { scanId } = useParams<{ scanId: string }>()
  return <AgentScanView onBack={() => navigate('/')} scanId={scanId} />
}

function RemediationPage({ readOnly }: { readOnly: boolean }) {
  const { companyId } = useParams<{ companyId: string }>()
  const navigate = useNavigate()
  const state = useCompany(companyId)
  if (state.status === 'loading') return <ResolvingCompany />
  if (state.status === 'error') return <CompanyNotFound />
  return (
    <ErrorBoundary>
      <RemediationView
        company={state.company}
        readOnly={readOnly}
        onBack={() => navigate(`/companies/${state.company.id}`)}
      />
    </ErrorBoundary>
  )
}

function HistoryPage({ readOnly }: { readOnly: boolean }) {
  const navigate = useNavigate()
  return (
    <ScanHistory
      readOnly={readOnly}
      onViewReport={(r) => navigate(`/report/${r.scan_id}`)}
      onScanStarted={(id) => navigate(`/scanning/${id}`)}
    />
  )
}

export default function App() {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const location = useLocation()
  const [user, setUser] = useState<AuthUser | null>(null)
  const [authReady, setAuthReady] = useState(false)
  const [scanMenuOpen, setScanMenuOpen] = useState(false)
  const [userMenuOpen, setUserMenuOpen] = useState(false)

  useEffect(() => {
    let cancelled = false
    setUnauthorizedHandler(() => {
      setUser(null)
    })
    // With AUTH_ENABLED=false the backend answers /me without a token (local admin),
    // so this call doubles as the "auth disabled" passthrough.
    axios.get<AuthUser>('/api/auth/me')
      .then(({ data }) => {
        if (!cancelled) setUser(data)
      })
      .catch(() => {
        // 401 already cleared the token and switched to the login view via the interceptor
      })
      .finally(() => {
        if (!cancelled) setAuthReady(true)
      })
    return () => {
      cancelled = true
      setUnauthorizedHandler(null)
    }
  }, [])

  const handleLogin = (resp: LoginResponse) => {
    setToken(resp.token)
    setUser(resp.user)
  }

  const handleLogout = async () => {
    try {
      await axios.post('/api/auth/logout')
    } catch {
      // Ignore — the session is dropped locally regardless
    }
    clearToken()
    setUser(null)
  }

  const handleScanStart = async (domain: string, agentMode = false) => {
    try {
      const payload: ScanRequestPayload = { domain }
      if (agentMode) payload.agent_mode = true
      const { data } = await axios.post('/api/scan', payload)
      navigate(agentMode ? `/agent/${data.scan_id}` : `/scanning/${data.scan_id}`)
    } catch (err: unknown) {
      const msg = axios.isAxiosError(err)
        ? err.response?.data?.detail || err.message
        : 'Unknown error'
      alert(t('home.scanStartError', { msg }))
    }
  }

  if (!authReady) {
    return (
      <div className="min-h-screen bg-dark-950 text-dark-500 flex items-center justify-center text-sm animate-pulse">
        {t('nav.appLoading')}
      </div>
    )
  }

  if (!user) {
    return <LoginView onLogin={handleLogin} />
  }

  const readOnly = user.role === 'viewer'
  const isAdmin = user.role === 'admin'

  const navItems: NavItem[] = [
    { to: '/dashboard', label: t('nav.dashboard'), icon: LayoutDashboard },
    { to: '/companies', label: t('nav.companies'), icon: Building2 },
    { to: '/history', label: t('nav.history'), icon: History },
    ...(isAdmin ? [{ to: '/users', label: t('nav.users'), icon: Users }] : []),
    ...(isAdmin ? [{ to: '/settings', label: t('nav.settings'), icon: Settings }] : []),
  ]

  const scanMenuActive = location.pathname === '/scan' || location.pathname === '/agent'

  return (
    <div className="min-h-screen bg-dark-950 text-dark-200">
      {/* Header */}
      <header className="border-b border-dark-800 px-6 h-14 flex items-center justify-between sticky top-0 bg-dark-950/90 backdrop-blur z-50">
        <button
          onClick={() => navigate('/')}
          className="flex items-center gap-2.5 rounded-lg transition-colors duration-150"
        >
          <img src="/logo.svg" alt="Sauron logo" className="w-7 h-7" />
          <span className="text-[17px] tracking-tight">
            <span className="font-bold text-dark-100">SAURON</span>
            <span className="font-light text-dark-500 ml-1">ASM</span>
          </span>
        </button>
        <nav className="flex gap-1 text-sm items-center">
          {!readOnly && (
            <div className="relative">
              <button
                onClick={() => setScanMenuOpen((o) => !o)}
                className={clsx(
                  'inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full transition-colors duration-150',
                  scanMenuActive
                    ? 'bg-cyber-100 text-cyber-700 font-medium'
                    : 'text-dark-500 hover:text-dark-100 hover:bg-dark-900',
                )}
              >
                <ScanSearch className="w-4 h-4" />
                {t('nav.scan')}
                <ChevronDown className={clsx('w-3.5 h-3.5 transition-transform duration-150', scanMenuOpen && 'rotate-180')} />
              </button>
              {scanMenuOpen && (
                <>
                  <div className="fixed inset-0 z-40" onClick={() => setScanMenuOpen(false)} />
                  <div className="absolute left-0 top-full mt-1.5 z-50 card p-1.5 min-w-[190px] shadow-lg">
                    {[
                      { to: '/scan', label: t('nav.newScan'), desc: t('nav.newScanDesc'), icon: ScanSearch },
                      { to: '/agent', label: t('nav.agentScan'), desc: t('nav.agentScanDesc'), icon: Bot },
                    ].map((opt) => (
                      <button
                        key={opt.to}
                        onClick={() => { navigate(opt.to); setScanMenuOpen(false) }}
                        className="w-full flex items-start gap-2.5 px-3 py-2 rounded-lg text-left hover:bg-cyber-50 transition-colors duration-150"
                      >
                        <opt.icon className="w-4 h-4 mt-0.5 text-cyber-600" />
                        <span>
                          <span className="block text-sm font-medium text-dark-100">{opt.label}</span>
                          <span className="block text-xs text-dark-500">{opt.desc}</span>
                        </span>
                      </button>
                    ))}
                  </div>
                </>
              )}
            </div>
          )}
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) => clsx(
                'inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full transition-colors duration-150',
                isActive
                  ? 'bg-cyber-100 text-cyber-700 font-medium'
                  : 'text-dark-500 hover:text-dark-100 hover:bg-dark-900',
              )}
            >
              <item.icon className="w-4 h-4" />
              {item.label}
            </NavLink>
          ))}
          <span className="w-px h-5 bg-dark-800 mx-2" />
          <button
            onClick={() => i18n.changeLanguage(i18n.language === 'es' ? 'en' : 'es')}
            title={t('nav.language')}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-dark-500 hover:text-dark-100 hover:bg-dark-900 transition-colors duration-150"
          >
            <Languages className="w-4 h-4" />
            <span className="text-xs font-semibold uppercase">{i18n.language === 'es' ? 'ES' : 'EN'}</span>
          </button>
          <div className="relative">
            <button
              onClick={() => setUserMenuOpen((o) => !o)}
              className={clsx(
                'inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full transition-colors duration-150',
                userMenuOpen ? 'bg-dark-900 text-dark-100' : 'text-dark-500 hover:text-dark-100 hover:bg-dark-900',
              )}
            >
              <span className="text-xs font-mono">{user.email}</span>
              <ChevronDown className={clsx('w-3.5 h-3.5 transition-transform duration-150', userMenuOpen && 'rotate-180')} />
            </button>
            {userMenuOpen && (
              <>
                <div className="fixed inset-0 z-40" onClick={() => setUserMenuOpen(false)} />
                <div className="absolute right-0 top-full mt-1.5 z-50 card p-1.5 min-w-[180px] shadow-lg">
                  <div className="px-3 py-2 border-b border-dark-800 mb-1">
                    <div className="text-xs font-medium text-dark-100">{user.email}</div>
                    <div className="text-[10px] text-dark-500 uppercase tracking-wider mt-0.5">{user.role}</div>
                  </div>
                  <button
                    onClick={() => { setUserMenuOpen(false); handleLogout() }}
                    className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-left text-sm text-red-600 hover:bg-red-50 transition-colors duration-150"
                  >
                    <LogOut className="w-4 h-4" />
                    {t('nav.signOut')}
                  </button>
                </div>
              </>
            )}
          </div>
        </nav>
      </header>

      {/* Content */}
      <main className="max-w-7xl mx-auto px-4 py-8">
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/scan" element={<HomePage readOnly={readOnly} onScan={handleScanStart} />} />
          <Route path="/scanning/:scanId" element={<ScanningPage />} />
          <Route path="/report/:scanId" element={<ReportPage />} />
          <Route path="/dashboard" element={<DashboardPage readOnly={readOnly} />} />
          <Route path="/companies" element={<CompaniesPage readOnly={readOnly} isAdmin={isAdmin} />} />
          <Route path="/companies/:companyId" element={<CompanyDashboardPage readOnly={readOnly} />} />
          <Route path="/companies/:companyId/assets/:hostValue" element={<AssetDetailPage readOnly={readOnly} />} />
          <Route path="/companies/:companyId/report" element={<CompanyReportPage />} />
          <Route path="/companies/:companyId/remediations" element={<RemediationPage readOnly={readOnly} />} />
          <Route path="/agent" element={readOnly ? <Navigate to="/history" replace /> : <AgentPage />} />
          <Route path="/agent/:scanId" element={readOnly ? <Navigate to="/history" replace /> : <AgentPage />} />
          <Route path="/history" element={<HistoryPage readOnly={readOnly} />} />
          <Route path="/users" element={isAdmin ? <UsersView currentUser={user} /> : <Navigate to="/dashboard" replace />} />
          <Route path="/settings" element={isAdmin ? <SettingsView /> : <Navigate to="/dashboard" replace />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>

      {/* Floating SauronBot — available on every view once authenticated */}
      <ChatView />

      {/* Footer */}
      <footer className="max-w-7xl mx-auto px-4 pb-6 text-center text-xs text-dark-500">
        Sauron ASM — Carlos Ganoza / <a href="https://punkbot.co" target="_blank" rel="noopener noreferrer" className="hover:text-dark-300 transition-colors duration-150">punkbot.co</a>
      </footer>
    </div>
  )
}
