import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ScanReport } from '../types/report'
import { getToken } from '../auth'
import { RiskBadge } from './ui'
import { Download, Plus } from 'lucide-react'
import ScoreCard from './sections/ScoreCard'
import FindingsPanel from './sections/FindingsPanel'
import ChangesSection from './sections/ChangesSection'
import AiSummarySection from './sections/AiSummarySection'
import WhoisSection from './sections/WhoisSection'
import DnsSection from './sections/DnsSection'
import SslSection from './sections/SslSection'
import HeadersSection from './sections/HeadersSection'
import EmailSection from './sections/EmailSection'
import TechSection from './sections/TechSection'
import BreachSection from './sections/BreachSection'
import ExposedFilesSection from './sections/ExposedFilesSection'
import BlacklistSection from './sections/BlacklistSection'
import PortsSection from './sections/PortsSection'
import SubdomainsSection from './sections/SubdomainsSection'
import CorsSection from './sections/CorsSection'
import CookieSection from './sections/CookieSection'
import JsSecretsSection from './sections/JsSecretsSection'
import SecretVerificationSection from './sections/SecretVerificationSection'
import WafSection from './sections/WafSection'
import RobotsSection from './sections/RobotsSection'
import DnssecSection from './sections/DnssecSection'
import AdminSection from './sections/AdminSection'
import TlsAuditSection from './sections/TlsAuditSection'
import CloudStorageSection from './sections/CloudStorageSection'
import ApiExposureSection from './sections/ApiExposureSection'
import WaybackSection from './sections/WaybackSection'
import NucleiSection from './sections/NucleiSection'

interface Props {
  report: ScanReport
  onNewScan: () => void
}

export default function ReportView({ report, onNewScan }: Props) {
  const { t } = useTranslation()
  const d = new Date(report.scanned_at)
  const dateStr = d.toLocaleString()
  const [downloading, setDownloading] = useState(false)
  const modules = report.modules ?? ({} as ScanReport['modules'])
  const findings = report.findings ?? []
  const scorecard = report.scorecard

  const handleDownloadPdf = async () => {
    setDownloading(true)
    try {
      const res = await fetch(`/api/scan/${report.scan_id}/report.pdf`, {
        headers: { Authorization: `Bearer ${getToken() ?? ''}` },
      })
      if (!res.ok) {
        let detail = `HTTP ${res.status}`
        try { const j = await res.json(); detail = j.detail || detail } catch {}
        throw new Error(detail)
      }
      const blob = await res.blob()
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href     = url
      a.download = `sauron_${report.domain}.pdf`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      console.error('PDF download failed:', e)
      alert(t('report.pdfError', { msg: e instanceof Error ? e.message : String(e) }))
    } finally {
      setDownloading(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Report Header */}
      <div className="card flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <h1 className="text-xl font-bold tracking-tight text-dark-100 font-mono">{report.domain}</h1>
            {scorecard?.overall_risk && <RiskBadge risk={scorecard.overall_risk} />}
          </div>
          <p className="text-dark-500 text-xs">
            {t('report.scannedOn', { date: dateStr, count: findings.length })}
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={onNewScan}
            className="btn-secondary"
          >
            <Plus className="w-3.5 h-3.5" />
            {t('report.newScan')}
          </button>
          <button
            onClick={handleDownloadPdf}
            disabled={downloading}
            className="px-4 py-1.5 bg-cyber-600 hover:bg-cyber-700 disabled:opacity-50 disabled:cursor-wait rounded-lg text-xs text-white font-semibold transition-colors duration-150 flex items-center gap-1.5"
          >
            {downloading ? (
              <>
                <svg className="animate-spin w-3 h-3" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"/>
                </svg>
                {t('report.generating')}
              </>
            ) : (
              <>
                <Download className="w-3.5 h-3.5" />
                {t('report.exportPdf')}
              </>
            )}
          </button>
        </div>
      </div>

      {/* Score + Findings */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <ScoreCard scorecard={scorecard} modules={modules} />
        <div className="lg:col-span-2">
          <FindingsPanel findings={findings} baseUrl={`https://${report.domain}`} />
        </div>
      </div>

      {/* Changes vs previous scan */}
      {report.changes && <ChangesSection changes={report.changes} />}

      {/* AI Summary */}
      {report.ai_summary && <AiSummarySection summary={report.ai_summary} />}

      {/* Infrastructure & DNS */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <WhoisSection data={modules.whois} />
        <DnsSection data={modules.dns} />
        {modules.dnssec && <DnssecSection data={modules.dnssec} />}
        {modules.waf && <WafSection data={modules.waf} />}
      </div>

      {/* TLS / SSL */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <SslSection data={modules.ssl} />
        {modules.tls && <TlsAuditSection data={modules.tls} />}
      </div>

      {/* HTTP Security */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <HeadersSection data={modules.headers} />
        {modules.cors && <CorsSection data={modules.cors} />}
        {modules.cookies && <CookieSection data={modules.cookies} />}
        <EmailSection data={modules.email} />
      </div>

      {/* Recon */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <TechSection data={modules.tech} frontendCve={modules.frontend_cve} />
        {modules.robots && <RobotsSection data={modules.robots} />}
        {modules.blacklist && <BlacklistSection data={modules.blacklist} />}
      </div>

      {/* Attack surface */}
      {modules.js_secrets && <JsSecretsSection data={modules.js_secrets} />}
      {modules.secret_verification && <SecretVerificationSection data={modules.secret_verification} />}
      {modules.admin && <AdminSection data={modules.admin} />}
      {modules.exposed && <ExposedFilesSection data={modules.exposed} />}
      {modules.breach && <BreachSection data={modules.breach} />}

      {/* Cloud & API */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {modules.cloud_storage && <CloudStorageSection data={modules.cloud_storage} />}
        {modules.api_exposure && <ApiExposureSection data={modules.api_exposure} />}
      </div>

      {/* Historical & Deep Scan */}
      {modules.wayback && <WaybackSection data={modules.wayback} />}
      {modules.nuclei && <NucleiSection data={modules.nuclei} />}

      {/* Network */}
      {modules.ports && <PortsSection data={modules.ports} />}
      {modules.subdomains && <SubdomainsSection data={modules.subdomains} />}
    </div>
  )
}
