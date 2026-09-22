// Copyright 2026 Carlos Ganoza
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from 'react'
import axios from 'axios'
import { useTranslation } from 'react-i18next'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { SectionCard } from './ui'
import { BarChart3 } from 'lucide-react'

const SEV_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#94a3b8',
}
const CAT_COLORS: Record<string, string> = {
  vulnerability: '#dc2626',
  misconfiguration: '#d97706',
  exposure: '#7c3aed',
  info: '#64748b',
}
const SURFACE_COLORS: Record<string, string> = {
  subdomain: '#7c3aed',
  ip: '#0891b2',
  port: '#d97706',
  endpoint: '#059669',
  app: '#db2777',
  neighbor: '#64748b',
}
const COMPANY_COLORS = ['#7c3aed', '#0891b2', '#059669', '#d97706', '#db2777', '#64748b', '#dc2626', '#2563eb']

interface Analytics {
  scope_company: string | null
  findings_by_severity: Record<string, number>
  findings_by_category: Record<string, number>
  per_company: { company: string; critical: number; high: number; medium: number; low: number; score: number | null; grade: string | null }[]
  surface_timeline: Record<string, unknown>[]
  rating_trend: { date: string; company: string; score: number }[]
  remediation: { company: string; open: number; accepted: number; fixed: number }[]
}

const chartText = { fontSize: 11, fill: '#64748b' }

export default function DashboardAnalytics({ companyId }: { companyId: number | null }) {
  const { t } = useTranslation()
  const [data, setData] = useState<Analytics | null>(null)

  useEffect(() => {
    setData(null)
    axios.get<Analytics>('/api/dashboard/analytics', { params: companyId ? { company_id: companyId } : {} })
      .then(({ data }) => setData(data))
      .catch(() => setData(null))
  }, [companyId])

  if (!data) return null

  const sevData = Object.entries(data.findings_by_severity)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }))
  const catData = Object.entries(data.findings_by_category)
    .map(([name, value]) => ({ name, value }))
  const surfaceKeys = Array.from(new Set(
    data.surface_timeline.flatMap((row) => Object.keys(row).filter((k) => k !== 'date')),
  ))
  const ratingCompanies = Array.from(new Set(data.rating_trend.map((p) => p.company)))
  // Pivot rating trend: one row per date, one key per company
  const ratingByDate = new Map<string, Record<string, unknown>>()
  for (const p of data.rating_trend) {
    const row = ratingByDate.get(p.date) ?? { date: p.date }
    row[p.company] = p.score
    ratingByDate.set(p.date, row)
  }
  const ratingRows = Array.from(ratingByDate.values()).sort((a, b) => String(a.date).localeCompare(String(b.date)))

  const hasFindings = sevData.length > 0
  const hasSurface = data.surface_timeline.length > 0
  const hasRatings = ratingRows.length > 1
  const hasRemediation = data.remediation.length > 0
  if (!hasFindings && !hasSurface && !hasRatings && !hasRemediation) return null

  return (
    <SectionCard title={t('analytics.title')} icon={<BarChart3 />}>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {hasFindings && (
          <div className="border border-dark-800 rounded-xl p-3">
            <h4 className="text-xs font-semibold text-dark-500 uppercase tracking-wider mb-2">{t('analytics.bySeverity')}</h4>
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie data={sevData} dataKey="value" nameKey="name" innerRadius={45} outerRadius={70} paddingAngle={2}>
                  {sevData.map((s) => <Cell key={s.name} fill={SEV_COLORS[s.name]} />)}
                </Pie>
                <Tooltip />
                <Legend formatter={(v) => <span style={chartText}>{v}</span>} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        )}

        {hasFindings && (
          <div className="border border-dark-800 rounded-xl p-3">
            <h4 className="text-xs font-semibold text-dark-500 uppercase tracking-wider mb-2">{t('analytics.byCategory')}</h4>
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={catData} layout="vertical">
                <XAxis type="number" tick={chartText} />
                <YAxis type="category" dataKey="name" width={110} tick={chartText} />
                <Tooltip />
                <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                  {catData.map((c) => <Cell key={c.name} fill={CAT_COLORS[c.name]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}

        {data.per_company.length > 1 && (
          <div className="border border-dark-800 rounded-xl p-3">
            <h4 className="text-xs font-semibold text-dark-500 uppercase tracking-wider mb-2">{t('analytics.perCompany')}</h4>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={data.per_company}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                <XAxis dataKey="company" tick={chartText} />
                <YAxis tick={chartText} />
                <Tooltip />
                <Legend formatter={(v) => <span style={chartText}>{v}</span>} />
                <Bar dataKey="critical" stackId="s" fill={SEV_COLORS.critical} />
                <Bar dataKey="high" stackId="s" fill={SEV_COLORS.high} />
                <Bar dataKey="medium" stackId="s" fill={SEV_COLORS.medium} />
                <Bar dataKey="low" stackId="s" fill={SEV_COLORS.low} radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}

        {hasSurface && (
          <div className="border border-dark-800 rounded-xl p-3">
            <h4 className="text-xs font-semibold text-dark-500 uppercase tracking-wider mb-2">{t('analytics.surfaceOverTime')}</h4>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={data.surface_timeline}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                <XAxis dataKey="date" tick={chartText} />
                <YAxis tick={chartText} />
                <Tooltip />
                <Legend formatter={(v) => <span style={chartText}>{v}</span>} />
                {surfaceKeys.map((k) => (
                  <Area key={k} type="monotone" dataKey={k} stackId="1"
                    stroke={SURFACE_COLORS[k] ?? '#94a3b8'} fill={SURFACE_COLORS[k] ?? '#94a3b8'} fillOpacity={0.35} />
                ))}
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}

        {hasRatings && (
          <div className="border border-dark-800 rounded-xl p-3">
            <h4 className="text-xs font-semibold text-dark-500 uppercase tracking-wider mb-2">{t('analytics.ratingTrend')}</h4>
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={ratingRows}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                <XAxis dataKey="date" tick={chartText} />
                <YAxis domain={[0, 100]} tick={chartText} />
                <Tooltip />
                <Legend formatter={(v) => <span style={chartText}>{v}</span>} />
                {ratingCompanies.map((c, i) => (
                  <Line key={c} type="monotone" dataKey={c} stroke={COMPANY_COLORS[i % COMPANY_COLORS.length]}
                    strokeWidth={2} dot={false} connectNulls />
                ))}
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}

        {hasRemediation && (
          <div className="border border-dark-800 rounded-xl p-3">
            <h4 className="text-xs font-semibold text-dark-500 uppercase tracking-wider mb-2">{t('analytics.remediation')}</h4>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={data.remediation} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                <XAxis type="number" tick={chartText} />
                <YAxis type="category" dataKey="company" width={110} tick={chartText} />
                <Tooltip />
                <Legend formatter={(v) => <span style={chartText}>{v}</span>} />
                <Bar dataKey="fixed" stackId="r" fill="#059669" />
                <Bar dataKey="accepted" stackId="r" fill="#d97706" />
                <Bar dataKey="open" stackId="r" fill="#dc2626" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    </SectionCard>
  )
}
