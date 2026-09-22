import clsx from 'clsx'
import { AgentScanStep } from '../types/report'
import { AlertTriangle } from 'lucide-react'

function toolBadgeClass(tool: string): string {
  const t = tool.toLowerCase()
  if (/subdomain|enum|dns|discover/.test(t)) return 'bg-cyan-50 text-cyan-700 border-cyan-200'
  if (/js|secret|wayback|code/.test(t)) return 'bg-purple-50 text-purple-700 border-purple-200'
  if (/verify|validat|confirm/.test(t)) return 'bg-red-50 text-red-700 border-red-200'
  if (/finish|final|summar|report|done/.test(t)) return 'bg-emerald-50 text-emerald-700 border-emerald-200'
  if (/port|nuclei|scan|probe/.test(t)) return 'bg-orange-50 text-orange-700 border-orange-200'
  return 'bg-dark-900 text-dark-300 border-dark-800'
}

export function AgentStepCard({ step }: { step: AgentScanStep }) {
  return (
    <div className="card space-y-2 border-l-2 border-l-cyber-400">
      <div className="flex items-center gap-3 flex-wrap">
        <span className="text-xs font-bold text-dark-500">#{step.n}</span>
        <span className={clsx('text-[10px] px-2 py-0.5 rounded-md border font-semibold uppercase tracking-wide', toolBadgeClass(step.tool))}>
          {step.tool}
        </span>
        <code className="text-xs text-cyber-700 break-all font-mono">{step.target}</code>
        {typeof step.duration_s === 'number' && (
          <span className="ml-auto text-[10px] text-dark-500">{step.duration_s.toFixed(1)}s</span>
        )}
      </div>
      {step.reasoning && (
        <blockquote className="border-l-2 border-purple-300 pl-3 text-sm italic text-purple-900/80 leading-relaxed">
          "{step.reasoning}"
        </blockquote>
      )}
      {step.result_summary && (
        <p className="text-xs text-dark-400">{step.result_summary}</p>
      )}
      {step.new_findings && step.new_findings.length > 0 && (
        <ul className="space-y-1 pt-1">
          {step.new_findings.map((f, i) => (
            <li key={i} className="flex items-start gap-2 text-xs text-amber-700">
              <AlertTriangle className="w-3.5 h-3.5 mt-px shrink-0 text-amber-500" />
              <span>{f}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
