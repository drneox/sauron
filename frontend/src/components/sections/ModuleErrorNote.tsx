import { AlertTriangle } from 'lucide-react'
import { useTranslation } from 'react-i18next'

// Narrows a module result that came back as an error stub: {"status":"error","error":"..."}
export function isModuleError(data: unknown): data is { status: 'error'; error?: unknown } {
  return !!data && typeof data === 'object' && (data as { status?: unknown }).status === 'error'
}

export default function ModuleErrorNote({ error }: { error?: unknown }) {
  const { t } = useTranslation()
  const msg = typeof error === 'string' && error ? error : t('common.unknownError')
  return (
    <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-700 flex items-center gap-2">
      <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
      <span>{t('report.moduleError', { msg })}</span>
    </div>
  )
}
