import { useState } from 'react'
import axios from 'axios'
import { useTranslation } from 'react-i18next'
import { Smartphone, X } from 'lucide-react'
import { CompanyDomain } from '../types/report'

interface Props {
  domains: CompanyDomain[]
  defaultDomain?: string
  onClose: () => void
  onAdded: () => void
}

const input = 'w-full bg-white border border-dark-700 rounded-lg px-3 py-2 text-sm text-dark-100 placeholder:text-dark-600 focus:outline-none focus:border-cyber-500 focus:ring-2 focus:ring-cyber-500/20 transition-colors duration-150'
const label = 'block text-[10px] font-semibold text-dark-500 uppercase tracking-wider mb-1'

export default function AddAppModal({ domains, defaultDomain, onClose, onAdded }: Props) {
  const { t } = useTranslation()
  const [domainId, setDomainId] = useState<number | ''>(
    domains.find((d) => d.domain === defaultDomain)?.id ?? domains[0]?.id ?? '',
  )
  const [store, setStore] = useState<'app_store' | 'google_play'>('google_play')
  const [name, setName] = useState('')
  const [developer, setDeveloper] = useState('')
  const [url, setUrl] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (domainId === '' || !name.trim()) return
    setSaving(true)
    setError('')
    try {
      await axios.post(`/api/domains/${domainId}/apps`, {
        store,
        name: name.trim(),
        developer: developer.trim() || null,
        url: url.trim() || null,
      })
      onAdded()
      onClose()
    } catch (err) {
      const detail = axios.isAxiosError(err) ? err.response?.data?.detail : null
      setError(typeof detail === 'string' ? detail : (axios.isAxiosError(err) ? err.message : t('common.unknownError')))
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-dark-50/40 backdrop-blur-sm p-4">
      <form onSubmit={submit} className="card w-full max-w-md shadow-lg space-y-4">
        <div className="flex items-center gap-2">
          <Smartphone className="w-4 h-4 text-cyber-600" />
          <h3 className="text-base font-semibold tracking-tight text-dark-100 flex-1">{t('assets.addApp.title')}</h3>
          <button type="button" onClick={onClose} className="p-1.5 text-dark-500 hover:text-dark-200 hover:bg-dark-900 rounded-lg" title={t('common.close')}>
            <X className="w-4 h-4" />
          </button>
        </div>
        <p className="text-xs text-dark-500">{t('assets.addApp.hint')}</p>

        {domains.length > 1 && (
          <div>
            <label className={label}>{t('assets.addApp.domain')}</label>
            <select value={domainId} onChange={(e) => setDomainId(Number(e.target.value))} className={input}>
              {domains.map((d) => <option key={d.id} value={d.id}>{d.domain}</option>)}
            </select>
          </div>
        )}
        <div>
          <label className={label}>{t('assets.addApp.store')}</label>
          <select value={store} onChange={(e) => setStore(e.target.value as 'app_store' | 'google_play')} className={input}>
            <option value="google_play">Google Play</option>
            <option value="app_store">App Store</option>
          </select>
        </div>
        <div>
          <label className={label}>{t('assets.addApp.name')}</label>
          <input value={name} onChange={(e) => setName(e.target.value)} autoFocus spellCheck={false} className={input} placeholder="Instagram" />
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label className={label}>{t('assets.addApp.developer')} <span className="normal-case font-normal text-dark-600">{t('agent.optional')}</span></label>
            <input value={developer} onChange={(e) => setDeveloper(e.target.value)} spellCheck={false} className={input} />
          </div>
          <div>
            <label className={label}>URL <span className="normal-case font-normal text-dark-600">{t('agent.optional')}</span></label>
            <input value={url} onChange={(e) => setUrl(e.target.value)} spellCheck={false} className={input} placeholder="https://" />
          </div>
        </div>

        {error && <p className="text-red-600 text-xs bg-red-50 border border-red-200 rounded-lg px-3 py-2">{error}</p>}

        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} disabled={saving} className="btn-secondary">{t('common.cancel')}</button>
          <button
            type="submit"
            disabled={saving || !name.trim() || domainId === ''}
            className="text-xs px-4 py-1.5 bg-cyber-600 hover:bg-cyber-700 disabled:opacity-50 text-white font-semibold rounded-lg transition-colors duration-150"
          >
            {saving ? t('companies.adding') : t('assets.addApp.submit')}
          </button>
        </div>
      </form>
    </div>
  )
}
