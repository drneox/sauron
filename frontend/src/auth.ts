import axios from 'axios'

export type UserRole = 'viewer' | 'operator' | 'admin'

export interface AuthUser {
  id: number
  email: string
  role: UserRole
}

export interface UserRow {
  id: number
  email: string
  role: UserRole
  active: boolean
  created_at: string
  last_login_at: string | null
}

export interface LoginResponse {
  token: string
  user: AuthUser
}

const TOKEN_KEY = 'asm_token'

export const getToken = (): string | null => localStorage.getItem(TOKEN_KEY)

export const setToken = (token: string): void => {
  localStorage.setItem(TOKEN_KEY, token)
}

export const clearToken = (): void => {
  localStorage.removeItem(TOKEN_KEY)
}

let unauthorizedHandler: (() => void) | null = null

export function setUnauthorizedHandler(cb: (() => void) | null): void {
  unauthorizedHandler = cb
}

axios.interceptors.request.use((config) => {
  const token = getToken()
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// FastAPI answers validation failures (422) with `detail` as a list of objects.
// Screens render `detail` as text, and a list of objects crashes React (#31),
// so flatten it into a readable string once, here.
function flattenValidationDetail(detail: unknown): string | null {
  if (!Array.isArray(detail)) return null
  const parts = detail.map((d) => {
    if (typeof d === 'string') return d
    const item = d as { loc?: unknown[]; msg?: string }
    const field = Array.isArray(item.loc) ? item.loc.filter((x) => x !== 'body').join('.') : ''
    const msg = (item.msg ?? 'invalid value').replace(/^Value error, /, '')
    return field ? `${field}: ${msg}` : msg
  })
  return parts.join('; ')
}

axios.interceptors.response.use(
  (response) => response,
  (error) => {
    if (axios.isAxiosError(error) && error.response?.data && typeof error.response.data === 'object') {
      const flat = flattenValidationDetail((error.response.data as { detail?: unknown }).detail)
      if (flat !== null) (error.response.data as { detail?: unknown }).detail = flat
    }
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      // Edge gate (HTTP Basic): browsers don't show the native dialog for XHR
      // 401s — force a full-page navigation so it pops and caches the creds.
      const isEdgeGate = error.response.headers['www-authenticate'] != null
      if (isEdgeGate) {
        window.location.href = '/api/auth/bootstrap'
        return new Promise(() => {})
      }
      clearToken()
      unauthorizedHandler?.()
    }
    return Promise.reject(error)
  },
)
