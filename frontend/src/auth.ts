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

axios.interceptors.response.use(
  (response) => response,
  (error) => {
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
