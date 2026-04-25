import { create } from 'zustand'
import apiClient, { AUTH_TOKEN_STORAGE_KEY } from '@/api/client'

type AuthUser = {
  name: string
  email: string
}

type StoredUser = AuthUser & {
  password: string
}

type AuthResult = {
  ok: boolean
  message: string
}

interface AuthState {
  user: AuthUser | null
  isAuthenticated: boolean
  login: (email: string, password: string) => Promise<AuthResult>
  signup: (name: string, email: string, password: string) => Promise<AuthResult>
  logout: () => void
}

const CURRENT_USER_KEY = 'nids_current_user'
const USERS_KEY = 'nids_users'

const LOGIN_PATH = import.meta.env.VITE_AUTH_LOGIN_PATH ?? '/login'
const SIGNUP_PATH = import.meta.env.VITE_AUTH_SIGNUP_PATH ?? '/signup'
const FALLBACK_LOCAL = (import.meta.env.VITE_AUTH_FALLBACK_LOCAL ?? 'true') === 'true'

function readUsers(): StoredUser[] {
  try {
    const raw = localStorage.getItem(USERS_KEY)
    if (!raw) return []
    return JSON.parse(raw) as StoredUser[]
  } catch {
    return []
  }
}

function writeUsers(users: StoredUser[]) {
  localStorage.setItem(USERS_KEY, JSON.stringify(users))
}

function readCurrentUser(): AuthUser | null {
  try {
    const raw = localStorage.getItem(CURRENT_USER_KEY)
    if (!raw) return null
    return JSON.parse(raw) as AuthUser
  } catch {
    return null
  }
}

function persistSession(user: AuthUser, token?: string) {
  localStorage.setItem(CURRENT_USER_KEY, JSON.stringify(user))
  if (token) {
    localStorage.setItem(AUTH_TOKEN_STORAGE_KEY, token)
  }
}

function clearSession() {
  localStorage.removeItem(CURRENT_USER_KEY)
  localStorage.removeItem(AUTH_TOKEN_STORAGE_KEY)
}

function normalizeUser(payload: any, fallbackEmail: string, fallbackName?: string): AuthUser {
  const name = payload?.user?.name ?? payload?.name ?? fallbackName ?? fallbackEmail.split('@')[0] ?? 'Analyst'
  const email = payload?.user?.email ?? payload?.email ?? fallbackEmail
  return { name: String(name), email: String(email) }
}

async function tryBackendLogin(email: string, password: string): Promise<{ user: AuthUser; token?: string } | null> {
  const response = await apiClient.post(LOGIN_PATH, { email, password })
  const data = response.data as any
  const token = data?.access_token ?? data?.token ?? data?.jwt ?? undefined
  const user = normalizeUser(data, email)
  return { user, token }
}

async function tryBackendSignup(name: string, email: string, password: string): Promise<{ user: AuthUser; token?: string } | null> {
  const response = await apiClient.post(SIGNUP_PATH, { name, email, password })
  const data = response.data as any
  const token = data?.access_token ?? data?.token ?? data?.jwt ?? undefined
  const user = normalizeUser(data, email, name)
  return { user, token }
}

function localLogin(email: string, password: string): AuthUser | null {
  const users = readUsers()
  const match = users.find(
    u => u.email.toLowerCase() === email.trim().toLowerCase() && u.password === password
  )
  if (!match) return null
  return { name: match.name, email: match.email }
}

function localSignup(name: string, email: string, password: string): { ok: boolean; user?: AuthUser; message: string } {
  const normalizedEmail = email.trim().toLowerCase()
  const users = readUsers()
  const exists = users.some(u => u.email.toLowerCase() === normalizedEmail)
  if (exists) {
    return { ok: false, message: 'Account already exists with this email' }
  }

  const newUser: StoredUser = {
    name: name.trim(),
    email: normalizedEmail,
    password,
  }
  users.push(newUser)
  writeUsers(users)
  return { ok: true, user: { name: newUser.name, email: newUser.email }, message: 'Signup successful' }
}

export const useAuthStore = create<AuthState>((set) => {
  const initialUser = readCurrentUser()

  return {
    user: initialUser,
    isAuthenticated: Boolean(initialUser),

    login: async (email, password) => {
      try {
        const backend = await tryBackendLogin(email, password)
        if (backend) {
          persistSession(backend.user, backend.token)
          set({ user: backend.user, isAuthenticated: true })
          return { ok: true, message: 'Login successful' }
        }
      } catch (e: any) {
        if (!FALLBACK_LOCAL) {
          return { ok: false, message: e?.message ?? 'Backend login failed' }
        }
      }

      if (!FALLBACK_LOCAL) {
        return { ok: false, message: 'Backend login endpoint is unavailable' }
      }

      const user = localLogin(email, password)
      if (!user) {
        return { ok: false, message: 'Invalid email or password' }
      }

      persistSession(user)
      set({ user, isAuthenticated: true })
      return { ok: true, message: 'Logged in (local fallback mode)' }
    },

    signup: async (name, email, password) => {
      try {
        const backend = await tryBackendSignup(name, email, password)
        if (backend) {
          persistSession(backend.user, backend.token)
          set({ user: backend.user, isAuthenticated: true })
          return { ok: true, message: 'Signup successful' }
        }
      } catch (e: any) {
        if (!FALLBACK_LOCAL) {
          return { ok: false, message: e?.message ?? 'Backend signup failed' }
        }
      }

      if (!FALLBACK_LOCAL) {
        return { ok: false, message: 'Backend signup endpoint is unavailable' }
      }

      const result = localSignup(name, email, password)
      if (!result.ok || !result.user) {
        return { ok: false, message: result.message }
      }

      persistSession(result.user)
      set({ user: result.user, isAuthenticated: true })
      return { ok: true, message: 'Account created (local fallback mode)' }
    },

    logout: () => {
      clearSession()
      set({ user: null, isAuthenticated: false })
    },
  }
})
