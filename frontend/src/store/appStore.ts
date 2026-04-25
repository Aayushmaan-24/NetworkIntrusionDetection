import { create } from 'zustand'
import type { HealthStatus, LookupCache, LiveTelemetryPayload } from '@/types/api'

interface AppState {
  // Health
  healthStatus: HealthStatus
  setHealthStatus: (s: HealthStatus) => void

  // Sidebar
  sidebarCollapsed: boolean
  toggleSidebar: () => void

  // Live telemetry stream
  liveStreamConnected: boolean
  liveLastEventAt: string | null
  liveTelemetry: LiveTelemetryPayload | null
  setLiveStreamConnected: (connected: boolean) => void
  setLiveTelemetry: (payload: LiveTelemetryPayload) => void

  // Lookup cache (pre-fetched at app init)
  lookupCache: LookupCache
  setLookupValues: (key: keyof LookupCache, values: string[]) => void

  // Toast queue
  toasts: Toast[]
  addToast: (t: Omit<Toast, 'id'>) => void
  removeToast: (id: string) => void

  // Notifications (persisted in localStorage)
  notifications: AppNotification[]
  addNotification: (n: Omit<AppNotification, 'id' | 'createdAt' | 'read'>) => void
  markAllNotificationsRead: () => void
  unreadNotificationsCount: () => number
  hydrateNotifications: () => void
}

export interface Toast {
  id:      string
  variant: 'success' | 'warning' | 'critical' | 'info'
  title:   string
  message?: string
}

export interface AppNotification {
  id: string
  variant: 'success' | 'warning' | 'critical' | 'info'
  title: string
  message?: string
  createdAt: string
  read: boolean
}

const NOTIFICATIONS_STORAGE_KEY = 'nids_notifications_v1'
const NOTIFICATION_LIMIT = 80

const loadPersistedNotifications = (): AppNotification[] => {
  try {
    const raw = localStorage.getItem(NOTIFICATIONS_STORAGE_KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw) as AppNotification[]
    if (!Array.isArray(parsed)) return []
    return parsed
      .filter(item => item && typeof item.id === 'string' && typeof item.title === 'string')
      .slice(0, NOTIFICATION_LIMIT)
  } catch {
    return []
  }
}

const saveNotifications = (items: AppNotification[]) => {
  try {
    localStorage.setItem(NOTIFICATIONS_STORAGE_KEY, JSON.stringify(items.slice(0, NOTIFICATION_LIMIT)))
  } catch {
    // ignore quota/write failures
  }
}

export const useAppStore = create<AppState>((set, get) => ({
  // Health
  healthStatus: 'online',
  setHealthStatus: (healthStatus) => set({ healthStatus }),

  // Sidebar
  sidebarCollapsed: false,
  toggleSidebar: () => set(s => ({ sidebarCollapsed: !s.sidebarCollapsed })),

  // Live telemetry stream
  liveStreamConnected: false,
  liveLastEventAt: null,
  liveTelemetry: null,
  setLiveStreamConnected: (connected) => set({ liveStreamConnected: connected }),
  setLiveTelemetry: (payload) => set({ liveTelemetry: payload, liveLastEventAt: payload.generated_at }),

  // Lookup cache
  lookupCache: { protocols: [], services: [], flags: [], attacks: [] },
  setLookupValues: (key, values) =>
    set(s => ({ lookupCache: { ...s.lookupCache, [key]: values } })),

  // Toasts
  toasts: [],
  addToast: (t) =>
    set(s => {
      const nextToasts = [...s.toasts, { ...t, id: crypto.randomUUID() }]
      const nextNotifications: AppNotification[] = [
        {
          id: crypto.randomUUID(),
          variant: t.variant,
          title: t.title,
          message: t.message,
          createdAt: new Date().toISOString(),
          read: false,
        },
        ...s.notifications,
      ].slice(0, NOTIFICATION_LIMIT)
      saveNotifications(nextNotifications)
      return { toasts: nextToasts, notifications: nextNotifications }
    }),
  removeToast: (id) =>
    set(s => ({ toasts: s.toasts.filter(t => t.id !== id) })),

  notifications: loadPersistedNotifications(),
  addNotification: (n) =>
    set(s => {
      const next = [
        {
          id: crypto.randomUUID(),
          variant: n.variant,
          title: n.title,
          message: n.message,
          createdAt: new Date().toISOString(),
          read: false,
        },
        ...s.notifications,
      ].slice(0, NOTIFICATION_LIMIT)
      saveNotifications(next)
      return { notifications: next }
    }),
  markAllNotificationsRead: () =>
    set(s => {
      const next = s.notifications.map(item => ({ ...item, read: true }))
      saveNotifications(next)
      return { notifications: next }
    }),
  unreadNotificationsCount: () => {
    const items = get().notifications
    return items.reduce((acc, item) => acc + (item.read ? 0 : 1), 0)
  },
  hydrateNotifications: () =>
    set(s => {
      const persisted = loadPersistedNotifications()
      if (persisted.length > 0) {
        return { notifications: persisted }
      }
      const seeded: AppNotification[] = [
        {
          id: crypto.randomUUID(),
          variant: 'info',
          title: 'Welcome to NIDS',
          message: 'Notification center is active. New system events will appear here.',
          createdAt: new Date().toISOString(),
          read: false,
        },
      ]
      saveNotifications(seeded)
      return { notifications: s.notifications.length ? s.notifications : seeded }
    }),
}))
