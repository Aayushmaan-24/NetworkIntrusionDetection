import { useEffect, useMemo, useRef, useState } from 'react'
import { Bell, HelpCircle, User, Search, LogOut } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '@/store/authStore'
import { useAppStore } from '@/store/appStore'
import { BrandLogo } from './BrandLogo'

const SEARCH_ROUTE_MAP: Array<{ keywords: string[]; route: string; label: string }> = [
  { keywords: ['dashboard', 'overview', 'home'], route: '/dashboard', label: 'Dashboard' },
  { keywords: ['predict', 'prediction', 'intrusion'], route: '/predict', label: 'Predict' },
  { keywords: ['connections', 'traffic', 'packets'], route: '/connections', label: 'Connections' },
  { keywords: ['stats', 'analytics', 'attacks', 'protocols', 'services'], route: '/stats', label: 'Analytics' },
  { keywords: ['health', 'status', 'system'], route: '/health', label: 'Health' },
  { keywords: ['settings', 'config'], route: '/settings', label: 'Settings' },
]

export function TopBar() {
  const [searchTerm, setSearchTerm] = useState('')
  const [showNotifications, setShowNotifications] = useState(false)
  const [showUserMenu, setShowUserMenu] = useState(false)
  const [showSearchMenu, setShowSearchMenu] = useState(false)
  const notifRef = useRef<HTMLDivElement | null>(null)
  const userRef = useRef<HTMLDivElement | null>(null)
  const searchRef = useRef<HTMLDivElement | null>(null)

  const navigate = useNavigate()
  const { user, logout } = useAuthStore()
  const addToast = useAppStore(s => s.addToast)
  const notifications = useAppStore(s => s.notifications)
  const markAllNotificationsRead = useAppStore(s => s.markAllNotificationsRead)
  const unreadCount = useAppStore(s => s.unreadNotificationsCount())
  const hydrateNotifications = useAppStore(s => s.hydrateNotifications)

  const searchResults = useMemo(() => {
    const q = searchTerm.trim().toLowerCase()
    if (!q) return SEARCH_ROUTE_MAP
    return SEARCH_ROUTE_MAP.filter(item => item.keywords.some(k => k.includes(q) || q.includes(k)))
  }, [searchTerm])

  useEffect(() => {
    hydrateNotifications()
  }, [hydrateNotifications])

  useEffect(() => {
    const onOutside = (e: MouseEvent) => {
      const target = e.target as Node
      if (notifRef.current && !notifRef.current.contains(target)) setShowNotifications(false)
      if (userRef.current && !userRef.current.contains(target)) setShowUserMenu(false)
      if (searchRef.current && !searchRef.current.contains(target)) setShowSearchMenu(false)
    }
    document.addEventListener('mousedown', onOutside)
    return () => document.removeEventListener('mousedown', onOutside)
  }, [])

  const goToRoute = (route: string, label?: string) => {
    navigate(route)
    setShowSearchMenu(false)
    if (label) {
      addToast({ variant: 'info', title: 'Search result', message: `Opened ${label}` })
    }
  }

  const runSearch = () => {
    if (searchResults.length > 0) {
      goToRoute(searchResults[0].route, searchResults[0].label)
      return
    }
    addToast({ variant: 'warning', title: 'No route match', message: 'Try dashboard, predict, connections, stats, health, or settings.' })
  }

  const openHelp = () => {
    addToast({
      variant: 'info',
      title: 'Quick Help',
      message: 'Search now has dropdown suggestions. Notifications, account menu, and sign-out are active.',
    })
  }

  const toggleNotifications = () => {
    setShowNotifications(prev => {
      const next = !prev
      if (next) markAllNotificationsRead()
      return next
    })
  }

  const onLogout = () => {
    logout()
    navigate('/auth', { replace: true })
  }

  return (
    <header
      className="sticky top-0 z-[120] flex h-topbar items-center justify-between border-b border-border bg-bg-surface px-4"
      role="banner"
    >
      <BrandLogo />

      <div className="flex items-center gap-2">
        <div className="relative hidden sm:block" ref={searchRef}>
          <Search
            size={13}
            className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-tertiary"
          />
          <input
            type="search"
            placeholder="SEARCH MODULES..."
            aria-label="Search modules"
            value={searchTerm}
            onFocus={() => setShowSearchMenu(true)}
            onChange={e => {
              setSearchTerm(e.target.value)
              setShowSearchMenu(true)
            }}
            onKeyDown={e => { if (e.key === 'Enter') runSearch() }}
            className="h-7 w-48 rounded-md border border-border bg-bg-input pl-7 pr-3 font-mono text-xs text-text-secondary placeholder:text-text-tertiary placeholder:tracking-wider focus:outline-none focus:shadow-focus focus:border-cyan transition-colors"
          />
          {showSearchMenu && (
            <div className="absolute right-0 top-9 z-[60] w-56 rounded-md border border-border bg-bg-surface p-1 shadow-modal">
              {searchResults.length === 0 && (
                <p className="px-2 py-2 font-ui text-xs text-text-tertiary">No matching modules</p>
              )}
              {searchResults.map(item => (
                <button
                  key={item.route}
                  onClick={() => goToRoute(item.route, item.label)}
                  className="flex w-full items-center justify-between rounded-md px-2 py-2 text-left hover:bg-bg-hover"
                >
                  <span className="font-ui text-xs text-text-primary">{item.label}</span>
                  <span className="font-mono text-[10px] text-text-tertiary">{item.route}</span>
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="relative" ref={notifRef}>
          <button
            aria-label="Notifications"
            onClick={toggleNotifications}
            className="relative flex h-7 w-7 items-center justify-center rounded-md text-text-tertiary hover:bg-bg-hover hover:text-text-primary transition-colors"
          >
            <Bell size={15} />
            {unreadCount > 0 && (
              <span className="absolute -right-1 -top-1 inline-flex min-w-[16px] items-center justify-center rounded-full bg-critical px-1 font-mono text-[10px] leading-4 text-white">
                {unreadCount > 99 ? '99+' : unreadCount}
              </span>
            )}
          </button>
          {showNotifications && (
            <div className="absolute right-0 top-9 z-[60] w-72 rounded-md border border-border bg-bg-surface p-2 shadow-modal">
              <p className="px-2 pb-2 font-ui text-xs tracking-wider text-text-secondary uppercase">Notifications</p>
              <div className="space-y-1">
                {notifications.length === 0 && (
                  <p className="px-2 py-2 font-ui text-xs text-text-tertiary">No notifications yet.</p>
                )}
                {notifications.map(n => (
                  <button
                    key={n.id}
                    onClick={() => addToast({ variant: n.variant, title: n.title, message: n.message })}
                    className="w-full rounded-md border border-transparent px-2 py-2 text-left hover:border-border hover:bg-bg-hover"
                  >
                    <div className="mb-0.5 flex items-center justify-between gap-2">
                      <p className="font-ui text-xs text-text-primary">{n.title}</p>
                      {!n.read && <span className="h-1.5 w-1.5 rounded-full bg-cyan" />}
                    </div>
                    <p className="font-mono text-[11px] text-text-tertiary">{n.message}</p>
                    <p className="mt-1 font-mono text-[10px] text-text-tertiary/70">
                      {new Date(n.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </p>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        <button
          aria-label="Help"
          onClick={openHelp}
          className="flex h-7 w-7 items-center justify-center rounded-md text-text-tertiary hover:bg-bg-hover hover:text-text-primary transition-colors"
        >
          <HelpCircle size={15} />
        </button>

        <div className="relative" ref={userRef}>
          <button
            aria-label="User menu"
            onClick={() => setShowUserMenu(s => !s)}
            className="flex h-7 w-7 items-center justify-center rounded-full border border-border-strong bg-bg-elevated text-text-secondary hover:border-cyan hover:text-cyan transition-colors"
          >
            <User size={13} />
          </button>
          {showUserMenu && (
            <div className="absolute right-0 top-9 z-[60] w-52 rounded-md border border-border bg-bg-surface p-2 shadow-modal">
              <div className="mb-2 border-b border-border px-2 pb-2">
                <p className="font-ui text-xs text-text-primary">{user?.name ?? 'Analyst'}</p>
                <p className="font-mono text-[11px] text-text-tertiary">{user?.email ?? 'local@operator'}</p>
              </div>
              <button
                onClick={onLogout}
                className="flex w-full items-center gap-2 rounded-md px-2 py-2 font-ui text-xs text-text-secondary hover:bg-bg-hover hover:text-text-primary"
              >
                <LogOut size={13} />
                Sign out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  )
}
