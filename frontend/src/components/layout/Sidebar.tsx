import { NavLink } from 'react-router-dom'
import { useNavigate } from 'react-router-dom'
import {
  LayoutDashboard,
  Network,
  Zap,
  BarChart2,
  ShieldCheck,
  Settings,
  LogOut,
  PanelLeftClose,
  PanelLeftOpen,
} from 'lucide-react'
import { useAppStore } from '@/store/appStore'
import { useAuthStore } from '@/store/authStore'
import { cn } from '@/lib/utils'
import { BrandLogo } from './BrandLogo'

const NAV_ITEMS = [
  { to: '/dashboard',      icon: LayoutDashboard, label: 'Dashboard'   },
  { to: '/connections',    icon: Network,         label: 'Connections' },
  { to: '/predict',        icon: Zap,             label: 'Predict'     },
  { to: '/stats',          icon: BarChart2,       label: 'Analytics'   },
  { to: '/health',         icon: ShieldCheck,     label: 'Health'      },
  { to: '/settings',       icon: Settings,        label: 'Settings'    },
]

export function Sidebar() {
  const navigate = useNavigate()
  const { sidebarCollapsed, toggleSidebar } = useAppStore()
  const { logout } = useAuthStore()

  const onSignout = () => {
    logout()
    navigate('/auth', { replace: true })
  }

  return (
    <aside
      aria-label="Primary navigation"
      className={cn(
        'hidden md:flex flex-col h-full border-r border-border bg-bg-surface',
        'transition-all duration-200',
        sidebarCollapsed ? 'w-sidebar-collapsed' : 'w-sidebar'
      )}
    >
      {/* Toggle button */}
      <div className="flex h-topbar items-center justify-between border-b border-border px-2">
        <BrandLogo compact />
        <button
          onClick={toggleSidebar}
          aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          className="flex h-7 w-7 items-center justify-center rounded-md text-text-tertiary hover:bg-bg-hover hover:text-text-primary transition-colors"
        >
          {sidebarCollapsed
            ? <PanelLeftOpen  size={16} />
            : <PanelLeftClose size={16} />
          }
        </button>
      </div>

      {/* Nav items */}
      <nav className="flex flex-1 flex-col gap-1 p-2" role="navigation">
        {NAV_ITEMS.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) => cn(
              'group flex items-center gap-3 rounded-md px-3 py-2.5',
              'text-text-secondary hover:bg-bg-hover hover:text-text-primary',
              'transition-colors duration-150',
              isActive && 'border-l-2 border-cyan bg-bg-hover text-cyan pl-[10px]'
            )}
          >
            <Icon size={16} className="shrink-0" />
            {!sidebarCollapsed && (
              <span className="font-ui text-xs font-medium tracking-wider uppercase">
                {label}
              </span>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Sign out */}
      <div className="border-t border-border p-2">
        <button
          onClick={onSignout}
          className="group flex w-full items-center gap-3 rounded-md px-3 py-2.5 text-text-tertiary hover:bg-bg-hover hover:text-text-primary transition-colors"
          aria-label="Sign out"
        >
          <LogOut size={16} className="shrink-0" />
          {!sidebarCollapsed && (
            <span className="font-ui text-xs tracking-wider uppercase">Sign Out</span>
          )}
        </button>
      </div>
    </aside>
  )
}
