import { NavLink } from 'react-router-dom'
import { LayoutDashboard, Network, Zap, BarChart2, ShieldCheck } from 'lucide-react'
import { cn } from '@/lib/utils'

const BOTTOM_ITEMS = [
  { to: '/dashboard',   icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/connections', icon: Network,         label: 'Connections' },
  { to: '/predict',     icon: Zap,             label: 'Predict' },
  { to: '/stats',       icon: BarChart2,       label: 'Analytics' },
  { to: '/health',      icon: ShieldCheck,     label: 'Health' },
] as const

export function BottomNav() {
  return (
    <nav
      aria-label="Primary navigation"
      className="md:hidden fixed bottom-0 left-0 right-0 z-50 flex h-14 items-center border-t border-border bg-bg-surface"
      style={{ paddingBottom: 'env(safe-area-inset-bottom)' }}
    >
      {BOTTOM_ITEMS.map(({ to, icon: Icon, label }) => (
        <NavLink
          key={to}
          to={to}
          className={({ isActive }) =>
            cn(
              'flex flex-1 flex-col items-center gap-0.5 py-1.5 text-text-tertiary',
              isActive && 'text-cyan'
            )
          }
          aria-label={label}
        >
          <Icon size={18} />
          <span className="text-[10px] tracking-wide">{label}</span>
        </NavLink>
      ))}
    </nav>
  )
}
