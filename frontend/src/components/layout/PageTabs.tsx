import { NavLink } from 'react-router-dom'
import { cn } from '@/lib/utils'

export function PageTabs({ tabs }: { tabs: Array<{ label: string; to: string }> }) {
  return (
    <nav className="nids-page-tabs" aria-label="Section tabs">
      {tabs.map(tab => (
        <NavLink
          key={tab.to}
          to={tab.to}
          className={({ isActive }) => cn('nids-page-tab', isActive && 'nids-page-tab-active')}
        >
          {tab.label}
        </NavLink>
      ))}
    </nav>
  )
}
