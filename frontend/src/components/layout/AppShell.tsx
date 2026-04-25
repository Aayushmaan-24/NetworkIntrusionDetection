import { Outlet } from 'react-router-dom'
import { Sidebar }     from './Sidebar'
import { TopBar }      from './TopBar'
import { HealthBanner } from './HealthBanner'
import { StatusBar }   from './StatusBar'
import { BottomNav }   from './BottomNav'
import { GradientBackground } from './GradientBackground'
import { CursorEffect } from './CursorEffect'
import { ToastContainer } from '../ui/index'
import { useHealth, useLiveTelemetry, usePrefetchLookups } from '@/hooks'

export function AppShell() {
  // Kick off health polling and lookup prefetch globally
  useHealth()
  useLiveTelemetry()
  usePrefetchLookups()

  return (
    <>
      {/* Skip to content — a11y */}
      <a href="#main-content" className="skip-to-content">
        Skip to main content
      </a>

      <div className="app-cosmos relative flex h-screen overflow-hidden bg-transparent font-ui">
        <GradientBackground />
        {/* Sidebar — hidden on mobile */}
        <div className="relative z-10">
          <Sidebar />
        </div>

        {/* Main column */}
        <div className="relative z-10 flex flex-1 flex-col overflow-visible">
          <TopBar />
          <HealthBanner />

          <main
            id="main-content"
            className="flex-1 overflow-auto p-4 lg:p-6"
            tabIndex={-1}
          >
            <div className="mx-auto max-w-[1280px]">
              <Outlet />
            </div>
          </main>

          <StatusBar />
        </div>

        {/* Bottom nav — visible on mobile only */}
        <BottomNav />
      </div>

      <CursorEffect />
      <ToastContainer />
    </>
  )
}
