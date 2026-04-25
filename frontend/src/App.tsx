import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClientProvider } from '@tanstack/react-query'
import { queryClient } from '@/lib/queryClient'
import { AppShell } from '@/components/layout/AppShell'
import { RequireAuth, RootRedirect } from '@/components/auth/RequireAuth'

// Pages
import { DashboardPage }        from '@/pages/DashboardPage'
import { PredictPage }          from '@/pages/PredictPage'
import { ConnectionsPage }      from '@/pages/ConnectionsPage'
import { ConnectionDetailPage } from '@/pages/ConnectionDetailPage'
import { StatsPage }            from '@/pages/StatsPage'
import { HealthStatusPage }     from '@/pages/HealthStatusPage'
import { SettingsPage }         from '@/pages/SettingsPage'
import { HeroDemoPage }         from '@/pages/HeroDemoPage'
import { AuthPage }             from '@/pages/AuthPage'

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="auth" element={<AuthPage />} />
          <Route
            path="hero"
            element={(
              <RequireAuth>
                <HeroDemoPage />
              </RequireAuth>
            )}
          />
          <Route
            element={(
              <RequireAuth>
                <AppShell />
              </RequireAuth>
            )}
          >
            {/* Root redirect */}
            <Route index element={<RootRedirect />} />

            {/* Dashboard */}
            <Route path="dashboard" element={<DashboardPage />} />

            {/* Predict */}
            <Route path="predict" element={<PredictPage />} />

            {/* Connections */}
            <Route path="connections">
              <Route index element={<ConnectionsPage />} />
              <Route path=":id" element={<ConnectionDetailPage />} />
            </Route>

            {/* Stats with tab sub-routes */}
            <Route path="stats">
              <Route index element={<Navigate to="/stats/attacks" replace />} />
              <Route path="attacks"   element={<StatsPage />} />
              <Route path="protocols" element={<StatsPage />} />
              <Route path="services"  element={<StatsPage />} />
            </Route>

            {/* Health */}
            <Route path="health" element={<HealthStatusPage />} />

            {/* Settings */}
            <Route path="settings" element={<SettingsPage />} />

            {/* 404 */}
            <Route path="*" element={<RootRedirect />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
