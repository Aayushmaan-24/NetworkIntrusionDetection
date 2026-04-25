import { cn } from '@/lib/utils'
import { useHealth } from '@/hooks'
import { useAppStore } from '@/store/appStore'

export function StatusBar() {
  const { data } = useHealth()
  const liveStreamConnected = useAppStore(s => s.liveStreamConnected)
  const liveLastEventAt = useAppStore(s => s.liveLastEventAt)

  const isOnline = !data || data.status === 'online'
  const isWarning = data?.status === 'warning'
  const liveTime = liveLastEventAt
    ? new Date(liveLastEventAt).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      })
    : '--:--:--'

  return (
    <footer
      className="flex h-statusbar items-center justify-between border-t border-border bg-bg-surface px-4"
      aria-label="System status"
    >
      <div className="flex items-center gap-3 font-mono text-xs text-text-tertiary">
        <div className="flex items-center gap-1.5">
          <span
            className={cn(
              'h-1.5 w-1.5 rounded-full',
              isOnline ? 'bg-success animate-pulse' : isWarning ? 'bg-warning animate-pulse' : 'bg-critical',
            )}
            aria-label={`System ${data?.status ?? 'connecting'}`}
          />
          <span className={cn(isOnline ? 'text-success' : isWarning ? 'text-warning' : 'text-critical')}>
            {data ? `SYSTEM ONLINE: ${data.uptime_human}` : 'CONNECTING...'}
          </span>
        </div>

        {data && (
          <>
            <span className="text-border-strong">·</span>
            <span>GLOBAL LOAD: {data.global_load.toFixed(1)}%</span>
            <span className="text-border-strong">·</span>
            <span className={liveStreamConnected ? 'text-cyan' : 'text-text-tertiary'}>
              LIVE STREAM: {liveStreamConnected ? `CONNECTED (${liveTime})` : 'RECONNECTING...'}
            </span>
          </>
        )}
      </div>

      <span className="font-mono text-xs tracking-widest text-text-tertiary/60">SECURED BY NIDS QUANTUM-SHIELD</span>
    </footer>
  )
}
