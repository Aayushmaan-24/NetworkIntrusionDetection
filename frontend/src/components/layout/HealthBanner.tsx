import { useAppStore } from '@/store/appStore'
import { cn } from '@/lib/utils'

export function HealthBanner() {
  const status = useAppStore(s => s.healthStatus)
  if (status === 'online') return null

  const isCritical = status === 'offline'

  return (
    <div
      role="alert"
      aria-live={isCritical ? 'assertive' : 'polite'}
      className={cn(
        'flex items-center justify-center gap-2 border-t px-4 py-1.5',
        'font-mono text-xs tracking-wider',
        isCritical
          ? 'border-critical bg-critical/10 text-critical'
          : 'border-warning bg-warning/10 text-warning'
      )}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current animate-pulse" aria-hidden="true" />
      {isCritical
        ? 'GATEWAY OFFLINE - ATTEMPTING AUTOMATIC RECONNECT...'
        : 'WARNING: ELEVATED LATENCY DETECTED ON SENSOR CLUSTER'
      }
    </div>
  )
}
