import { cn } from '@/lib/utils'
import { NidsShieldIcon } from '@/components/ui/NidsLogoSvg'

export function BrandLogo({ compact = false }: { compact?: boolean }) {
  return (
    <div className={cn('nids-live-logo', compact && 'nids-live-logo-compact')}>
      {/* Custom split-shield icon */}
      <div className="nids-logo-emblem" aria-hidden="true">
        <NidsShieldIcon size={compact ? 22 : 28} />
      </div>

      {!compact && (
        <div className="nids-logo-wordmark">
          <span className="nids-logo-wordmark-n">NIDS</span>
        </div>
      )}
    </div>
  )
}
