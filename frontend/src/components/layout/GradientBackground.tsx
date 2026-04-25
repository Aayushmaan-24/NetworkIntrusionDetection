import { GradientBars } from '@/components/ui/gradient-bars-background'

export function GradientBackground() {
  return (
    <div aria-hidden="true" className="pointer-events-none fixed inset-0 z-0">
      {/* Dark base */}
      <div className="absolute inset-0 bg-[#06080D]" />
      {/* Gradient bars fill the full viewport */}
      <GradientBars
        numBars={24}
        gradientFrom="rgba(0,200,200,0.55)"
        gradientTo="transparent"
        animationDuration={2}
      />
      {/* Subtle vignette so edges don't compete with UI */}
      <div
        className="absolute inset-0"
        style={{
          background: 'radial-gradient(ellipse 80% 80% at 50% 100%, transparent 40%, rgba(6,8,13,0.85) 100%)',
        }}
      />
    </div>
  )
}
