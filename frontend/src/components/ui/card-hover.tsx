import React from 'react'
import { Activity, BrainCircuit, ChevronRight, ShieldCheck, ServerCog } from 'lucide-react'

interface CardHoverProps extends React.HTMLAttributes<HTMLDivElement> {
  title?: string
  tagLabel?: string
  linkLabel?: string
  linkHref?: string
  imageAlt?: string
  variant?: 'core' | 'ml' | 'health'
}

const variantConfig = {
  core: {
    icon: ShieldCheck,
    background:
      'radial-gradient(circle at 20% 20%, rgba(34,224,255,0.28), transparent 44%), radial-gradient(circle at 86% 20%, rgba(57,120,255,0.25), transparent 42%), linear-gradient(140deg, #061528 0%, #0a1f33 46%, #102a45 100%)',
    accent: 'from-cyan to-sky-500',
    wire: 'rgba(34,224,255,0.22)',
  },
  ml: {
    icon: BrainCircuit,
    background:
      'radial-gradient(circle at 18% 26%, rgba(124,255,193,0.24), transparent 38%), radial-gradient(circle at 82% 12%, rgba(34,224,255,0.2), transparent 45%), linear-gradient(135deg, #0a1524 0%, #102730 45%, #12374a 100%)',
    accent: 'from-emerald-300 to-cyan',
    wire: 'rgba(124,255,193,0.2)',
  },
  health: {
    icon: ServerCog,
    background:
      'radial-gradient(circle at 22% 18%, rgba(70,170,255,0.25), transparent 42%), radial-gradient(circle at 78% 78%, rgba(34,224,255,0.18), transparent 48%), linear-gradient(140deg, #0a1524 0%, #14253b 45%, #1b3452 100%)',
    accent: 'from-sky-300 to-blue-500',
    wire: 'rgba(90,176,255,0.24)',
  },
} as const

const Component = React.forwardRef<HTMLDivElement, CardHoverProps>(
  (
    {
      className,
      title = 'Incorporate your company',
      tagLabel = 'Security',
      linkLabel = 'Learn about NIDS',
      linkHref = '#',
      imageAlt = 'network visualization',
      variant = 'core',
      ...props
    },
    ref,
  ) => {
    const config = variantConfig[variant]
    const VariantIcon = config.icon

    return (
      <div
        ref={ref}
        className={`nids-hover-box w-[90%] h-[480px] group mx-auto bg-[#111520] border border-[rgba(0,200,200,0.15)] p-2 overflow-hidden rounded-md text-white ${className ?? ''}`}
        {...props}
      >
        <figure className="w-full h-80 group-hover:h-72 transition-all duration-300 bg-[#0a121a] p-2 rounded-md relative overflow-hidden">
          <div className="absolute inset-0" style={{ background: config.background }} aria-label={imageAlt} />

          <div className="absolute inset-0 opacity-75" style={{ backgroundImage: `linear-gradient(${config.wire} 1px, transparent 1px), linear-gradient(90deg, ${config.wire} 1px, transparent 1px)`, backgroundSize: '30px 30px' }} />

          <div className="absolute inset-x-8 top-8 bottom-8 rounded-xl border border-white/10 bg-black/20 backdrop-blur-[1px]" />

          <div className="absolute left-8 top-8 flex h-11 w-11 items-center justify-center rounded-lg border border-white/15 bg-black/35 text-cyan shadow-[0_0_20px_rgba(0,200,200,0.35)]">
            <VariantIcon size={18} />
          </div>

          <div className="absolute bottom-8 left-8 right-8 grid grid-cols-4 gap-2">
            {Array.from({ length: 4 }).map((_, i) => (
              <div
                key={i}
                className="h-2 rounded-full bg-white/10"
                style={{ boxShadow: i % 2 === 0 ? '0 0 12px rgba(34,224,255,0.45)' : 'none' }}
              />
            ))}
          </div>

          <svg
            className="absolute bottom-16 left-8 right-8 h-12 w-[calc(100%-4rem)] opacity-80"
            viewBox="0 0 240 48"
            preserveAspectRatio="none"
            aria-hidden="true"
          >
            <defs>
              <linearGradient id={`trend-${variant}`} x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="rgba(34,224,255,0.3)" />
                <stop offset="45%" stopColor="rgba(34,224,255,0.9)" />
                <stop offset="100%" stopColor="rgba(96,165,250,0.65)" />
              </linearGradient>
            </defs>
            <polyline
              fill="none"
              stroke={`url(#trend-${variant})`}
              strokeWidth="2"
              points="0,36 24,28 48,30 72,18 96,22 120,12 144,16 168,11 192,22 216,18 240,9"
            />
          </svg>

          <div className="absolute right-8 top-10 flex flex-col gap-2">
            <Activity size={14} className="text-cyan/80" />
            <Activity size={11} className="text-cyan/60" />
            <Activity size={9} className="text-cyan/40" />
          </div>
        </figure>

        <article className="p-4 space-y-1">
          <div
            className={`h-5 w-20 rounded-md font-mono text-[9px] text-bg-base flex items-center justify-center tracking-widest uppercase bg-gradient-to-r ${config.accent}`}
          >
            {tagLabel}
          </div>
          <h1 className="text-xl font-semibold capitalize text-text-primary">{title}</h1>
          <a
            href={linkHref}
            className="text-sm text-cyan font-normal group-hover:opacity-100 opacity-0 translate-y-2 group-hover:translate-y-0 pt-2 flex items-center gap-1 transition-all duration-300 hover:text-cyan-dim"
          >
            {linkLabel}
            <ChevronRight size={14} />
          </a>
        </article>
      </div>
    )
  },
)

Component.displayName = 'CardHover'
export default Component
export { Component }
