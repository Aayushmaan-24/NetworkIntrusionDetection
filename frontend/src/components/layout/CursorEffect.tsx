import { useEffect, useRef } from 'react'

export function CursorEffect() {
  const innerRef = useRef<HTMLDivElement>(null)
  const rafRef = useRef<number | null>(null)

  useEffect(() => {
    const inner = innerRef.current
    if (!inner) return

    let mouseX = window.innerWidth * 0.5
    let mouseY = window.innerHeight * 0.5
    let innerX = mouseX
    let innerY = mouseY
    let visible = false

    const onPointerMove = (e: PointerEvent) => {
      mouseX = e.clientX
      mouseY = e.clientY
      if (!visible) {
        visible = true
        inner.style.opacity = '1'
      }
    }

    inner.style.transform = `translate3d(${innerX}px, ${innerY}px, 0) translate(-50%, -50%)`
    inner.style.opacity = '0'

    const animate = () => {
      innerX += (mouseX - innerX) * 0.26
      innerY += (mouseY - innerY) * 0.26

      inner.style.transform = `translate3d(${innerX}px, ${innerY}px, 0) translate(-50%, -50%)`

      rafRef.current = requestAnimationFrame(animate)
    }

    window.addEventListener('pointermove', onPointerMove)
    animate()

    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current)
      window.removeEventListener('pointermove', onPointerMove)
    }
  }, [])

  return (
    <div aria-hidden="true" className="pointer-events-none fixed inset-0 z-[9999]">
      <div
        ref={innerRef}
        className="absolute left-0 top-0 h-6 w-6 rounded-full border border-cyan/45 bg-[radial-gradient(circle,rgba(34,224,255,0.2)_0%,rgba(34,224,255,0.04)_66%,rgba(34,224,255,0)_86%)]"
        style={{ boxShadow: '0 0 14px rgba(34,224,255,0.35)', transition: 'opacity 120ms ease' }}
      />
    </div>
  )
}
