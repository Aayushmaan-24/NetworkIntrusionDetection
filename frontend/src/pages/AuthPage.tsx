import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { Lock, Shield, User } from 'lucide-react'
import { useAuthStore } from '@/store/authStore'
import { useAppStore } from '@/store/appStore'
import { ToastContainer } from '@/components/ui/index'
import { NidsLogoFull } from '@/components/ui/NidsLogoSvg'
import { GradientBackground } from '@/components/layout/GradientBackground'
import { CursorEffect } from '@/components/layout/CursorEffect'

/* Light-ray angles for the aura behind the logo */
const RAYS = [0, 30, 60, 90, 120, 150, 180, 210, 240, 270, 300, 330]

function LogoAura() {
  return (
    <div className="relative flex flex-col items-center justify-center">
      {/* ── Expanding pulse rings ─── */}
      <span
        className="pointer-events-none absolute rounded-full border border-cyan/30"
        style={{
          width: 340, height: 340,
          animation: 'auth-ring-out 3s ease-out infinite',
        }}
      />
      <span
        className="pointer-events-none absolute rounded-full border border-cyan/20"
        style={{
          width: 340, height: 340,
          animation: 'auth-ring-out 3s ease-out infinite',
          animationDelay: '1s',
        }}
      />
      <span
        className="pointer-events-none absolute rounded-full border border-cyan/10"
        style={{
          width: 340, height: 340,
          animation: 'auth-ring-out 3s ease-out infinite',
          animationDelay: '2s',
        }}
      />

      {/* ── Soft inner glow blob ─── */}
      <div
        className="pointer-events-none absolute rounded-full"
        style={{
          width: 220, height: 220,
          background: 'radial-gradient(circle, rgba(0,200,255,0.14) 0%, rgba(0,100,200,0.06) 60%, transparent 80%)',
          animation: 'auth-glow-breathe 2.6s ease-in-out infinite',
        }}
      />

      {/* ── Light rays ─── */}
      {RAYS.map(deg => (
        <div
          key={deg}
          className="pointer-events-none absolute"
          style={{
            width: 1,
            height: 160,
            background: 'linear-gradient(to top, rgba(0,200,255,0.35), transparent)',
            transform: `rotate(${deg}deg) translateY(-50%)`,
            transformOrigin: 'bottom center',
            bottom: '50%',
            left: 'calc(50% - 0.5px)',
            animation: `auth-ray-fade 3.5s ease-in-out infinite`,
            animationDelay: `${(deg / 360) * 3.5}s`,
            opacity: 0.5,
          }}
        />
      ))}

      {/* ── The logo itself ─── */}
      <div className="relative z-10" style={{ filter: 'drop-shadow(0 0 28px rgba(0,200,255,0.5)) drop-shadow(0 0 60px rgba(0,100,200,0.25))' }}>
        <NidsLogoFull size={260} showIcons />
      </div>
    </div>
  )
}

export function AuthPage() {
  const [mode, setMode] = useState<'login' | 'signup'>('login')
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)

  const navigate = useNavigate()
  const { login, signup } = useAuthStore()
  const addToast = useAppStore(s => s.addToast)

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setLoading(true)

    const result = mode === 'login'
      ? await login(email, password)
      : await signup(name, email, password)

    if (result.ok) {
      addToast({ variant: 'success', title: mode === 'login' ? 'Welcome back' : 'Account created', message: result.message })
      navigate('/dashboard', { replace: true })
    } else {
      addToast({ variant: 'critical', title: mode === 'login' ? 'Login failed' : 'Signup failed', message: result.message })
    }

    setLoading(false)
  }

  return (
    <div className="relative min-h-screen overflow-hidden text-text-primary">
      {/* Animation keyframes for logo aura */}
      <style>{`
        @keyframes auth-ring-out {
          0%   { transform: scale(1);   opacity: 0.6; }
          100% { transform: scale(1.5); opacity: 0; }
        }
        @keyframes auth-glow-breathe {
          0%,100% { opacity: 0.7; transform: scale(1); }
          50%      { opacity: 1;   transform: scale(1.15); }
        }
        @keyframes auth-ray-fade {
          0%,100% { opacity: 0.2; }
          50%      { opacity: 0.7; }
        }
      `}</style>

      <GradientBackground />
      <CursorEffect />

      <div className="relative z-10 mx-auto flex min-h-screen w-full max-w-6xl items-center justify-center px-4 py-8">
        <div className="grid w-full max-w-4xl grid-cols-1 overflow-hidden rounded-2xl border border-border bg-bg-surface/75 shadow-modal backdrop-blur-xl lg:grid-cols-2">

          {/* ── Left: animated logo panel ─── */}
          <section className="hidden flex-col items-center justify-between border-r border-border bg-bg-base/40 px-6 py-10 lg:flex">
            <div className="flex flex-1 flex-col items-center justify-center">
              <LogoAura />
            </div>

            {/* Bottom capability tags */}
            <div className="flex flex-col items-center gap-2 font-mono text-[10px] tracking-widest text-text-tertiary/60 uppercase">
              <p className="flex items-center gap-2">
                <span className="h-px w-8 bg-cyan/30" />
                REAL-TIME PACKET INSPECTION
                <span className="h-px w-8 bg-cyan/30" />
              </p>
              <p className="flex items-center gap-2">
                <span className="h-px w-8 bg-critical/30" />
                ML-BASED THREAT PREDICTION
                <span className="h-px w-8 bg-critical/30" />
              </p>
              <p className="flex items-center gap-2">
                <span className="h-px w-8 bg-cyan/30" />
                LIVE SENSOR TELEMETRY
                <span className="h-px w-8 bg-cyan/30" />
              </p>
            </div>
          </section>

          {/* ── Right: form panel ─── */}
          <section className="p-6 sm:p-8 lg:p-10">
            <div className="mb-6 flex items-center justify-between">
              <h2 className="font-display text-xl tracking-wide text-text-primary">
                {mode === 'login' ? 'Sign In' : 'Create Account'}
              </h2>
              <div className="rounded-md border border-border bg-bg-elevated p-1">
                <button
                  onClick={() => setMode('login')}
                  className={`rounded px-3 py-1 text-xs font-ui transition-colors ${mode === 'login' ? 'bg-cyan text-bg-base' : 'text-text-secondary hover:text-text-primary'}`}
                >
                  Login
                </button>
                <button
                  onClick={() => setMode('signup')}
                  className={`rounded px-3 py-1 text-xs font-ui transition-colors ${mode === 'signup' ? 'bg-cyan text-bg-base' : 'text-text-secondary hover:text-text-primary'}`}
                >
                  Signup
                </button>
              </div>
            </div>

            <form onSubmit={onSubmit} className="space-y-4">
              {mode === 'signup' && (
                <div className="space-y-1.5">
                  <label className="font-ui text-xs tracking-wider text-text-secondary uppercase">Name</label>
                  <div className="relative">
                    <User size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-text-tertiary" />
                    <input
                      value={name}
                      onChange={e => setName(e.target.value)}
                      required={mode === 'signup'}
                      className="h-10 w-full rounded-md border border-border bg-bg-input pl-9 pr-3 font-ui text-sm text-text-primary focus:border-cyan focus:outline-none"
                      placeholder="Your name"
                    />
                  </div>
                </div>
              )}

              <div className="space-y-1.5">
                <label className="font-ui text-xs tracking-wider text-text-secondary uppercase">Email</label>
                <input
                  type="email"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  required
                  className="h-10 w-full rounded-md border border-border bg-bg-input px-3 font-ui text-sm text-text-primary focus:border-cyan focus:outline-none"
                  placeholder="admin@nids.local"
                />
              </div>

              <div className="space-y-1.5">
                <label className="font-ui text-xs tracking-wider text-text-secondary uppercase">Password</label>
                <div className="relative">
                  <Lock size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-text-tertiary" />
                  <input
                    type="password"
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    required
                    minLength={6}
                    className="h-10 w-full rounded-md border border-border bg-bg-input pl-9 pr-3 font-ui text-sm text-text-primary focus:border-cyan focus:outline-none"
                    placeholder="Minimum 6 characters"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="mt-2 inline-flex h-10 w-full items-center justify-center gap-2 rounded-md bg-cyan px-4 font-display text-sm tracking-wider text-bg-base transition-colors hover:bg-cyan-dim disabled:opacity-60"
              >
                <Shield size={14} />
                {loading ? 'Please wait...' : mode === 'login' ? 'Enter Dashboard' : 'Create & Continue'}
              </button>
            </form>

            <p className="mt-4 font-ui text-xs text-text-tertiary">
              Uses backend auth endpoints when available; local fallback stays enabled for offline/demo use.
            </p>
          </section>
        </div>
      </div>
      <ToastContainer />
    </div>
  )
}
