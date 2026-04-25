import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: {
          base:     '#0B0E14',
          surface:  '#111520',
          elevated: '#161B27',
          input:    '#0D1018',
          hover:    '#1A2030',
        },
        border: {
          DEFAULT: '#1E2535',
          strong:  '#2A3448',
        },
        cyan: {
          DEFAULT: '#00C8C8',
          dim:     '#00A0A0',
          glow:    'rgba(0,200,200,0.12)',
        },
        critical: { DEFAULT: '#FF3B3B', bg: 'rgba(255,59,59,0.12)' },
        warning:  { DEFAULT: '#F5A623', bg: 'rgba(245,166,35,0.12)' },
        success:  { DEFAULT: '#2ECC71', bg: 'rgba(46,204,113,0.12)' },
        info:     { DEFAULT: '#4A90D9', bg: 'rgba(74,144,217,0.12)' },
        muted:    '#6B7A99',
        text: {
          primary:   '#E8ECF5',
          secondary: '#8A95B0',
          tertiary:  '#4A5570',
          code:      '#00C8C8',
        },
        chart: { 1: '#00C8C8', 2: '#4A90D9', 3: '#F5A623', 4: '#FF3B3B', 5: '#2ECC71' },
      },
      fontFamily: {
        display: ['"Orbitron"', 'system-ui', 'sans-serif'],
        ui:      ['"Inter"', 'system-ui', 'sans-serif'],
        mono:    ['"JetBrains Mono"', '"Fira Code"', 'monospace'],
      },
      fontSize: {
        'xs':   ['11px', '16px'],
        'sm':   ['12px', '18px'],
        'base': ['13px', '20px'],
        'md':   ['14px', '22px'],
        'lg':   ['16px', '24px'],
        'xl':   ['20px', '28px'],
        '2xl':  ['28px', '36px'],
        '3xl':  ['36px', '44px'],
      },
      letterSpacing: { tight: '-0.01em', wide: '0.06em', wider: '0.10em' },
      borderRadius: { none: '0px', sm: '2px', DEFAULT: '4px', md: '4px', lg: '6px', xl: '8px', full: '9999px' },
      boxShadow: {
        card:       '0 1px 3px rgba(0,0,0,0.4), 0 0 0 1px #1E2535',
        modal:      '0 8px 32px rgba(0,0,0,0.6), 0 0 0 1px #2A3448',
        focus:      '0 0 0 2px rgba(0,200,200,0.12), 0 0 0 1px #00C8C8',
        glow:       '0 0 12px rgba(0,200,200,0.35), 0 0 24px rgba(0,200,200,0.15)',
        'glow-lg':  '0 0 20px rgba(0,200,200,0.45), 0 0 40px rgba(0,200,200,0.2)',
        'glow-red': '0 0 12px rgba(255,59,59,0.4), 0 0 24px rgba(255,59,59,0.15)',
        'neon-btn': '0 0 8px rgba(0,200,200,0.6), inset 0 0 8px rgba(0,200,200,0.1)',
      },
      width:  { sidebar: '220px', 'sidebar-collapsed': '56px' },
      height: { topbar: '52px', statusbar: '28px' },
      keyframes: {
        shimmer:    { '0%': { backgroundPosition: '-200% 0' }, '100%': { backgroundPosition: '200% 0' } },
        'fade-in':  { from: { opacity: '0', transform: 'translateY(4px)' }, to: { opacity: '1', transform: 'translateY(0)' } },
        'pulse-glow': {
          '0%, 100%': { boxShadow: '0 0 4px rgba(0,200,200,0.3), 0 0 8px rgba(0,200,200,0.1)' },
          '50%':       { boxShadow: '0 0 12px rgba(0,200,200,0.7), 0 0 24px rgba(0,200,200,0.3)' },
        },
        'pulse-red': {
          '0%, 100%': { boxShadow: '0 0 4px rgba(255,59,59,0.3)' },
          '50%':       { boxShadow: '0 0 14px rgba(255,59,59,0.7), 0 0 28px rgba(255,59,59,0.3)' },
        },
        'scan': {
          '0%':   { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
      },
      animation: {
        shimmer:      'shimmer 1.5s ease-in-out infinite',
        'fade-in':    'fade-in 200ms ease-out',
        'pulse-glow': 'pulse-glow 2.4s ease-in-out infinite',
        'pulse-red':  'pulse-red 1.8s ease-in-out infinite',
        'scan':       'scan 8s linear infinite',
      },
    },
  },
  plugins: [],
} satisfies Config
