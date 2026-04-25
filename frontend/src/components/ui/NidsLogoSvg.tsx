/**
 * NIDS full-brand SVG logo — Orbitron typeface, split cyan/red shield.
 * Props:
 *   size      — controls viewBox scale (default 300)
 *   showIcons — render the 4 pillars beneath the wordmark (default true)
 *   compact   — sidebar/topbar mini version (just the shield icon)
 */

interface NidsLogoProps {
  size?: number
  showIcons?: boolean
  compact?: boolean
  className?: string
}

export function NidsLogoFull({ size = 300, showIcons = true, className }: NidsLogoProps) {
  const W  = 360
  const H  = showIcons ? 560 : 490
  const cx = 180   // horizontal center

  /* Shield outline path (heraldic, center-split) */
  const shield = `M${cx} 22 C${cx} 22 342 68 342 68 L342 228 Q342 355 ${cx} 392 Q18 355 18 228 L18 68 Z`

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      width={size}
      height={Math.round(size * H / W)}
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-label="NIDS logo"
      role="img"
    >
      <defs>
        {/* ── Keyframe animations ─────────────────── */}
        <style>{`
          @keyframes nlg-border-breathe {
            0%,100% { opacity: 0.9; filter: drop-shadow(0 0 4px #22e0ff); }
            50%     { opacity: 0.4; filter: drop-shadow(0 0 12px #22e0ff); }
          }
          @keyframes nlg-eye-pulse {
            0%,100% { opacity: 0.95; }
            50%     { opacity: 0.4; }
          }
          @keyframes nlg-scan {
            0%   { transform: translateY(-160px); opacity: 0; }
            10%  { opacity: 1; }
            90%  { opacity: 1; }
            100% { transform: translateY(240px);  opacity: 0; }
          }
          @keyframes nlg-ring-out {
            0%   { r: 180; opacity: 0.5; }
            100% { r: 240; opacity: 0; }
          }
          @keyframes nlg-ring-out2 {
            0%   { r: 180; opacity: 0.3; }
            100% { r: 260; opacity: 0; }
          }
          @keyframes nlg-node-blink {
            0%,100% { opacity: 1; }
            50%      { opacity: 0.2; }
          }
          @keyframes nlg-red-border {
            0%,100% { opacity: 0.9; filter: drop-shadow(0 0 4px #ff3b3b); }
            50%     { opacity: 0.4; filter: drop-shadow(0 0 12px #ff3b3b); }
          }
        `}</style>

        {/* ── Gradients ──────────────────────────── */}
        <linearGradient id="nlg-shieldL" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%"   stopColor="#071324" />
          <stop offset="100%" stopColor="#0c1e38" />
        </linearGradient>
        <linearGradient id="nlg-shieldR" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%"   stopColor="#160609" />
          <stop offset="100%" stopColor="#1e0810" />
        </linearGradient>
        <linearGradient id="nlg-borderL" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%"   stopColor="#22e0ff" stopOpacity="0.9" />
          <stop offset="100%" stopColor="#22e0ff" stopOpacity="0.2" />
        </linearGradient>
        <linearGradient id="nlg-borderR" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%"   stopColor="#ff3b3b" stopOpacity="0.9" />
          <stop offset="100%" stopColor="#ff3b3b" stopOpacity="0.2" />
        </linearGradient>
        <linearGradient id="nlg-nids" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%"   stopColor="#a0e8ff" />
          <stop offset="40%"  stopColor="#cce8ff" />
          <stop offset="55%"  stopColor="#e8f0ff" />
          <stop offset="75%"  stopColor="#ff8888" />
          <stop offset="100%" stopColor="#ff3b3b" />
        </linearGradient>
        <linearGradient id="nlg-divLeft" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%"   stopColor="#22e0ff" stopOpacity="0.6" />
          <stop offset="100%" stopColor="#22e0ff" stopOpacity="0" />
        </linearGradient>
        <linearGradient id="nlg-divRight" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%"   stopColor="#ff3b3b" stopOpacity="0" />
          <stop offset="100%" stopColor="#ff3b3b" stopOpacity="0.6" />
        </linearGradient>

        {/* ── Glow filters ───────────────────────── */}
        <filter id="nlg-cyanGlow" x="-40%" y="-40%" width="180%" height="180%">
          <feGaussianBlur stdDeviation="4" result="b" />
          <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
        <filter id="nlg-redGlow" x="-40%" y="-40%" width="180%" height="180%">
          <feGaussianBlur stdDeviation="4" result="b" />
          <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
        <filter id="nlg-softGlow" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="3" result="b" />
          <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
        <filter id="nlg-textGlow" x="-10%" y="-30%" width="120%" height="160%">
          <feGaussianBlur stdDeviation="6" result="b" />
          <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>

        {/* ── Scan beam gradient ─────────────────── */}
        <linearGradient id="nlg-scanBeam" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%"   stopColor="#22e0ff" stopOpacity="0" />
          <stop offset="30%"  stopColor="#22e0ff" stopOpacity="0.8" />
          <stop offset="50%"  stopColor="#ffffff" stopOpacity="1" />
          <stop offset="70%"  stopColor="#22e0ff" stopOpacity="0.8" />
          <stop offset="100%" stopColor="#22e0ff" stopOpacity="0" />
        </linearGradient>

        {/* ── Clip paths ─────────────────────────── */}
        <clipPath id="nlg-leftClip">
          <rect x="0" y="0" width={cx} height={H} />
        </clipPath>
        <clipPath id="nlg-rightClip">
          <rect x={cx} y="0" width={W - cx} height={H} />
        </clipPath>
        <clipPath id="nlg-shieldClip">
          <path d={shield} />
        </clipPath>
      </defs>

      {/* ══ SHIELD ══════════════════════════════════════════ */}

      {/* Left half fill */}
      <g clipPath="url(#nlg-leftClip)">
        <path d={shield} fill="url(#nlg-shieldL)" />
      </g>
      {/* Right half fill */}
      <g clipPath="url(#nlg-rightClip)">
        <path d={shield} fill="url(#nlg-shieldR)" />
      </g>

      {/* ── Left: circuit network pattern ────────── */}
      <g clipPath="url(#nlg-shieldClip)">
        {/* Connection lines */}
        <g stroke="#22e0ff" strokeWidth="1" strokeOpacity="0.45" fill="none">
          <line x1="68"  y1="108" x2="95"  y2="162" />
          <line x1="95"  y1="162" x2="130" y2="128" />
          <line x1="95"  y1="162" x2="115" y2="210" />
          <line x1="68"  y1="108" x2="130" y2="128" />
          <line x1="115" y1="210" x2="82"  y2="240" />
          <line x1="130" y1="128" x2="152" y2="148" />
          <line x1="115" y1="210" x2="140" y2="240" />
          <line x1="50"  y1="155" x2="68"  y2="108" />
          <line x1="50"  y1="155" x2="95"  y2="162" />
        </g>
        {/* Node dots */}
        <g fill="#22e0ff" filter="url(#nlg-cyanGlow)">
          <circle cx="68"  cy="108" r="4" />
          <circle cx="95"  cy="162" r="5.5" />
          <circle cx="130" cy="128" r="4" />
          <circle cx="115" cy="210" r="4" />
          <circle cx="82"  cy="240" r="3" />
          <circle cx="50"  cy="155" r="3" />
          <circle cx="140" cy="240" r="3" />
        </g>

        {/* ── Right: pixel/glitch fragments ──────── */}
        <g opacity="1">
          {/* Cluster 1 — upper right */}
          <rect x="215" y="88"  width="13" height="13" fill="#ff3b3b" opacity="0.9" filter="url(#nlg-redGlow)" />
          <rect x="232" y="82"  width="7"  height="7"  fill="#ff5050" opacity="0.7" />
          <rect x="242" y="95"  width="9"  height="9"  fill="#ff3030" opacity="0.6" />
          <rect x="252" y="80"  width="5"  height="5"  fill="#ff4444" opacity="0.5" />
          <rect x="262" y="92"  width="7"  height="18" fill="#ff3b3b" opacity="0.4" />
          <rect x="272" y="76"  width="4"  height="4"  fill="#ff3b3b" opacity="0.35" />
          <rect x="278" y="88"  width="3"  height="8"  fill="#ff4040" opacity="0.3" />

          {/* Cluster 2 — mid right */}
          <rect x="220" y="148" width="11" height="11" fill="#ff3b3b" opacity="0.85" filter="url(#nlg-redGlow)" />
          <rect x="236" y="143" width="6"  height="6"  fill="#ff5555" opacity="0.65" />
          <rect x="248" y="138" width="8"  height="8"  fill="#ff3030" opacity="0.55" />
          <rect x="260" y="150" width="5"  height="14" fill="#ff3b3b" opacity="0.45" />
          <rect x="270" y="140" width="4"  height="4"  fill="#ff4040" opacity="0.4" />

          {/* Cluster 3 — lower right */}
          <rect x="225" y="210" width="10" height="10" fill="#ff3b3b" opacity="0.8" filter="url(#nlg-redGlow)" />
          <rect x="240" y="205" width="5"  height="5"  fill="#ff5050" opacity="0.55" />
          <rect x="250" y="218" width="7"  height="7"  fill="#ff3030" opacity="0.45" />
          <rect x="262" y="208" width="4"  height="11" fill="#ff3b3b" opacity="0.35" />
        </g>
      </g>

      {/* ── Scan beam sweeping through shield ────── */}
      <g clipPath="url(#nlg-shieldClip)" style={{ animation: 'nlg-scan 3.5s ease-in-out infinite' }}>
        <rect
          x="18" y="0" width="324" height="3"
          fill="url(#nlg-scanBeam)"
          opacity="0.7"
        />
      </g>

      {/* ── Spartan helmet visor (centered) ──────── */}
      <g>
        {/* Outer helmet silhouette */}
        <path
          d="M180 78 L224 100 L238 168 L228 222 L212 242 L180 252 L148 242 L132 222 L122 168 L136 100 Z"
          fill="#050c18"
          opacity="0.85"
        />
        {/* Inner face plate */}
        <path
          d="M180 92 L218 111 L228 165 L220 212 L206 228 L180 236 L154 228 L140 212 L132 165 L142 111 Z"
          fill="#080f20"
          opacity="0.9"
        />

        {/* Helmet crest / top ridge */}
        <path
          d="M165 78 L180 68 L195 78"
          fill="none"
          stroke="#22e0ff"
          strokeWidth="1.5"
          strokeOpacity="0.5"
          filter="url(#nlg-cyanGlow)"
        />

        {/* LEFT EYE — cyan, animated */}
        <path
          d="M142 148 L170 138 L176 164 L148 174 Z"
          fill="#00c8c8"
          filter="url(#nlg-cyanGlow)"
          style={{ animation: 'nlg-eye-pulse 2s ease-in-out infinite' }}
        />
        <path
          d="M142 148 L170 138 L176 164 L148 174 Z"
          fill="none"
          stroke="#22e0ff"
          strokeWidth="1"
          opacity="0.8"
        />

        {/* RIGHT EYE — red, animated */}
        <path
          d="M184 138 L212 148 L206 174 L178 164 Z"
          fill="#ff3b3b"
          filter="url(#nlg-redGlow)"
          style={{ animation: 'nlg-eye-pulse 2s ease-in-out infinite', animationDelay: '1s' }}
        />
        <path
          d="M184 138 L212 148 L206 174 L178 164 Z"
          fill="none"
          stroke="#ff3b3b"
          strokeWidth="1"
          opacity="0.8"
        />

        {/* Center nose bridge */}
        <rect x="174" y="164" width="12" height="22" fill="#050c18" opacity="0.9" />

        {/* Mouth slit */}
        <rect x="162" y="198" width="36" height="5" rx="1" fill="#030812" opacity="0.9" />
        <rect x="170" y="205" width="20" height="3" rx="1" fill="#030812" opacity="0.8" />
      </g>

      {/* ── Shield border (split cyan/red) ───────── */}
      {/* Left border glow — animated breathe */}
      <g clipPath="url(#nlg-leftClip)" style={{ animation: 'nlg-border-breathe 2.8s ease-in-out infinite' }}>
        <path
          d={shield}
          fill="none"
          stroke="url(#nlg-borderL)"
          strokeWidth="2.5"
          filter="url(#nlg-cyanGlow)"
        />
      </g>
      {/* Right border glow — animated breathe (offset) */}
      <g clipPath="url(#nlg-rightClip)" style={{ animation: 'nlg-red-border 2.8s ease-in-out infinite', animationDelay: '1.4s' }}>
        <path
          d={shield}
          fill="none"
          stroke="url(#nlg-borderR)"
          strokeWidth="2.5"
          filter="url(#nlg-redGlow)"
        />
      </g>
      {/* Clean top border */}
      <path
        d={shield}
        fill="none"
        stroke="rgba(255,255,255,0.08)"
        strokeWidth="1"
      />

      {/* Center dividing line */}
      <g clipPath="url(#nlg-shieldClip)">
        <line
          x1={cx} y1="22"
          x2={cx} y2="392"
          stroke="rgba(255,255,255,0.12)"
          strokeWidth="1.5"
        />
        <line
          x1={cx} y1="22"
          x2={cx} y2="392"
          stroke="rgba(255,255,255,0.06)"
          strokeWidth="4"
        />
      </g>

      {/* ══ WORDMARK ═══════════════════════════════════════ */}

      {/* Glow layer behind text */}
      <text
        x={cx}
        y="450"
        textAnchor="middle"
        fontFamily="Orbitron, sans-serif"
        fontWeight="900"
        fontSize="94"
        fill="rgba(255,255,255,0.05)"
        filter="url(#nlg-textGlow)"
      >
        NIDS
      </text>

      {/* Main NIDS text with gradient */}
      <text
        x={cx}
        y="450"
        textAnchor="middle"
        fontFamily="Orbitron, sans-serif"
        fontWeight="900"
        fontSize="94"
        fill="url(#nlg-nids)"
      >
        NIDS
      </text>

      {/* Metallic highlight stripe */}
      <text
        x={cx}
        y="450"
        textAnchor="middle"
        fontFamily="Orbitron, sans-serif"
        fontWeight="900"
        fontSize="94"
        fill="rgba(255,255,255,0.12)"
        style={{ clipPath: 'polygon(0 0, 100% 0, 100% 35%, 0 35%)' }}
      >
        NIDS
      </text>

      {/* ══ TAGLINE ═════════════════════════════════════════ */}
      <text
        x={cx}
        y="472"
        textAnchor="middle"
        fontFamily="Inter, sans-serif"
        fontWeight="400"
        fontSize="10"
        letterSpacing="3.5"
        fill="#6B7A99"
      >
        NETWORK INTRUSION DETECTION SYSTEM
      </text>

      {/* ── Divider line ─────────────────────────── */}
      <rect x="36"  y="484" width={cx - 36 - 12}  height="1" fill="url(#nlg-divLeft)"  />
      <circle cx={cx} cy="484.5" r="3.5" fill="#660000" stroke="#ff3b3b" strokeWidth="1" />
      <rect x={cx + 12} y="484" width={W - cx - 12 - 36} height="1" fill="url(#nlg-divRight)" />

      {/* ══ 4 PILLAR ICONS ══════════════════════════════════ */}
      {showIcons && (
        <g>
          {/* DETECT */}
          <g transform="translate(36, 500)">
            <circle cx="22" cy="20" r="18" fill="rgba(0,200,200,0.06)" stroke="rgba(0,200,200,0.3)" strokeWidth="1" />
            {/* Radar sweep icon */}
            <circle cx="22" cy="20" r="12" fill="none" stroke="rgba(0,200,200,0.25)" strokeWidth="1" />
            <circle cx="22" cy="20" r="6"  fill="none" stroke="rgba(0,200,200,0.4)"  strokeWidth="1" />
            <circle cx="22" cy="20" r="2"  fill="#22e0ff" />
            <line x1="22" y1="20" x2="32" y2="11" stroke="#22e0ff" strokeWidth="1.5" strokeLinecap="round" />
            <text x="22" y="50" textAnchor="middle" fontFamily="Inter,sans-serif" fontSize="8" letterSpacing="2" fill="#6B7A99">DETECT</text>
          </g>

          {/* PROTECT */}
          <g transform="translate(116, 500)">
            <circle cx="22" cy="20" r="18" fill="rgba(0,200,200,0.06)" stroke="rgba(0,200,200,0.3)" strokeWidth="1" />
            {/* Lock + shield icon */}
            <path d="M22 10 C14 10 14 17 14 17 L14 26 Q14 30 22 32 Q30 30 30 26 L30 17 C30 17 30 10 22 10 Z" fill="none" stroke="#22e0ff" strokeWidth="1.5" />
            <rect x="19" y="20" width="6" height="7" rx="1" fill="none" stroke="#22e0ff" strokeWidth="1.5" />
            <circle cx="22" cy="20" r="1.5" fill="#22e0ff" />
            <text x="22" y="50" textAnchor="middle" fontFamily="Inter,sans-serif" fontSize="8" letterSpacing="2" fill="#6B7A99">PROTECT</text>
          </g>

          {/* ANALYZE */}
          <g transform="translate(196, 500)">
            <circle cx="22" cy="20" r="18" fill="rgba(255,59,59,0.06)" stroke="rgba(255,59,59,0.3)" strokeWidth="1" />
            {/* Crosshair / target icon */}
            <circle cx="22" cy="20" r="10" fill="none" stroke="#ff3b3b" strokeWidth="1.5" />
            <circle cx="22" cy="20" r="4"  fill="none" stroke="#ff3b3b" strokeWidth="1.5" />
            <line x1="22" y1="10" x2="22" y2="14" stroke="#ff3b3b" strokeWidth="1.5" strokeLinecap="round" />
            <line x1="22" y1="26" x2="22" y2="30" stroke="#ff3b3b" strokeWidth="1.5" strokeLinecap="round" />
            <line x1="12" y1="20" x2="16" y2="20" stroke="#ff3b3b" strokeWidth="1.5" strokeLinecap="round" />
            <line x1="28" y1="20" x2="32" y2="20" stroke="#ff3b3b" strokeWidth="1.5" strokeLinecap="round" />
            <circle cx="22" cy="20" r="2" fill="#ff3b3b" />
            <text x="22" y="50" textAnchor="middle" fontFamily="Inter,sans-serif" fontSize="8" letterSpacing="2" fill="#6B7A99">ANALYZE</text>
          </g>

          {/* DEFEND */}
          <g transform="translate(276, 500)">
            <circle cx="22" cy="20" r="18" fill="rgba(255,59,59,0.06)" stroke="rgba(255,59,59,0.3)" strokeWidth="1" />
            {/* Shield + check icon */}
            <path d="M22 10 L32 14 L32 22 Q32 30 22 34 Q12 30 12 22 L12 14 Z" fill="none" stroke="#ff3b3b" strokeWidth="1.5" />
            <polyline points="17,20 21,24 27,16" fill="none" stroke="#ff3b3b" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
            <text x="22" y="50" textAnchor="middle" fontFamily="Inter,sans-serif" fontSize="8" letterSpacing="2" fill="#6B7A99">DEFEND</text>
          </g>

          {/* Vertical dividers between icons */}
          <line x1="104" y1="506" x2="104" y2="534" stroke="rgba(255,255,255,0.08)" strokeWidth="1" />
          <line x1="184" y1="506" x2="184" y2="534" stroke="rgba(255,255,255,0.08)" strokeWidth="1" />
          <line x1="264" y1="506" x2="264" y2="534" stroke="rgba(255,255,255,0.08)" strokeWidth="1" />
        </g>
      )}
    </svg>
  )
}

/* ── Compact shield icon for sidebar / topbar ──────────────── */
export function NidsShieldIcon({ size = 28 }: { size?: number }) {
  const cx = 50
  const shield = `M${cx} 8 C${cx} 8 90 24 90 24 L90 56 Q90 84 ${cx} 94 Q10 84 10 56 L10 24 Z`

  return (
    <svg
      viewBox="0 0 100 100"
      width={size}
      height={size}
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      <defs>
        <filter id="nsi-cglow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="3" result="b" />
          <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
        <filter id="nsi-rglow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="3" result="b" />
          <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
        <clipPath id="nsi-left"><rect x="0" y="0" width="50" height="100" /></clipPath>
        <clipPath id="nsi-right"><rect x="50" y="0" width="50" height="100" /></clipPath>
      </defs>
      {/* Left fill */}
      <g clipPath="url(#nsi-left)">
        <path d={shield} fill="#0a1828" />
        <path d={shield} fill="none" stroke="#22e0ff" strokeWidth="2.5" filter="url(#nsi-cglow)" opacity="0.9" />
      </g>
      {/* Right fill */}
      <g clipPath="url(#nsi-right)">
        <path d={shield} fill="#180608" />
        <path d={shield} fill="none" stroke="#ff3b3b" strokeWidth="2.5" filter="url(#nsi-rglow)" opacity="0.9" />
      </g>
      {/* Base outline */}
      <path d={shield} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="1" />
      {/* Center line */}
      <line x1="50" y1="8" x2="50" y2="94" stroke="rgba(255,255,255,0.1)" strokeWidth="1" />
      {/* Eyes */}
      <path d="M30 44 L46 39 L48 50 L32 55 Z" fill="#00c8c8" filter="url(#nsi-cglow)" opacity="0.9" />
      <path d="M52 39 L68 44 L66 55 L50 50 Z" fill="#ff3b3b" filter="url(#nsi-rglow)" opacity="0.9" />
    </svg>
  )
}
