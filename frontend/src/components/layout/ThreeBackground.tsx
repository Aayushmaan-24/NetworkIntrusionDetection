import { useEffect, useRef } from 'react'
import * as THREE from 'three'
import { EffectComposer } from 'three/examples/jsm/postprocessing/EffectComposer.js'
import { RenderPass } from 'three/examples/jsm/postprocessing/RenderPass.js'
import { UnrealBloomPass } from 'three/examples/jsm/postprocessing/UnrealBloomPass.js'

type StarField = THREE.Points<THREE.BufferGeometry, THREE.ShaderMaterial>
type Mountain  = THREE.Mesh<THREE.ShapeGeometry, THREE.MeshBasicMaterial>

type Refs = {
  scene:       THREE.Scene | null
  camera:      THREE.PerspectiveCamera | null
  renderer:    THREE.WebGLRenderer | null
  composer:    EffectComposer | null
  stars:       StarField[]
  nebula:      THREE.Mesh<THREE.PlaneGeometry, THREE.ShaderMaterial> | null
  mountains:   Mountain[]
  animationId: number | null
  targetX:     number
  targetY:     number
}

export function ThreeBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const smoothPos  = useRef({ x: 0, y: 30 })
  const refs       = useRef<Refs>({
    scene: null, camera: null, renderer: null, composer: null,
    stars: [], nebula: null, mountains: [], animationId: null,
    targetX: 0, targetY: 30,
  })

  useEffect(() => {
    const r = refs.current
    if (!canvasRef.current) return

    // ── Scene ────────────────────────────────────────────────────
    r.scene = new THREE.Scene()
    r.scene.fog = new THREE.FogExp2(0x000000, 0.00025)

    r.camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 2000)
    r.camera.position.set(0, 30, 100)

    r.renderer = new THREE.WebGLRenderer({ canvas: canvasRef.current, antialias: true, alpha: true })
    r.renderer.setSize(window.innerWidth, window.innerHeight)
    r.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    r.renderer.toneMapping = THREE.ACESFilmicToneMapping
    r.renderer.toneMappingExposure = 0.5

    r.composer = new EffectComposer(r.renderer)
    r.composer.addPass(new RenderPass(r.scene, r.camera))
    r.composer.addPass(
      new UnrealBloomPass(new THREE.Vector2(window.innerWidth, window.innerHeight), 0.8, 0.4, 0.85)
    )

    // ── Stars ────────────────────────────────────────────────────
    for (let layer = 0; layer < 3; layer++) {
      const count = 5000
      const geo   = new THREE.BufferGeometry()
      const pos   = new Float32Array(count * 3)
      const col   = new Float32Array(count * 3)
      const sz    = new Float32Array(count)

      for (let j = 0; j < count; j++) {
        const radius = 200 + Math.random() * 800
        const theta  = Math.random() * Math.PI * 2
        const phi    = Math.acos(Math.random() * 2 - 1)
        pos[j*3]   = radius * Math.sin(phi) * Math.cos(theta)
        pos[j*3+1] = radius * Math.sin(phi) * Math.sin(theta)
        pos[j*3+2] = radius * Math.cos(phi)

        const c = new THREE.Color()
        const t = Math.random()
        if      (t < 0.7) c.setHSL(0,    0,   0.8 + Math.random() * 0.2)
        else if (t < 0.9) c.setHSL(0.08, 0.5, 0.8)
        else               c.setHSL(0.6,  0.5, 0.8)
        col[j*3] = c.r; col[j*3+1] = c.g; col[j*3+2] = c.b
        sz[j] = Math.random() * 2 + 0.5
      }

      geo.setAttribute('position', new THREE.BufferAttribute(pos, 3))
      geo.setAttribute('color',    new THREE.BufferAttribute(col, 3))
      geo.setAttribute('size',     new THREE.BufferAttribute(sz,  1))

      const mat = new THREE.ShaderMaterial({
        uniforms: { time: { value: 0 }, depth: { value: layer } },
        vertexShader: `
          attribute float size; attribute vec3 color; varying vec3 vColor;
          uniform float time; uniform float depth;
          void main() {
            vColor = color;
            vec3 p = position;
            float a = time * 0.05 * (1.0 - depth * 0.3);
            mat2 rot = mat2(cos(a), -sin(a), sin(a), cos(a));
            p.xy = rot * p.xy;
            vec4 mv = modelViewMatrix * vec4(p, 1.0);
            gl_PointSize = size * (300.0 / -mv.z);
            gl_Position  = projectionMatrix * mv;
          }`,
        fragmentShader: `
          varying vec3 vColor;
          void main() {
            float d = length(gl_PointCoord - vec2(0.5));
            if (d > 0.5) discard;
            float o = 1.0 - smoothstep(0.0, 0.5, d);
            gl_FragColor = vec4(vColor, o);
          }`,
        transparent: true, blending: THREE.AdditiveBlending, depthWrite: false,
      })

      const stars = new THREE.Points(geo, mat)
      r.scene.add(stars)
      r.stars.push(stars as StarField)
    }

    // ── Nebula ───────────────────────────────────────────────────
    {
      const geo = new THREE.PlaneGeometry(8000, 4000, 100, 100)
      const mat = new THREE.ShaderMaterial({
        uniforms: {
          time:    { value: 0 },
          color1:  { value: new THREE.Color(0x0033ff) },
          color2:  { value: new THREE.Color(0xff0066) },
          opacity: { value: 0.25 },
        },
        vertexShader: `
          varying vec2 vUv; varying float vElev; uniform float time;
          void main() {
            vUv = uv;
            vec3 p = position;
            float e = sin(p.x*0.01+time)*cos(p.y*0.01+time)*20.0;
            p.z += e; vElev = e;
            gl_Position = projectionMatrix * modelViewMatrix * vec4(p,1.0);
          }`,
        fragmentShader: `
          uniform vec3 color1; uniform vec3 color2; uniform float opacity; uniform float time;
          varying vec2 vUv; varying float vElev;
          void main() {
            float m = sin(vUv.x*10.0+time)*cos(vUv.y*10.0+time);
            vec3 c = mix(color1, color2, m*0.5+0.5);
            float a = opacity * (1.0 - length(vUv-0.5)*2.0);
            a *= 1.0 + vElev*0.01;
            gl_FragColor = vec4(c, a);
          }`,
        transparent: true, blending: THREE.AdditiveBlending,
        side: THREE.DoubleSide, depthWrite: false,
      })
      const nebula = new THREE.Mesh(geo, mat)
      nebula.position.z = -1050
      r.scene.add(nebula)
      r.nebula = nebula
    }

    // ── Mountains ────────────────────────────────────────────────
    const layers = [
      { z: -50,  h: 60,  color: 0x1a1a2e, opacity: 1   },
      { z: -100, h: 80,  color: 0x16213e, opacity: 0.8 },
      { z: -150, h: 100, color: 0x0f3460, opacity: 0.6 },
      { z: -200, h: 120, color: 0x0a4668, opacity: 0.4 },
    ]
    layers.forEach((layer) => {
      const pts: THREE.Vector2[] = []
      for (let i = 0; i <= 50; i++) {
        const x = (i / 50 - 0.5) * 1000
        const y = Math.sin(i*0.1)*layer.h + Math.sin(i*0.05)*layer.h*0.5 + Math.random()*layer.h*0.2 - 100
        pts.push(new THREE.Vector2(x, y))
      }
      pts.push(new THREE.Vector2(5000, -300), new THREE.Vector2(-5000, -300))
      const geo = new THREE.ShapeGeometry(new THREE.Shape(pts))
      const mat = new THREE.MeshBasicMaterial({
        color: layer.color, transparent: true, opacity: layer.opacity, side: THREE.DoubleSide,
      })
      const mesh = new THREE.Mesh(geo, mat) as Mountain
      mesh.position.set(0, layer.z, layer.z)
      r.scene!.add(mesh)
      r.mountains.push(mesh)
    })

    // ── Atmosphere ───────────────────────────────────────────────
    {
      const geo = new THREE.SphereGeometry(600, 32, 32)
      const mat = new THREE.ShaderMaterial({
        uniforms: { time: { value: 0 } },
        vertexShader: `
          varying vec3 vNormal;
          void main() {
            vNormal = normalize(normalMatrix * normal);
            gl_Position = projectionMatrix * modelViewMatrix * vec4(position,1.0);
          }`,
        fragmentShader: `
          varying vec3 vNormal; uniform float time;
          void main() {
            float i = pow(0.7 - dot(vNormal, vec3(0.0,0.0,1.0)), 2.0);
            vec3 atm = vec3(0.3,0.6,1.0) * i;
            atm *= sin(time*2.0)*0.1+0.9;
            gl_FragColor = vec4(atm, i*0.25);
          }`,
        side: THREE.BackSide, blending: THREE.AdditiveBlending, transparent: true,
      })
      r.scene.add(new THREE.Mesh(geo, mat))
    }

    // ── Animate ──────────────────────────────────────────────────
    const animate = () => {
      r.animationId = requestAnimationFrame(animate)
      const t = Date.now() * 0.001

      r.stars.forEach(s => { s.material.uniforms.time.value = t })
      if (r.nebula) r.nebula.material.uniforms.time.value = t * 0.5

      if (r.camera) {
        const sx = 0.06
        const sy = 0.04
        smoothPos.current.x += (r.targetX - smoothPos.current.x) * sx
        smoothPos.current.y += (r.targetY - smoothPos.current.y) * sy

        r.camera.position.x = smoothPos.current.x + Math.sin(t * 0.1) * 2
        r.camera.position.y = smoothPos.current.y + Math.cos(t * 0.15) * 1
        r.camera.position.z = 100
        r.camera.lookAt(0, 10, -600)
      }

      r.mountains.forEach((m, i) => {
        const p = 1 + i * 0.5
        m.position.x = Math.sin(t * 0.1) * 2 * p
        m.position.y = 50 + Math.cos(t * 0.15) * p
      })

      r.composer?.render()
    }
    animate()

    // ── Mouse parallax ───────────────────────────────────────────
    const onMouseMove = (e: MouseEvent) => {
      const nx = (e.clientX / window.innerWidth  - 0.5) * 2   // -1 → 1
      const ny = (e.clientY / window.innerHeight - 0.5) * 2
      refs.current.targetX = nx * 8
      refs.current.targetY = 30 - ny * 4
    }
    window.addEventListener('mousemove', onMouseMove)

    // ── Resize ───────────────────────────────────────────────────
    const onResize = () => {
      if (!r.camera || !r.renderer || !r.composer) return
      r.camera.aspect = window.innerWidth / window.innerHeight
      r.camera.updateProjectionMatrix()
      r.renderer.setSize(window.innerWidth, window.innerHeight)
      r.composer.setSize(window.innerWidth, window.innerHeight)
    }
    window.addEventListener('resize', onResize)

    // ── Cleanup ──────────────────────────────────────────────────
    return () => {
      if (r.animationId) cancelAnimationFrame(r.animationId)
      window.removeEventListener('mousemove', onMouseMove)
      window.removeEventListener('resize', onResize)
      r.stars.forEach(s => { s.geometry.dispose(); s.material.dispose() })
      r.mountains.forEach(m => { m.geometry.dispose(); m.material.dispose() })
      if (r.nebula) { r.nebula.geometry.dispose(); r.nebula.material.dispose() }
      r.renderer?.dispose()
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 z-0 h-full w-full"
    />
  )
}
