export function CosmosBackdrop() {
  return (
    <div aria-hidden="true" className="cosmos-backdrop">
      {/* Ambient glow blobs */}
      <div className="cosmos-glow cosmos-glow-a" />
      <div className="cosmos-glow cosmos-glow-b" />
      {/* Fine grid */}
      <div className="cosmos-grid" />
      {/* Moving scan line */}
      <div className="cosmos-scanline" />
      {/* CRT texture */}
      <div className="cosmos-crt" />
      {/* Edge vignette */}
      <div className="cosmos-vignette" />
    </div>
  )
}
