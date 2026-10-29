// Piezas de interfaz compartidas por las vistas.

export function Card({ title, subtitle, children }: { title: string; subtitle?: string; children: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-line bg-surface p-5">
      <h2 className="text-sm font-semibold">{title}</h2>
      {subtitle && <p className="mt-1 text-sm text-ink-2">{subtitle}</p>}
      <div className="mt-4">{children}</div>
    </section>
  )
}

export function TooltipBox({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-md border border-line bg-surface px-3 py-2 text-xs text-ink-2 shadow-sm">
      <div className="mb-1 font-medium text-ink">{title}</div>
      {children}
    </div>
  )
}

export type Tone = 'good' | 'warning' | 'critical' | 'none'

/** Estado con icono y texto: el color nunca va solo. */
export function Status({ label, tone }: { label: string; tone: Tone }) {
  if (tone === 'none') return <span className="text-muted">{label}</span>
  const color = { good: 'text-good', warning: 'text-warning', critical: 'text-critical' }[tone]
  const icon = { good: '✓', warning: '!', critical: '✕' }[tone]
  return (
    <span className="inline-flex items-center gap-1.5">
      <span aria-hidden className={`font-bold ${color}`}>{icon}</span>
      {label}
    </span>
  )
}

/** Severidad 0–100 con una barra de referencia (la longitud es el número). */
export function SeverityBar({ value }: { value: number }) {
  return (
    <span className="inline-flex items-center gap-2 tabular-nums">
      <span className="w-7 text-right">{value}</span>
      <span className="h-1.5 w-16 rounded-full bg-line" aria-hidden>
        <span className="block h-1.5 rounded-full bg-accent" style={{ width: `${value}%` }} />
      </span>
    </span>
  )
}

/** Marca de indicador disputado (decisión 10): severidad rebajada a la mitad. */
export function DisputedBadge() {
  return (
    <span
      className="inline-flex items-center gap-1 rounded border border-line px-1.5 py-0.5 text-xs text-ink-2"
      title="Dominio popular (top 10.000 de Tranco): severidad × 0,5"
    >
      <span aria-hidden className="font-bold text-warning">!</span>
      disputado
    </span>
  )
}

export function ErrorNote({ message }: { message: string }) {
  return (
    <p className="text-sm">
      <Status label={message} tone="critical" />
    </p>
  )
}
