// Vista aún no construida: dice qué hará, para que el esqueleto se pueda navegar entero.
export default function Pending({ title, description }: { title: string; description: string }) {
  return (
    <section className="rounded-lg border border-line bg-surface p-6">
      <h1 className="text-lg font-semibold">{title}</h1>
      <p className="mt-2 max-w-2xl text-sm text-ink-2">{description}</p>
      <p className="mt-4 text-sm text-muted">Pendiente: siguiente paso del bloque 06.</p>
    </section>
  )
}
