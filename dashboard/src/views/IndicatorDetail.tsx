import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { type FamilyTerm, type IndicatorDetail as Detail, type Score, type Sighting, useApi } from '../api'
import { categoryLabel, fmtDateTime, fmtFixed, fmtInt, gradeLabel } from '../format'
import { Card, DisputedBadge, ErrorNote, Status, type Tone, TooltipBox } from '../ui'

// Detalle de un indicador. La pieza central es la explicación de la severidad: se rehace la cuenta de score.py
// (CLAUDE.md, decisión 13) con los términos guardados en components y se comprueba que da la severidad guardada.

export default function IndicatorDetail({ id }: { id: string }) {
  const { data, error, loading } = useApi<Detail>(`/api/v1/indicators/${encodeURIComponent(id)}`)

  if (error) return <ErrorNote message={error} />
  if (!data) return <p className="text-sm text-muted">{loading ? 'Cargando…' : 'Sin datos'}</p>

  const { indicator: ind, sightings, scoreHistory } = data
  const s = ind.summary
  return (
    <div className="space-y-6">
      <a href="#/indicators" className="text-sm text-ink-2 hover:underline">
        ← Indicadores
      </a>

      <section className="rounded-lg border border-line bg-surface p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <p className="text-sm text-ink-2">
              {ind.type} · {categoryLabel(ind.score?.components.category ?? s?.categories[0] ?? null)}
            </p>
            <p className="mt-1 max-h-32 overflow-auto font-mono text-base break-all">{ind.value}</p>
          </div>
          <div className="text-right">
            <p className="text-sm text-ink-2">Severidad</p>
            <p className="text-5xl font-semibold">{ind.score ? ind.score.severity : '—'}</p>
            {ind.score?.disputed && <DisputedBadge />}
          </div>
        </div>
        {s && (
          <dl className="mt-5 grid grid-cols-2 gap-x-6 gap-y-3 text-sm sm:grid-cols-4">
            <Fact label="Visto por primera vez">{fmtDateTime(s.firstSeen)}</Fact>
            <Fact label="Última confirmación">{fmtDateTime(s.lastConfirmed)}</Fact>
            <Fact label="Fuentes">{s.sourceNames.join(', ')}</Fact>
            <Fact label="Familias independientes">{s.families}</Fact>
            <Fact label="Observaciones">{fmtInt(s.sightings)}</Fact>
            <Fact label="Categorías">{s.categories.map(categoryLabel).join(', ')}</Fact>
            {s.ipsumLevel !== null && <Fact label="Nivel de IPsum">{s.ipsumLevel} listas</Fact>}
            <Fact label="Huella (sha256)">
              <span className="font-mono text-xs break-all">{ind.fingerprint}</span>
            </Fact>
          </dl>
        )}
      </section>

      {ind.score ? (
        <Explanation score={ind.score} type={ind.type} />
      ) : (
        <Card title="Severidad pendiente">
          <p className="text-sm text-ink-2">
            Aún no se ha puntuado: score.py lo hará en su siguiente ejecución horaria.
          </p>
        </Card>
      )}

      <SightingsTable sightings={sightings} />
      <History points={scoreHistory} />
    </div>
  )
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-muted">{label}</dt>
      <dd className="mt-0.5">{children}</dd>
    </div>
  )
}

const f2 = (n: number) => fmtFixed(n, 2)
const f3 = (n: number) => fmtFixed(n, 3)

/** La cuenta de score.py, paso a paso, con los números guardados. */
function Explanation({ score, type }: { score: Score; type: string }) {
  const c = score.components
  const terms = Object.entries(c.families)
    .map(([family, t]) => ({ family, ...t, contribution: t.reliability * t.decay }))
    .sort((a, b) => b.contribution - a.contribution)
  const E = c.evidence
  const withModel = c.model ? 1 - (1 - E) * (1 - c.model.beta * c.model.p_malicious) : E
  const S = c.disputed ? withModel * c.disputed.factor : withModel
  const recomputed = Math.round(100 * S)

  return (
    <Card
      title={`Por qué tiene severidad ${score.severity}`}
      subtitle={`Calculada el ${fmtDateTime(score.computedAt)} (configuración ${c.config}). Los decaimientos son los de esa fecha: score.py solo guarda una puntuación nueva si cambia 5 puntos o más.`}
    >
      <ol className="space-y-6 text-sm">
        <Step n={1} title="Fiabilidad y decaimiento de la mejor observación de cada familia de fuentes">
          <p className="text-ink-2">
            r = fiabilidad de la fuente para este tipo, medida con VirusTotal; d = 0,5^(días / vida media), por
            antigüedad de la última confirmación. Dentro de una familia solo cuenta la mejor observación.
          </p>
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-left tabular-nums">
              <thead className="text-muted">
                <tr>
                  <th className="py-1 font-normal">Familia</th>
                  <th className="py-1 font-normal">Fuente</th>
                  <th className="py-1 font-normal">Fiabilidad r</th>
                  <th className="py-1 font-normal">Decaimiento d</th>
                  <th className="py-1 font-normal">Aporta r·d</th>
                </tr>
              </thead>
              <tbody>
                {terms.map((t) => (
                  <tr key={t.family} className="border-t border-line align-top">
                    <td className="py-1.5">{t.family}</td>
                    <td className="py-1.5 text-ink-2">{t.source}</td>
                    <td className="py-1.5">
                      {f2(t.reliability)} <span className="text-muted">· {gradeLabel(t.grade)}</span>
                    </td>
                    <td className="py-1.5">
                      {f2(t.decay)} <span className="text-muted">· {ageLabel(t, type)}</span>
                    </td>
                    <td className="py-1.5">
                      <span className="inline-flex items-center gap-2">
                        <span className="w-10">{f2(t.contribution)}</span>
                        <span className="h-1.5 w-20 rounded-full bg-line" aria-hidden>
                          <span
                            className="block h-1.5 rounded-full bg-accent"
                            style={{ width: `${Math.min(100, t.contribution * 100)}%` }}
                          />
                        </span>
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Step>

        <Step n={2} title="Evidencia combinada (OR probabilístico entre familias)">
          <Formula>
            E = 1 − {terms.map((t) => `(1 − ${f2(t.contribution)})`).join(' · ')} = <b>{f3(E)}</b>
          </Formula>
          <p className="mt-1 text-ink-2">
            {terms.length > 1
              ? 'Cada familia independiente que lo confirma acerca la evidencia a 1; dos fuentes de la misma familia no cuentan doble.'
              : 'Una sola familia: la evidencia es su aportación.'}
          </p>
        </Step>

        <Step n={3} title="Modelo A (señal débil sobre el nombre del dominio)">
          {c.model ? (
            <>
              <Formula>
                S = 1 − (1 − {f3(E)}) · (1 − {f2(c.model.beta)} · {f2(c.model.p_malicious)}) = <b>{f3(withModel)}</b>
              </Formula>
              <p className="mt-1 text-ink-2">
                El modelo puntúa el host <span className="font-mono">{c.model.host}</span> solo por su forma
                (longitud, entropía, TLD…): p = {f2(c.model.p_malicious)}, con peso β = {f2(c.model.beta)}.
              </p>
            </>
          ) : (
            <p className="text-ink-2">
              No aplica: el modelo solo puntúa dominios y hosts de URL que no sean IP ni de una plataforma de doble uso.
              S = E = {f3(E)}.
            </p>
          )}
        </Step>

        <Step n={4} title="Dominio popular (disputado)">
          {c.disputed ? (
            <Formula>
              S × {f2(c.disputed.factor)} = {f3(withModel)} × {f2(c.disputed.factor)} = <b>{f3(S)}</b>
              <span className="ml-2 text-ink-2">({c.disputed.reason})</span>
            </Formula>
          ) : (
            <p className="text-ink-2">No está disputado: S no cambia.</p>
          )}
        </Step>

        <Step n={5} title="Severidad">
          <Formula>
            round(100 · {f3(S)}) = <b>{recomputed}</b>
          </Formula>
          {recomputed !== score.severity && (
            <p className="mt-1 text-ink-2">
              La severidad guardada es {score.severity}: la diferencia viene del redondeo de los términos guardados.
            </p>
          )}
        </Step>
      </ol>
    </Card>
  )
}

const HASHES = new Set(['sha256', 'md5', 'sha1'])

function ageLabel(t: FamilyTerm & { family: string }, type: string): string {
  if (t.family === 'ipsum') return 'señal diaria de IPsum, no decae'
  if (HASHES.has(type)) return 'los hashes no decaen'
  const hours = t.age_days * 24
  if (hours < 1) return 'confirmada al calcular'
  return hours < 24 ? `confirmada hace ${fmtFixed(hours, 0)} h` : `confirmada hace ${fmtFixed(t.age_days, 1)} días`
}

function Step({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <li className="grid grid-cols-[1.75rem_1fr] gap-x-2">
      <span className="flex h-6 w-6 items-center justify-center rounded-full bg-accent/10 text-xs font-semibold">
        {n}
      </span>
      <div>
        <p className="font-medium">{title}</p>
        <div className="mt-1">{children}</div>
      </div>
    </li>
  )
}

function Formula({ children }: { children: React.ReactNode }) {
  return <p className="rounded-md bg-line/50 px-3 py-2 font-mono text-xs leading-relaxed">{children}</p>
}

const FABRIC: Record<string, { label: string; tone: Tone }> = {
  registered: { label: 'registrada', tone: 'good' },
  pending: { label: 'pendiente', tone: 'warning' },
  failed: { label: 'fallida', tone: 'critical' },
}

function SightingsTable({ sightings }: { sightings: Sighting[] }) {
  return (
    <Card
      title="Observaciones"
      subtitle="Una por registro de cada fuente (las 200 más recientes). Las aportaciones de organizaciones llevan su registro en Fabric."
    >
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm tabular-nums">
          <thead className="text-muted">
            <tr>
              <th className="py-1 pr-3 font-normal">Fuente</th>
              <th className="py-1 pr-3 font-normal">Categoría</th>
              <th className="py-1 pr-3 font-normal">Vista</th>
              <th className="py-1 pr-3 font-normal">Confirmada</th>
              <th className="py-1 pr-3 font-normal">Detalles</th>
              <th className="py-1 font-normal">Fabric</th>
            </tr>
          </thead>
          <tbody>
            {sightings.map((s, i) => (
              <tr key={i} className="border-t border-line align-top">
                <td className="py-1.5 pr-3">{s.source}</td>
                <td className="py-1.5 pr-3 text-ink-2">{categoryLabel(s.category)}</td>
                <td className="py-1.5 pr-3 text-ink-2">{fmtDateTime(s.seenAt)}</td>
                <td className="py-1.5 pr-3 text-ink-2">{fmtDateTime(s.lastConfirmedAt)}</td>
                <td className="py-1.5 pr-3 text-ink-2">{details(s) || '—'}</td>
                <td className="py-1.5">
                  {s.fabric ? (
                    <span className="flex flex-col gap-0.5">
                      <Status {...FABRIC[s.fabric.status]} />
                      {s.fabric.txId && (
                        <span className="font-mono text-xs text-muted" title={`hash ${s.fabric.canonicalHash}`}>
                          {s.fabric.mspId} · tx {s.fabric.txId.slice(0, 12)}…
                        </span>
                      )}
                      {s.fabric.status !== 'registered' && s.fabric.attempts > 0 && (
                        <span className="text-xs text-muted">{s.fabric.attempts} intentos</span>
                      )}
                    </span>
                  ) : (
                    <span className="text-muted">—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

function details(s: Sighting): string {
  return [
    s.malwareFamily,
    s.status,
    s.confidence !== null ? `confianza ${s.confidence}` : null,
    s.reporter ? `por ${s.reporter}` : null,
    s.corroborated ? 'corroborado' : null,
  ]
    .filter(Boolean)
    .join(' · ')
}

const dayMonth = new Intl.DateTimeFormat('es-ES', { day: 'numeric', month: 'short' })

function History({ points }: { points: Detail['scoreHistory'] }) {
  const rows = [...points].reverse().map((p) => ({ ...p, t: new Date(p.computedAt).getTime() }))
  // Cinco marcas repartidas entre la primera y la última puntuación (Recharts pone muy pocas en escalas de tiempo)
  const first = rows[0]?.t ?? 0
  const last = rows.at(-1)?.t ?? 0
  const ticks = Array.from({ length: 5 }, (_, i) => first + ((last - first) * i) / 4)
  return (
    <Card title="Historial de severidad" subtitle="Una fila por cambio de 5 puntos o más, o de la marca de disputado.">
      {rows.length === 0 ? (
        <p className="text-sm text-ink-2">Aún no tiene puntuaciones.</p>
      ) : rows.length === 1 ? (
        <p className="text-sm text-ink-2">
          Sin cambios desde la primera puntuación ({rows[0].severity}, el {fmtDateTime(rows[0].computedAt)}).
        </p>
      ) : (
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={rows} margin={{ top: 8, right: 16, bottom: 4, left: 0 }}>
            <CartesianGrid vertical={false} stroke="var(--grid)" />
            <XAxis
              dataKey="t"
              type="number"
              scale="time"
              domain={[first, last]}
              ticks={ticks}
              tickFormatter={(t: number) => dayMonth.format(t)}
              tick={{ fill: 'var(--muted)', fontSize: 12 }}
              stroke="var(--axis)"
            />
            <YAxis domain={[0, 100]} ticks={[0, 25, 50, 75, 100]} tick={{ fill: 'var(--muted)', fontSize: 12 }} stroke="var(--axis)" width={36} />
            <Tooltip
              content={({ active, payload }) => {
                const p = active ? (payload?.[0]?.payload as (typeof rows)[number] | undefined) : undefined
                return p ? (
                  <TooltipBox title={fmtDateTime(p.computedAt)}>
                    Severidad {p.severity}
                    {p.disputed ? ' · disputado' : ''}
                  </TooltipBox>
                ) : null
              }}
            />
            <Line
              type="stepAfter"
              dataKey="severity"
              stroke="var(--series-1)"
              strokeWidth={2}
              dot={{ r: 4, fill: 'var(--series-1)', stroke: 'var(--surface)', strokeWidth: 2 }}
              isAnimationActive={false}
            />
          </LineChart>
        </ResponsiveContainer>
      )}
    </Card>
  )
}
