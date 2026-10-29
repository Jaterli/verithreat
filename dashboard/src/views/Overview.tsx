import { useMemo, useState } from 'react'
import {
  Bar,
  BarChart,
  CartesianGrid,
  LabelList,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { type GroupStats, type SourceStats, type Stats, useApi } from '../api'
import { categoryLabel, fmtAgo, fmtCompact, fmtDateTime, fmtDecimal, fmtInt } from '../format'
import { Card, Status, type Tone, TooltipBox } from '../ui'

// Panel general: cifras clave, severidad por categoría, frescura de las fuentes y registro en Fabric (GET /api/v1/stats).

/** Grupos (tipo × categoría) que se dibujan; el resto queda en la tabla. */
const TOP_GROUPS = 12

/** Frecuencia de cada fuente en ingest.py, en horas: una fuente va retrasada si su última descarga supera el doble. */
const EXPECTED_HOURS: Record<string, number> = {
  threatfox: 1,
  urlhaus: 1,
  'blocklist.de': 1,
  tweetfeed: 1,
  phishtank: 6,
  ipsum: 24,
}

const ROLE_LABELS: Record<SourceStats['role'], string> = {
  indicators: 'Feed',
  signal: 'Señal',
  organization: 'Organización',
}

export default function Overview() {
  const { data, error, loading } = useApi<Stats>('/api/v1/stats')

  if (error) {
    return (
      <Card title="No se pudo cargar el panel">

        <p className="text-sm text-ink-2">{error}</p>
        <p className="mt-2 text-sm text-muted">
          Comprueba que el Gateway (puerto 8080) e ioc-service (8081) están en marcha y que la clave de
          dashboard/.env.local es válida.
        </p>
      </Card>
    )
  }
  if (!data) {
    return <p className="text-sm text-muted">{loading ? 'Cargando…' : 'Sin datos'}</p>
  }

  const feeds = data.sources.filter((s) => s.role !== 'organization')
  const lastIngest = feeds
    .map((s) => s.lastFetchedAt)
    .filter((t): t is string => t !== null)
    .sort()
    .at(-1)

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Tile label="Indicadores" value={fmtInt(data.indicators)} hero>
          {data.scored === data.indicators
            ? 'todos con severidad'
            : `${fmtInt(data.indicators - data.scored)} pendientes de puntuar`}
        </Tile>
        <Tile label="Disputados" value={fmtInt(data.disputed)}>
          dominios populares (top 10.000 de Tranco), severidad × 0,5
        </Tile>
        <Tile
          label="Modelo A · PR-AUC temporal"
          value={data.model?.temporalPrAuc != null ? fmtDecimal(data.model.temporalPrAuc) : '—'}
        >
          {data.model
            ? `ROC-AUC ${data.model.temporalRocAuc != null ? fmtDecimal(data.model.temporalRocAuc) : '—'} · versión ${data.model.version}`
            : 'ninguna versión activa'}
        </Tile>
        <Tile label="Última ingesta" value={lastIngest ? fmtAgo(lastIngest) : '—'}>
          {lastIngest ? fmtDateTime(lastIngest) : 'sin descargas'}
        </Tile>
      </div>

      <SeverityByGroup groups={data.byTypeAndCategory} />
      <SeverityHistogram stats={data} />

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <SourcesTable sources={data.sources} />
        </div>
        <FabricTable stats={data} />
      </div>

      <p className="text-xs text-muted">Datos generados {fmtDateTime(data.generatedAt)}.</p>
    </div>
  )
}

function Tile({ label, value, hero, children }: { label: string; value: string; hero?: boolean; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-line bg-surface p-4">
      <p className="text-sm text-ink-2">{label}</p>
      <p className={`mt-1 font-semibold ${hero ? 'text-4xl' : 'text-2xl'}`}>{value}</p>
      <p className="mt-1 text-xs text-muted">{children}</p>
    </div>
  )
}

/** Severidad mediana de cada tipo dentro de su categoría, con la línea hasta el p90. */
function SeverityByGroup({ groups }: { groups: GroupStats[] }) {
  const rows = useMemo(
    () =>
      [...groups]
        .slice(0, TOP_GROUPS) // ya vienen por número de indicadores, de mayor a menor
        .sort((a, b) => categoryLabel(a.category).localeCompare(categoryLabel(b.category)) || b.count - a.count)
        .map((g) => ({ ...g, label: `${categoryLabel(g.category)} · ${g.type}` })),
    [groups],
  )
  const rest = groups.slice(TOP_GROUPS)
  const restCount = rest.reduce((n, g) => n + g.count, 0)

  return (
    <Card
      title="Severidad mediana por categoría y tipo"
      subtitle={`Barra = mediana; línea = hasta el percentil 90. La severidad solo se compara dentro de una categoría. Los ${TOP_GROUPS} grupos con más indicadores.`}
    >
      <ResponsiveContainer width="100%" height={rows.length * 30 + 40}>
        <BarChart data={rows} layout="vertical" margin={{ top: 4, right: 40, bottom: 4, left: 8 }}>
          <CartesianGrid horizontal={false} stroke="var(--grid)" />
          <XAxis
            type="number"
            domain={[0, 100]}
            ticks={[0, 25, 50, 75, 100]}
            tick={{ fill: 'var(--muted)', fontSize: 12 }}
            stroke="var(--axis)"
          />
          <YAxis
            type="category"
            dataKey="label"
            width={270}
            tick={{ fill: 'var(--ink-2)', fontSize: 12 }}
            stroke="var(--axis)"
            tickLine={false}
          />
          <Tooltip
            cursor={{ fill: 'var(--line)' }}
            content={({ active, payload }) => {
              const g = active ? (payload?.[0]?.payload as (GroupStats & { label: string }) | undefined) : undefined
              return g ? (
                <TooltipBox title={g.label}>
                  <div>Mediana {g.medianSeverity} · p90 {g.p90Severity}</div>
                  <div>{fmtInt(g.count)} indicadores{g.disputed ? ` · ${fmtInt(g.disputed)} disputados` : ''}</div>
                </TooltipBox>
              ) : null
            }}
          />
          <Bar dataKey="medianSeverity" barSize={14} shape={MedianWithP90} isAnimationActive={false}>
            <LabelList dataKey="medianSeverity" position="insideRight" fill="#ffffff" fontSize={11} />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
      <details className="mt-3 text-sm">
        <summary className="cursor-pointer text-ink-2">
          Ver la tabla completa ({groups.length} grupos{rest.length ? `; ${rest.length} fuera del gráfico, ${fmtInt(restCount)} indicadores` : ''})
        </summary>
        <table className="mt-3 w-full text-left tabular-nums">
          <thead className="text-muted">
            <tr>
              <th className="py-1 font-normal">Categoría</th>
              <th className="py-1 font-normal">Tipo</th>
              <th className="py-1 text-right font-normal">Indicadores</th>
              <th className="py-1 text-right font-normal">Mediana</th>
              <th className="py-1 text-right font-normal">p90</th>
              <th className="py-1 text-right font-normal">Disputados</th>
            </tr>
          </thead>
          <tbody>
            {groups.map((g) => (
              <tr key={`${g.type}|${g.category}`} className="border-t border-line">
                <td className="py-1">{categoryLabel(g.category)}</td>
                <td className="py-1">{g.type}</td>
                <td className="py-1 text-right">{fmtInt(g.count)}</td>
                <td className="py-1 text-right">{g.medianSeverity}</td>
                <td className="py-1 text-right">{g.p90Severity}</td>
                <td className="py-1 text-right">{fmtInt(g.disputed)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </Card>
  )
}

/**
 * Barra horizontal hasta la mediana con extremo redondeado y, a continuación, una línea fina hasta el p90 rematada con
 * una marca vertical. La escala se deduce de la propia barra (ancho / mediana), así que no depende del eje.
 */
function MedianWithP90(props: BarShapeProps) {
  const { x = 0, y = 0, width = 0, height = 0, payload } = props
  const g = payload as GroupStats
  const r = Math.min(4, width / 2, height / 2)
  const cy = y + height / 2
  const p90x = g.medianSeverity > 0 ? x + (width * g.p90Severity) / g.medianSeverity : x
  return (
    <g>
      {g.p90Severity > g.medianSeverity && (
        <g stroke="var(--ink-2)" strokeWidth={1.5}>
          <line x1={x + width} x2={p90x} y1={cy} y2={cy} />
          <line x1={p90x} x2={p90x} y1={cy - 5} y2={cy + 5} />
        </g>
      )}
      <path
        fill="var(--series-1)"
        d={`M${x},${y} H${x + width - r} A${r},${r} 0 0 1 ${x + width},${y + r} V${y + height - r} A${r},${r} 0 0 1 ${x + width - r},${y + height} H${x} Z`}
      />
    </g>
  )
}

type BarShapeProps = { x?: number; y?: number; width?: number; height?: number; payload?: unknown }

/** Distribución de la severidad (tramos de 10) en la categoría elegida. */
function SeverityHistogram({ stats }: { stats: Stats }) {
  const categories = useMemo(() => {
    const totals = new Map<string, number>()
    for (const g of stats.byTypeAndCategory) {
      const key = g.category ?? ''
      totals.set(key, (totals.get(key) ?? 0) + g.count)
    }
    return [...totals.entries()].sort((a, b) => b[1] - a[1])
  }, [stats])
  const [category, setCategory] = useState(categories[0]?.[0] ?? '')
  const bins = stats.severityHistogram
    .filter((b) => (b.category ?? '') === category)
    .map((b) => ({ ...b, label: `${b.from}–${b.from === 90 ? 100 : b.from + 9}` }))

  return (
    <Card title="Distribución de la severidad" subtitle="Indicadores por tramo de severidad en una categoría.">
      <label className="flex items-center gap-2 text-sm text-ink-2">
        Categoría
        <select
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          className="rounded-md border border-line bg-surface px-2 py-1 text-ink"
        >
          {categories.map(([c, n]) => (
            <option key={c} value={c}>
              {categoryLabel(c || null)} ({fmtInt(n)})
            </option>
          ))}
        </select>
      </label>
      <ResponsiveContainer width="100%" height={240}>
        <BarChart data={bins} margin={{ top: 16, right: 8, bottom: 4, left: 0 }}>
          <CartesianGrid vertical={false} stroke="var(--grid)" />
          <XAxis dataKey="label" tick={{ fill: 'var(--muted)', fontSize: 12 }} stroke="var(--axis)" tickLine={false} />
          <YAxis
            tickFormatter={fmtCompact}
            tick={{ fill: 'var(--muted)', fontSize: 12 }}
            stroke="var(--axis)"
            tickLine={false}
            width={48}
          />
          <Tooltip
            cursor={{ fill: 'var(--line)' }}
            content={({ active, payload }) => {
              const b = active ? (payload?.[0]?.payload as { label: string; count: number } | undefined) : undefined
              return b ? (
                <TooltipBox title={`Severidad ${b.label}`}>
                  <div>{fmtInt(b.count)} indicadores</div>
                </TooltipBox>
              ) : null
            }}
          />
          <Bar dataKey="count" fill="var(--series-1)" maxBarSize={24} radius={[4, 4, 0, 0]} isAnimationActive={false} />
        </BarChart>
      </ResponsiveContainer>
    </Card>
  )
}

type Freshness = { label: string; tone: Tone }

function freshness(s: SourceStats, now: number): Freshness {
  if (s.role === 'organization') return { label: '—', tone: 'none' }
  if (!s.lastFetchedAt) return { label: 'Sin descargas', tone: 'critical' }
  const hours = (now - new Date(s.lastFetchedAt).getTime()) / 3_600_000
  const expected = EXPECTED_HOURS[s.code] ?? 1
  return hours <= 2 * expected ? { label: 'Al día', tone: 'good' } : { label: 'Retrasada', tone: 'warning' }
}

function SourcesTable({ sources }: { sources: SourceStats[] }) {
  const now = Date.now()
  return (
    <Card title="Fuentes" subtitle="Última descarga y observaciones que siguen apareciendo (confirmadas en las últimas 48 h).">
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm tabular-nums">
          <thead className="text-muted">
            <tr>
              <th className="py-1 font-normal">Fuente</th>
              <th className="py-1 font-normal">Papel</th>
              <th className="py-1 font-normal">Última descarga</th>
              <th className="py-1 text-right font-normal">Observaciones</th>
              <th className="py-1 text-right font-normal">Activas 48 h</th>
              <th className="py-1 pl-4 font-normal">Estado</th>
            </tr>
          </thead>
          <tbody>
            {sources.map((s) => (
              <tr key={s.code} className="border-t border-line">
                <td className="py-1.5">
                  {s.code}
                  {s.family !== s.code && <span className="text-muted"> · {s.family}</span>}
                </td>
                <td className="py-1.5 text-ink-2">{ROLE_LABELS[s.role]}</td>
                <td className="py-1.5 text-ink-2" title={s.lastFetchedAt ? fmtDateTime(s.lastFetchedAt) : undefined}>
                  {s.lastFetchedAt ? fmtAgo(s.lastFetchedAt, now) : '—'}
                </td>
                <td className="py-1.5 text-right">{s.role === 'signal' ? '—' : fmtInt(s.sightings)}</td>
                <td className="py-1.5 text-right">{s.role === 'signal' ? '—' : fmtInt(s.activeLast48h)}</td>
                <td className="py-1.5 pl-4">
                  <Status {...freshness(s, now)} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

function FabricTable({ stats }: { stats: Stats }) {
  return (
    <Card title="Registro en Fabric" subtitle="Aportaciones de cada organización según su estado en la cadena.">
      <table className="w-full text-left text-sm tabular-nums">
        <thead className="text-muted">
          <tr>
            <th className="py-1 font-normal">Organización</th>
            <th className="py-1 text-right font-normal">Registradas</th>
            <th className="py-1 text-right font-normal">Pendientes</th>
            <th className="py-1 text-right font-normal">Fallidas</th>
          </tr>
        </thead>
        <tbody>
          {stats.fabric.map((f) => (
            <tr key={f.organization} className="border-t border-line">
              <td className="py-1.5">{f.organization}</td>
              <td className="py-1.5 text-right">{fmtInt(f.registered)}</td>
              <td className="py-1.5 text-right">{fmtInt(f.pending)}</td>
              <td className="py-1.5 text-right">
                {f.failed > 0 ? <Status label={fmtInt(f.failed)} tone="critical" /> : '0'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="mt-3 text-xs text-muted">
        Solo se registran las aportaciones de las organizaciones; los feeds públicos conservan su procedencia en la base
        de datos.
      </p>
    </Card>
  )
}
