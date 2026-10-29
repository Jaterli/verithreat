import { type FormEvent, useState } from 'react'
import { ApiError, getJson, INDICATOR_TYPES, type IndicatorRow, type IndicatorView, type Page, useApi } from '../api'
import { CATEGORIES, categoryLabel, fmtDateTime } from '../format'
import { Card, ErrorNote, SeverityBar } from '../ui'

// Búsqueda de un IOC por su valor y listado priorizado (por severidad) con filtros. Los filtros viven en el hash
// (#/indicators?category=phishing&type=url&min=70&page=0): atrás y adelante del navegador los conservan.

const PAGE_SIZE = 50

export default function Indicators({ query }: { query: URLSearchParams }) {
  const category = query.get('category') ?? ''
  const type = query.get('type') ?? ''
  const min = Number(query.get('min') ?? 0)
  const page = Number(query.get('page') ?? 0)

  const setFilters = (changes: Record<string, string | number>) => {
    const q = new URLSearchParams(query)
    for (const [k, v] of Object.entries(changes)) {
      if (v === '' || v === 0) q.delete(k)
      else q.set(k, String(v))
    }
    if (!('page' in changes)) q.delete('page') // un filtro nuevo vuelve a la primera página
    window.location.hash = `/indicators${q.size ? `?${q}` : ''}`
  }

  const api = new URLSearchParams({ page: String(page), size: String(PAGE_SIZE) })
  if (category) api.set('category', category)
  if (type) api.set('type', type)
  if (min) api.set('minSeverity', String(min))
  const { data, error, loading } = useApi<Page<IndicatorRow>>(`/api/v1/indicators?${api}`)

  return (
    <div className="space-y-6">
      <Lookup />

      <Card
        title="Indicadores por severidad"
        subtitle="La severidad solo es comparable dentro de una categoría: filtra por categoría para priorizar."
      >
        <div className="flex flex-wrap items-end gap-4 text-sm">
          <label className="flex flex-col gap-1 text-ink-2">
            Categoría
            <select value={category} onChange={(e) => setFilters({ category: e.target.value })} className={INPUT}>
              <option value="">Todas</option>
              {CATEGORIES.map((c) => (
                <option key={c} value={c}>
                  {categoryLabel(c)}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-ink-2">
            Tipo
            <select value={type} onChange={(e) => setFilters({ type: e.target.value })} className={INPUT}>
              <option value="">Todos</option>
              {INDICATOR_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-ink-2">
            Severidad mínima: <span className="tabular-nums text-ink">{min}</span>
            <input
              type="range"
              min={0}
              max={100}
              step={5}
              defaultValue={min}
              key={min} // se reinicia si cambia el hash (atrás / adelante)
              onPointerUp={(e) => setFilters({ min: Number(e.currentTarget.value) })}
              onKeyUp={(e) => setFilters({ min: Number(e.currentTarget.value) })}
              className="w-48 accent-[var(--series-1)]"
            />
          </label>
        </div>

        <div className="mt-4 overflow-x-auto">
          {error && <ErrorNote message={error} />}
          {!error && (
            <table className={`w-full table-fixed text-left text-sm ${loading ? 'opacity-60' : ''}`}>
              <colgroup>
                <col />
                <col className="w-20" />
                <col className="w-48" />
                <col className="w-32" />
                <col className="w-28" />
              </colgroup>
              <thead className="text-muted">
                <tr>
                  <th className="py-1 font-normal">Valor</th>
                  <th className="py-1 font-normal">Tipo</th>
                  <th className="py-1 font-normal">Categoría</th>
                  <th className="py-1 font-normal">Severidad</th>
                  <th className="py-1 font-normal">Calculada</th>
                </tr>
              </thead>
              <tbody>
                {data?.items.map((r) => (
                  <tr key={r.id} className="border-t border-line hover:bg-line/50">
                    <td className="truncate py-1.5 pr-4 font-mono text-xs" title={r.value.slice(0, 500)}>
                      <a href={`#/indicators/${r.id}`} className="hover:underline">
                        {r.value}
                      </a>
                    </td>
                    <td className="py-1.5 text-ink-2">{r.type}</td>
                    <td className="py-1.5 text-ink-2">{categoryLabel(r.category)}</td>
                    <td className="py-1.5">
                      <span className="inline-flex items-center gap-2">
                        <SeverityBar value={r.severity} />
                        {r.disputed && <span aria-label="disputado" title="disputado" className="font-bold text-warning">!</span>}
                      </span>
                    </td>
                    <td className="py-1.5 text-xs text-muted">{fmtDateTime(r.computedAt)}</td>
                  </tr>
                ))}
                {data && data.items.length === 0 && (
                  <tr>
                    <td colSpan={5} className="py-4 text-center text-muted">
                      Ningún indicador cumple los filtros.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </div>

        {data && (
          <div className="mt-4 flex items-center justify-between text-sm">
            <button
              type="button"
              disabled={page === 0}
              onClick={() => setFilters({ page: page - 1 })}
              className={BUTTON}
            >
              ← Anterior
            </button>
            <span className="text-muted">
              Página {page + 1} · {data.items.length} indicadores
            </span>
            <button
              type="button"
              disabled={!data.hasNext}
              onClick={() => setFilters({ page: page + 1 })}
              className={BUTTON}
            >
              Siguiente →
            </button>
          </div>
        )}
      </Card>
    </div>
  )
}

const INPUT = 'rounded-md border border-line bg-surface px-2 py-1 text-ink'
const BUTTON = 'rounded-md border border-line px-3 py-1.5 hover:bg-line disabled:cursor-default disabled:opacity-40 disabled:hover:bg-transparent'

/** ¿Conocemos este IOC? El servicio normaliza el valor igual que la ingesta (mayúsculas, espacios, punto final…). */
function Lookup() {
  const [type, setType] = useState<string>('domain')
  const [value, setValue] = useState('')
  const [message, setMessage] = useState<{ text: string; notFound: boolean }>()
  const [busy, setBusy] = useState(false)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!value.trim()) return
    setBusy(true)
    setMessage(undefined)
    try {
      const params = new URLSearchParams({ type, value: value.trim() })
      const found = await getJson<IndicatorView>(`/api/v1/indicators/lookup?${params}`)
      window.location.hash = `/indicators/${found.id}`
    } catch (err) {
      const notFound = err instanceof ApiError && err.status === 404
      setMessage({
        text: notFound
          ? 'No está en la base de datos: ninguna fuente ni organización lo ha reportado.'
          : err instanceof Error
            ? err.message
            : String(err),
        notFound,
      })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card title="Buscar un IOC" subtitle="Dominio, URL, IP, bloque /24 o hash, tal como lo tengas.">
      <form onSubmit={submit} className="flex flex-wrap gap-2 text-sm">
        <select value={type} onChange={(e) => setType(e.target.value)} className={INPUT} aria-label="Tipo">
          {INDICATOR_TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="evil.example.com"
          aria-label="Valor"
          className={`${INPUT} min-w-64 flex-1 font-mono`}
        />
        <button type="submit" disabled={busy} className={BUTTON}>
          {busy ? 'Buscando…' : 'Buscar'}
        </button>
      </form>
      {message && (
        <div className="mt-3">
          {message.notFound ? <p className="text-sm text-ink-2">{message.text}</p> : <ErrorNote message={message.text} />}
        </div>
      )}
    </Card>
  )
}
