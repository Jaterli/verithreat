import { type FormEvent, useState } from 'react'
import { INDICATOR_TYPES, type Score } from '../api'
import { CATEGORIES, categoryLabel } from '../format'
import { Card, ErrorNote, Status } from '../ui'

// Aportación de un IOC por la organización del dashboard (POST /api/v1/sightings, decisión 14). La organización no
// se elige: la fija el Gateway a partir de la clave de API.

interface SightingResponse {
  indicatorId: number
  sightingId: number
  type: string
  value: string
  fingerprint: string
  created: boolean
  severityStatus: string
  fabricStatus: string | null
  currentScore: Score | null
}

const EMPTY = { type: 'domain', value: '', category: '', seenAt: '', malwareFamily: '', confidence: '', description: '' }

export default function Submit() {
  const [form, setForm] = useState(EMPTY)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string>()
  const [result, setResult] = useState<{ response: SightingResponse; submittedValue: string }>()

  const set = (field: keyof typeof EMPTY) => (e: { target: { value: string } }) =>
    setForm((f) => ({ ...f, [field]: e.target.value }))

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(undefined)
    setResult(undefined)
    const body = {
      type: form.type,
      value: form.value.trim(),
      category: form.category,
      // datetime-local no lleva zona: se interpreta en la hora local del navegador y se envía en UTC
      seenAt: form.seenAt ? new Date(form.seenAt).toISOString() : null,
      malwareFamily: form.malwareFamily.trim() || null,
      confidence: form.confidence === '' ? null : Number(form.confidence),
      description: form.description.trim() || null,
    }
    try {
      const res = await fetch('/api/v1/sightings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify(body),
      })
      const json = await res.json().catch(() => null)
      if (!res.ok) {
        throw new Error(json?.detail ?? json?.title ?? `HTTP ${res.status}`)
      }
      setResult({ response: json as SightingResponse, submittedValue: body.value })
      setForm((f) => ({ ...EMPTY, type: f.type, category: f.category }))
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="grid gap-6 lg:grid-cols-5">
      <div className="lg:col-span-3">
        <Card
          title="Aportar un IOC"
          subtitle="Se guarda como una observación de tu organización y cuenta para la severidad como una fuente más (fiabilidad 0,5)."
        >
          <form onSubmit={submit} className="space-y-4 text-sm">
            <div className="grid gap-4 sm:grid-cols-[10rem_1fr]">
              <Field label="Tipo">
                <select value={form.type} onChange={set('type')} className={INPUT}>
                  {INDICATOR_TYPES.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Valor" hint="Tal como lo tengas: se normaliza igual que los feeds.">
                <input
                  required
                  maxLength={30_000}
                  value={form.value}
                  onChange={set('value')}
                  placeholder={PLACEHOLDERS[form.type]}
                  className={`${INPUT} font-mono`}
                />
              </Field>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Categoría">
                <select required value={form.category} onChange={set('category')} className={INPUT}>
                  <option value="" disabled>
                    Elige una…
                  </option>
                  {CATEGORIES.map((c) => (
                    <option key={c} value={c}>
                      {categoryLabel(c)}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Visto el (opcional)" hint="Hora local. Si lo dejas vacío, ahora.">
                <input type="datetime-local" value={form.seenAt} onChange={set('seenAt')} className={INPUT} />
              </Field>
              <Field label="Familia de malware (opcional)">
                <input maxLength={200} value={form.malwareFamily} onChange={set('malwareFamily')} className={INPUT} />
              </Field>
              <Field label="Confianza 0–100 (opcional)">
                <input
                  type="number"
                  min={0}
                  max={100}
                  value={form.confidence}
                  onChange={set('confidence')}
                  className={INPUT}
                />
              </Field>
            </div>
            <Field label="Descripción (opcional)" hint="Contexto para otros analistas; se guarda con la aportación.">
              <textarea
                rows={3}
                maxLength={2_000}
                value={form.description}
                onChange={set('description')}
                className={INPUT}
              />
            </Field>
            <div className="flex flex-wrap items-center gap-4">
              <button
                type="submit"
                disabled={busy}
                className="rounded-md bg-accent px-4 py-2 font-medium text-white hover:opacity-90 disabled:opacity-50"
              >
                {busy ? 'Enviando…' : 'Aportar'}
              </button>
              <p className="text-xs text-muted">
                La primera aportación de cada IOC se registra en Hyperledger Fabric y no se puede borrar de la cadena.
              </p>
            </div>
            {error && <ErrorNote message={error} />}
          </form>
        </Card>
      </div>

      <div className="lg:col-span-2">
        {result ? (
          <Result {...result} />
        ) : (
          <Card title="Qué pasa al aportar">
            <ol className="list-decimal space-y-2 pl-5 text-sm text-ink-2">
              <li>El valor se normaliza y se guarda como observación de tu organización.</li>
              <li>Si tu organización ya lo había aportado, solo se renueva su última confirmación.</li>
              <li>Una aportación nueva queda pendiente de registro en Fabric; el servicio la envía en segundos.</li>
              <li>La severidad se recalcula en la siguiente ejecución horaria de score.py.</li>
            </ol>
          </Card>
        )}
      </div>
    </div>
  )
}

const INPUT = 'w-full rounded-md border border-line bg-surface px-2 py-1.5 text-ink'

const PLACEHOLDERS: Record<string, string> = {
  domain: 'evil.example.com',
  url: 'https://evil.example.com/login.php',
  ip: '203.0.113.7',
  cidr: '203.0.113.0/24',
  sha256: '64 caracteres hexadecimales',
  md5: '32 caracteres hexadecimales',
  sha1: '40 caracteres hexadecimales',
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="flex flex-col gap-1 text-ink-2">
      {label}
      {children}
      {hint && <span className="text-xs text-muted">{hint}</span>}
    </label>
  )
}

function Result({ response: r, submittedValue }: { response: SightingResponse; submittedValue: string }) {
  return (
    <Card title={r.created ? 'Aportación registrada' : 'Ya lo habías aportado'}>
      <div className="space-y-3 text-sm">
        <Status
          label={r.created ? 'Nueva observación de tu organización' : 'Se ha renovado su última confirmación'}
          tone="good"
        />
        <div>
          <p className="text-muted">Valor guardado ({r.type})</p>
          <p className="font-mono break-all">{r.value}</p>
          {r.value !== submittedValue && <p className="text-xs text-muted">Normalizado a partir de «{submittedValue}».</p>}
        </div>
        <div>
          <p className="text-muted">Huella (sha256), lo que va a la cadena</p>
          <p className="font-mono text-xs break-all">{r.fingerprint}</p>
        </div>
        <div>
          <p className="text-muted">Registro en Fabric</p>
          {r.fabricStatus === 'registered' ? (
            <Status label="registrado" tone="good" />
          ) : r.fabricStatus === 'failed' ? (
            <Status label="rechazado por la red (ver detalle)" tone="critical" />
          ) : r.fabricStatus === 'pending' ? (
            <Status label="pendiente: el servicio lo envía en segundos" tone="warning" />
          ) : (
            <span className="text-muted">sin registro</span>
          )}
        </div>
        <div>
          <p className="text-muted">Severidad</p>
          <p>
            {r.currentScore
              ? `${r.currentScore.severity} (la de antes de tu aportación; se recalcula en la próxima ejecución horaria)`
              : 'Pendiente: se calcula en la próxima ejecución horaria de score.py.'}
          </p>
        </div>
        <a href={`#/indicators/${r.indicatorId}`} className="inline-block text-accent hover:underline">
          Ver el indicador →
        </a>
      </div>
    </Card>
  )
}
