// Cliente de la API de ioc-service (a través del Gateway; el proxy de Vite añade la clave). Los tipos reflejan
// services/ioc-service/.../api/Dtos.java.

import { useEffect, useState } from 'react'

export interface GroupStats {
  type: string
  category: string | null
  count: number
  disputed: number
  medianSeverity: number
  p90Severity: number
}

export interface HistogramBin {
  category: string | null
  from: number
  count: number
}

export interface SourceStats {
  code: string
  family: string
  role: 'indicators' | 'signal' | 'organization'
  lastFetchedAt: string | null
  sightings: number
  activeLast48h: number
  lastConfirmedAt: string | null
}

export interface FabricStats {
  organization: string
  pending: number
  registered: number
  failed: number
}

export interface ModelInfo {
  name: string
  version: string
  trainedAt: string
  temporalPrAuc: number | null
  temporalRocAuc: number | null
}

export interface Stats {
  generatedAt: string
  indicators: number
  scored: number
  disputed: number
  byTypeAndCategory: GroupStats[]
  severityHistogram: HistogramBin[]
  sources: SourceStats[]
  fabric: FabricStats[]
  model: ModelInfo | null
}

export const INDICATOR_TYPES = ['domain', 'url', 'ip', 'cidr', 'sha256', 'md5', 'sha1'] as const

/** Mejor observación de una familia de fuentes, tal como la guarda score.py en components.families. */
export interface FamilyTerm {
  source: string
  reliability: number
  grade: string
  decay: number
  age_days: number
}

/** components de una puntuación (ai/src/score.py, función components). */
export interface ScoreComponents {
  config: string
  category: string | null
  families: Record<string, FamilyTerm>
  evidence: number
  ipsum_level?: number
  model?: { host: string; p_malicious: number; beta: number }
  disputed?: { reason: string; factor: number }
}

export interface Score {
  severity: number
  disputed: boolean
  pMalicious: number | null
  computedAt: string
  components: ScoreComponents
}

export interface SightingSummary {
  firstSeen: string
  lastConfirmed: string
  sightings: number
  sources: number
  families: number
  categories: string[]
  sourceNames: string[]
  ipsumLevel: number | null
}

export interface IndicatorView {
  id: number
  type: string
  value: string
  fingerprint: string
  score: Score | null
  summary: SightingSummary | null
}

export interface IndicatorRow {
  id: number
  type: string
  value: string
  category: string | null
  severity: number
  disputed: boolean
  computedAt: string
}

export interface Page<T> {
  items: T[]
  page: number
  size: number
  hasNext: boolean
}

export interface FabricRecord {
  status: 'pending' | 'registered' | 'failed'
  canonicalHash: string | null
  txId: string | null
  mspId: string | null
  registeredAt: string | null
  attempts: number
}

export interface Sighting {
  source: string
  category: string
  seenAt: string
  lastConfirmedAt: string
  status: string | null
  malwareFamily: string | null
  confidence: number | null
  reporter: string | null
  corroborated: boolean | null
  fabric: FabricRecord | null
}

export interface ScorePoint {
  computedAt: string
  severity: number
  disputed: boolean
}

export interface IndicatorDetail {
  indicator: IndicatorView
  sightings: Sighting[]
  scoreHistory: ScorePoint[]
}

export class ApiError extends Error {
  constructor(readonly status: number, message: string) {
    super(message)
  }
}

/** GET de JSON; los errores de la API llegan como ProblemDetail (title, detail). */
export async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(path, { headers: { Accept: 'application/json' }, signal })
  if (!res.ok) {
    let message = `HTTP ${res.status}`
    try {
      const problem = await res.json()
      message = problem.detail ?? problem.title ?? message
    } catch {
      // cuerpo vacío o no JSON (p. ej. el Gateway no está en marcha y responde el proxy)
    }
    throw new ApiError(res.status, message)
  }
  return res.json() as Promise<T>
}

export interface ApiState<T> {
  data?: T
  error?: string
  loading: boolean
}

/** Carga una ruta de la API y la vuelve a pedir si cambia. */
export function useApi<T>(path: string): ApiState<T> {
  const [state, setState] = useState<ApiState<T>>({ loading: true })
  useEffect(() => {
    const ctrl = new AbortController()
    setState((s) => ({ data: s.data, loading: true }))
    getJson<T>(path, ctrl.signal)
      .then((data) => setState({ data, loading: false }))
      .catch((e: unknown) => {
        if (!ctrl.signal.aborted) {
          setState({ error: e instanceof Error ? e.message : String(e), loading: false })
        }
      })
    return () => ctrl.abort()
  }, [path])
  return state
}
