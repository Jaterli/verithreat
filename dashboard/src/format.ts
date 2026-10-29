// Formato de números, fechas y etiquetas (interfaz en español).

const integer = new Intl.NumberFormat('es-ES', { useGrouping: 'always' })
const compact = new Intl.NumberFormat('es-ES', { notation: 'compact', maximumFractionDigits: 1 })
const decimal = new Intl.NumberFormat('es-ES', { minimumFractionDigits: 2, maximumFractionDigits: 2 })
const relative = new Intl.RelativeTimeFormat('es', { numeric: 'auto' })
const dateTime = new Intl.DateTimeFormat('es-ES', { dateStyle: 'short', timeStyle: 'short' })

export const fmtInt = (n: number) => integer.format(n)
export const fmtCompact = (n: number) => compact.format(n)
export const fmtDecimal = (n: number) => decimal.format(n)
export const fmtDateTime = (iso: string) => dateTime.format(new Date(iso))
export const fmtFixed = (n: number, digits: number) =>
  n.toLocaleString('es-ES', { minimumFractionDigits: digits, maximumFractionDigits: digits })

/** «hace 38 minutos», «hace 2 horas»… */
export function fmtAgo(iso: string, now = Date.now()): string {
  const minutes = Math.round((new Date(iso).getTime() - now) / 60_000)
  if (Math.abs(minutes) < 60) return relative.format(minutes, 'minute')
  const hours = Math.round(minutes / 60)
  if (Math.abs(hours) < 48) return relative.format(hours, 'hour')
  return relative.format(Math.round(hours / 24), 'day')
}

/** Nombres de las categorías de la base de datos (sighting.category). */
const CATEGORY_LABELS: Record<string, string> = {
  malware_distribution: 'Distribución de malware',
  c2: 'C2',
  phishing: 'Phishing',
  skimming: 'Skimming',
  malware: 'Malware',
  attack_source: 'Origen de ataques',
  attack_network: 'Red atacante (/24)',
  other: 'Otra',
  unspecified: 'Sin especificar',
}

export const categoryLabel = (c: string | null) => (c ? (CATEGORY_LABELS[c] ?? c) : 'Sin categoría')

export const CATEGORIES = Object.keys(CATEGORY_LABELS)

/** Grado con el que se eligió la fiabilidad de una observación (score.py: categoría, corroboración o IPsum). */
export function gradeLabel(grade: string): string {
  if (grade === 'corroborated') return 'corroborado por otros feeds'
  if (grade === 'ipsum_3+') return 'IPsum: 3 o más listas'
  if (grade === 'ipsum_1-2') return 'IPsum: 1–2 listas'
  if (grade === 'ipsum_0') return 'IPsum: en ninguna lista'
  return CATEGORY_LABELS[grade] ? `categoría ${CATEGORY_LABELS[grade].toLowerCase()}` : grade
}
