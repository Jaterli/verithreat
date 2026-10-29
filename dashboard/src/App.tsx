import { useEffect, useState } from 'react'
import Overview from './views/Overview'
import Pending from './views/Pending'

// Enrutado mínimo por hash (#/, #/indicators, #/submit): tres vistas no justifican un router.
function useRoute(): string {
  const [hash, setHash] = useState(window.location.hash)
  useEffect(() => {
    const onChange = () => setHash(window.location.hash)
    window.addEventListener('hashchange', onChange)
    return () => window.removeEventListener('hashchange', onChange)
  }, [])
  return hash.replace(/^#/, '') || '/'
}

const NAV = [
  { href: '#/', route: '/', label: 'Panel general' },
  { href: '#/indicators', route: '/indicators', label: 'Indicadores' },
  { href: '#/submit', route: '/submit', label: 'Aportar un IOC' },
]

export default function App() {
  const route = useRoute()
  const active = NAV.find((n) => n.route !== '/' && route.startsWith(n.route))?.route ?? '/'

  return (
    <div className="min-h-screen font-sans">
      <header className="border-b border-line bg-surface">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-8 gap-y-2 px-4 py-3">
          <span className="text-base font-semibold">VeriThreat</span>
          <nav className="flex gap-1 text-sm">
            {NAV.map((n) => (
              <a
                key={n.route}
                href={n.href}
                aria-current={active === n.route ? 'page' : undefined}
                className={`rounded-md px-3 py-1.5 ${
                  active === n.route ? 'bg-accent/10 font-medium text-ink' : 'text-ink-2 hover:bg-line'
                }`}
              >
                {n.label}
              </a>
            ))}
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-4 py-6">
        {active === '/' && <Overview />}
        {active === '/indicators' && (
          <Pending
            title="Indicadores"
            description="Búsqueda por valor, listado filtrado por categoría, tipo y severidad mínima, y detalle de cada indicador con la severidad explicada término a término, sus observaciones y su registro en Fabric."
          />
        )}
        {active === '/submit' && (
          <Pending
            title="Aportar un IOC"
            description="Formulario sobre POST /api/v1/sightings: la aportación se guarda como observación de la organización y queda pendiente de registro en Fabric."
          />
        )}
      </main>
    </div>
  )
}
