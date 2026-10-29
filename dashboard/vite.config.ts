import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// El navegador nunca ve la clave de API: vive en dashboard/.env.local sin el prefijo VITE_ (Vite solo mete en el
// bundle las variables VITE_*) y el proxy del servidor de desarrollo la añade a cada petición /api hacia el Gateway.
// El dashboard actúa, por tanto, como la organización dueña de esa clave.
export default defineConfig(({ command, mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const apiKey = env.VERITHREAT_API_KEY
  if (command === 'serve' && !apiKey) {
    throw new Error('VERITHREAT_API_KEY is not set: create dashboard/.env.local (see .env.example)')
  }
  return {
    plugins: [react(), tailwindcss()],
    server: {
      host: '127.0.0.1',
      port: 5173,
      strictPort: true,
      // En WSL, los cambios hechos desde Windows en /mnt/* no generan eventos de fichero: hay que sondear
      watch: { usePolling: process.cwd().startsWith('/mnt/') },
      proxy: {
        '/api': {
          target: env.GATEWAY_URL || 'http://127.0.0.1:8080',
          changeOrigin: true,
          headers: { 'X-API-Key': apiKey ?? '' },
        },
      },
    },
  }
})
