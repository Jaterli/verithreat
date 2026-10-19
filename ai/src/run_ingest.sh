#!/bin/sh
# Lanza una ejecución de la ingesta dentro de WSL y añade la salida al log. Lo invoca cada hora el Programador de
# tareas de Windows (wsl.exe arranca WSL si está apagado), o cron si WSL está siempre en marcha.
# Claves y contraseña: .env en la raíz del repo (AUTH_KEY, POSTGRES_PASSWORD), leído por python-dotenv.
SRC=$(cd "$(dirname "$0")" && pwd) || exit 1
ROOT=$(cd "$SRC/../.." && pwd) || exit 1
mkdir -p "$ROOT/ai/data/raw/ingest"
cd "$SRC" || exit 1
exec "$ROOT/.venv/bin/python" ingest.py --data-dir ../data/raw >> "$ROOT/ai/data/raw/ingest/ingest.log" 2>&1
