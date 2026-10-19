#!/bin/sh
# Ingesta + puntuación, dentro de WSL; la salida se añade al log. Lo invoca cada hora el Programador de tareas de
# Windows (wsl.exe arranca WSL si está apagado), o cron si WSL está siempre en marcha.
# Claves y contraseña: .env en la raíz del repo (AUTH_KEY, POSTGRES_PASSWORD), leído por python-dotenv.
# La puntuación se ejecuta aunque falle alguna fuente: el decaimiento cambia con el tiempo aunque no haya datos nuevos.
SRC=$(cd "$(dirname "$0")" && pwd) || exit 1
ROOT=$(cd "$SRC/../.." && pwd) || exit 1
LOG="$ROOT/ai/data/raw/ingest/ingest.log"
mkdir -p "$ROOT/ai/data/raw/ingest"
cd "$SRC" || exit 1
"$ROOT/.venv/bin/python" ingest.py --data-dir ../data/raw >> "$LOG" 2>&1
status=$?
"$ROOT/.venv/bin/python" score.py --data-dir ../data/raw --quiet >> "$LOG" 2>&1 || status=1
exit $status
