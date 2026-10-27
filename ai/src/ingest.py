#!/usr/bin/env python3
"""Ingesta programada de las fuentes de VeriThreat: descarga, valida y carga en PostgreSQL.

Pensado para lanzarse cada hora con cron. En cada ejecución solo procesa las fuentes a las que les toca según su
frecuencia (tabla SOURCES), respetando los términos de uso de cada una (CLAUDE.md, sección 3):

  threatfox     API get_iocs (Auth-Key)                     cada hora (días pedidos = desde el último éxito, máx. 7)
  urlhaus       exportación recent.csv (clave en la URL)    cada hora (se genera cada 5 min)
  blocklist.de  all.txt                                     cada hora (se regenera cada 30 min)
  tweetfeed     month.csv + exclusive.csv (tweetfeed.live)  cada hora, petición condicional (ETag)
  phishtank     online-valid.csv, sin clave                 cada 6 h («unas pocas descargas al día»), con ETag
  ipsum         ipsum_level1..8.txt (GitHub)                cada 24 h

Cada descarga se guarda en <data-dir>/ingest/<fuente>/<fecha UTC>/ con los nombres que espera load_db.py y se carga
con load_source (idempotente: un contenido ya cargado no cambia nada). Se conservan las 3 últimas descargas por
fuente; el registro original de cada observación queda además en la columna `raw` de la base de datos. Si una fuente
falla, las demás siguen; el código de salida es 1 si alguna falló.

Claves: AUTH_KEY (abuse.ch) en el entorno o en .env (python-dotenv, opcional). Nunca se imprime: los mensajes de
error se limpian antes de mostrarse (la URL de URLhaus lleva la clave).

Uso:
    python ingest.py --data-dir ../data/raw                     # lo que toque (para cron)
    python ingest.py --data-dir ../data/raw --sources phishtank --force
    python ingest.py --data-dir ../data/raw --no-db             # descarga y valida, sin cargar

Ejemplo de crontab en WSL (cada hora, minuto 7):
    7 * * * * cd /ruta/verithreat/ai/src && /ruta/venv/bin/python ingest.py --data-dir ../data/raw >> ../data/raw/ingest/ingest.log 2>&1
"""
import argparse
import io
import json
import math
import os
import shutil
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from loaders import SOURCE_FILES  # noqa: E402

try:  # python-dotenv es opcional: sin él, AUTH_KEY y la conexión tienen que estar ya en el entorno
    from dotenv import load_dotenv
except ImportError:
    pass
else:
    load_dotenv()

USER_AGENT = "VeriThreat-ingest/1.0 (MSc thesis research; threat intelligence sharing platform)"
KEEP_SNAPSHOTS = 3
TOLERANCE = timedelta(minutes=10)  # margen para que el cron horario no se salte una ejecución por segundos
LOCK_STALE = timedelta(hours=2)


@dataclass(frozen=True)
class Source:
    name: str
    interval: timedelta


SOURCES = [  # IPsum al final: solo guarda el nivel de las IPs que ya son indicadores
    Source("threatfox", timedelta(hours=1)),
    Source("urlhaus", timedelta(hours=1)),
    Source("blocklist.de", timedelta(hours=1)),
    Source("tweetfeed", timedelta(hours=1)),
    Source("phishtank", timedelta(hours=6)),
    Source("ipsum", timedelta(hours=24)),
]
URLS = {
    "threatfox": "https://threatfox-api.abuse.ch/api/v1/",
    "urlhaus": "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv",
    "blocklist.de": "https://lists.blocklist.de/lists/all.txt",
    # Feeds oficiales (https://tweetfeed.live/api/): los 30 días completos y sin el tope de 10.000 filas de la API
    # JSON, que además no trae la corroboración. Su README desaconseja descargar del repositorio de GitHub.
    "tweetfeed_month": "https://tweetfeed.live/feeds/month.csv",
    "tweetfeed_exclusive": "https://tweetfeed.live/feeds/exclusive.csv",
    "phishtank": "http://data.phishtank.com/data/online-valid.csv",
    "ipsum": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/{n}.txt",
}


class NotModified(Exception):
    """La fuente responde 304: no hay nada nuevo desde la última descarga."""


class ValidationError(Exception):
    """El contenido descargado no tiene el formato esperado: no se carga."""


# ----------------------------------------------------------------------------- utilidades
def now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def log(msg: str) -> None:
    print(f"{now():%Y-%m-%d %H:%M:%S}Z {msg}", flush=True)


def redact(msg: str) -> str:
    """Quita la clave de abuse.ch de cualquier texto (las URLs de exportación la llevan en la ruta)."""
    key = os.environ.get("AUTH_KEY")
    return msg.replace(key, "***") if key else msg


def load_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(path: Path, state: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def is_due(source: Source, state: dict, t: datetime) -> bool:
    last = state.get(source.name, {}).get("last_attempt")
    return last is None or t - datetime.fromisoformat(last) >= source.interval - TOLERANCE


def acquire_lock(path: Path) -> bool:
    """Evita dos ejecuciones a la vez (p. ej. si una descarga se alarga más de una hora)."""
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        if now() - datetime.fromtimestamp(path.stat().st_mtime, timezone.utc) < LOCK_STALE:
            return False
        path.unlink(missing_ok=True)  # cerrojo abandonado por una ejecución que murió
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    os.write(fd, str(os.getpid()).encode())
    os.close(fd)
    return True


# ----------------------------------------------------------------------------- HTTP
def request(session, method: str, url: str, retries: int = 3, etag: str = None, **kw):
    """Petición con reintentos (red, 429 y 5xx). Lanza NotModified si la respuesta es 304."""
    import requests
    headers = dict(kw.pop("headers", {}) or {})
    if etag:
        headers["If-None-Match"] = etag
    last = None
    for attempt in range(retries + 1):
        try:
            r = session.request(method, url, headers=headers, timeout=120, **kw)
        except requests.RequestException as e:
            last = f"network error: {type(e).__name__}"
        else:
            if r.status_code == 304:
                raise NotModified()
            if r.status_code == 200:
                return r
            if r.status_code != 429 and r.status_code < 500:
                raise RuntimeError(f"HTTP {r.status_code}")  # un 401, 403 o 404 no se arregla reintentando
            last = f"HTTP {r.status_code}"
        if attempt < retries:
            time.sleep(min(120, 10 * 2 ** attempt))
    raise RuntimeError(f"gave up after {retries + 1} attempts ({last})")


# ----------------------------------------------------------------------------- descarga y validación por fuente
def fetch_threatfox(session, state: dict, t: datetime) -> dict:
    key = os.environ.get("AUTH_KEY")
    if not key:
        raise RuntimeError("missing AUTH_KEY (abuse.ch)")
    last_ok = state.get("last_success")
    hours = (t - datetime.fromisoformat(last_ok)).total_seconds() / 3600 if last_ok else 24 * 7
    days = max(1, min(7, math.ceil(hours / 24) + 1))  # un día de solape: la carga ignora lo ya visto
    r = request(session, "POST", URLS["threatfox"], headers={"Auth-Key": key}, json={"query": "get_iocs", "days": days})
    body = r.json()
    if body.get("query_status") == "no_result":
        raise NotModified()
    if body.get("query_status") != "ok" or not isinstance(body.get("data"), list):
        raise ValidationError(f"unexpected query_status: {body.get('query_status')!r}")
    df = pd.DataFrame(body["data"])
    missing = {"id", "ioc", "ioc_type", "threat_type", "first_seen", "confidence_level"} - set(df.columns)
    if missing:
        raise ValidationError(f"missing columns: {sorted(missing)}")
    buf = io.StringIO()
    df.to_csv(buf, index=False)
    return {"threatfox.csv": buf.getvalue().encode("utf-8")}


def fetch_urlhaus(session, state: dict, t: datetime) -> dict:
    key = os.environ.get("AUTH_KEY")
    if not key:
        raise RuntimeError("missing AUTH_KEY (abuse.ch)")
    content = request(session, "GET", URLS["urlhaus"].format(key=key)).content
    # La exportación oficial empieza con un bloque de comentarios («####...», fecha, términos) y después la cabecera
    if not any(l.startswith(b"# id,dateadded,url") for l in content.splitlines()[:20]):
        raise ValidationError("URLhaus header '# id,dateadded,url' not found")
    return {"urlhaus.csv": content}


def fetch_blocklist(session, state: dict, t: datetime) -> dict:
    content = request(session, "GET", URLS["blocklist.de"]).content
    lines = [l for l in content.decode("utf-8", "replace").splitlines() if l.strip() and not l.startswith("#")]
    if len(lines) < 1000:  # all.txt suele tener más de 20.000 IPs: una lista casi vacía es un fallo
        raise ValidationError(f"only {len(lines)} IPs in all.txt")
    return {"export-ips_all.txt": content}


def fetch_tweetfeed(session, state: dict, t: datetime) -> dict:
    r = request(session, "GET", URLS["tweetfeed_month"], etag=state.get("etag"))
    month = r.content
    if not month.strip() or len(month.splitlines()[0].split(b",")) < 6:
        raise ValidationError("unexpected month.csv format")
    exclusive = request(session, "GET", URLS["tweetfeed_exclusive"]).content
    state["_new_etag"] = r.headers.get("ETag")
    return {"month.csv": month, "exclusive.csv": exclusive}


def fetch_phishtank(session, state: dict, t: datetime) -> dict:
    r = request(session, "GET", URLS["phishtank"], etag=state.get("etag"))
    if not r.content.startswith(b"phish_id,url,phish_detail_url"):
        raise ValidationError("unexpected PhishTank header")
    state["_new_etag"] = r.headers.get("ETag")
    return {"verified_online.csv": r.content}  # el nombre que espera load_db (mismas columnas que online-valid.csv)


def fetch_ipsum(session, state: dict, t: datetime) -> dict:
    files = {}
    for n in range(1, 9):
        content = request(session, "GET", URLS["ipsum"].format(n=n)).content
        if n == 1 and len(content.splitlines()) < 1000:
            raise ValidationError("IPsum level 1 is almost empty")
        files[f"ipsum_level{n}.txt"] = content
    return files


FETCHERS = {"threatfox": fetch_threatfox, "urlhaus": fetch_urlhaus, "blocklist.de": fetch_blocklist,
            "tweetfeed": fetch_tweetfeed, "phishtank": fetch_phishtank, "ipsum": fetch_ipsum}


# ----------------------------------------------------------------------------- instantáneas
def write_snapshot(root: Path, source: str, t: datetime, files: dict) -> Path:
    folder = root / source.replace(".", "_") / t.strftime("%Y%m%dT%H%M%SZ")
    folder.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (folder / name).write_bytes(content)
    return folder


def prune_snapshots(root: Path, source: str, keep: int = KEEP_SNAPSHOTS) -> None:
    folder = root / source.replace(".", "_")
    if folder.is_dir():
        for old in sorted(p for p in folder.iterdir() if p.is_dir())[:-keep]:
            shutil.rmtree(old)


# ----------------------------------------------------------------------------- main
def run_source(source: Source, session, conn, root: Path, state: dict, phishtank_window: int) -> bool:
    """Procesa una fuente. Devuelve False si falló."""
    st = state.setdefault(source.name, {})
    t = now()
    st["last_attempt"] = t.isoformat()
    try:
        files = FETCHERS[source.name](session, st, t)
        folder = write_snapshot(root, source.name, t, files)
        if conn is None:
            result = f"downloaded {sum(len(c) for c in files.values()):,} bytes (not loaded: --no-db)"
        else:
            from load_db import load_source
            result = load_source(conn, source.name, folder, pd.Timestamp(t), phishtank_window)
        if st.get("_new_etag"):
            st["etag"] = st["_new_etag"]
        st["last_success"] = t.isoformat()
        st["last_result"] = result
        st.pop("last_error", None)
        prune_snapshots(root, source.name)
        log(f"{source.name:13} {result}")
        return True
    except NotModified:
        st["last_success"] = t.isoformat()
        st["last_result"] = "not modified"
        log(f"{source.name:13} not modified since the last download")
        return True
    except Exception as e:  # una fuente que falla no detiene a las demás
        st["last_error"] = redact(f"{type(e).__name__}: {e}")
        log(f"{source.name:13} FAILED: {st['last_error']}")
        return False
    finally:
        st.pop("_new_etag", None)


def main() -> None:
    names = [s.name for s in SOURCES]
    assert set(names) - {"ipsum"} == set(SOURCE_FILES), "SOURCES and loaders.SOURCE_FILES are out of sync"
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data-dir", type=Path, default=Path("../data/raw"))
    p.add_argument("--sources", default=",".join(names), help=f"comma-separated list (default: {','.join(names)})")
    p.add_argument("--force", action="store_true", help="ignore the per-source interval")
    p.add_argument("--no-db", action="store_true", help="download and validate, but do not load into PostgreSQL")
    p.add_argument("--phishtank-window", type=int, default=90)
    a = p.parse_args()

    chosen = [s.strip() for s in a.sources.split(",") if s.strip()]
    unknown = set(chosen) - set(names)
    if unknown:
        sys.exit(f"Unknown sources: {', '.join(sorted(unknown))}")
    root = a.data_dir / "ingest"
    root.mkdir(parents=True, exist_ok=True)
    lock = root / "ingest.lock"
    if not acquire_lock(lock):
        log("another ingest run is in progress: exiting")
        return
    try:
        state_path = root / "state.json"
        state = load_state(state_path)
        t = now()
        due = [s for s in SOURCES if s.name in chosen and (a.force or is_due(s, state, t))]
        if not due:
            log("nothing due")
            return
        import requests
        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT})
        conn = None
        if not a.no_db:
            from load_db import connect
            conn = connect()
        ok = True
        try:
            for source in due:
                ok &= run_source(source, session, conn, root, state, a.phishtank_window)
                save_state(state_path, state)  # tras cada fuente: un corte no pierde lo ya hecho
        finally:
            if conn is not None:
                conn.close()
        if not ok:
            sys.exit(1)
    finally:
        lock.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
