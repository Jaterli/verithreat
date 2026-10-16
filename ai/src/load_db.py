#!/usr/bin/env python3
"""Carga idempotente de las fuentes de VeriThreat en PostgreSQL (esquema db/schema.sql).

Por cada fuente:
  1. Calcula el sha256 de sus ficheros crudos y registra la DESCARGA (tabla download). Si ese contenido ya estaba
     cargado, la salta: volver a lanzar la carga con los mismos ficheros no cambia nada.
  2. Normaliza los registros con `source_sightings` (loaders.py, la misma lógica del notebook).
  3. En una sola transacción: inserta los indicadores nuevos (ON CONFLICT DO NOTHING) y las observaciones; si una
     observación ya existía (misma fuente y registro de origen), solo actualiza last_confirmed_at, status,
     corroborated y la última descarga, y solo si la descarga es más reciente que la que ya tenía.
IPsum se carga aparte, como señal: el nivel de cada IP que ya es indicador.

Conexión: variables estándar de PostgreSQL (PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD) o VERITHREAT_DSN. Se leen
del entorno o de .env (python-dotenv, opcional). Nunca se imprimen.

Uso:
    python load_db.py --data-dir ../data/raw --dry-run          # sin base de datos: cuenta lo que se cargaría
    python load_db.py --data-dir ../data/raw                    # todas las fuentes
    python load_db.py --data-dir ../data/raw --sources urlhaus,phishtank --fetched-at 2026-10-09T16:45:00Z

Necesita psycopg 3 (pip install "psycopg[binary]") salvo con --dry-run.
"""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from loaders import SOURCE_FILES, load_ipsum, source_sightings  # noqa: E402

try:  # python-dotenv es opcional: sin él, la conexión tiene que estar ya en el entorno
    from dotenv import load_dotenv
except ImportError:
    pass
else:
    load_dotenv()

SOURCES = tuple(SOURCE_FILES) + ("ipsum",)
STG_COLS = ["type", "value", "source_record_id", "category", "seen_at", "malware_family", "confidence", "status",
            "reporter", "corroborated", "raw"]


# ----------------------------------------------------------------------------- ficheros
def files_for(source: str, data_dir: Path) -> list:
    if source == "ipsum":
        return sorted(data_dir.glob("ipsum_level*.txt"), key=lambda p: int("".join(filter(str.isdigit, p.stem)) or 0))
    return [data_dir / f for f in SOURCE_FILES[source] if (data_dir / f).exists()]


def content_hash(files: list) -> tuple:
    """sha256 del contenido (de todos los ficheros de la fuente, en orden) y nº de bytes."""
    h, n = hashlib.sha256(), 0
    for p in files:
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
                n += len(chunk)
    return h.hexdigest(), n


def fetch_date(files: list, forced) -> pd.Timestamp:
    if forced is not None:
        return forced
    # como el notebook; PostgreSQL guarda microsegundos
    return pd.Timestamp(max(p.stat().st_mtime for p in files), unit="s", tz="UTC").floor("us")


def _json(v):
    if hasattr(v, "item"):
        return v.item()
    return str(v)


def stg_rows(sightings: pd.DataFrame):
    """Filas para COPY: nulos de pandas como None, fechas como datetime y `raw` como texto JSON."""
    for r in sightings[STG_COLS].itertuples(index=False):
        row = []
        for c, v in zip(STG_COLS, r):
            if c == "raw":
                row.append(json.dumps(v, ensure_ascii=False, allow_nan=False, default=_json))
            elif v is None or (not isinstance(v, (list, dict)) and pd.isna(v)):
                row.append(None)
            elif isinstance(v, pd.Timestamp):
                row.append(v.to_pydatetime())
            elif c == "confidence":
                row.append(int(v))
            elif c == "corroborated":
                row.append(bool(v))
            else:
                row.append(v)
        yield row


# ----------------------------------------------------------------------------- SQL
SQL_DOWNLOAD = """
INSERT INTO download (source, file_name, sha256, size_bytes, rows_read, fetched_at)
VALUES (%s, %s, %s, %s, %s, %s)
ON CONFLICT (source, sha256) DO NOTHING
RETURNING id"""

SQL_STG = """
CREATE TEMP TABLE stg (
    type text, value text, source_record_id text, category text, seen_at timestamptz, malware_family text,
    confidence smallint, status text, reporter text, corroborated boolean, raw jsonb
) ON COMMIT DROP"""

SQL_INDICATORS = """
INSERT INTO indicator (type, value)
SELECT DISTINCT type, value FROM stg
ON CONFLICT (type, fingerprint) DO NOTHING"""

SQL_SIGHTINGS = """
INSERT INTO sighting AS o (indicator_id, source, source_record_id, category, seen_at, last_confirmed_at, malware_family,
                           confidence, status, reporter, corroborated, raw, first_download_id, last_download_id)
SELECT i.id, %(source)s, s.source_record_id, s.category, s.seen_at, %(fetched_at)s, s.malware_family, s.confidence,
       s.status, s.reporter, s.corroborated, s.raw, %(download)s, %(download)s
FROM stg s
JOIN indicator i ON i.type = s.type AND i.fingerprint = fingerprint(s.value)
ON CONFLICT (source, source_record_id) DO UPDATE
SET last_confirmed_at = EXCLUDED.last_confirmed_at,
    status            = EXCLUDED.status,
    corroborated      = EXCLUDED.corroborated,
    last_download_id  = EXCLUDED.last_download_id
WHERE o.last_confirmed_at < EXCLUDED.last_confirmed_at"""   # una descarga más antigua no pisa el estado más reciente

SQL_IPSUM = """
INSERT INTO ipsum_signal (indicator_id, download_id, level)
SELECT i.id, %(download)s, s.level
FROM stg_ipsum s
JOIN indicator i ON i.type = 'ip' AND i.fingerprint = fingerprint(s.ip)
ON CONFLICT DO NOTHING"""


def connect():
    import psycopg
    dsn = os.environ.get("VERITHREAT_DSN", "")  # vacío: psycopg usa PGHOST, PGUSER, PGPASSWORD...
    return psycopg.connect(dsn, options="-c search_path=verithreat")


def load_source(conn, source: str, data_dir: Path, forced, phishtank_window: int) -> str:
    files = files_for(source, data_dir)
    if not files:
        return "no files"
    sha, nbytes = content_hash(files)
    fetched_at = fetch_date(files, forced)
    with conn.transaction(), conn.cursor() as cur:
        if source == "ipsum":
            ips = load_ipsum(data_dir)
            cur.execute(SQL_DOWNLOAD, (source, "ipsum_level1-8.txt", sha, nbytes, len(ips), fetched_at.to_pydatetime()))
            row = cur.fetchone()
            if row is None:
                return "already loaded (same content)"
            cur.execute("CREATE TEMP TABLE stg_ipsum (ip text, level smallint) ON COMMIT DROP")
            with cur.copy("COPY stg_ipsum (ip, level) FROM STDIN") as cp:
                for ip, level in zip(ips["ip"], ips["level"]):
                    cp.write_row((ip, int(level)))
            cur.execute(SQL_IPSUM, {"download": row[0]})
            return f"{len(ips):,} IPs in IPsum; {cur.rowcount:,} are indicators"

        sightings = source_sightings(source, data_dir, fetched_at, phishtank_window)
        duplicated = int(sightings["source_record_id"].duplicated().sum())
        sightings = sightings.drop_duplicates("source_record_id")
        cur.execute(SQL_DOWNLOAD, (source, files[0].name, sha, nbytes, len(sightings) + duplicated, fetched_at.to_pydatetime()))
        row = cur.fetchone()
        if row is None:
            return "already loaded (same content)"
        cur.execute(SQL_STG)
        with cur.copy(f"COPY stg ({', '.join(STG_COLS)}) FROM STDIN") as cp:
            for r in stg_rows(sightings):
                cp.write_row(r)
        cur.execute(SQL_INDICATORS)
        new_indicators = cur.rowcount
        cur.execute(SQL_SIGHTINGS, {"source": source, "fetched_at": fetched_at.to_pydatetime(), "download": row[0]})
        return (f"{len(sightings):,} sightings ({cur.rowcount:,} new or updated), {new_indicators:,} new indicators"
                + (f"; {duplicated} repeated records ignored" if duplicated else ""))


def dry_run(sources, data_dir: Path, forced, phishtank_window: int) -> None:
    """Sin base de datos: lo que se cargaría, con los totales del esquema común para comparar con el notebook."""
    all_sightings = []
    for source in sources:
        files = files_for(source, data_dir)
        if not files:
            print(f"{source:13} no files")
            continue
        sha, nbytes = content_hash(files)
        if source == "ipsum":
            print(f"{source:13} {len(load_ipsum(data_dir)):,} IPs | sha256 {sha[:12]}…")
            continue
        s = source_sightings(source, data_dir, fetch_date(files, forced), phishtank_window)
        print(f"{source:13} {len(s):,} sightings | repeated records: {int(s['source_record_id'].duplicated().sum())} | "
              f"types: {s['type'].value_counts().to_dict()} | sha256 {sha[:12]}… ({nbytes:,} bytes)")
        all_sightings.append(s.assign(source=source))
    if all_sightings:
        t = pd.concat(all_sightings, ignore_index=True)
        ind = t.drop_duplicates(["type", "value"])
        print(f"\nTOTAL: {len(t):,} sightings | {len(ind):,} unique indicators | by type: {ind['type'].value_counts().to_dict()}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data-dir", type=Path, default=Path("../data/raw"))
    p.add_argument("--sources", default=",".join(SOURCES), help=f"comma-separated list (default: {','.join(SOURCES)})")
    p.add_argument("--fetched-at", default=None,
                   help="snapshot date in UTC (ISO 8601); default: the file modification date")
    p.add_argument("--phishtank-window", type=int, default=90)
    p.add_argument("--dry-run", action="store_true", help="do not connect to the database: only count")
    a = p.parse_args()

    sources = [s.strip() for s in a.sources.split(",") if s.strip()]
    unknown = set(sources) - set(SOURCES)
    if unknown:
        sys.exit(f"Unknown sources: {', '.join(sorted(unknown))}")
    # IPsum al final: solo guarda el nivel de las IPs que ya son indicadores
    sources = sorted(sources, key=lambda s: s == "ipsum")
    forced = None
    if a.fetched_at:
        forced = pd.Timestamp(a.fetched_at)
        if forced.tzinfo is None:
            sys.exit("--fetched-at needs a time zone (e.g. 2026-10-09T16:45:00Z)")
        forced = forced.tz_convert("UTC")

    if a.dry_run:
        dry_run(sources, a.data_dir, forced, a.phishtank_window)
        return
    start = datetime.now(timezone.utc)
    with connect() as conn:
        for source in sources:
            print(f"{source:13} {load_source(conn, source, a.data_dir, forced, a.phishtank_window)}")
    print(f"Done in {(datetime.now(timezone.utc) - start).total_seconds():.0f} s")


if __name__ == "__main__":
    main()
