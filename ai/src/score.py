#!/usr/bin/env python3
"""Severidad de cada indicador de VeriThreat (0-100), explicable componente a componente.

Fórmula (pesos en severity_config.json, regla 8 de CLAUDE.md):
  1. Fiabilidad de cada observación r: peso de su fuente para ese tipo de indicador (medido con VirusTotal);
     TweetFeed graduado por corroboración/categoría, IPs de blocklist.de por nivel de IPsum. URLhaus offline × 0,8.
     Para las demás IPs, IPsum cuenta como una familia más (peso por analogía, sin decaimiento). Las organizaciones
     participantes (role = 'organization') usan organization_reliability (0,5 por defecto).
  2. Decaimiento d = 0,5 ^ (días desde last_confirmed_at / vida media del tipo); los hashes no decaen.
  3. Evidencia por familias (OR probabilístico): E = 1 − Π (1 − máx(r·d) de cada familia). Dos observaciones de la
     misma familia no cuentan doble (decisión 4).
  4. Modelo A como señal débil (dominios y hosts de URL que no sean IP ni de doble uso): S = 1 − (1 − E)(1 − β·p).
  5. Disputado: dominio cuyo registrable está en el top N de Tranco (salvo plataformas de doble uso) → se marca y
     S × factor (decisión 10).
  6. Severidad = round(100·S). Cada término va a `components` (jsonb) con la versión de la configuración.

Historial: se añade una fila a `score` solo si el indicador no tenía puntuación, si la severidad cambia al menos
`history_min_change` puntos o si cambia la marca de disputado (la vista v_current_score da la última).

Uso:
    python score.py --data-dir ../data/raw              # calcula y guarda los cambios
    python score.py --data-dir ../data/raw --dry-run    # calcula y resume, sin escribir
"""
import argparse
import hashlib
import io
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from loaders import is_dual_use, is_ip, load_tranco, registered_domain, to_punycode  # noqa: E402

CONFIG_PATH = Path(__file__).resolve().parent / "severity_config.json"
MODELS_DIR = Path(__file__).resolve().parent.parent / "models" / "model_a"

SQL_SIGHTINGS = """
SELECT s.indicator_id, i.type, i.value, s.source, src.family, s.category, s.status, s.corroborated, s.last_confirmed_at
FROM sighting s
JOIN indicator i ON i.id = s.indicator_id
JOIN source src  ON src.code = s.source"""

SQL_IPSUM = """
SELECT ip.indicator_id, ip.level FROM ipsum_signal ip
WHERE ip.download_id = (SELECT id FROM download WHERE source = 'ipsum' ORDER BY fetched_at DESC, id DESC LIMIT 1)"""

SQL_CURRENT = "SELECT indicator_id, severity, disputed FROM v_current_score"

SQL_ORGANIZATIONS = "SELECT code FROM source WHERE role = 'organization'"


# ----------------------------------------------------------------------------- configuración
def load_config(path: Path) -> tuple:
    raw = path.read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()[:12]


def _grade(value, key: str):
    """Un peso puede ser un número o un dict graduado (por categoría, corroboración o nivel de IPsum)."""
    if isinstance(value, dict):
        return value.get(key, value.get("*"))
    return value


def reliability(cfg: dict, source: str, typ: str, grade_key: str) -> float:
    by_type = cfg["reliability"][source]
    value = by_type.get(typ, by_type.get("*"))
    r = _grade(value, grade_key)
    if r is None:
        raise KeyError(f"no reliability for {source}/{typ}/{grade_key}")
    return float(r)


def ipsum_bucket(level) -> str:
    level = 0 if pd.isna(level) else int(level)
    return "ipsum_3+" if level >= 3 else ("ipsum_1-2" if level >= 1 else "ipsum_0")


# ----------------------------------------------------------------------------- cálculo
def evidence(sightings: pd.DataFrame, ipsum: dict, cfg: dict, now: pd.Timestamp) -> pd.DataFrame:
    """Una fila por observación con r, d y su contribución r·d."""
    s = sightings.copy()
    s["ipsum_level"] = s["indicator_id"].map(ipsum).where(s["type"] == "ip")
    grade = np.where(s["source"] == "blocklist.de", s["ipsum_level"].map(ipsum_bucket),
                     np.where(s["corroborated"].fillna(False).astype(bool), "corroborated", s["category"]))
    s["reliability"] = [reliability(cfg, src, t, g) for src, t, g in zip(s["source"], s["type"], grade)]
    s["grade"] = grade
    status_factor = s["status"].map(cfg["status_factor"]).fillna(1.0)
    s["reliability"] *= status_factor
    hl = s["type"].map(cfg["half_life_days"]).astype(float)
    s["age_days"] = (now - pd.to_datetime(s["last_confirmed_at"], utc=True)).dt.total_seconds() / 86400
    s["decay"] = np.where(hl.isna(), 1.0, 0.5 ** (s["age_days"].clip(lower=0) / hl))
    s["contribution"] = s["reliability"] * s["decay"]
    return pd.concat([s, ipsum_rows(s, ipsum, cfg)], ignore_index=True)


def ipsum_rows(s: pd.DataFrame, ipsum: dict, cfg: dict) -> pd.DataFrame:
    """IPsum como familia propia para las IPs que no vienen de blocklist.de (con ellas ya gradúa su fiabilidad)."""
    ips = s[s["type"] == "ip"].drop_duplicates("indicator_id")
    from_blocklist = set(s.loc[s["source"] == "blocklist.de", "indicator_id"])
    ips = ips[~ips["indicator_id"].isin(from_blocklist)].copy()
    ips["grade"] = ips["indicator_id"].map(ipsum).map(ipsum_bucket)
    ips["reliability"] = ips["grade"].map(cfg["ipsum_signal"])
    ips = ips[ips["reliability"].notna()]
    return ips.assign(source="ipsum", family="ipsum", category=ips["category"], decay=1.0, age_days=0.0,
                      contribution=ips["reliability"])


def combine(s: pd.DataFrame) -> pd.DataFrame:
    """Mejor observación de cada familia y OR probabilístico entre familias."""
    best = s.sort_values("contribution", ascending=False).drop_duplicates(["indicator_id", "family"])
    best = best.assign(log_miss=np.log1p(-best["contribution"].clip(upper=1 - 1e-12)))
    agg = best.groupby("indicator_id").agg(
        type=("type", "first"), value=("value", "first"), log_miss=("log_miss", "sum"),
        category=("category", "first"))  # categoría de la familia con mayor contribución (orden descendente)
    agg["evidence"] = 1 - np.exp(agg["log_miss"])  # 1 − Π(1 − c), vectorizado
    families = {}
    for r in best.itertuples():  # un bucle es mucho más rápido que groupby().apply con 100.000 indicadores
        families.setdefault(r.indicator_id, {})[r.family] = {
            "source": r.source, "reliability": round(r.reliability, 3), "grade": r.grade,
            "decay": round(r.decay, 3), "age_days": round(r.age_days, 1)}
    agg = agg.reset_index()
    agg["families"] = agg["indicator_id"].map(families)
    return agg


def model_host(typ: str, value: str) -> str:
    """Host al que se aplica el modelo A ('' si no aplica: IPs, hashes, cidr, plataformas de doble uso)."""
    if typ == "domain":
        host = value
    elif typ == "url":
        host = to_punycode((urlparse(value).hostname or "").lower())
    else:
        return ""
    return "" if (not host or is_ip(host) or is_dual_use(host)) else host


def active_model(conn):
    row = conn.execute("SELECT id, version, artifact_sha256, params->'versions'->>'scikit-learn' FROM model_version "
                       "WHERE name = 'model_a' AND active").fetchone()
    if row is None:
        return None, None
    import sklearn
    from model_a import load_artifact, sha256_file
    path = MODELS_DIR / row[1] / "model.joblib"
    if not path.exists() or sha256_file(path) != row[2]:
        raise RuntimeError(f"model_a {row[1]}: artifact missing or sha256 mismatch ({path})")
    if row[3] != sklearn.__version__:  # un modelo de scikit-learn solo se carga con la versión que lo entrenó
        raise RuntimeError(f"model_a {row[1]} was trained with scikit-learn {row[3]} but this environment has "
                           f"{sklearn.__version__}: retrain it here with model_a.py --activate")
    return row[0], load_artifact(path)


def add_organizations(cfg: dict, codes) -> None:
    """Cada organización participante es una fuente con un único peso para todos los tipos (decisión 14)."""
    weights = cfg["organization_reliability"]
    for code in codes:
        cfg["reliability"].setdefault(code, {"*": float(weights.get(code, weights["*"]))})


def compute(conn, cfg: dict, tranco_path: Path, now: pd.Timestamp) -> tuple:
    add_organizations(cfg, [r[0] for r in conn.execute(SQL_ORGANIZATIONS).fetchall()])
    sightings = pd.DataFrame(conn.execute(SQL_SIGHTINGS).fetchall(),
                             columns=["indicator_id", "type", "value", "source", "family", "category", "status",
                                      "corroborated", "last_confirmed_at"])
    ipsum = dict(conn.execute(SQL_IPSUM).fetchall())
    df = combine(evidence(sightings, ipsum, cfg, now))
    df["ipsum_level"] = df["indicator_id"].map(ipsum).where(df["type"] == "ip")

    model_id, artifact = active_model(conn)
    df["host"] = [model_host(t, v) for t, v in zip(df["type"], df["value"])]
    df["p_malicious"] = np.nan
    if artifact is not None:
        from model_a import score_hosts
        hosts = df.loc[df["host"] != "", "host"].drop_duplicates()
        p = dict(zip(hosts, score_hosts(artifact, hosts)))
        df.loc[df["host"] != "", "p_malicious"] = df.loc[df["host"] != "", "host"].map(p)
    beta = cfg["model_beta"]
    df["s"] = 1 - (1 - df["evidence"]) * (1 - beta * df["p_malicious"].fillna(0))

    top = set(load_tranco(tranco_path).head(cfg["disputed"]["tranco_top"])["domain"])
    # Un subdominio de una plataforma de doble uso (x.workers.dev) es de un usuario: no hereda la popularidad
    df["disputed"] = (df["type"] == "domain") & df["value"].map(lambda v: not is_dual_use(v) and registered_domain(v) in top)
    df.loc[df["disputed"], "s"] *= cfg["disputed"]["factor"]
    df["severity"] = (100 * df["s"]).round().astype(int).clip(0, 100)
    return df, model_id


def components(r, cfg_version: str, cfg: dict) -> dict:
    out = {"config": cfg_version, "category": r.category, "families": r.families, "evidence": round(r.evidence, 4)}
    if not pd.isna(r.ipsum_level):
        out["ipsum_level"] = int(r.ipsum_level)
    if not pd.isna(r.p_malicious):
        out["model"] = {"host": r.host, "p_malicious": round(float(r.p_malicious), 4), "beta": cfg["model_beta"]}
    if r.disputed:
        out["disputed"] = {"reason": f"registered domain in Tranco top {cfg['disputed']['tranco_top']:,}",
                           "factor": cfg["disputed"]["factor"]}
    return out


def changed(df: pd.DataFrame, current: pd.DataFrame, min_change: int) -> pd.Series:
    cur = df["indicator_id"].map(dict(zip(current["indicator_id"], current["severity"])))
    cur_d = df["indicator_id"].map(dict(zip(current["indicator_id"], current["disputed"])))
    return cur.isna() | ((df["severity"] - cur).abs() >= min_change) | (cur_d.fillna(df["disputed"]) != df["disputed"])


def summary(df: pd.DataFrame) -> None:
    g = df.groupby(["category", "type"])["severity"]
    t = pd.DataFrame({"n": g.size(), "median": g.median(), "p90": g.quantile(0.9).round(), "max": g.max()})
    print(t[t["n"] >= 20].to_string())
    print(f"disputed: {int(df['disputed'].sum()):,} | with model term: {int(df['p_malicious'].notna().sum()):,}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data-dir", type=Path, default=Path("../data/raw"), help="folder with top-1m.csv (Tranco)")
    p.add_argument("--config", type=Path, default=CONFIG_PATH)
    p.add_argument("--dry-run", action="store_true", help="compute and summarize without writing")
    p.add_argument("--quiet", action="store_true", help="one-line output (for the hourly log)")
    a = p.parse_args()

    from load_db import connect
    cfg, cfg_version = load_config(a.config)
    now = pd.Timestamp(datetime.now(timezone.utc))
    with connect() as conn:
        df, model_id = compute(conn, cfg, a.data_dir / "top-1m.csv", now)
        current = pd.DataFrame(conn.execute(SQL_CURRENT).fetchall(), columns=["indicator_id", "severity", "disputed"])
        new = df[changed(df, current, cfg["history_min_change"])]
        if a.quiet:
            print(f"{now:%Y-%m-%d %H:%M:%S}Z score         {len(df):,} indicators scored, {len(new):,} new score rows "
                  f"(config {cfg_version}, model_version_id {model_id})")
        else:
            print(f"Scored {len(df):,} indicators (config {cfg_version}, model_version_id {model_id})")
            summary(df)
            print(f"New score rows: {len(new):,} (no previous score or change ≥{cfg['history_min_change']} points / disputed)")
        if a.dry_run or new.empty:
            return
        if not a.quiet:
            print("Saving…")
        with conn.transaction(), conn.cursor() as cur:
            with cur.copy("COPY score (indicator_id, computed_at, model_version_id, p_malicious, components, severity, "
                          "disputed) FROM STDIN") as cp:
                for r in new.itertuples():
                    has_p = not pd.isna(r.p_malicious)
                    cp.write_row((int(r.indicator_id), now.to_pydatetime(), model_id if has_p else None,
                                  float(r.p_malicious) if has_p else None,
                                  json.dumps(components(r, cfg_version, cfg), ensure_ascii=False),
                                  int(r.severity), bool(r.disputed)))


if __name__ == "__main__":
    main()
