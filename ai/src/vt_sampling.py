#!/usr/bin/env python3
"""Muestreo y validación con VirusTotal para el conjunto de referencia de VeriThreat.

1) Construye una muestra reproducible (semilla fija) de IPs, dominios, URLs y hashes:
     - IPs maliciosas:         blocklist.de (aleatoria, no las primeras alfabéticamente)
     - Dominios maliciosos:    abuse.ch (ThreatFox + URLhaus), PhishTank (ventana reciente) y TweetFeed,
                               sin plataformas de doble uso
     - Dominios no maliciosos: Tranco en tramos de ranking, sin choques con las fuentes maliciosas
     - URLs completas:         URLhaus, PhishTank y TweetFeed (máx. 2 por dominio registrable, para que una sola
                               campaña no domine) y, como base de falsos positivos, la raíz de sitios muy populares
     - Hashes (sha256):        ThreatFox y TweetFeed
2) Consulta la API v3 de VirusTotal con pausa entre peticiones, reintentos con espera y
   reanudación: puede interrumpirse y volver a lanzarse sin repetir lo ya consultado.

Si ya existe una muestra anterior, se reutiliza: se descartan los grupos que ya no forman parte del diseño
(p. ej. dom_threatcluster) y se AÑADEN los grupos que falten (dom_tweetfeed, url_*, hash_*), sin tocar el resto.
Las URLs y los hashes usan puntos de acceso distintos de la API (/urls y /files); si VirusTotal nunca analizó
una URL o un hash, la respuesta es 404 y queda como not_found (no se envía nada a analizar).

Uso:
    export VT_API_KEY=tu_clave                     # nunca se guarda en ficheros ni en logs
    python vt_sampling.py --data-dir data/raw --sample-only
    python vt_sampling.py --data-dir data/raw --pause 16 --max-queries 200

Necesita loaders.py en la misma carpeta y, en --data-dir, los CSV de las fuentes (month.csv de TweetFeed
incluido). Los límites de la cuenta gratuita de VirusTotal no están verificados aquí: ajusta --pause y
--max-queries a los de tu clave.
"""
import argparse
import base64
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd

try:  # python-dotenv es opcional: sin él, VT_API_KEY tiene que estar ya en el entorno
    from dotenv import load_dotenv
except ImportError:
    pass
else:
    load_dotenv()  # carga .env (buscándolo hacia arriba desde este script) en os.environ

sys.path.insert(0, str(Path(__file__).resolve().parent))
from loaders import (is_dual_use, is_ip, load_blocklist, load_phishtank, load_threatfox,  # noqa: E402
                     load_tweetfeed, load_urlhaus, registered_domain)

API = "https://www.virustotal.com/api/v3"
TRANCO_TIERS = [(1, 1_000), (1_001, 10_000), (10_001, 50_000)]
ACTIVE_GROUPS = ("ip_blocklist", "dom_abusech", "dom_phishtank", "dom_tweetfeed", "dom_tranco_", "url_", "hash_")
RESULT_COLS = ["indicator", "type", "group", "expected_class", "status", "http_status", "reputation", "malicious",
               "suspicious", "harmless", "undetected", "timeout", "as_owner", "country", "categories",
               "last_analysis_at", "queried_at"]


class QuotaExhausted(Exception):
    """VirusTotal sigue devolviendo 429 tras los reintentos: se detiene la ejecución y se reanuda más tarde."""


class InvalidKey(Exception):
    pass


# ----------------------------------------------------------------------------- muestra
def _clean(series: pd.Series, top_exclude: set) -> pd.Series:
    s = series.dropna().astype(str).str.lower()
    s = s[(s != "") & ~s.map(is_ip) & ~s.map(is_dual_use) & ~s.isin(top_exclude)]
    return s.drop_duplicates()


def _tweetfeed_pool(data_dir: Path) -> pd.Series:
    tw = load_tweetfeed(data_dir / "month.csv")
    return pd.concat([tw.loc[tw["type"] == "url", "host"], tw.loc[tw["type"] == "domain", "value_norm"]])


def _pools(data_dir: Path, window_days: int) -> dict:
    host = lambda u: (urlparse(u).hostname or "").lower()  # noqa: E731
    tf = load_threatfox(data_dir / "threatfox.csv")
    uh = load_urlhaus(data_dir / "urlhaus.csv")
    pt = load_phishtank(data_dir / "verified_online.csv", window_days=window_days)
    return {
        "dom_abusech": pd.concat([uh["url"].map(host),
                                  tf.loc[tf["ioc_type"] == "domain", "ioc"].str.lower(),
                                  tf.loc[tf["ioc_type"] == "url", "ioc"].map(host)]),
        "dom_phishtank": pt.loc[pt["recent"], "host"],
        "dom_tweetfeed": _tweetfeed_pool(data_dir),
    }


def _url_registered_domain(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    return registered_domain(host) if host else ""


def _url_hash_pools(data_dir: Path, window_days: int) -> tuple:
    tf = load_threatfox(data_dir / "threatfox.csv")
    uh = load_urlhaus(data_dir / "urlhaus.csv")
    pt = load_phishtank(data_dir / "verified_online.csv", window_days=window_days)
    tw = load_tweetfeed(data_dir / "month.csv")
    urls = {"url_urlhaus": uh["url"], "url_phishtank": pt.loc[pt["recent"], "url"],
            "url_tweetfeed": tw.loc[tw["type"] == "url", "value"]}
    hashes = {"hash_threatfox": tf.loc[tf["ioc_type"] == "sha256_hash", "ioc"].str.lower(),
              "hash_tweetfeed": tw.loc[(tw["type"] == "sha256") & ~tw["derived"], "value_norm"]}
    return urls, hashes


def build_url_hash_groups(data_dir: Path, n_urls: int, n_benign_urls: int, n_hashes: int, seed: int,
                          window_days: int, max_per_domain: int, exclude_top: int,
                          existing: frozenset = frozenset(), only=("url_", "hash_")) -> pd.DataFrame:
    """Filas de muestra para URLs y hashes. `only` limita qué familias se generan (para añadir solo las que faltan)."""
    urls, hashes = _url_hash_pools(data_dir, window_days)
    rows = []
    if n_urls > 0 and "url_" in only:
        per_group = max(1, n_urls // len(urls))
        for group, series in urls.items():
            s = series.dropna().astype(str).drop_duplicates()
            s = s[~s.isin(existing)].sample(frac=1, random_state=seed)
            dom = s.map(_url_registered_domain)
            s = s[dom.groupby(dom).cumcount() < max_per_domain]  # una campaña no puede dominar la muestra
            rows += [{"indicator": u, "type": "url", "group": group, "expected_class": "malicious"} for u in s.head(per_group)]
        if n_benign_urls > 0:
            tr = pd.read_csv(data_dir / "top-1m.csv", header=None, names=["rank", "domain"])
            malicious = set().union(*[set(p.dropna().astype(str).str.lower()) for p in _pools(data_dir, window_days).values()])
            t = tr["domain"].head(exclude_top)
            t = t[~t.map(is_dual_use) & ~t.isin(malicious)]
            roots = ("https://" + t.sample(min(n_benign_urls, len(t)), random_state=seed) + "/")
            rows += [{"indicator": u, "type": "url", "group": "url_tranco_root", "expected_class": "benign"} for u in roots]
    if n_hashes > 0 and "hash_" in only:
        per_group = max(1, n_hashes // len(hashes))
        for group, series in hashes.items():
            s = series.dropna().astype(str).str.lower().drop_duplicates()
            s = s[~s.isin(existing)]
            rows += [{"indicator": h, "type": "sha256", "group": group, "expected_class": "malicious"}
                     for h in s.sample(min(per_group, len(s)), random_state=seed)]
    return pd.DataFrame(rows, columns=["indicator", "type", "group", "expected_class"])


def build_sample(data_dir: Path, n_ips: int, n_mal_domains: int, n_benign_domains: int, seed: int,
                 exclude_top: int, window_days: int, n_urls: int = 0, n_benign_urls: int = 0, n_hashes: int = 0,
                 max_per_domain: int = 2) -> pd.DataFrame:
    bl = load_blocklist(data_dir / "export-ips_all.txt")
    ips = bl.loc[(bl["version"] > 0) & ~bl["private"], "ip"].drop_duplicates()
    sampled_ips = ips.sample(min(n_ips, len(ips)), random_state=seed)
    rows = [{"indicator": ip, "type": "ip", "group": "ip_blocklist", "expected_class": "malicious"} for ip in sampled_ips]

    tr = pd.read_csv(data_dir / "top-1m.csv", header=None, names=["rank", "domain"])
    top_exclude = set(tr["domain"].head(exclude_top))
    pools = _pools(data_dir, window_days)
    used = set()
    per_family = max(1, n_mal_domains // len(pools))
    for group, series in pools.items():
        s = _clean(series, top_exclude)
        s = s[~s.isin(used)]
        chosen = s.sample(min(per_family, len(s)), random_state=seed)
        used |= set(chosen)
        rows += [{"indicator": d, "type": "domain", "group": group, "expected_class": "malicious"} for d in chosen]

    # Todos los dominios maliciosos conocidos: un candidato benigno no puede estar entre ellos
    malicious = set().union(*[set(p.dropna().astype(str).str.lower()) for p in pools.values()])
    per_tier = max(1, n_benign_domains // len(TRANCO_TIERS))
    for lo, hi in TRANCO_TIERS:
        t = tr[(tr["rank"] >= lo) & (tr["rank"] <= hi)]["domain"]
        t = t[~t.map(is_dual_use) & ~t.isin(malicious)]
        chosen = t.sample(min(per_tier, len(t)), random_state=seed)
        rows += [{"indicator": d, "type": "domain", "group": f"dom_tranco_{lo}-{hi}", "expected_class": "benign"}
                 for d in chosen]
    base = pd.DataFrame(rows)
    extra = build_url_hash_groups(data_dir, n_urls, n_benign_urls, n_hashes, seed, window_days, max_per_domain, exclude_top)
    return pd.concat([base, extra], ignore_index=True)


def adapt_sample(sample: pd.DataFrame, data_dir: Path, n_tweetfeed: int, seed: int, exclude_top: int,
                 n_urls: int = 0, n_benign_urls: int = 0, n_hashes: int = 0, window_days: int = 90,
                 max_per_domain: int = 2) -> pd.DataFrame:
    """Reutiliza una muestra anterior: quita grupos obsoletos, plataformas de doble uso y añade los grupos que falten."""
    active = sample["group"].map(lambda g: g.startswith(ACTIVE_GROUPS))
    if (~active).any():
        print(f"Dropping {int((~active).sum())} indicators from groups outside the current design: "
              f"{sample.loc[~active, 'group'].value_counts().to_dict()}")
    sample = sample[active]
    platform = (sample["type"] == "domain") & sample["indicator"].map(is_dual_use)
    if platform.any():
        print(f"Excluding {int(platform.sum())} dual-use platform domains")
    sample = sample[~platform]
    if "dom_tweetfeed" not in set(sample["group"]):
        tr = pd.read_csv(data_dir / "top-1m.csv", header=None, names=["rank", "domain"])
        s = _clean(_tweetfeed_pool(data_dir), set(tr["domain"].head(exclude_top)))
        s = s[~s.isin(set(sample["indicator"]))]
        new = s.sample(min(n_tweetfeed, len(s)), random_state=seed)
        print(f"Adding group dom_tweetfeed with {len(new)} domains")
        extra = pd.DataFrame({"indicator": new.values, "type": "domain", "group": "dom_tweetfeed", "expected_class": "malicious"})
        sample = pd.concat([sample, extra], ignore_index=True)
    missing = tuple(p for p, n in (("url_", n_urls), ("hash_", n_hashes))
                    if n > 0 and not sample["group"].str.startswith(p).any())
    if missing:
        new = build_url_hash_groups(data_dir, n_urls, n_benign_urls, n_hashes, seed, window_days, max_per_domain,
                                    exclude_top, frozenset(sample["indicator"]), only=missing)
        print(f"Adding {', '.join(missing)} groups: {new['group'].value_counts().to_dict()}")
        sample = pd.concat([sample, new], ignore_index=True)
    return sample.reset_index(drop=True)


# ----------------------------------------------------------------------------- consulta
def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _endpoint(typ: str, value: str) -> str:
    """Punto de acceso de la API v3 según el tipo de indicador."""
    if typ == "ip":
        return f"ip_addresses/{value}"
    if typ == "domain":
        return f"domains/{value}"
    if typ == "url":  # identificador: la URL en base64 «url-safe» y sin relleno (=)
        return "urls/" + base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
    if typ in ("sha256", "md5", "sha1"):
        return f"files/{value}"
    raise ValueError(f"unsupported type: {typ}")


def query(session, typ: str, value: str, max_retries: int = 4) -> dict:
    """Devuelve un dict con 'status' (ok | not_found | error). Lanza QuotaExhausted o InvalidKey."""
    import requests
    url = f"{API}/{_endpoint(typ, value)}"
    last = "no response"
    for attempt in range(max_retries + 1):
        try:
            r = session.get(url, timeout=30)
        except requests.RequestException as e:
            last = f"network: {type(e).__name__}"
            time.sleep(min(60, 5 * 2 ** attempt))
            continue
        if r.status_code == 200:
            a = r.json()["data"]["attributes"]
            s = a.get("last_analysis_stats", {})
            ts = a.get("last_analysis_date")
            cats = a.get("categories") or {}
            if typ in ("sha256", "md5", "sha1"):  # en ficheros, la etiqueta de amenaza sugerida por VirusTotal
                label = (a.get("popular_threat_classification") or {}).get("suggested_threat_label") or a.get("type_description") or ""
            else:
                label = ";".join(sorted(set(cats.values())))
            return {"status": "ok", "http_status": 200, "reputation": a.get("reputation"),
                    "malicious": s.get("malicious"), "suspicious": s.get("suspicious"), "harmless": s.get("harmless"),
                    "undetected": s.get("undetected"), "timeout": s.get("timeout"), "as_owner": a.get("as_owner"),
                    "country": a.get("country"), "categories": label,
                    "last_analysis_at": datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if ts else ""}
        if r.status_code == 404:
            return {"status": "not_found", "http_status": 404}
        if r.status_code in (401, 403):
            raise InvalidKey(f"HTTP {r.status_code}: check VT_API_KEY")
        if r.status_code == 429:
            last = "429"
            try:
                wait = int(r.headers.get("Retry-After", 0))
            except (TypeError, ValueError):
                wait = 0
            time.sleep(wait or min(120, 15 * 2 ** attempt))
            continue
        if r.status_code >= 500:
            last = f"HTTP {r.status_code}"
            time.sleep(min(60, 5 * 2 ** attempt))
            continue
        return {"status": "error", "http_status": r.status_code}
    if last == "429":
        raise QuotaExhausted("VirusTotal keeps rate-limiting the requests: progress has been saved")
    return {"status": "error", "http_status": None, "categories": last}


def run(sample: pd.DataFrame, output: Path, session, pause: float, max_queries: int) -> None:
    done = set()
    if output.exists():
        previous = pd.read_csv(output, dtype=str)
        done = set(previous.loc[previous["status"].isin(["ok", "not_found"]), "indicator"])
    pending = sample[~sample["indicator"].isin(done)]
    if max_queries:
        pending = pending.head(max_queries)
    print(f"Sample: {len(sample)} | already queried: {int(sample['indicator'].isin(done).sum())} | to query now: "
          f"{len(pending)} (≈ {len(pending) * pause / 60:.0f} min at {pause:g} s per query)")
    new_file = not output.exists()
    with open(output, "a", encoding="utf-8", newline="") as f:
        if new_file:
            f.write(",".join(RESULT_COLS) + "\n")
        for i, row in enumerate(pending.itertuples(index=False), 1):
            try:
                res = query(session, row.type, row.indicator)
            except QuotaExhausted as e:
                print(f"\nStopped: {e}. Run the script again later: it resumes where it left off.")
                return
            res.update({"indicator": row.indicator, "type": row.type, "group": row.group,
                        "expected_class": row.expected_class, "queried_at": _now()})
            df = pd.DataFrame([res]).reindex(columns=RESULT_COLS)
            df.to_csv(f, header=False, index=False)
            f.flush()
            print(f"[{i}/{len(pending)}] {row.type:6} {row.indicator:40} {res['status']}", end="\r")
            if i < len(pending):
                time.sleep(pause)
    print()


def summary(output: Path) -> None:
    if not output.exists():
        return
    r = pd.read_csv(output)
    ok = r[r["status"] == "ok"].copy()
    print("\nStatuses:", r["status"].value_counts().to_dict())
    nf = r[r["status"] == "not_found"]
    if not nf.empty:
        print("not_found (VirusTotal has no analysis) by group:", nf["group"].value_counts().to_dict())
    if ok.empty:
        return
    platform = (ok["type"] == "domain") & ok["indicator"].map(is_dual_use)
    if platform.any():
        print(f"Excluding {int(platform.sum())} dual-use platform domains from the summary")
        ok = ok[~platform].copy()
    ok["malicious"] = pd.to_numeric(ok["malicious"])
    ok["detected"] = ok["malicious"] >= 1
    ok["detected_3"] = ok["malicious"] >= 3
    historic = ~ok["group"].str.startswith(ACTIVE_GROUPS)
    if historic.any():
        print(f"Historic groups (outside the current design): {ok.loc[historic, 'group'].value_counts().to_dict()}")
    table = ok.groupby(["expected_class", "group"]).agg(
        n=("indicator", "size"), detected=("detected", "mean"), detected_3=("detected_3", "mean"),
        malicious_median=("malicious", "median"))
    # Cobertura: parte del grupo que VirusTotal conoce (not_found = nunca lo analizó). Las tasas se calculan solo sobre n.
    nf = r[r["status"] == "not_found"].groupby(["expected_class", "group"]).size()
    table.insert(1, "not_found", nf.reindex(table.index, fill_value=0))
    table.insert(2, "coverage", table["n"] / (table["n"] + table["not_found"]))
    print(table.round(2).to_string())


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data-dir", type=Path, default=Path("data/raw"))
    p.add_argument("--sample", type=Path, default=Path("vt_sample.csv"))
    p.add_argument("--output", type=Path, default=Path("vt_results.csv"))
    p.add_argument("--n-ips", type=int, default=200)
    p.add_argument("--n-mal-domains", type=int, default=198, help="total split evenly between abuse.ch, PhishTank and TweetFeed")
    p.add_argument("--n-benign-domains", type=int, default=198)
    p.add_argument("--n-urls", type=int, default=100, help="full malicious URLs (split between URLhaus, PhishTank and TweetFeed); 0 = do not validate URLs")
    p.add_argument("--n-benign-urls", type=int, default=30, help="https://domain/ roots of popular sites as a false-positive baseline")
    p.add_argument("--n-hashes", type=int, default=100, help="sha256 hashes (ThreatFox and TweetFeed); 0 = do not validate hashes")
    p.add_argument("--max-per-domain", type=int, default=2, help="maximum URLs from the same registered domain")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--exclude-top", type=int, default=10_000, help="do not sample malicious domains within Tranco's top N")
    p.add_argument("--phishtank-window", type=int, default=90)
    p.add_argument("--pause", type=float, default=16.0, help="seconds between queries (adjust to your quota)")
    p.add_argument("--max-queries", type=int, default=0, help="cap per run (0 = no cap)")
    p.add_argument("--regenerate", action="store_true", help="rebuild the sample even if it exists")
    p.add_argument("--sample-only", action="store_true", help="build the sample and exit (no key needed)")
    a = p.parse_args()

    if a.sample.exists() and not a.regenerate:
        sample = pd.read_csv(a.sample)
        print(f"Using the existing sample: {a.sample} ({len(sample)} indicators)")
        n_tw = max(1, a.n_mal_domains // 3)
        adapted = adapt_sample(sample, a.data_dir, n_tw, a.seed, a.exclude_top, a.n_urls, a.n_benign_urls,
                               a.n_hashes, a.phishtank_window, a.max_per_domain)
        if len(adapted) != len(sample) or not adapted["indicator"].equals(sample["indicator"]):
            sample = adapted
            sample.to_csv(a.sample, index=False)
            print(f"Sample updated: {a.sample} ({len(sample)} indicators)")
    else:
        sample = build_sample(a.data_dir, a.n_ips, a.n_mal_domains, a.n_benign_domains, a.seed, a.exclude_top,
                              a.phishtank_window, a.n_urls, a.n_benign_urls, a.n_hashes, a.max_per_domain)
        sample.to_csv(a.sample, index=False)
        print(f"Sample created: {a.sample} ({len(sample)} indicators)")
    print(sample.groupby(["expected_class", "group"]).size().to_string())
    if a.sample_only:
        return
    # Orden de consulta barajado (estable con la semilla): una ejecución parcial cubre todos los grupos
    sample = sample.sample(frac=1, random_state=a.seed).reset_index(drop=True)

    key = os.environ.get("VT_API_KEY")
    if not key:
        sys.exit("Missing environment variable VT_API_KEY")
    import requests
    session = requests.Session()
    session.headers.update({"x-apikey": key, "accept": "application/json"})
    try:
        run(sample, a.output, session, a.pause, a.max_queries)
    except InvalidKey as e:
        sys.exit(str(e))
    summary(a.output)


if __name__ == "__main__":
    main()
