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
    python vt_muestreo.py --data-dir data/raw --solo-muestra
    python vt_muestreo.py --data-dir data/raw --pausa 16 --max-consultas 200

Necesita cargadores_corregidos.py en la misma carpeta y, en --data-dir, los CSV de las fuentes
(month.csv de TweetFeed incluido). Los límites de la cuenta gratuita de VirusTotal no están
verificados aquí: ajusta --pausa y --max-consultas a los de tu clave.
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
from cargadores_corregidos import (DOBLE_USO, es_doble_uso, es_ip, load_blocklist, load_phishtank,  # noqa: E402
                                   registrable,
                                   load_threatfox, load_tweetfeed, load_urlhaus)

API = "https://www.virustotal.com/api/v3"
TRAMOS_TRANCO = [(1, 1_000), (1_001, 10_000), (10_001, 50_000)]
GRUPOS_ACTIVOS = ("ip_blocklist", "dom_abusech", "dom_phishtank", "dom_tweetfeed", "dom_tranco_", "url_", "hash_")
COLS_RESULTADO = ["indicador", "tipo", "grupo", "clase_esperada", "status", "http_status", "reputation", "malicious",
                  "suspicious", "harmless", "undetected", "timeout", "as_owner", "country", "categorias",
                  "last_analysis_at", "queried_at"]


class CuotaAgotada(Exception):
    """VirusTotal sigue devolviendo 429 tras los reintentos: se detiene la ejecución y se reanuda más tarde."""


class ClaveInvalida(Exception):
    pass


# ----------------------------------------------------------------------------- muestra
def _limpiar(serie: pd.Series, top_excluir: set) -> pd.Series:
    s = serie.dropna().astype(str).str.lower()
    s = s[(s != "") & ~s.map(es_ip) & ~s.map(es_doble_uso) & ~s.isin(top_excluir)]
    return s.drop_duplicates()


def _pool_tweetfeed(data_dir: Path) -> pd.Series:
    tw = load_tweetfeed(data_dir / "month.csv")
    return pd.concat([tw.loc[tw["type"] == "url", "host"], tw.loc[tw["type"] == "domain", "value_norm"]])


def _pools(data_dir: Path, ventana_dias: int) -> dict:
    host = lambda u: (urlparse(u).hostname or "").lower()  # noqa: E731
    tf = load_threatfox(data_dir / "threatfox.csv")
    uh = load_urlhaus(data_dir / "urlhaus.csv")
    pt = load_phishtank(data_dir / "verified_online.csv", ventana_dias=ventana_dias)
    return {
        "dom_abusech": pd.concat([uh["url"].map(host),
                                  tf.loc[tf["ioc_type"] == "domain", "ioc"].str.lower(),
                                  tf.loc[tf["ioc_type"] == "url", "ioc"].map(host)]),
        "dom_phishtank": pt.loc[pt["reciente"], "host"],
        "dom_tweetfeed": _pool_tweetfeed(data_dir),
    }


def _dom_registrable(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    return registrable(host) if host else ""


def _pools_url_hash(data_dir: Path, ventana_dias: int) -> tuple:
    tf = load_threatfox(data_dir / "threatfox.csv")
    uh = load_urlhaus(data_dir / "urlhaus.csv")
    pt = load_phishtank(data_dir / "verified_online.csv", ventana_dias=ventana_dias)
    tw = load_tweetfeed(data_dir / "month.csv")
    urls = {"url_urlhaus": uh["url"], "url_phishtank": pt.loc[pt["reciente"], "url"],
            "url_tweetfeed": tw.loc[tw["type"] == "url", "value"]}
    hashes = {"hash_threatfox": tf.loc[tf["ioc_type"] == "sha256_hash", "ioc"].str.lower(),
              "hash_tweetfeed": tw.loc[(tw["type"] == "sha256") & ~tw["derivado"], "value_norm"]}
    return urls, hashes


def construir_grupos_url_hash(data_dir: Path, n_urls: int, n_urls_ben: int, n_hashes: int, semilla: int,
                              ventana_dias: int, max_por_dominio: int, excluir_top: int,
                              existentes: frozenset = frozenset(), solo=("url_", "hash_")) -> pd.DataFrame:
    """Filas de muestra para URLs y hashes. `solo` limita qué familias se generan (para añadir solo las que faltan)."""
    urls, hashes = _pools_url_hash(data_dir, ventana_dias)
    filas = []
    if n_urls > 0 and "url_" in solo:
        por = max(1, n_urls // len(urls))
        for grupo, serie in urls.items():
            s = serie.dropna().astype(str).drop_duplicates()
            s = s[~s.isin(existentes)].sample(frac=1, random_state=semilla)
            dom = s.map(_dom_registrable)
            s = s[dom.groupby(dom).cumcount() < max_por_dominio]  # una campaña no puede dominar la muestra
            filas += [{"indicador": u, "tipo": "url", "grupo": grupo, "clase_esperada": "malicioso"} for u in s.head(por)]
        if n_urls_ben > 0:
            tr = pd.read_csv(data_dir / "top-1m.csv", header=None, names=["rank", "domain"])
            maliciosos = set().union(*[set(p.dropna().astype(str).str.lower()) for p in _pools(data_dir, ventana_dias).values()])
            t = tr["domain"].head(excluir_top)
            t = t[~t.map(es_doble_uso) & ~t.isin(maliciosos)]
            raices = ("https://" + t.sample(min(n_urls_ben, len(t)), random_state=semilla) + "/")
            filas += [{"indicador": u, "tipo": "url", "grupo": "url_tranco_raiz", "clase_esperada": "no_malicioso"} for u in raices]
    if n_hashes > 0 and "hash_" in solo:
        por = max(1, n_hashes // len(hashes))
        for grupo, serie in hashes.items():
            s = serie.dropna().astype(str).str.lower().drop_duplicates()
            s = s[~s.isin(existentes)]
            filas += [{"indicador": h, "tipo": "sha256", "grupo": grupo, "clase_esperada": "malicioso"}
                      for h in s.sample(min(por, len(s)), random_state=semilla)]
    return pd.DataFrame(filas, columns=["indicador", "tipo", "grupo", "clase_esperada"])


def construir_muestra(data_dir: Path, n_ips: int, n_dom_mal: int, n_dom_ben: int, semilla: int,
                      excluir_top: int, ventana_dias: int, n_urls: int = 0, n_urls_ben: int = 0, n_hashes: int = 0,
                      max_por_dominio: int = 2) -> pd.DataFrame:
    bl = load_blocklist(data_dir / "export-ips_all.txt")
    ips = bl.loc[(bl["version"] > 0) & ~bl["privada"], "ip"].drop_duplicates()
    m_ips = ips.sample(min(n_ips, len(ips)), random_state=semilla)
    filas = [{"indicador": ip, "tipo": "ip", "grupo": "ip_blocklist", "clase_esperada": "malicioso"} for ip in m_ips]

    tr = pd.read_csv(data_dir / "top-1m.csv", header=None, names=["rank", "domain"])
    top_excluir = set(tr["domain"].head(excluir_top))
    pools = _pools(data_dir, ventana_dias)
    usados = set()
    por_familia = max(1, n_dom_mal // len(pools))
    for grupo, serie in pools.items():
        s = _limpiar(serie, top_excluir)
        s = s[~s.isin(usados)]
        elegidos = s.sample(min(por_familia, len(s)), random_state=semilla)
        usados |= set(elegidos)
        filas += [{"indicador": d, "tipo": "domain", "grupo": grupo, "clase_esperada": "malicioso"} for d in elegidos]

    # Todos los dominios maliciosos conocidos: un candidato benigno no puede estar entre ellos
    maliciosos = set().union(*[set(p.dropna().astype(str).str.lower()) for p in pools.values()])
    por_tramo = max(1, n_dom_ben // len(TRAMOS_TRANCO))
    for lo, hi in TRAMOS_TRANCO:
        t = tr[(tr["rank"] >= lo) & (tr["rank"] <= hi)]["domain"]
        t = t[~t.map(es_doble_uso) & ~t.isin(maliciosos)]
        elegidos = t.sample(min(por_tramo, len(t)), random_state=semilla)
        filas += [{"indicador": d, "tipo": "domain", "grupo": f"dom_tranco_{lo}-{hi}", "clase_esperada": "no_malicioso"}
                  for d in elegidos]
    base = pd.DataFrame(filas)
    extra = construir_grupos_url_hash(data_dir, n_urls, n_urls_ben, n_hashes, semilla, ventana_dias, max_por_dominio, excluir_top)
    return pd.concat([base, extra], ignore_index=True)


def adaptar_muestra(muestra: pd.DataFrame, data_dir: Path, n_tweetfeed: int, semilla: int, excluir_top: int,
                    n_urls: int = 0, n_urls_ben: int = 0, n_hashes: int = 0, ventana_dias: int = 90,
                    max_por_dominio: int = 2) -> pd.DataFrame:
    """Reutiliza una muestra anterior: quita grupos obsoletos, plataformas de doble uso y añade dom_tweetfeed si falta."""
    activo = muestra["grupo"].map(lambda g: g.startswith(GRUPOS_ACTIVOS))
    if (~activo).any():
        print(f"Se descartan {int((~activo).sum())} indicadores de grupos fuera del diseño actual: "
              f"{muestra.loc[~activo, 'grupo'].value_counts().to_dict()}")
    muestra = muestra[activo]
    plataforma = (muestra["tipo"] == "domain") & muestra["indicador"].map(es_doble_uso)
    if plataforma.any():
        print(f"Se excluyen {int(plataforma.sum())} dominios de plataformas de doble uso")
    muestra = muestra[~plataforma]
    if "dom_tweetfeed" not in set(muestra["grupo"]):
        tr = pd.read_csv(data_dir / "top-1m.csv", header=None, names=["rank", "domain"])
        s = _limpiar(_pool_tweetfeed(data_dir), set(tr["domain"].head(excluir_top)))
        s = s[~s.isin(set(muestra["indicador"]))]
        nuevos = s.sample(min(n_tweetfeed, len(s)), random_state=semilla)
        print(f"Se añade el grupo dom_tweetfeed con {len(nuevos)} dominios")
        extra = pd.DataFrame({"indicador": nuevos.values, "tipo": "domain", "grupo": "dom_tweetfeed", "clase_esperada": "malicioso"})
        muestra = pd.concat([muestra, extra], ignore_index=True)
    faltan = tuple(p for p, n in (("url_", n_urls), ("hash_", n_hashes))
                   if n > 0 and not muestra["grupo"].str.startswith(p).any())
    if faltan:
        nuevos = construir_grupos_url_hash(data_dir, n_urls, n_urls_ben, n_hashes, semilla, ventana_dias, max_por_dominio,
                                           excluir_top, frozenset(muestra["indicador"]), solo=faltan)
        print(f"Se añaden grupos de {', '.join(faltan)}: {nuevos['grupo'].value_counts().to_dict()}")
        muestra = pd.concat([muestra, nuevos], ignore_index=True)
    return muestra.reset_index(drop=True)


# ----------------------------------------------------------------------------- consulta
def _ahora() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _ruta(tipo: str, valor: str) -> str:
    """Punto de acceso de la API v3 según el tipo de indicador."""
    if tipo == "ip":
        return f"ip_addresses/{valor}"
    if tipo == "domain":
        return f"domains/{valor}"
    if tipo == "url":  # identificador: la URL en base64 «url-safe» y sin relleno (=)
        return "urls/" + base64.urlsafe_b64encode(valor.encode()).decode().rstrip("=")
    if tipo in ("sha256", "md5", "sha1"):
        return f"files/{valor}"
    raise ValueError(f"tipo no soportado: {tipo}")


def consultar(sesion, tipo: str, valor: str, max_reintentos: int = 4) -> dict:
    """Devuelve un dict con 'status' (ok | not_found | error). Lanza CuotaAgotada o ClaveInvalida."""
    import requests
    url = f"{API}/{_ruta(tipo, valor)}"
    ultimo = "sin respuesta"
    for intento in range(max_reintentos + 1):
        try:
            r = sesion.get(url, timeout=30)
        except requests.RequestException as e:
            ultimo = f"red: {type(e).__name__}"
            time.sleep(min(60, 5 * 2 ** intento))
            continue
        if r.status_code == 200:
            a = r.json()["data"]["attributes"]
            s = a.get("last_analysis_stats", {})
            ts = a.get("last_analysis_date")
            cats = a.get("categories") or {}
            if tipo in ("sha256", "md5", "sha1"):  # en ficheros, la etiqueta de amenaza sugerida por VirusTotal
                etiqueta = (a.get("popular_threat_classification") or {}).get("suggested_threat_label") or a.get("type_description") or ""
            else:
                etiqueta = ";".join(sorted(set(cats.values())))
            return {"status": "ok", "http_status": 200, "reputation": a.get("reputation"),
                    "malicious": s.get("malicious"), "suspicious": s.get("suspicious"), "harmless": s.get("harmless"),
                    "undetected": s.get("undetected"), "timeout": s.get("timeout"), "as_owner": a.get("as_owner"),
                    "country": a.get("country"), "categorias": etiqueta,
                    "last_analysis_at": datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if ts else ""}
        if r.status_code == 404:
            return {"status": "not_found", "http_status": 404}
        if r.status_code in (401, 403):
            raise ClaveInvalida(f"HTTP {r.status_code}: revisa VT_API_KEY")
        if r.status_code == 429:
            ultimo = "429"
            try:
                espera = int(r.headers.get("Retry-After", 0))
            except (TypeError, ValueError):
                espera = 0
            time.sleep(espera or min(120, 15 * 2 ** intento))
            continue
        if r.status_code >= 500:
            ultimo = f"HTTP {r.status_code}"
            time.sleep(min(60, 5 * 2 ** intento))
            continue
        return {"status": "error", "http_status": r.status_code}
    if ultimo == "429":
        raise CuotaAgotada("VirusTotal sigue limitando las peticiones: se guarda el progreso")
    return {"status": "error", "http_status": None, "categorias": ultimo}


def ejecutar(muestra: pd.DataFrame, salida: Path, sesion, pausa: float, max_consultas: int) -> None:
    hechos = set()
    if salida.exists():
        previo = pd.read_csv(salida, dtype=str)
        hechos = set(previo.loc[previo["status"].isin(["ok", "not_found"]), "indicador"])
    pendientes = muestra[~muestra["indicador"].isin(hechos)]
    if max_consultas:
        pendientes = pendientes.head(max_consultas)
    print(f"Muestra: {len(muestra)} | ya consultados: {int(muestra['indicador'].isin(hechos).sum())} | a consultar ahora: "
          f"{len(pendientes)} (≈ {len(pendientes) * pausa / 60:.0f} min a {pausa:g} s por consulta)")
    nuevo = not salida.exists()
    with open(salida, "a", encoding="utf-8", newline="") as f:
        if nuevo:
            f.write(",".join(COLS_RESULTADO) + "\n")
        for i, fila in enumerate(pendientes.itertuples(index=False), 1):
            try:
                res = consultar(sesion, fila.tipo, fila.indicador)
            except CuotaAgotada as e:
                print(f"\nDetenido: {e}. Vuelve a lanzar el script más tarde: reanuda donde se quedó.")
                return
            res.update({"indicador": fila.indicador, "tipo": fila.tipo, "grupo": fila.grupo,
                        "clase_esperada": fila.clase_esperada, "queried_at": _ahora()})
            df = pd.DataFrame([res]).reindex(columns=COLS_RESULTADO)
            df.to_csv(f, header=False, index=False)
            f.flush()
            print(f"[{i}/{len(pendientes)}] {fila.tipo:6} {fila.indicador:40} {res['status']}", end="\r")
            if i < len(pendientes):
                time.sleep(pausa)
    print()


def resumen(salida: Path) -> None:
    if not salida.exists():
        return
    r = pd.read_csv(salida)
    ok = r[r["status"] == "ok"].copy()
    print("\nEstados:", r["status"].value_counts().to_dict())
    if ok.empty:
        return
    plataforma = (ok["tipo"] == "domain") & ok["indicador"].map(es_doble_uso)
    if plataforma.any():
        print(f"Se excluyen del resumen {int(plataforma.sum())} dominios de plataformas de doble uso")
        ok = ok[~plataforma].copy()
    for c in ("malicious",):
        ok[c] = pd.to_numeric(ok[c])
    ok["con_deteccion"] = ok["malicious"] >= 1
    ok["con_3_detecciones"] = ok["malicious"] >= 3
    historico = ~ok["grupo"].str.startswith(GRUPOS_ACTIVOS)
    if historico.any():
        print(f"Grupos históricos (fuera del diseño actual): {ok.loc[historico, 'grupo'].value_counts().to_dict()}")
    tabla = ok.groupby(["clase_esperada", "grupo"]).agg(
        n=("indicador", "size"), con_deteccion=("con_deteccion", "mean"), con_3_detecciones=("con_3_detecciones", "mean"),
        malicious_mediana=("malicious", "median"))
    # Cobertura: parte del grupo que VirusTotal conoce (not_found = nunca lo analizó). Las tasas se calculan solo sobre n.
    nf = r[r["status"] == "not_found"].groupby(["clase_esperada", "grupo"]).size()
    tabla.insert(1, "not_found", nf.reindex(tabla.index, fill_value=0))
    tabla.insert(2, "cobertura", tabla["n"] / (tabla["n"] + tabla["not_found"]))
    print(tabla.round(2).to_string())


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data-dir", type=Path, default=Path("data/raw"))
    p.add_argument("--muestra", type=Path, default=Path("muestra_vt.csv"))
    p.add_argument("--salida", type=Path, default=Path("resultados_vt.csv"))
    p.add_argument("--n-ips", type=int, default=200)
    p.add_argument("--n-dom-mal", type=int, default=198, help="total repartido a partes iguales entre abuse.ch, PhishTank y TweetFeed")
    p.add_argument("--n-dom-ben", type=int, default=198)
    p.add_argument("--n-urls", type=int, default=100, help="URLs maliciosas completas (repartidas entre URLhaus, PhishTank y TweetFeed); 0 = no validar URLs")
    p.add_argument("--n-urls-benignas", type=int, default=30, help="raíces https://dominio/ de sitios populares como base de falsos positivos")
    p.add_argument("--n-hashes", type=int, default=100, help="hashes sha256 (ThreatFox y TweetFeed); 0 = no validar hashes")
    p.add_argument("--max-por-dominio", type=int, default=2, help="máximo de URLs de un mismo dominio registrable")
    p.add_argument("--semilla", type=int, default=42)
    p.add_argument("--excluir-top", type=int, default=10_000, help="no muestrear maliciosos dentro del top N de Tranco")
    p.add_argument("--ventana-phishtank", type=int, default=90)
    p.add_argument("--pausa", type=float, default=16.0, help="segundos entre consultas (ajústalo a tu cuota)")
    p.add_argument("--max-consultas", type=int, default=0, help="tope por ejecución (0 = sin tope)")
    p.add_argument("--regenerar", action="store_true", help="rehacer la muestra aunque ya exista")
    p.add_argument("--solo-muestra", action="store_true", help="generar la muestra y salir (no necesita clave)")
    a = p.parse_args()

    if a.muestra.exists() and not a.regenerar:
        muestra = pd.read_csv(a.muestra)
        print(f"Usando la muestra existente: {a.muestra} ({len(muestra)} indicadores)")
        n_tw = max(1, a.n_dom_mal // 3)
        adaptada = adaptar_muestra(muestra, a.data_dir, n_tw, a.semilla, a.excluir_top, a.n_urls, a.n_urls_benignas,
                                   a.n_hashes, a.ventana_phishtank, a.max_por_dominio)
        if len(adaptada) != len(muestra) or not adaptada["indicador"].equals(muestra["indicador"]):
            muestra = adaptada
            muestra.to_csv(a.muestra, index=False)
            print(f"Muestra actualizada: {a.muestra} ({len(muestra)} indicadores)")
    else:
        muestra = construir_muestra(a.data_dir, a.n_ips, a.n_dom_mal, a.n_dom_ben, a.semilla, a.excluir_top,
                                    a.ventana_phishtank, a.n_urls, a.n_urls_benignas, a.n_hashes, a.max_por_dominio)
        muestra.to_csv(a.muestra, index=False)
        print(f"Muestra creada: {a.muestra} ({len(muestra)} indicadores)")
    print(muestra.groupby(["clase_esperada", "grupo"]).size().to_string())
    if a.solo_muestra:
        return
    # Orden de consulta barajado (estable con la semilla): una ejecución parcial cubre todos los grupos
    muestra = muestra.sample(frac=1, random_state=a.semilla).reset_index(drop=True)

    clave = os.environ.get("VT_API_KEY")
    if not clave:
        sys.exit("Falta la variable de entorno VT_API_KEY")
    import requests
    sesion = requests.Session()
    sesion.headers.update({"x-apikey": clave, "accept": "application/json"})
    try:
        ejecutar(muestra, a.salida, sesion, a.pausa, a.max_consultas)
    except ClaveInvalida as e:
        sys.exit(str(e))
    resumen(a.salida)


if __name__ == "__main__":
    main()