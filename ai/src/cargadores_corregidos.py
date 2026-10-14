"""Cargadores y utilidades de VeriThreat (fase de datos).

Fuentes del núcleo:   ThreatFox, URLhaus, blocklist.de, PhishTank, TweetFeed (month.csv) y Tranco.
Señal de fiabilidad:  IPsum (nivel = nº de listas en las que aparece una IP).
Descartadas:          MalwareBazaar y ThreatCluster (ver cargadores_opcionales.py), OTX, Feodo, etc.
"""
import ast
import html
import io
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd

# --------------------------------------------------------------------------- doble uso
# Plataformas y servicios en los que cualquier host pertenece a un usuario, no a la plataforma.
# No se etiquetan como maliciosos ni benignos a nivel de dominio (siguen valiendo como URL u host).
DOBLE_USO = {
    # almacenamiento y compartición de ficheros / código
    "github.com", "githubusercontent.com", "raw.githubusercontent.com", "dropbox.com", "pastebin.com", "discord.com",
    "discordapp.com", "drive.google.com", "docs.google.com", "mediafire.com", "mega.nz", "telegram.org", "t.me",
    "google.com", "adobe.com",
    # acortadores y generadores de QR
    "bit.ly", "tinyurl.com", "t.co", "qrco.de", "q-r.to", "l.ead.me", "linkin.bio",
    # plataformas de subdominios, constructores de sitios y DNS dinámico
    "github.io", "workers.dev", "herokuapp.com", "vercel.app", "netlify.app", "blogspot.com", "wordpress.com",
    "pages.dev", "weebly.com", "weeblysite.com", "framer.app", "framer.website", "framer.ai", "duckdns.org",
    "replit.app", "wixstudio.com", "wixsite.com", "webflow.io", "eu.cc", "us.cc", "edgeone.dev", "godaddysites.com",
    "bolt.host", "typedream.app", "surge.sh", "square.site", "webcindario.com", "gitbook.io",
    # nube y almacenamiento de objetos
    "ipfs.io", "windows.net", "r2.dev", "amazonaws.com",
}


def es_ip(host: str) -> bool:
    return bool(host) and bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))


def es_doble_uso(host: str) -> bool:
    host = (host or "").lower()
    return any(host == d or host.endswith("." + d) for d in DOBLE_USO)


_EXT = None


def registrable(host: str) -> str:
    """Dominio registrable (example.com en a.b.example.com). Usa tldextract si está instalado."""
    global _EXT
    try:
        import tldextract
        if _EXT is None:
            _EXT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # lista incluida: sin red
        r = _EXT(host)
        return getattr(r, "top_domain_under_public_suffix", None) or r.registered_domain
    except ImportError:
        p = host.split(".")
        return ".".join(p[-2:]) if len(p) >= 2 else host


def a_punycode(s: str) -> str:
    """Nombre IDN (homógrafos, .zip japoneses...) a su forma ASCII; si no se puede, se devuelve igual."""
    try:
        return s.encode("idna").decode("ascii")
    except UnicodeError:
        return s


def _host(u: str) -> str:
    return a_punycode((urlparse(u).hostname or "").lower())


# --------------------------------------------------------------------------- abuse.ch
UH_COLS = ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"]


def load_threatfox(path) -> pd.DataFrame:
    df = pd.read_csv(path)
    for c in ("first_seen", "last_seen"):
        df[c] = pd.to_datetime(df[c], utc=True, errors="coerce")
    df["tags_list"] = df["tags"].apply(lambda s: ast.literal_eval(s) if isinstance(s, str) and s.startswith("[") else [])
    return df


def load_urlhaus(path) -> pd.DataFrame:
    df = pd.read_csv(path, skiprows=1, header=None, names=UH_COLS)  # la cabecera es "# id,..."
    for c in ("dateadded", "last_online"):
        df[c] = pd.to_datetime(df[c], utc=True, errors="coerce")
    df["tags_list"] = df["tags"].fillna("").str.split(",").apply(lambda l: [t.strip() for t in l if t.strip()])
    df["host"] = df["url"].map(lambda u: (urlparse(u).hostname or "").lower())
    return df


# --------------------------------------------------------------------------- IPs
def load_blocklist(path) -> pd.DataFrame:
    """blocklist.de: una IP por línea, sin fecha ni categoría (IPv4 e IPv6)."""
    ips = pd.read_csv(path, header=None, names=["ip"], dtype=str)["ip"].str.strip()

    def info(x):
        try:
            a = ipaddress.ip_address(x)
            return a.version, a.is_private or a.is_reserved or a.is_loopback, a.compressed
        except ValueError:
            return 0, False, x

    parsed = ips.map(info)
    return pd.DataFrame({"ip": parsed.map(lambda t: t[2]), "version": parsed.map(lambda t: t[0]),
                         "privada": parsed.map(lambda t: t[1])})


def marcar_bloques_completos(ips, umbral: int = 250) -> pd.Series:
    """Para cada IPv4, el /24 (a.b.c.0/24) si ese /24 tiene >= `umbral` IPs listadas; cadena vacía en el resto.

    all.txt de blocklist.de incluye /24 completos (256 IPs seguidas) que no son ataques individuales: en una lista de
    24.714 IPs había 30 bloques (el 32 % del IPv4). Una IP individual rara vez comparte /24 con más de 100 más."""
    s = pd.Series(list(ips), dtype="object")
    es4 = ~s.str.contains(":", regex=False)
    p24 = s.where(es4).str.rsplit(".", n=1).str[0]
    n = p24.map(p24.value_counts())
    return (p24 + ".0/24").where(es4 & (n >= umbral), "").set_axis(s.index)


def load_blocklist_historico(path) -> pd.DataFrame:
    """Histórico generado por blocklist_historico.py (una fila por IP, con fechas propias, servicios y subtipos)."""
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    for c in ("first_seen_utc", "last_seen_utc", "dns_last_attack_utc", "dns_consultado_utc", "api_consultado_utc"):
        df[c] = pd.to_datetime(df[c].replace("", pd.NA), utc=True, errors="coerce")
    for c in ("en_ultima_lista", "strongips"):
        df[c] = df[c].eq("True")
    for c in ("n_sondeos", "window_s", "attacks", "reports"):
        df[c] = pd.to_numeric(df[c], errors="coerce")
    for c in ("services", "subtipos", "dns_services"):
        df[c + "_list"] = df[c].str.split("|").apply(lambda l: [x for x in l if x])
    df["version"] = df["ip"].map(lambda x: 6 if ":" in x else 4)
    return df


IPSUM_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/{n}.txt"


def descargar_ipsum(directorio, niveles=range(1, 9), timeout=60) -> list:
    """Descarga los ficheros de niveles de IPsum (ipsum_level1.txt ... ipsum_level8.txt). Omite los que ya existen."""
    import requests
    directorio = Path(directorio)
    directorio.mkdir(parents=True, exist_ok=True)
    nuevos = []
    for n in niveles:
        destino = directorio / f"ipsum_level{n}.txt"
        if destino.exists():
            continue
        r = requests.get(IPSUM_URL.format(n=n), timeout=timeout)
        r.raise_for_status()
        destino.write_bytes(r.content)
        nuevos.append(destino.name)
    return nuevos


def load_ipsum(directorio) -> pd.DataFrame:
    """IPsum: el nivel N contiene las IPs que aparecen en >=N listas. Devuelve ip y nivel máximo (nº de listas)."""
    nivel = {}
    for p in sorted(Path(directorio).glob("ipsum_level*.txt"), key=lambda p: int(re.search(r"(\d+)", p.stem).group(1))):
        n = int(re.search(r"(\d+)", p.stem).group(1))
        for linea in open(p, encoding="utf-8", errors="replace"):
            ip = linea.strip()
            if ip and not ip.startswith("#"):
                nivel[ip] = n  # al recorrer en orden creciente queda el nivel más alto
    return pd.DataFrame({"ip": list(nivel), "nivel": list(nivel.values())})


# --------------------------------------------------------------------------- phishing y comunidad
def load_phishtank(path, ventana_dias=90) -> pd.DataFrame:
    """PhishTank trae histórico desde 2011: se marca como 'reciente' lo de los últimos `ventana_dias`."""
    df = pd.read_csv(path)
    df["url_raw"] = df["url"]
    df["url"] = df["url"].map(html.unescape)  # "&amp;" -> "&"
    for c in ("submission_time", "verification_time"):
        df[c] = pd.to_datetime(df[c], utc=True, errors="coerce")
    df["host"] = df["url"].map(lambda u: (urlparse(u).hostname or "").lower())
    df["reciente"] = df["submission_time"] >= df["submission_time"].max() - pd.Timedelta(days=ventana_dias)
    return df


TW_COLS = ["date", "reporter", "type", "value", "tags", "tweet"]


def load_tweetfeed(month_path, exclusive_path=None) -> pd.DataFrame:
    """TweetFeed (month.csv, sin cabecera). Con exclusive.csv marca qué filas corroboran sus 5 feeds de referencia.

    - `derivado`: fila de dominio que es solo el host de una URL del mismo tweet (no es una observación nueva).
    - `value_norm`: minúsculas y punycode en dominios; las URLs se conservan tal cual (el host va en `host`).
    - `corroborado`: True si NO aparece en exclusive.csv (otro feed de referencia también lo reporta).
    """
    df = pd.read_csv(month_path, header=None, names=TW_COLS, dtype=str)
    df["date"] = pd.to_datetime(df["date"], utc=True, errors="coerce")
    df["tags_list"] = df["tags"].fillna("").str.split()
    df["no_ascii"] = ~df["value"].map(lambda s: s.isascii())
    es_url, es_dom = df["type"] == "url", df["type"] == "domain"
    df["value_norm"] = df["value"].str.lower()
    df.loc[es_dom, "value_norm"] = df.loc[es_dom, "value_norm"].map(a_punycode)
    df.loc[es_url, "value_norm"] = df.loc[es_url, "value"]
    df["host"] = ""
    df.loc[es_url, "host"] = df.loc[es_url, "value"].map(_host)
    hosts_url = set(zip(df.loc[es_url, "tweet"], df.loc[es_url, "host"]))
    df["derivado"] = es_dom & pd.Series([(t, v) in hosts_url for t, v in zip(df["tweet"], df["value_norm"])], index=df.index)
    if exclusive_path is not None:
        ex = pd.read_csv(exclusive_path, header=None, names=TW_COLS, dtype=str)
        claves = set(zip(ex["type"], ex["value"]))
        df["corroborado"] = [(t, v) not in claves for t, v in zip(df["type"], df["value"])]
    else:
        df["corroborado"] = pd.NA
    return df


# --------------------------------------------------------------------------- clase no maliciosa
def load_tranco(path) -> pd.DataFrame:
    return pd.read_csv(path, header=None, names=["rank", "domain"])