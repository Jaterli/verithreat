"""Cargadores y utilidades de VeriThreat (fase de datos).

Fuentes del núcleo:   ThreatFox, URLhaus, blocklist.de, PhishTank, TweetFeed (month.csv) y Tranco.
Señal de fiabilidad:  IPsum (nivel = nº de listas en las que aparece una IP).
Descartadas:          MalwareBazaar y ThreatCluster (ver optional_loaders.py), OTX, Feodo, etc.
"""
import ast
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd

# --------------------------------------------------------------------------- doble uso
# Plataformas y servicios en los que cualquier host pertenece a un usuario, no a la plataforma.
# No se etiquetan como maliciosos ni benignos a nivel de dominio (siguen valiendo como URL u host).
DUAL_USE = {
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


def is_ip(host: str) -> bool:
    return bool(host) and bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))


def is_dual_use(host: str) -> bool:
    host = (host or "").lower()
    return any(host == d or host.endswith("." + d) for d in DUAL_USE)


_EXT = None


def registered_domain(host: str) -> str:
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


_EXT_PRIVATE = None


def under_private_suffix(host: str) -> bool:
    """¿Cuelga el host de un sufijo de la sección privada de la PSL (us.com, ddns.net, ngrok.io, poznan.pl…)?

    En esos espacios cada subdominio es de alguien distinto, como en las plataformas de doble uso, así que no hereda
    la popularidad del dominio padre. registered_domain() sigue sin usar esa sección: de ella dependen la partición
    del modelo A, la clase no maliciosa y DUAL_USE. Sin tldextract devuelve False."""
    global _EXT_PRIVATE
    try:
        import tldextract
    except ImportError:
        return False
    if _EXT_PRIVATE is None:
        _EXT_PRIVATE = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)
    return bool(_EXT_PRIVATE(host).is_private)


def to_punycode(s: str) -> str:
    """Nombre IDN (homógrafos, .zip japoneses...) a su forma ASCII; si no se puede, se devuelve igual."""
    try:
        return s.encode("idna").decode("ascii")
    except UnicodeError:
        return s


def _host(u: str) -> str:
    return to_punycode((urlparse(u).hostname or "").lower())


# --------------------------------------------------------------------------- normalización de un valor suelto
# Las mismas reglas que aplican los cargadores y que exige db/schema.sql (CHECK normalized_value). La implementación
# Java (ioc-service, Normalizer) debe dar exactamente lo mismo: ambas se prueban con db/normalization_cases.json.
_HEX = {"sha256": 64, "sha1": 40, "md5": 32}
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")


def normalize_value(typ: str, value: str) -> str:
    """Valor normalizado de un indicador; ValueError si el valor no es válido para su tipo."""
    v = (value or "").strip()
    if not v:
        raise ValueError("empty value")
    if typ in _HEX:
        v = v.lower()
        if not re.fullmatch(rf"[0-9a-f]{{{_HEX[typ]}}}", v):
            raise ValueError(f"not a {typ}: {value!r}")
        return v
    if typ == "domain":
        v = v.lower().rstrip(".")
        try:
            v = v.encode("idna").decode("ascii")
        except UnicodeError as e:
            raise ValueError(f"invalid domain: {value!r}") from e
        if not _DOMAIN_RE.match(v):
            raise ValueError(f"invalid domain: {value!r}")
        return v
    if typ == "url":
        if not re.match(r"^[a-z][a-z0-9+.-]*://\S+$", v, re.I):
            raise ValueError(f"invalid url: {value!r}")
        return v
    if typ == "ip":
        if "%" in v:  # IPv6 con zona (fe80::1%eth0): local a un equipo, no es un indicador
            raise ValueError(f"scoped IPv6 not accepted: {value!r}")
        try:
            a = ipaddress.ip_address(v)
        except ValueError as e:
            raise ValueError(f"invalid ip: {value!r}") from e
        if a.version == 6 and a.ipv4_mapped is not None:
            raise ValueError(f"IPv4-mapped IPv6 not accepted, use the IPv4 address: {value!r}")
        return a.compressed
    if typ == "cidr":
        try:
            return str(ipaddress.ip_network(v, strict=True))
        except ValueError as e:
            raise ValueError(f"invalid cidr: {value!r}") from e
    raise ValueError(f"unknown type: {typ!r}")


# --------------------------------------------------------------------------- abuse.ch
UH_COLS = ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"]


def load_threatfox(path) -> pd.DataFrame:
    df = pd.read_csv(path)
    for c in ("first_seen", "last_seen"):
        df[c] = pd.to_datetime(df[c], utc=True, errors="coerce")
    df["tags_list"] = df["tags"].apply(lambda s: ast.literal_eval(s) if isinstance(s, str) and s.startswith("[") else [])
    return df


def _leading_comment_lines(path) -> int:
    """Nº de líneas iniciales que empiezan por '#': el bloque de cabecera de la exportación oficial y la línea
    «# id,dateadded,...». No se usa comment='#' de pandas porque cortaría las URLs que llevan '#'."""
    n = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.startswith("#"):
                break
            n += 1
    return n


def load_urlhaus(path) -> pd.DataFrame:
    df = pd.read_csv(path, skiprows=_leading_comment_lines(path), header=None, names=UH_COLS)
    for c in ("dateadded", "last_online"):
        df[c] = pd.to_datetime(df[c], utc=True, errors="coerce")
    df["tags_list"] = df["tags"].fillna("").str.split(",").apply(lambda l: [t.strip() for t in l if t.strip()])
    df["host"] = df["url"].map(lambda u: (urlparse(u).hostname or "").lower())
    return df


# --------------------------------------------------------------------------- IPs
def load_blocklist(path) -> pd.DataFrame:
    """blocklist.de: una IP por línea, sin fecha ni categoría (IPv4 e IPv6). Columnas: ip, version, private."""
    ips = pd.read_csv(path, header=None, names=["ip"], dtype=str)["ip"].str.strip()

    def info(x):
        try:
            a = ipaddress.ip_address(x)
            return a.version, a.is_private or a.is_reserved or a.is_loopback, a.compressed
        except ValueError:
            return 0, False, x

    parsed = ips.map(info)
    return pd.DataFrame({"ip": parsed.map(lambda t: t[2]), "version": parsed.map(lambda t: t[0]),
                         "private": parsed.map(lambda t: t[1])})


def mark_full_blocks(ips, threshold: int = 250) -> pd.Series:
    """Para cada IPv4, el /24 (a.b.c.0/24) si ese /24 tiene >= `threshold` IPs listadas; cadena vacía en el resto.

    all.txt de blocklist.de incluye /24 completos (256 IPs seguidas) que no son ataques individuales: en una lista de
    24.714 IPs había 30 bloques (el 32 % del IPv4). Una IP individual rara vez comparte /24 con más de 100 más."""
    s = pd.Series(list(ips), dtype="object")
    is4 = ~s.str.contains(":", regex=False)
    p24 = s.where(is4).str.rsplit(".", n=1).str[0]
    n = p24.map(p24.value_counts())
    return (p24 + ".0/24").where(is4 & (n >= threshold), "").set_axis(s.index)


def load_blocklist_history(path) -> pd.DataFrame:
    """Histórico generado por blocklist_history.py (una fila por IP, con fechas propias, servicios y subtipos)."""
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    for c in ("first_seen_utc", "last_seen_utc", "dns_last_attack_utc", "dns_queried_utc", "api_queried_utc"):
        df[c] = pd.to_datetime(df[c].replace("", pd.NA), utc=True, errors="coerce")
    for c in ("in_latest_list", "strongips"):
        df[c] = df[c].eq("True")
    for c in ("n_polls", "window_s", "attacks", "reports"):
        df[c] = pd.to_numeric(df[c], errors="coerce")
    for c in ("services", "subtypes", "dns_services"):
        df[c + "_list"] = df[c].str.split("|").apply(lambda l: [x for x in l if x])
    df["version"] = df["ip"].map(lambda x: 6 if ":" in x else 4)
    return df


IPSUM_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/{n}.txt"


def download_ipsum(directory, levels=range(1, 9), timeout=60) -> list:
    """Descarga los ficheros de niveles de IPsum (ipsum_level1.txt ... ipsum_level8.txt). Omite los que ya existen."""
    import requests
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    new = []
    for n in levels:
        target = directory / f"ipsum_level{n}.txt"
        if target.exists():
            continue
        r = requests.get(IPSUM_URL.format(n=n), timeout=timeout)
        r.raise_for_status()
        target.write_bytes(r.content)
        new.append(target.name)
    return new


def load_ipsum(directory) -> pd.DataFrame:
    """IPsum: el nivel N contiene las IPs que aparecen en >=N listas. Devuelve ip y level (nivel máximo = nº de listas)."""
    level = {}
    for p in sorted(Path(directory).glob("ipsum_level*.txt"), key=lambda p: int(re.search(r"(\d+)", p.stem).group(1))):
        n = int(re.search(r"(\d+)", p.stem).group(1))
        for line in open(p, encoding="utf-8", errors="replace"):
            ip = line.strip()
            if ip and not ip.startswith("#"):
                level[ip] = n  # al recorrer en orden creciente queda el nivel más alto
    return pd.DataFrame({"ip": list(level), "level": list(level.values())})


# --------------------------------------------------------------------------- phishing y comunidad
def unescape_amp(url: str) -> str:
    """Deshace "&amp;" (también el doble escape "&amp;amp;") y nada más.

    html.unescape no sirve: convierte entidades sin «;» que son parámetros legítimos
    («&regform=» -> «®form=», «&params=» -> «¶ms=»).
    """
    while "&amp;" in url:
        url = url.replace("&amp;", "&")
    return url


def load_phishtank(path, window_days=90) -> pd.DataFrame:
    """PhishTank trae histórico desde 2011: se marca como `recent` lo de los últimos `window_days`."""
    df = pd.read_csv(path)
    df["url_raw"] = df["url"]
    df["url"] = df["url"].map(unescape_amp)
    for c in ("submission_time", "verification_time"):
        df[c] = pd.to_datetime(df[c], utc=True, errors="coerce")
    df["host"] = df["url"].map(lambda u: (urlparse(u).hostname or "").lower())
    df["recent"] = df["submission_time"] >= df["submission_time"].max() - pd.Timedelta(days=window_days)
    return df


TW_COLS = ["date", "reporter", "type", "value", "tags", "tweet"]


def load_tweetfeed(month_path, exclusive_path=None) -> pd.DataFrame:
    """TweetFeed (month.csv, sin cabecera). Con exclusive.csv marca qué filas corroboran sus 5 feeds de referencia.

    - `derived`: fila de dominio que es solo el host de una URL del mismo tweet (no es una observación nueva).
    - `value_norm`: minúsculas y punycode en dominios; las URLs se conservan tal cual (el host va en `host`).
    - `corroborated`: True si NO aparece en exclusive.csv (otro feed de referencia también lo reporta).
    """
    df = pd.read_csv(month_path, header=None, names=TW_COLS, dtype=str)
    df["date"] = pd.to_datetime(df["date"], utc=True, errors="coerce")
    df["tags_list"] = df["tags"].fillna("").str.split()
    df["non_ascii"] = ~df["value"].map(lambda s: s.isascii())
    is_url, is_dom = df["type"] == "url", df["type"] == "domain"
    df["value_norm"] = df["value"].str.lower()
    df.loc[is_dom, "value_norm"] = df.loc[is_dom, "value_norm"].map(to_punycode)
    df.loc[is_url, "value_norm"] = df.loc[is_url, "value"]
    df["host"] = ""
    df.loc[is_url, "host"] = df.loc[is_url, "value"].map(_host)
    url_hosts = set(zip(df.loc[is_url, "tweet"], df.loc[is_url, "host"]))
    df["derived"] = is_dom & pd.Series([(t, v) in url_hosts for t, v in zip(df["tweet"], df["value_norm"])], index=df.index)
    if exclusive_path is not None:
        ex = pd.read_csv(exclusive_path, header=None, names=TW_COLS, dtype=str)
        keys = set(zip(ex["type"], ex["value"]))
        df["corroborated"] = [(t, v) not in keys for t, v in zip(df["type"], df["value"])]
    else:
        df["corroborated"] = pd.NA
    return df


# --------------------------------------------------------------------------- clase no maliciosa
def load_tranco(path) -> pd.DataFrame:
    return pd.read_csv(path, header=None, names=["rank", "domain"])


# --------------------------------------------------------------------------- esquema común (observaciones)
# Una fila por registro de una fuente, con el formato de la tabla `sighting` de db/schema.sql. La misma lógica
# que la sección 11 del notebook: la usan el notebook y ai/src/load_db.py.
SOURCE_FILES = {
    "threatfox": ("threatfox.csv",),
    "urlhaus": ("urlhaus.csv",),
    "blocklist.de": ("export-ips_all.txt",),
    "phishtank": ("verified_online.csv",),
    "tweetfeed": ("month.csv", "exclusive.csv"),  # exclusive.csv solo aporta `corroborated`
}
SIGHTING_COLS = ["type", "value", "source_record_id", "category", "seen_at", "malware_family", "confidence",
                 "status", "reporter", "corroborated", "raw"]
TF_TYPE_MAP = {"sha256_hash": "sha256", "md5_hash": "md5", "sha1_hash": "sha1", "domain": "domain", "url": "url",
               "ip:port": "ip"}
TF_CATEGORY_MAP = {"botnet_cc": "c2", "payload_delivery": "malware_distribution", "payload": "malware_distribution",
                   "cc_skimming": "skimming"}


def tweetfeed_category(tags) -> str:
    t = {x.lower() for x in tags}
    if t & {"#phishing", "#scam"}:
        return "phishing"
    if "#c2" in t:
        return "c2"
    return "malware" if t else "unspecified"


def _json_value(v):
    """Valor serializable a JSON estricto: nulos de pandas (NaN, NaT, NA) como None, fechas en ISO, escalares numpy nativos."""
    if v is None or (not isinstance(v, (list, dict, str)) and pd.isna(v)):
        return None
    if isinstance(v, pd.Timestamp):
        return v.isoformat()
    return v.item() if hasattr(v, "item") else v


def _raw_records(df: pd.DataFrame, columns, rename=None) -> list:
    """Registros originales como dicts serializables a JSON (fechas ISO, nulos como None)."""
    d = df[list(columns)].rename(columns=rename or {})
    return [{c: _json_value(v) for c, v in zip(d.columns, row)} for row in d.itertuples(index=False)]


def _as_sightings(d: dict) -> pd.DataFrame:
    return pd.DataFrame(d).reindex(columns=SIGHTING_COLS).reset_index(drop=True)


def source_sightings(source: str, data_dir, fetched_at: pd.Timestamp, phishtank_window: int = 90) -> pd.DataFrame:
    """Observaciones normalizadas de una fuente a partir de sus ficheros en `data_dir`.

    `fetched_at` es la fecha de la foto (UTC); se usa como `seen_at` cuando la fuente no trae fecha (blocklist.de).
    """
    data_dir = Path(data_dir)
    if source == "threatfox":
        t = load_threatfox(data_dir / "threatfox.csv")
        t = t[t["ioc_type"].isin(TF_TYPE_MAP)]
        typ = t["ioc_type"].map(TF_TYPE_MAP)
        value = t["ioc"].str.strip().where(typ == "url", t["ioc"].str.strip().str.lower())
        value = value.where(typ != "ip", t["ioc"].str.strip().str.replace(r":\d+$", "", regex=True))
        return _as_sightings({"type": typ, "value": value, "source_record_id": t["id"].astype(str),
                              "category": t["threat_type"].map(TF_CATEGORY_MAP).fillna("other"), "seen_at": t["first_seen"],
                              "malware_family": t["malware_printable"], "confidence": t["confidence_level"], "status": None,
                              "reporter": t["reporter"], "corroborated": None,
                              "raw": _raw_records(t, [c for c in t.columns if c != "tags_list"])})
    if source == "urlhaus":
        u = load_urlhaus(data_dir / "urlhaus.csv")
        return _as_sightings({"type": "url", "value": u["url"].str.strip(), "source_record_id": u["id"].astype(str),
                              "category": "malware_distribution", "seen_at": u["dateadded"],
                              "malware_family": u["tags_list"].map(lambda l: l[0] if l else None), "confidence": None,
                              "status": u["url_status"], "reporter": u["reporter"], "corroborated": None,
                              "raw": _raw_records(u, UH_COLS)})
    if source == "blocklist.de":
        b = load_blocklist(data_dir / "export-ips_all.txt")
        b = b[(b["version"] > 0) & ~b["private"]].drop_duplicates("ip")
        b["block"] = mark_full_blocks(b["ip"]).values
        single, blk = b[b["block"] == ""], b[b["block"] != ""]
        per_block = blk["block"].value_counts()
        blk = blk.drop_duplicates("block")  # un /24 completo es un indicador de red, no 256 IPs
        common = {"seen_at": fetched_at, "malware_family": None, "confidence": None, "status": None,
                  "reporter": None, "corroborated": None}
        return pd.concat([
            _as_sightings({"type": "ip", "value": single["ip"], "source_record_id": single["ip"], "category": "attack_source",
                           "raw": [{"ip": ip} for ip in single["ip"]], **common}),
            _as_sightings({"type": "cidr", "value": blk["block"], "source_record_id": blk["block"], "category": "attack_network",
                           "raw": [{"block": c, "listed_ips": int(per_block[c])} for c in blk["block"]], **common}),
        ], ignore_index=True)
    if source == "phishtank":
        p = load_phishtank(data_dir / "verified_online.csv", window_days=phishtank_window)
        p = p[p["recent"]].drop_duplicates("url")
        original = ["phish_id", "url_raw", "phish_detail_url", "submission_time", "verified", "verification_time",
                    "online", "target"]
        return _as_sightings({"type": "url", "value": p["url"].str.strip(), "source_record_id": p["phish_id"].astype(str),
                              "category": "phishing", "seen_at": p["submission_time"],
                              "malware_family": p["target"].where(p["target"] != "Other"), "confidence": None,
                              "status": None, "reporter": None, "corroborated": None,
                              "raw": _raw_records(p, original, {"url_raw": "url"})})
    if source == "tweetfeed":
        exclusive = data_dir / "exclusive.csv"
        w = load_tweetfeed(data_dir / "month.csv", exclusive if exclusive.exists() else None)
        w = w[~w["derived"]]  # el host de una URL del mismo tweet no es una observación nueva
        return _as_sightings({"type": w["type"], "value": w["value_norm"].where(w["type"] == "url", w["value_norm"].str.lower()),
                              "source_record_id": w["tweet"] + "|" + w["value"], "category": w["tags_list"].map(tweetfeed_category),
                              "seen_at": w["date"], "malware_family": None, "confidence": None, "status": None,
                              "reporter": w["reporter"],
                              "corroborated": w["corroborated"].astype("boolean") if exclusive.exists() else None,
                              "raw": _raw_records(w, TW_COLS)})
    raise ValueError(f"source has no sightings: {source}")
