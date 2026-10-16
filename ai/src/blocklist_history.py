#!/usr/bin/env python3
"""Histórico de IPs de blocklist.de para VeriThreat.

Cada ejecución (pensada para lanzarse cada hora, p. ej. con cron):
  1. Descarga all.txt y las listas por servicio (últimas 48 h, regeneradas cada 30 min por blocklist.de).
  2. Actualiza un histórico propio (un CSV, una fila por IP) con primera y última vez vista, servicios y subtipos.
  3. Opcional (--dns): consulta el DNS bl.blocklist.de solo de las IPs nuevas o con datos viejos, para obtener el
     servicio y la fecha REAL del último ataque (Last-Attack).
  4. Opcional (--api): consulta api.php con start=1 solo de las IPs nuevas, para los contadores históricos
     attacks y reports. Desactivado por defecto: primero conviene comprobar con VirusTotal si aporta algo.

Uso:
    python blocklist_history.py                          # listas + histórico
    python blocklist_history.py --dns --max-dns 2000     # además, DNS para IPs nuevas (necesita dnspython)
    python blocklist_history.py --verify 50 --verify-only   # comprueba el DNS con una muestra y sale

Notas:
  - Las listas se ofrecen «tal cual y bajo tu propio riesgo». No se descargan más de una vez cada 30 min.
  - Los términos de uso de blocklist.de no se han revisado aquí.
  - Muchos DNSBL rechazan consultas que llegan por resolvedores públicos grandes: si --dns falla, usa --resolver con
    tu propio resolvedor.
  - La consulta DNS por IPv6 no está documentada: esas IPs quedan con dns_status = IPV6_UNSUPPORTED.
  - all.txt incluye BLOQUES /24 COMPLETOS (256 IPs seguidas) que no son ataques individuales (en una lista de 24.714 IPs
    había 30 bloques, el 32 % del IPv4). No tienen registro DNS propio: se marcan como entry_type = block y no se
    consultan por DNS. Umbral: --block-threshold (por defecto 250 IPs del mismo /24).
"""
import argparse
import csv
import ipaddress
import os
import re
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

LISTS_URL = "https://lists.blocklist.de/lists/{name}.txt"
SERVICES = ["ssh", "mail", "apache", "imap", "ftp", "sip", "bots", "bruteforcelogin", "strongips"]
WINDOW_S = 172_800  # las listas contienen las IPs que atacaron en las últimas 48 h
DNS_ZONE = "bl.blocklist.de"
API_URL = "https://api.blocklist.de/api.php"
UA = {"User-Agent": "VeriThreat-research/1.0 (MSc thesis; reading public lists)"}

COLS = ["ip", "first_seen_utc", "last_seen_utc", "in_latest_list", "n_polls", "services", "subtypes", "strongips",
        "entry_type", "block", "window_s", "dns_status", "dns_last_attack_utc", "dns_services", "dns_txt_raw",
        "dns_queried_utc", "api_status", "attacks", "reports", "api_queried_utc"]

# Subtipo de la categoría «attack_source». Nombres de listas y códigos del DNS (según su documentación).
SUBTYPE = {
    "ssh": "auth", "ftp": "auth", "imap": "auth", "pop3": "auth", "sasl": "auth", "mail": "auth", "amavis": "auth",
    "asterisk": "auth", "sip": "auth", "webmin": "auth", "mysql": "auth",
    "apache": "web", "apacheddos": "web", "w00tw00t": "web", "rfi-attack": "web", "sql-injection": "web",
    "bruteforcelogin": "web",
    "bots": "bots", "ircbot": "bots", "regbot": "bots", "badbot": "bots",
    "portflood": "other", "trigger-spam": "other", "manuall": "other",
}
# Código final de la respuesta A (127.0.0.N) -> servicio, según la documentación del DNS de blocklist.de
A_CODES = {2: "amavis", 3: "apacheddos", 4: "asterisk", 5: "badbot", 6: "ftp", 7: "imap", 8: "ircbot", 9: "mail",
           10: "pop3", 11: "regbot", 12: "rfi-attack", 13: "sasl", 14: "ssh", 15: "w00tw00t", 16: "portflood",
           17: "sql-injection", 18: "webmin", 19: "trigger-spam", 20: "manuall", 21: "bruteforcelogin", 22: "mysql"}
# Equivalencia aproximada código DNS -> lista, solo para la verificación (heurística, no documentada)
DNS_TO_LIST = {"ssh": "ssh", "ftp": "ftp", "imap": "imap", "pop3": "imap", "sasl": "imap", "mail": "mail", "amavis": "mail",
               "apacheddos": "apache", "w00tw00t": "apache", "rfi-attack": "apache", "sql-injection": "apache",
               "asterisk": "sip", "badbot": "bots", "regbot": "bots", "ircbot": "bots", "bruteforcelogin": "bruteforcelogin"}
RETRYABLE_DNS = ("OK", "OK_NO_DATE", "TIMEOUT", "NOT_LISTED", "NO_TXT")


# ----------------------------------------------------------------------------- utilidades
def now() -> datetime:
    return datetime.now(timezone.utc)


def fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def parse_fmt(s: str):
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def normalize_ip(s: str):
    try:
        return ipaddress.ip_address(s.strip()).compressed
    except ValueError:
        return None


def with_retries(action, retries=4, base=5):
    """Ejecuta action() reintentando con espera creciente. Devuelve el resultado o lanza la última excepción."""
    last = None
    for i in range(retries + 1):
        try:
            return action()
        except (requests.RequestException, OSError) as e:
            resp = getattr(e, "response", None)
            if resp is not None and 400 <= resp.status_code < 500 and resp.status_code != 429:
                raise  # un 404 o 403 no se arregla reintentando
            last = e
            time.sleep(min(120, base * 2 ** i))
    raise last


# ----------------------------------------------------------------------------- bloques completos
def detect_blocks(ips, threshold=250) -> dict:
    """{ip: '<a.b.c.0/24>'} para las IPv4 que pertenecen a un /24 con >= threshold IPs listadas (listados en bloque)."""
    by_24 = {}
    for ip in ips:
        if ":" not in ip:
            by_24.setdefault(ip.rsplit(".", 1)[0], []).append(ip)
    return {ip: f"{p}.0/24" for p, members in by_24.items() if len(members) >= threshold for ip in members}


# ----------------------------------------------------------------------------- listas
def download_list(session, name: str) -> set:
    def fetch():
        r = session.get(LISTS_URL.format(name=name), timeout=60)
        r.raise_for_status()
        return r.text
    text = with_retries(fetch)
    ips = set()
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            ip = normalize_ip(line)
            if ip:
                ips.add(ip)
    return ips


def download_all(session, services):
    """Devuelve (all_ips, {servicio: set}, avisos). Si falla all.txt se aborta; si falla un servicio, se avisa."""
    all_ips = download_list(session, "all")
    if not all_ips:
        raise RuntimeError("all.txt is empty: aborting so as not to corrupt the history")
    by_service, warnings = {}, []
    for s in services:
        try:
            by_service[s] = download_list(session, s)
        except requests.RequestException as e:
            warnings.append(f"{s}: {type(e).__name__}")
    return all_ips, by_service, warnings


# ----------------------------------------------------------------------------- histórico
def load_history(path: Path) -> dict:
    if not path.exists():
        return {}
    with open(path, newline="", encoding="utf-8") as f:
        return {row["ip"]: row for row in csv.DictReader(f)}


def save_history(path: Path, hist: dict) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent or "."), suffix=".tmp")
    with os.fdopen(fd, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLS, extrasaction="ignore")
        w.writeheader()
        for ip in sorted(hist):
            w.writerow(hist[ip])
    os.replace(tmp, path)


def _union(current: str, new) -> str:
    return "|".join(sorted(set(filter(None, (current or "").split("|"))) | set(new)))


def update_history(hist: dict, all_ips: set, by_service: dict, t: datetime, blocks: dict = None) -> dict:
    """Actualiza el histórico con un sondeo. Devuelve estadísticas del sondeo."""
    now_s = fmt(t)
    blocks = blocks or {}
    new = 0
    for row in hist.values():
        row["in_latest_list"] = "False"
    for ip in all_ips:
        row = hist.get(ip)
        if row is None:
            row = {c: "" for c in COLS}
            row.update({"ip": ip, "first_seen_utc": now_s, "n_polls": "0", "strongips": "False"})
            hist[ip] = row
            new += 1
        row["last_seen_utc"] = now_s
        row["in_latest_list"] = "True"
        row["n_polls"] = str(int(row["n_polls"] or 0) + 1)
        row["window_s"] = str(WINDOW_S)
        row["block"] = blocks.get(ip, "")
        row["entry_type"] = "block" if ip in blocks else "individual"
        services = [s for s, ips in by_service.items() if ip in ips and s != "strongips"]
        row["services"] = _union(row["services"], services)
        row["subtypes"] = _union(row["subtypes"], [SUBTYPE[s] for s in services if s in SUBTYPE])
        if ip in by_service.get("strongips", ()):
            row["strongips"] = "True"
    return {"listed": len(all_ips), "new": new, "history": len(hist),
            "in_blocks": len(blocks), "blocks": len(set(blocks.values()))}


# ----------------------------------------------------------------------------- DNS
def make_resolver(server=None, timeout=5):
    import dns.resolver
    r = dns.resolver.Resolver()
    r.lifetime = timeout
    r.timeout = timeout
    if server:
        r.nameservers = [server]
    return r


def dns_query(resolver, ip: str) -> dict:
    """TXT de <ip invertida>.bl.blocklist.de -> {status, last_attack, services}."""
    import dns.exception
    import dns.resolver
    if ":" in ip:
        return {"status": "IPV6_UNSUPPORTED"}
    name = ".".join(reversed(ip.split("."))) + "." + DNS_ZONE
    try:
        answer = resolver.resolve(name, "TXT")
    except dns.resolver.NXDOMAIN:
        return {"status": "NOT_LISTED"}
    except dns.resolver.NoAnswer:
        return {"status": "NO_TXT"}
    except dns.exception.Timeout:
        return {"status": "TIMEOUT"}
    except dns.exception.DNSException as e:
        return {"status": f"DNS_ERR_{type(e).__name__}"}
    attacks, services, raw_parts = [], set(), []
    for rdata in answer:
        text = b"".join(rdata.strings).decode("utf-8", errors="replace")
        raw_parts.append(text)
        found = False
        for svc_list, ts in re.findall(r"Service:\s*([^()]*?)\s*,?\s*Last-Attack:\s*(\d+)", text):
            services |= {x.lower() for x in re.split(r"[,\s]+", svc_list) if x}
            attacks.append(int(ts))
            found = True
        if not found:  # servicio sin fecha, o formato desconocido
            for svc_list in re.findall(r"Service:\s*([^,()]+)", text):
                services |= {x.lower() for x in re.split(r"[,\s]+", svc_list.strip()) if x}
    raw = " || ".join(raw_parts)[:300]
    if attacks:
        return {"status": "OK", "last_attack": datetime.fromtimestamp(max(attacks), timezone.utc), "services": services, "raw": raw}
    # TXT genérico («Infected System, see ...»): el servicio puede venir en el registro A (127.0.0.N)
    try:
        for rdata in resolver.resolve(name, "A"):
            code = int(str(rdata).split(".")[-1])
            if code in A_CODES:
                services.add(A_CODES[code])
    except (dns.exception.DNSException, ValueError):
        pass
    if services:
        return {"status": "OK_NO_DATE", "services": services, "raw": raw}
    return {"status": "TXT_UNRECOGNIZED", "raw": raw}


def enrich_dns(hist: dict, resolver, max_n: int, pause: float, refresh_h: float, t: datetime,
               include_blocks: bool = False) -> dict:
    def pending(row):
        if row["in_latest_list"] != "True" or ":" in row["ip"]:
            return False
        if row.get("entry_type") == "block" and not include_blocks:
            return False
        if not row["dns_status"] or (include_blocks and row["dns_status"] == "BLOCK_NOT_QUERIED"):
            return True
        previous = parse_fmt(row["dns_queried_utc"])
        retryable = row["dns_status"] in RETRYABLE_DNS or row["dns_status"].startswith("DNS_ERR")
        return retryable and previous is not None and (t - previous).total_seconds() > refresh_h * 3600

    for r in hist.values():
        if ":" in r["ip"] and not r["dns_status"]:
            r["dns_status"] = "IPV6_UNSUPPORTED"
        elif r.get("entry_type") == "block" and not include_blocks and not r["dns_status"]:
            r["dns_status"] = "BLOCK_NOT_QUERIED"
    queue = [r for r in hist.values() if pending(r)]
    queue.sort(key=lambda r: (r["dns_status"] != "", r["first_seen_utc"]), reverse=False)
    queue = queue[:max_n] if max_n else queue
    statuses = {}
    for i, row in enumerate(queue, 1):
        r = dns_query(resolver, row["ip"])
        row["dns_status"] = r["status"]
        row["dns_queried_utc"] = fmt(now())
        if r["status"] in ("OK", "OK_NO_DATE"):
            if r["status"] == "OK":
                row["dns_last_attack_utc"] = fmt(r["last_attack"])
            row["dns_services"] = "|".join(sorted(r["services"]))
            row["subtypes"] = _union(row["subtypes"], [SUBTYPE[s] for s in r["services"] if s in SUBTYPE])
        if r["status"] != "OK":
            row["dns_txt_raw"] = r.get("raw", "")
        statuses[r["status"]] = statuses.get(r["status"], 0) + 1
        print(f"  DNS [{i}/{len(queue)}] {row['ip']:40} {r['status']}", end="\r")
        if pause and i < len(queue):
            time.sleep(pause)
    if queue:
        print()
    return statuses


# ----------------------------------------------------------------------------- api.php (opcional)
def enrich_api(hist: dict, session, max_n: int, pause: float) -> dict:
    queue = [r for r in hist.values() if r["in_latest_list"] == "True" and r["api_status"] != "OK"]
    queue = queue[:max_n] if max_n else queue
    statuses = {}
    for i, row in enumerate(queue, 1):
        try:
            r = with_retries(lambda: session.get(API_URL, params={"ip": row["ip"], "start": 1, "format": "json"}, timeout=30),
                             retries=2)
            if r.status_code == 200:
                data = r.json()
                row["attacks"], row["reports"] = str(data.get("attacks", "")), str(data.get("reports", ""))
                row["api_status"] = "OK"
            else:
                row["api_status"] = f"HTTP_{r.status_code}"
        except (requests.RequestException, ValueError) as e:
            row["api_status"] = f"ERR_{type(e).__name__}"
        row["api_queried_utc"] = fmt(now())
        statuses[row["api_status"]] = statuses.get(row["api_status"], 0) + 1
        print(f"  API [{i}/{len(queue)}] {row['ip']:40} {row['api_status']}", end="\r")
        if pause and i < len(queue):
            time.sleep(pause)
    if queue:
        print()
    return statuses


# ----------------------------------------------------------------------------- verificación
def verify(all_ips: set, by_service: dict, resolver, n: int, t: datetime, seed=42, threshold=250) -> None:
    """Compara una muestra de IPs de all.txt con el DNS, separando IPs individuales y listadas en bloque:
    ¿el Last-Attack cae en 48 h? ¿el servicio coincide con las listas? Imprime los casos que no encajan."""
    import random
    blocks = detect_blocks(all_ips, threshold)
    ipv4 = sorted(ip for ip in all_ips if ":" not in ip)
    sample = random.Random(seed).sample(ipv4, min(n, len(ipv4)))
    print(f"Full /24 blocks in all.txt: {len(set(blocks.values()))} ({len(blocks):,} IPs, "
          f"{len(blocks) / len(all_ips):.0%} of the list)")
    statuses = {"individual": {}, "block": {}}
    ages, matches, with_service = [], 0, 0
    odd = []
    for ip in sample:
        r = dns_query(resolver, ip)
        kind = "block" if ip in blocks else "individual"
        statuses[kind][r["status"]] = statuses[kind].get(r["status"], 0) + 1
        lists = sorted(s for s, ips in by_service.items() if ip in ips and s != "strongips")
        if kind == "individual" and r["status"] not in ("OK",):
            odd.append((ip, r["status"], lists, r.get("raw", "")))
        if r["status"] == "OK":
            ages.append((t - r["last_attack"]).total_seconds() / 3600)
            equiv = {DNS_TO_LIST[s] for s in r["services"] if s in DNS_TO_LIST}
            if equiv:
                with_service += 1
                matches += bool(equiv & set(lists))
        time.sleep(0.05)
    print(f"DNS check on {len(sample)} IPs from all.txt (seed {seed}):")
    for kind in ("individual", "block"):
        print(f"  {kind:10s} ({sum(statuses[kind].values()):3d} IPs): {statuses[kind]}")
    if ages:
        ages.sort()
        within = sum(e <= 48 + 1 for e in ages) / len(ages)
        print(f"  Last-Attack: median {ages[len(ages) // 2]:.1f} h | within 48 h (+1 h margin): {within:.0%} "
              f"| max {ages[-1]:.1f} h")
    if with_service:
        print(f"  The TXT service matches one of the IP's lists: {matches}/{with_service} ({matches / with_service:.0%})")
    if odd:
        print("  INDIVIDUAL IPs without Last-Attack (to review):")
        for ip, status, lists, raw in odd[:10]:
            print(f"    {ip:18} {status:18} lists: {','.join(lists) or '(all only)'} | {raw!r}")


# ----------------------------------------------------------------------------- main
def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--history", type=Path, default=Path("blocklist_history.csv"))
    p.add_argument("--services", nargs="+", default=SERVICES)
    p.add_argument("--dns", action="store_true", help="query the bl.blocklist.de DNS for new IPs or IPs with stale data")
    p.add_argument("--max-dns", type=int, default=2000, help="cap of DNS queries per run (0 = no cap)")
    p.add_argument("--dns-pause", type=float, default=0.05)
    p.add_argument("--dns-refresh-hours", type=float, default=72.0, help="query the DNS again if the data is older than N hours")
    p.add_argument("--block-threshold", type=int, default=250, help="IPs of the same /24 from which it counts as a fully listed block")
    p.add_argument("--dns-blocks", action="store_true", help="also query the DNS for IPs listed in blocks (they rarely have a record)")
    p.add_argument("--resolver", default=None, help="IP of your own DNS resolver (default: the system one)")
    p.add_argument("--api", action="store_true", help="query api.php (start=1) for new IPs")
    p.add_argument("--max-api", type=int, default=500)
    p.add_argument("--api-pause", type=float, default=0.5)
    p.add_argument("--verify", type=int, default=0, metavar="N", help="check the DNS with a sample of N IPs")
    p.add_argument("--seed", type=int, default=42, help="seed of the --verify sample (change it to repeat with another one)")
    p.add_argument("--verify-only", action="store_true", help="do not touch the history")
    a = p.parse_args()

    session = requests.Session()
    session.headers.update(UA)
    t = now()
    try:
        all_ips, by_service, warnings = download_all(session, a.services)
    except (RuntimeError, requests.RequestException) as e:
        sys.exit(f"Could not download the lists: {e}")
    print(f"all.txt: {len(all_ips):,} IPs | services downloaded: {len(by_service)}"
          + (f" | WARNINGS: {warnings}" if warnings else ""))

    resolver = None
    if a.dns or a.verify:
        try:
            resolver = make_resolver(a.resolver)
        except ImportError:
            sys.exit("Missing dnspython: pip install dnspython")
    if a.verify:
        verify(all_ips, by_service, resolver, a.verify, t, a.seed, a.block_threshold)
        if a.verify_only:
            return

    hist = load_history(a.history)
    stats = update_history(hist, all_ips, by_service, t, detect_blocks(all_ips, a.block_threshold))
    print(f"Poll: {stats['listed']:,} listed ({stats['in_blocks']:,} in {stats['blocks']} full /24 blocks), "
          f"{stats['new']:,} new, history of {stats['history']:,} IPs")
    if a.dns:
        print("DNS:", enrich_dns(hist, resolver, a.max_dns, a.dns_pause, a.dns_refresh_hours, t, a.dns_blocks) or "nothing pending")
    if a.api:
        print("API:", enrich_api(hist, session, a.max_api, a.api_pause) or "nothing pending")
    save_history(a.history, hist)
    print(f"History saved to {a.history}")


if __name__ == "__main__":
    main()
