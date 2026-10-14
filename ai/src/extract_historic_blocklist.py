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
    python blocklist_historico.py                          # listas + histórico
    python blocklist_historico.py --dns --max-dns 2000     # además, DNS para IPs nuevas (necesita dnspython)
    python blocklist_historico.py --verificar 50 --solo-verificar   # comprueba el DNS con una muestra y sale

Notas:
  - Las listas se ofrecen «tal cual y bajo tu propio riesgo». No se descargan más de una vez cada 30 min.
  - Los términos de uso de blocklist.de no se han revisado aquí.
  - Muchos DNSBL rechazan consultas que llegan por resolvedores públicos grandes: si --dns falla, usa --resolver con
    tu propio resolvedor.
  - La consulta DNS por IPv6 no está documentada: esas IPs quedan con dns_status = IPV6_NO_SOPORTADO.
  - all.txt incluye BLOQUES /24 COMPLETOS (256 IPs seguidas) que no son ataques individuales (en una lista de 24.714 IPs
    había 30 bloques, el 32 % del IPv4). No tienen registro DNS propio: se marcan como tipo_entrada = bloque y no se
    consultan por DNS. Umbral: --umbral-bloque (por defecto 250 IPs del mismo /24).
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

LISTAS_URL = "https://lists.blocklist.de/lists/{nombre}.txt"
SERVICIOS = ["ssh", "mail", "apache", "imap", "ftp", "sip", "bots", "bruteforcelogin", "strongips"]
VENTANA_S = 172_800  # las listas contienen las IPs que atacaron en las últimas 48 h
DNS_ZONA = "bl.blocklist.de"
API_URL = "https://api.blocklist.de/api.php"
UA = {"User-Agent": "VeriThreat-research/1.0 (TFM; lectura de listas publicas)"}

COLS = ["ip", "first_seen_utc", "last_seen_utc", "en_ultima_lista", "n_sondeos", "services", "subtipos", "strongips", "tipo_entrada", "bloque",
        "window_s", "dns_status", "dns_last_attack_utc", "dns_services", "dns_txt_raw", "dns_consultado_utc",
        "api_status", "attacks", "reports", "api_consultado_utc"]

# Subtipo de la categoría «attack_source». Nombres de listas y códigos del DNS (según su documentación).
SUBTIPO = {
    "ssh": "auth", "ftp": "auth", "imap": "auth", "pop3": "auth", "sasl": "auth", "mail": "auth", "amavis": "auth",
    "asterisk": "auth", "sip": "auth", "webmin": "auth", "mysql": "auth",
    "apache": "web", "apacheddos": "web", "w00tw00t": "web", "rfi-attack": "web", "sql-injection": "web",
    "bruteforcelogin": "web",
    "bots": "bots", "ircbot": "bots", "regbot": "bots", "badbot": "bots",
    "portflood": "otros", "trigger-spam": "otros", "manuall": "otros",
}
# Código final de la respuesta A (127.0.0.N) -> servicio, según la documentación del DNS de blocklist.de
CODIGOS_A = {2: "amavis", 3: "apacheddos", 4: "asterisk", 5: "badbot", 6: "ftp", 7: "imap", 8: "ircbot", 9: "mail",
             10: "pop3", 11: "regbot", 12: "rfi-attack", 13: "sasl", 14: "ssh", 15: "w00tw00t", 16: "portflood",
             17: "sql-injection", 18: "webmin", 19: "trigger-spam", 20: "manuall", 21: "bruteforcelogin", 22: "mysql"}
# Equivalencia aproximada código DNS -> lista, solo para la verificación (heurística, no documentada)
DNS_A_LISTA = {"ssh": "ssh", "ftp": "ftp", "imap": "imap", "pop3": "imap", "sasl": "imap", "mail": "mail", "amavis": "mail",
               "apacheddos": "apache", "w00tw00t": "apache", "rfi-attack": "apache", "sql-injection": "apache",
               "asterisk": "sip", "badbot": "bots", "regbot": "bots", "ircbot": "bots", "bruteforcelogin": "bruteforcelogin"}


# ----------------------------------------------------------------------------- utilidades
def ahora() -> datetime:
    return datetime.now(timezone.utc)


def fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def parse_fmt(s: str):
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def normalizar_ip(s: str):
    try:
        return ipaddress.ip_address(s.strip()).compressed
    except ValueError:
        return None


def con_reintentos(accion, reintentos=4, base=5):
    """Ejecuta accion() reintentando con espera creciente. Devuelve el resultado o lanza la última excepción."""
    ultimo = None
    for i in range(reintentos + 1):
        try:
            return accion()
        except (requests.RequestException, OSError) as e:
            resp = getattr(e, "response", None)
            if resp is not None and 400 <= resp.status_code < 500 and resp.status_code != 429:
                raise  # un 404 o 403 no se arregla reintentando
            ultimo = e
            time.sleep(min(120, base * 2 ** i))
    raise ultimo


# ----------------------------------------------------------------------------- bloques completos
def detectar_bloques(ips, umbral=250) -> dict:
    """{ip: '<a.b.c.0/24>'} para las IPv4 que pertenecen a un /24 con >= umbral IPs listadas (listados en bloque)."""
    por_24 = {}
    for ip in ips:
        if ":" not in ip:
            por_24.setdefault(ip.rsplit(".", 1)[0], []).append(ip)
    return {ip: f"{p}.0/24" for p, lista in por_24.items() if len(lista) >= umbral for ip in lista}


# ----------------------------------------------------------------------------- listas
def descargar_lista(sesion, nombre: str) -> set:
    def pedir():
        r = sesion.get(LISTAS_URL.format(nombre=nombre), timeout=60)
        r.raise_for_status()
        return r.text
    texto = con_reintentos(pedir)
    ips = set()
    for linea in texto.splitlines():
        linea = linea.strip()
        if linea and not linea.startswith("#"):
            ip = normalizar_ip(linea)
            if ip:
                ips.add(ip)
    return ips


def descargar_todo(sesion, servicios):
    """Devuelve (all_ips, {servicio: set}, avisos). Si falla all.txt se aborta; si falla un servicio, se avisa."""
    all_ips = descargar_lista(sesion, "all")
    if not all_ips:
        raise RuntimeError("all.txt vacío: se aborta para no estropear el histórico")
    por_servicio, avisos = {}, []
    for s in servicios:
        try:
            por_servicio[s] = descargar_lista(sesion, s)
        except requests.RequestException as e:
            avisos.append(f"{s}: {type(e).__name__}")
    return all_ips, por_servicio, avisos


# ----------------------------------------------------------------------------- histórico
def cargar_historico(ruta: Path) -> dict:
    if not ruta.exists():
        return {}
    with open(ruta, newline="", encoding="utf-8") as f:
        return {fila["ip"]: fila for fila in csv.DictReader(f)}


def guardar_historico(ruta: Path, hist: dict) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(ruta.parent or "."), suffix=".tmp")
    with os.fdopen(fd, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLS, extrasaction="ignore")
        w.writeheader()
        for ip in sorted(hist):
            w.writerow(hist[ip])
    os.replace(tmp, ruta)


def _union(actual: str, nuevos) -> str:
    return "|".join(sorted(set(filter(None, (actual or "").split("|"))) | set(nuevos)))


def actualizar_historico(hist: dict, all_ips: set, por_servicio: dict, t: datetime, bloques: dict = None) -> dict:
    """Actualiza el histórico con un sondeo. Devuelve estadísticas del sondeo."""
    ahora_s = fmt(t)
    bloques = bloques or {}
    nuevas = 0
    for fila in hist.values():
        fila["en_ultima_lista"] = "False"
    for ip in all_ips:
        fila = hist.get(ip)
        if fila is None:
            fila = {c: "" for c in COLS}
            fila.update({"ip": ip, "first_seen_utc": ahora_s, "n_sondeos": "0", "strongips": "False"})
            hist[ip] = fila
            nuevas += 1
        fila["last_seen_utc"] = ahora_s
        fila["en_ultima_lista"] = "True"
        fila["n_sondeos"] = str(int(fila["n_sondeos"] or 0) + 1)
        fila["window_s"] = str(VENTANA_S)
        fila["bloque"] = bloques.get(ip, "")
        fila["tipo_entrada"] = "bloque" if ip in bloques else "individual"
        servicios = [s for s, ips in por_servicio.items() if ip in ips and s != "strongips"]
        fila["services"] = _union(fila["services"], servicios)
        fila["subtipos"] = _union(fila["subtipos"], [SUBTIPO[s] for s in servicios if s in SUBTIPO])
        if ip in por_servicio.get("strongips", ()):
            fila["strongips"] = "True"
    return {"listadas": len(all_ips), "nuevas": nuevas, "historico": len(hist),
            "en_bloque": len(bloques), "bloques": len(set(bloques.values()))}


# ----------------------------------------------------------------------------- DNS
def crear_resolver(servidor=None, timeout=5):
    import dns.resolver
    r = dns.resolver.Resolver()
    r.lifetime = timeout
    r.timeout = timeout
    if servidor:
        r.nameservers = [servidor]
    return r


def consulta_dns(resolver, ip: str) -> dict:
    """TXT de <ip invertida>.bl.blocklist.de -> {status, last_attack, services}."""
    import dns.exception
    import dns.resolver
    if ":" in ip:
        return {"status": "IPV6_NO_SOPORTADO"}
    nombre = ".".join(reversed(ip.split("."))) + "." + DNS_ZONA
    try:
        respuesta = resolver.resolve(nombre, "TXT")
    except dns.resolver.NXDOMAIN:
        return {"status": "NO_LISTADA"}
    except dns.resolver.NoAnswer:
        return {"status": "SIN_TXT"}
    except dns.exception.Timeout:
        return {"status": "TIMEOUT"}
    except dns.exception.DNSException as e:
        return {"status": f"DNS_ERR_{type(e).__name__}"}
    ataques, servicios, crudo = [], set(), []
    for rdata in respuesta:
        texto = b"".join(rdata.strings).decode("utf-8", errors="replace")
        crudo.append(texto)
        encontrado = False
        for lista, ts in re.findall(r"Service:\s*([^()]*?)\s*,?\s*Last-Attack:\s*(\d+)", texto):
            servicios |= {x.lower() for x in re.split(r"[,\s]+", lista) if x}
            ataques.append(int(ts))
            encontrado = True
        if not encontrado:  # servicio sin fecha, o formato desconocido
            for lista in re.findall(r"Service:\s*([^,()]+)", texto):
                servicios |= {x.lower() for x in re.split(r"[,\s]+", lista.strip()) if x}
    raw = " || ".join(crudo)[:300]
    if ataques:
        return {"status": "OK", "last_attack": datetime.fromtimestamp(max(ataques), timezone.utc), "services": servicios, "raw": raw}
    # TXT genérico («Infected System, see ...»): el servicio puede venir en el registro A (127.0.0.N)
    try:
        for rdata in resolver.resolve(nombre, "A"):
            codigo = int(str(rdata).split(".")[-1])
            if codigo in CODIGOS_A:
                servicios.add(CODIGOS_A[codigo])
    except (dns.exception.DNSException, ValueError):
        pass
    if servicios:
        return {"status": "OK_SIN_FECHA", "services": servicios, "raw": raw}
    return {"status": "TXT_NO_RECONOCIDO", "raw": raw}


def enriquecer_dns(hist: dict, resolver, max_n: int, pausa: float, refresco_h: float, t: datetime,
                   incluir_bloques: bool = False) -> dict:
    def pendiente(fila):
        if fila["en_ultima_lista"] != "True" or ":" in fila["ip"]:
            return False
        if fila.get("tipo_entrada") == "bloque" and not incluir_bloques:
            return False
        if not fila["dns_status"] or (incluir_bloques and fila["dns_status"] == "BLOQUE_NO_CONSULTADA"):
            return True
        previo = parse_fmt(fila["dns_consultado_utc"])
        reintentable = fila["dns_status"] in ("OK", "OK_SIN_FECHA", "TIMEOUT", "NO_LISTADA", "SIN_TXT") \
            or fila["dns_status"].startswith("DNS_ERR")
        return reintentable and previo is not None and (t - previo).total_seconds() > refresco_h * 3600

    for f in hist.values():
        if ":" in f["ip"] and not f["dns_status"]:
            f["dns_status"] = "IPV6_NO_SOPORTADO"
        elif f.get("tipo_entrada") == "bloque" and not incluir_bloques and not f["dns_status"]:
            f["dns_status"] = "BLOQUE_NO_CONSULTADA"
    cola = [f for f in hist.values() if pendiente(f)]
    cola.sort(key=lambda f: (f["dns_status"] != "", f["first_seen_utc"]), reverse=False)
    cola = cola[:max_n] if max_n else cola
    estados = {}
    for i, fila in enumerate(cola, 1):
        r = consulta_dns(resolver, fila["ip"])
        fila["dns_status"] = r["status"]
        fila["dns_consultado_utc"] = fmt(ahora())
        if r["status"] in ("OK", "OK_SIN_FECHA"):
            if r["status"] == "OK":
                fila["dns_last_attack_utc"] = fmt(r["last_attack"])
            fila["dns_services"] = "|".join(sorted(r["services"]))
            fila["subtipos"] = _union(fila["subtipos"], [SUBTIPO[s] for s in r["services"] if s in SUBTIPO])
        if r["status"] != "OK":
            fila["dns_txt_raw"] = r.get("raw", "")
        estados[r["status"]] = estados.get(r["status"], 0) + 1
        print(f"  DNS [{i}/{len(cola)}] {fila['ip']:40} {r['status']}", end="\r")
        if pausa and i < len(cola):
            time.sleep(pausa)
    if cola:
        print()
    return estados


# ----------------------------------------------------------------------------- api.php (opcional)
def enriquecer_api(hist: dict, sesion, max_n: int, pausa: float) -> dict:
    cola = [f for f in hist.values() if f["en_ultima_lista"] == "True" and f["api_status"] != "OK"]
    cola = cola[:max_n] if max_n else cola
    estados = {}
    for i, fila in enumerate(cola, 1):
        try:
            r = con_reintentos(lambda: sesion.get(API_URL, params={"ip": fila["ip"], "start": 1, "format": "json"}, timeout=30),
                               reintentos=2)
            if r.status_code == 200:
                datos = r.json()
                fila["attacks"], fila["reports"] = str(datos.get("attacks", "")), str(datos.get("reports", ""))
                fila["api_status"] = "OK"
            else:
                fila["api_status"] = f"HTTP_{r.status_code}"
        except (requests.RequestException, ValueError) as e:
            fila["api_status"] = f"ERR_{type(e).__name__}"
        fila["api_consultado_utc"] = fmt(ahora())
        estados[fila["api_status"]] = estados.get(fila["api_status"], 0) + 1
        print(f"  API [{i}/{len(cola)}] {fila['ip']:40} {fila['api_status']}", end="\r")
        if pausa and i < len(cola):
            time.sleep(pausa)
    if cola:
        print()
    return estados


# ----------------------------------------------------------------------------- verificación
def verificar(all_ips: set, por_servicio: dict, resolver, n: int, t: datetime, semilla=42, umbral=250) -> None:
    """Compara una muestra de IPs de all.txt con el DNS, separando IPs individuales y listadas en bloque:
    ¿el Last-Attack cae en 48 h? ¿el servicio coincide con las listas? Imprime los casos que no encajan."""
    import random
    bloques = detectar_bloques(all_ips, umbral)
    ipv4 = sorted(ip for ip in all_ips if ":" not in ip)
    muestra = random.Random(semilla).sample(ipv4, min(n, len(ipv4)))
    print(f"Bloques /24 completos en all.txt: {len(set(bloques.values()))} ({len(bloques):,} IPs, "
          f"{len(bloques) / len(all_ips):.0%} de la lista)")
    estados = {"individual": {}, "bloque": {}}
    edades, coincide, total_serv = [], 0, 0
    raros = []
    for ip in muestra:
        r = consulta_dns(resolver, ip)
        tipo = "bloque" if ip in bloques else "individual"
        estados[tipo][r["status"]] = estados[tipo].get(r["status"], 0) + 1
        listas = sorted(s for s, ips in por_servicio.items() if ip in ips and s != "strongips")
        if tipo == "individual" and r["status"] not in ("OK",):
            raros.append((ip, r["status"], listas, r.get("raw", "")))
        if r["status"] == "OK":
            edades.append((t - r["last_attack"]).total_seconds() / 3600)
            equiv = {DNS_A_LISTA[s] for s in r["services"] if s in DNS_A_LISTA}
            if equiv:
                total_serv += 1
                coincide += bool(equiv & set(listas))
        time.sleep(0.05)
    print(f"Verificación DNS sobre {len(muestra)} IPs de all.txt (semilla {semilla}):")
    for tipo in ("individual", "bloque"):
        print(f"  {tipo:10s} ({sum(estados[tipo].values()):3d} IPs): {estados[tipo]}")
    if edades:
        edades.sort()
        dentro = sum(e <= 48 + 1 for e in edades) / len(edades)
        print(f"  Last-Attack: mediana {edades[len(edades) // 2]:.1f} h | dentro de 48 h (+1 h de margen): {dentro:.0%} "
              f"| máximo {edades[-1]:.1f} h")
    if total_serv:
        print(f"  El servicio del TXT coincide con alguna lista de la IP: {coincide}/{total_serv} ({coincide / total_serv:.0%})")
    if raros:
        print("  IPs INDIVIDUALES sin Last-Attack (a revisar):")
        for ip, estado, listas, raw in raros[:10]:
            print(f"    {ip:18} {estado:18} listas: {','.join(listas) or '(solo all)'} | {raw!r}")


# ----------------------------------------------------------------------------- main
def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--historico", type=Path, default=Path("blocklist_historico.csv"))
    p.add_argument("--servicios", nargs="+", default=SERVICIOS)
    p.add_argument("--dns", action="store_true", help="consultar el DNS bl.blocklist.de de las IPs nuevas o con datos viejos")
    p.add_argument("--max-dns", type=int, default=2000, help="tope de consultas DNS por ejecución (0 = sin tope)")
    p.add_argument("--pausa-dns", type=float, default=0.05)
    p.add_argument("--dns-refresco-horas", type=float, default=72.0, help="reconsultar el DNS si el dato tiene más de N horas")
    p.add_argument("--umbral-bloque", type=int, default=250, help="IPs de un mismo /24 a partir de las cuales se considera un bloque listado entero")
    p.add_argument("--dns-bloques", action="store_true", help="consultar también el DNS de las IPs listadas en bloque (no suelen tener registro)")
    p.add_argument("--resolver", default=None, help="IP de un resolvedor DNS propio (por defecto, el del sistema)")
    p.add_argument("--api", action="store_true", help="consultar api.php (start=1) de las IPs nuevas")
    p.add_argument("--max-api", type=int, default=500)
    p.add_argument("--pausa-api", type=float, default=0.5)
    p.add_argument("--verificar", type=int, default=0, metavar="N", help="comprobar el DNS con una muestra de N IPs")
    p.add_argument("--semilla", type=int, default=42, help="semilla de la muestra de --verificar (cámbiala para repetir con otra)")
    p.add_argument("--solo-verificar", action="store_true", help="no tocar el histórico")
    a = p.parse_args()

    sesion = requests.Session()
    sesion.headers.update(UA)
    t = ahora()
    try:
        all_ips, por_servicio, avisos = descargar_todo(sesion, a.servicios)
    except (RuntimeError, requests.RequestException) as e:
        sys.exit(f"No se pudieron descargar las listas: {e}")
    print(f"all.txt: {len(all_ips):,} IPs | servicios descargados: {len(por_servicio)}"
          + (f" | AVISOS: {avisos}" if avisos else ""))

    resolver = None
    if a.dns or a.verificar:
        try:
            resolver = crear_resolver(a.resolver)
        except ImportError:
            sys.exit("Falta dnspython: pip install dnspython")
    if a.verificar:
        verificar(all_ips, por_servicio, resolver, a.verificar, t, a.semilla, a.umbral_bloque)
        if a.solo_verificar:
            return

    hist = cargar_historico(a.historico)
    stats = actualizar_historico(hist, all_ips, por_servicio, t, detectar_bloques(all_ips, a.umbral_bloque))
    print(f"Sondeo: {stats['listadas']:,} listadas ({stats['en_bloque']:,} en {stats['bloques']} bloques /24 completos), "
          f"{stats['nuevas']:,} nuevas, histórico de {stats['historico']:,} IPs")
    if a.dns:
        print("DNS:", enriquecer_dns(hist, resolver, a.max_dns, a.pausa_dns, a.dns_refresco_horas, t, a.dns_bloques) or "nada pendiente")
    if a.api:
        print("API:", enriquecer_api(hist, sesion, a.max_api, a.pausa_api) or "nada pendiente")
    guardar_historico(a.historico, hist)
    print(f"Histórico guardado en {a.historico}")


if __name__ == "__main__":
    main()