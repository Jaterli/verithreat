import argparse
import csv
from datetime import datetime, timezone
import os
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def crear_sesion_https(retries=3, backoff_factor=1.0):
  """Crea una sesión HTTP/HTTPS con estrategia de reintentos automáticos."""
  session = requests.Session()
  retry_strategy = Retry(
      total=retries,
      backoff_factor=backoff_factor,
      status_forcelist=[
          429,
          500,
          502,
          503,
          504,
      ],  # Reintenta ante límites de tasa y errores de servidor
      allowed_methods=["GET"],
  )
  adapter = HTTPAdapter(max_retries=retry_strategy)
  session.mount("https://", adapter)
  session.mount("http://", adapter)
  return session

def cargar_estado_historico(archivo_csv):
  """Carga el historial de IPs almacenado en el archivo CSV si existe."""
  historico = {}
  if not os.path.exists(archivo_csv):
    return historico

  with open(archivo_csv, mode="r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
      ip = row.get("ip")
      if ip:
        historico[ip] = {
            "ip": ip,
            "first_seen_utc": row.get("first_seen_utc", ""),
            "last_seen_utc": row.get("last_seen_utc", ""),
            "attacks": int(row["attacks"]) if row.get("attacks", "").isdigit() else "",
            "reports": int(row["reports"]) if row.get("reports", "").isdigit() else "",
            "status": row.get("status", "UNKNOWN"),
            "window_s": row.get("window_s", ""),
        }
  return historico

def guardar_estado_historico(archivo_csv, historico):
  """Escribe el estado actualizado de todas las IPs en el CSV manteniendo columnas numéricas limpias."""
  fieldnames = [
      "ip",
      "first_seen_utc",
      "last_seen_utc",
      "attacks",
      "reports",
      "status",
      "window_s",
  ]

  with open(archivo_csv, mode="w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for registro in historico.values():
      writer.writerow(registro)

def descargar_lista_masiva(session, usar_lista_completa=False, window_s="3600"):
  """Obtiene el listado masivo de IPs de blocklist.de vía HTTPS."""
  if usar_lista_completa:
    url = "https://lists.blocklist.de/lists/all.txt"
    print("[*] Descargando lista global completa de 48 horas (all.txt)...")
    response = session.get(url, timeout=20)
  else:
    url = "https://api.blocklist.de/getlast.php"
    print(f"[*] Descargando lista de los últimos {window_s} segundos vía HTTPS...")
    response = session.get(url, params={"time": str(window_s)}, timeout=20)

  response.raise_for_status()
  ips = [
      linea.strip()
      for linea in response.text.strip().splitlines()
      if linea.strip() and not linea.startswith("#")
  ]
  return ips

def consultar_detalle_ip(session, ip):
  """Consulta los detalles de una IP específica mediante api.php vía HTTPS."""
  url = "https://api.blocklist.de/api.php"
  params = {"ip": ip, "start": 1, "format": "json"}

  try:
    res = session.get(url, params=params, timeout=10)
    if res.status_code == 200:
      data = res.json()
      attacks = data.get("attacks")
      reports = data.get("reports")

      # Convertir a entero si el dato devuelto es válido
      attacks_val = int(attacks) if attacks is not None else ""
      reports_val = int(reports) if reports is not None else ""

      return attacks_val, reports_val, "SUCCESS"
    else:
      return "", "", f"HTTP_{res.status_code}"
  except requests.exceptions.Timeout:
    return "", "", "TIMEOUT"
  except Exception as e:
    return "", "", f"ERROR_{type(e).__name__}"

def procesar_ingesta_hibrida(
    archivo_csv="blocklist_historico.csv",
    window_s="3600",
    usar_lista_completa=False,
    limite_nuevas=None,
    pausa=0.0,
):
  session = crear_sesion_https()
  now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

  # 1. Cargar historial local para no duplicar consultas
  historico = cargar_estado_historico(archivo_csv)
  print(f"[✓] Historial cargado: {len(historico)} registro(s) existente(s).")

  # 2. Descargar la lista masiva actual
  try:
    ips_masivas = descargar_lista_masiva(
        session, usar_lista_completa=usar_lista_completa, window_s=window_s
    )
    print(f"[✓] Se obtuvieron {len(ips_masivas)} IP(s) de la lista masiva.")
  except Exception as e:
    print(f"[-] Error al descargar la lista masiva HTTPS: {e}")
    return

  ips_nuevas = []

  # 3. Clasificar IPs entre conocidas y nuevas
  for ip in ips_masivas:
    if ip in historico:
      # Si la IP ya existe, actualizamos su última vista sin consumir la API de detalle
      historico[ip]["last_seen_utc"] = now_utc
      if historico[ip]["status"] != "SUCCESS":
        ips_nuevas.append(ip)  # Reintentar si quedó pendiente o con error previo
    else:
      # Registro de una nueva IP detectada
      historico[ip] = {
          "ip": ip,
          "first_seen_utc": now_utc,
          "last_seen_utc": now_utc,
          "attacks": "",
          "reports": "",
          "status": "PENDING",
          "window_s": str(window_s) if not usar_lista_completa else "172800",
      }
      ips_nuevas.append(ip)

  print(f"[*] IPs nuevas o pendientes de detalle API: {len(ips_nuevas)}")

  if limite_nuevas and limite_nuevas > 0:
    ips_nuevas = ips_nuevas[:limite_nuevas]
    print(f"[*] Procesando muestra limitada a {len(ips_nuevas)} IP(s) nuevas.")

  # 4. Consultar api.php únicamente para las IPs nuevas/pendientes
  for index, ip in enumerate(ips_nuevas, 1):
    attacks, reports, status = consultar_detalle_ip(session, ip)

    historico[ip]["attacks"] = attacks
    historico[ip]["reports"] = reports
    historico[ip]["status"] = status

    print(
        f"[{index}/{len(ips_nuevas)}] IP: {ip:<15} | Estado: {status:<10} |"
        f" Ataques: {str(attacks):<5} | Reportes: {str(reports):<5}"
    )

    # Autoguardado periódico para permitir reanudación si el proceso se cancela
    if index % 20 == 0:
      guardar_estado_historico(archivo_csv, historico)

    if pausa > 0 and index < len(ips_nuevas):
      time.sleep(pausa)

  # 5. Guardado final del estado
  guardar_estado_historico(archivo_csv, historico)
  print(
      f"\n[✓] Ingesta completada con éxito. Datos preservados en:"
      f" '{archivo_csv}'"
  )

if __name__ == "__main__":
  parser = argparse.ArgumentParser(
      description=(
          "Ingesta híbrida e incremental de blocklist.de vía HTTPS con soporte"
          " de reanudación e historial."
      )
  )
  parser.add_argument(
      "--window",
      "-w",
      default="3600",
      help=(
          "Ventana de tiempo en segundos para getlast.php (por defecto: 3600 = 1h)."
      ),
  )
  parser.add_argument(
      "--all-list",
      "-a",
      action="store_true",
      help=(
          "Descargar la lista completa global de 48 horas"
          " (https://lists.blocklist.de/lists/all.txt)."
      ),
  )
  parser.add_argument(
      "--output",
      "-o",
      default="blocklist_historico.csv",
      help="Ruta del CSV de histórico (por defecto: blocklist_historico.csv).",
  )
  parser.add_argument(
      "--limit",
      "-l",
      type=int,
      default=None,
      help="Límite máximo de IPs nuevas a consultar en api.php.",
  )
  parser.add_argument(
      "--delay",
      "-d",
      type=float,
      default=0.1,
      help="Pausa en segundos entre peticiones a la API (por defecto: 0.2s).",
  )

  args = parser.parse_args()

  procesar_ingesta_hibrida(
      archivo_csv=args.output,
      window_s=args.window,
      usar_lista_completa=args.all_list,
      limite_nuevas=args.limit,
      pausa=args.delay,
  )
