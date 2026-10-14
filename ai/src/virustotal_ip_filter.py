import argparse
import csv
from datetime import datetime, timezone
import os
import time
from dotenv import load_dotenv
import requests

# Cargar variables de entorno (.env)
load_dotenv()
ENV_API_KEY = os.environ.get("VT_API_KEY")

parser = argparse.ArgumentParser(
    description=(
        "Enriquece IPs con reputación y timestamps desde VirusTotal v3."
    )
)
parser.add_argument(
    "--apikey",
    default=ENV_API_KEY,
    help="API Key de VirusTotal (por defecto se lee del .env)",
)
parser.add_argument(
    "--input",
    default="../data/raw/blocklist.de/export-ips_all.txt",
    help="Archivo de entrada con IPs (por defecto: ips.txt)",
)
parser.add_argument(
    "--output",
    default="reporte_ips_vt.csv",
    help="Archivo CSV de salida (por defecto: reporte_ips_vt.csv)",
)
parser.add_argument(
    "--limit",
    "-l",
    type=int,
    default=None,
    help="Número máximo de IPs a analizar",
)

args = parser.parse_args()

if not args.apikey:
  print("[-] Error: No se ha proporcionado una API Key válida.")
  exit(1)

headers = {"x-apikey": args.apikey}


def format_timestamp(ts):
  """Convierte un timestamp Unix a una fecha ISO UTC comprensible."""
  if ts:
    return (
        datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    )
  return "N/A"


try:
  with open(args.input, "r", encoding="utf-8") as file:
    ips = [line.strip() for line in file if line.strip()]
except FileNotFoundError:
  print(f"[-] Error: Archivo '{args.input}' no encontrado.")
  exit(1)

if args.limit and args.limit > 0:
  ips = ips[: args.limit]

print(f"[*] Iniciando análisis de {len(ips)} IP(s)...")

with open(args.output, mode="w", newline="", encoding="utf-8") as csv_file:
  writer = csv.writer(csv_file)

  # Cabecera estándar (Standard IOC/STIX alignment)
  writer.writerow([
      "ip",
      "reputation",
      "malicious",
      "suspicious",
      "harmless",
      "undetected",
      "as_owner",
      "country",
      "first_reported_at",
      "last_analysis_at",
  ])

  for index, ip in enumerate(ips, 1):
    print(f"[{index}/{len(ips)}] Procesando IP: {ip}...")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
      attributes = response.json()["data"]["attributes"]

      stats = attributes.get("last_analysis_stats", {})
      malicious = stats.get("malicious", 0)
      suspicious = stats.get("suspicious", 0)
      harmless = stats.get("harmless", 0)
      undetected = stats.get("undetected", 0)

      reputation = attributes.get("reputation", 0)
      as_owner = attributes.get("as_owner", "N/A")
      country = attributes.get("country", "N/A")

      # Extracción de timestamps
      first_reported_ts = attributes.get("first_submission_date")
      last_analysis_ts = attributes.get("last_analysis_date")

      first_reported_at = format_timestamp(first_reported_ts)
      last_analysis_at = format_timestamp(last_analysis_ts)

      writer.writerow([
          ip,
          reputation,
          malicious,
          suspicious,
          harmless,
          undetected,
          as_owner,
          country,
          first_reported_at,
          last_analysis_at,
      ])
      print("    [+] Guardado correctamente.")
    else:
      print(f"    [-] Error HTTP {response.status_code} en IP {ip}")
      writer.writerow([
          ip,
          "ERROR",
          "ERROR",
          "ERROR",
          "ERROR",
          "ERROR",
          "N/A",
          "N/A",
          "N/A",
          "N/A",
      ])

    # Pausa de 15 segundos para la cuota gratuita (4 req/min)
    # if index < len(ips):
    #   time.sleep(1)

print(f"\n[✓] Proceso finalizado. CSV generado: '{args.output}'")