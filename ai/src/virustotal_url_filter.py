import argparse
import base64
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
        "Enriquece URLs con reputación y timestamps desde VirusTotal v3."
    )
)
parser.add_argument(
    "--apikey",
    default=ENV_API_KEY,
    help="API Key de VirusTotal (por defecto se lee del .env)",
)
parser.add_argument(
    "--input",
    default="urls.txt",
    help="Archivo de entrada con las URLs (por defecto: urls.txt)",
)
parser.add_argument(
    "--output",
    default="reporte_urls_vt.csv",
    help="Archivo CSV de salida (por defecto: reporte_urls_vt.csv)",
)
parser.add_argument(
    "--limit",
    "-l",
    type=int,
    default=None,
    help="Número máximo de URLs a analizar",
)

args = parser.parse_args()

if not args.apikey:
  print("[-] Error: No se ha proporcionado una API Key válida.")
  exit(1)

headers = {"x-apikey": args.apikey}


def get_url_id(url: str) -> str:
  """Genera el ID en Base64 sin '=' requerido por VirusTotal v3 para URLs."""
  return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


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
    urls = [line.strip() for line in file if line.strip()]
except FileNotFoundError:
  print(f"[-] Error: Archivo '{args.input}' no encontrado.")
  exit(1)

if args.limit and args.limit > 0:
  urls = urls[: args.limit]

print(f"[*] Iniciando análisis de {len(urls)} URL(s)...")

with open(args.output, mode="w", newline="", encoding="utf-8") as csv_file:
  writer = csv.writer(csv_file)

  # Cabecera estándar (Standard IOC alignment)
  writer.writerow([
      "url",
      "reputation",
      "malicious",
      "suspicious",
      "harmless",
      "undetected",
      "first_reported_at",
      "last_analysis_at",
  ])

  for index, target_url in enumerate(urls, 1):
    print(f"[{index}/{len(urls)}] Procesando URL: {target_url}...")

    # Se genera el identificador URL en Base64
    url_id = get_url_id(target_url)
    api_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    response = requests.get(api_endpoint, headers=headers)

    if response.status_code == 200:
      attributes = response.json()["data"]["attributes"]

      stats = attributes.get("last_analysis_stats", {})
      malicious = stats.get("malicious", 0)
      suspicious = stats.get("suspicious", 0)
      harmless = stats.get("harmless", 0)
      undetected = stats.get("undetected", 0)

      reputation = attributes.get("reputation", 0)

      # Extracción de timestamps Unix
      first_reported_ts = attributes.get("first_submission_date")
      last_analysis_ts = attributes.get("last_analysis_date")

      first_reported_at = format_timestamp(first_reported_ts)
      last_analysis_at = format_timestamp(last_analysis_ts)

      writer.writerow([
          target_url,
          reputation,
          malicious,
          suspicious,
          harmless,
          undetected,
          first_reported_at,
          last_analysis_at,
      ])
      print("    [+] Guardado correctamente.")
    else:
      print(f"    [-] Error HTTP {response.status_code} en URL {target_url}")
      writer.writerow([
          target_url,
          "ERROR",
          "ERROR",
          "ERROR",
          "ERROR",
          "ERROR",
          "N/A",
          "N/A",
      ])

    # Pausa de 15 segundos para la cuota gratuita de VirusTotal (4 req/min)
    # if index < len(urls):
    #   time.sleep(15)

print(f"\n[✓] Proceso finalizado. CSV generado: '{args.output}'")