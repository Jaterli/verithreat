import requests
from pathlib import Path
import os

AUTH_KEY = os.environ.get("AUTH_KEY")

DATA_DIR = Path("../data/raw")
DATA_DIR.mkdir(parents=True, exist_ok=True)

url = f"https://urlhaus-api.abuse.ch/v2/files/exports/{AUTH_KEY}/recent.csv"
resp = requests.get(url, timeout=60)
resp.raise_for_status()

with open(DATA_DIR / "urlhaus.csv", "wb") as f:
    f.write(resp.content)
print("Descargado:", (DATA_DIR / "urlhaus.csv").stat().st_size, "bytes")