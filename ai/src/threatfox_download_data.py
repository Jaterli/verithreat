import os
import requests
import pandas as pd
from pathlib import Path
import os

AUTH_KEY = os.environ.get("AUTH_KEY")

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
RAW_DIR = Path("data/raw")
RAW_DIR.mkdir(parents=True, exist_ok=True)

def download_threatfox(days: int = 7):
    auth_key = AUTH_KEY
    if not auth_key:
        raise RuntimeError("Falta AUTH_KEY")
    resp = requests.post(
        THREATFOX_URL,
        headers={"Auth-Key": auth_key},
        json={"query": "get_iocs", "days": days},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json().get("data", [])
    df = pd.DataFrame(data)
    out = RAW_DIR / "threatfox.csv"
    df.to_csv(out, index=False)
    print(f"ThreatFox: {len(df)} IOCs guardados en {out}")
    return df

if __name__ == "__main__":
    download_threatfox(days=7)