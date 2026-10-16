"""Cargadores de fuentes evaluadas y DESCARTADAS del núcleo de VeriThreat.

Se conservan por si se reconsidera su uso; ninguna pieza del flujo principal depende de este módulo.
- MalwareBazaar: solo hashes (1.383 muestras en 2 días), sin uso en el modelo y sin validar; el valor añadido
  (vincular md5/sha1/sha256 y atributos de fichero) no compensa la complejidad de su formato.
- ThreatCluster: 607 dominios y 862 hashes (≈1,7 % de los indicadores), solape casi nulo, confianza constante
  y extracción automática con falsos positivos.
"""
import io

import pandas as pd

MB_COLS = ["first_seen_utc", "sha256_hash", "md5_hash", "sha1_hash", "reporter", "file_name",
           "file_type_guess", "mime_type", "signature", "clamav", "vtpercent", "imphash", "ssdeep", "tlsh"]


def _strip_comments(path) -> io.StringIO:
    """Quita las líneas que EMPIEZAN por '#' (no un '#' dentro de un campo)."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return io.StringIO("".join(l for l in f if not l.lstrip().startswith("#")))


def load_malwarebazaar(path) -> pd.DataFrame:
    df = pd.read_csv(_strip_comments(path), header=None, names=MB_COLS, skipinitialspace=True, quotechar='"')
    df["first_seen_utc"] = pd.to_datetime(df["first_seen_utc"], utc=True, errors="coerce")
    return df  # "n/a" ya se interpreta como NaN; clamav y vtpercent llegan vacías


def load_threatcluster(path) -> pd.DataFrame:
    df = pd.read_csv(path)
    for c in ("first_seen", "last_seen"):
        df[c] = pd.to_datetime(df[c], utc=True, errors="coerce")
    df["source_names"] = df["sources"].fillna("").str.split("|").apply(lambda l: [x.rsplit(":", 1)[0] for x in l if x])
    return df
