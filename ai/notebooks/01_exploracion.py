# -*- coding: utf-8 -*-
"""
Converted from IPYNB to PY
"""

# %% [markdown] Cell 1
# # 01 - Análisis Exploratorio de IOCs
# 
# **Objetivo:** Explorar los datasets crudos de ThreatFox, MalwareBazaar y URLhaus
# para entender su estructura, calidad y utilidad para construir features.
# 
# **Datasets:**
# - `threatfox.csv`
# - `malwarebazaar.csv`
# - `urlhaus.csv`

# %% [code] Cell 2
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

# Configuración de visualización
pd.set_option("display.max_columns", None)
pd.set_option("display.width", 200)
plt.rcParams["figure.figsize"] = (10, 5)

# Rutas relativas al proyecto (ajusta según dónde ejecutes)
DATA_DIR = Path("../data/raw")

print("Pandas:", pd.__version__)

# %% [code] Cell 3
tf = pd.read_csv(DATA_DIR / "threatfox.csv")
print("Shape:", tf.shape)
print("\nColumnas:", tf.columns.tolist())
tf.head()

# %% [code] Cell 4
print(tf["ioc_type"].value_counts())
print("\nPorcentaje:")
print(tf["ioc_type"].value_counts(normalize=True).mul(100).round(2))

# %% [code] Cell 5
print("=== Top fuentes (reporter) ===")
print(tf["reporter"].value_counts().head(10))

print("\n=== Top familias de malware ===")
print(tf["malware_printable"].value_counts().head(10))

# %% [code] Cell 6
print(tf["confidence_level"].describe())
print("\nDistribución:")
print(tf["confidence_level"].value_counts().sort_index())

# %% [code] Cell 7
print("=== Valores nulos por columna ===")
print(tf.isnull().sum().sort_values(ascending=False))

print("\n=== Duplicados (fila completa) ===")
print("Total duplicados:", tf.duplicated().sum())

print("\n=== Duplicados por IOC ===")
print("IOCs únicos:", tf["ioc"].nunique(), "de", len(tf))

# %% [code] Cell 8
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

tf["ioc_type"].value_counts().plot(kind="bar", ax=axes[0], title="Tipos de IOC")
axes[0].set_xlabel("Tipo")
axes[0].set_ylabel("Cantidad")

tf["malware_printable"].value_counts().head(10).plot(
    kind="barh", ax=axes[1], title="Top 10 familias de malware"
)
axes[1].invert_yaxis()

plt.tight_layout()
plt.savefig("../reports/01_ioc_distribucion.png", dpi=120, bbox_inches="tight")
plt.show()

# %% [markdown] Cell 9
# ## Hallazgos
# 
# - **Total de IOCs:** X registros
# - **Tipos predominantes:** domain (~%), ip:port (~%), url (~%), md5/sha256 (~%)
# - **Fuentes más activas:** reporter1, reporter2, ...
# - **Familias más reportadas:** ...
# 
# ### Campos útiles para features
# - `ioc_type`, `malware_printable`, `confidence_level`, `first_seen_utc`,
#   `last_seen_utc`, `reporter`, `tags`, TLD del dominio, longitud del IOC.
# 
# ### Limitaciones detectadas
# - **Sesgo:** sobrerrepresentación de ciertas familias (ej. Cobalt Strike).
# - **Datos expirados:** registros con `last_seen_utc` muy antiguo.
# - **Nulos:** columnas como `malware_printable` o `tags` con muchos vacíos.
# - **Duplicados:** IOCs repetidos entre fuentes → riesgo de leakage.
