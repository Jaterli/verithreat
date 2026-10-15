#!/usr/bin/env python3
"""Ensayo de aprendizaje del modelo A de VeriThreat (dominio malicioso vs no malicioso).

Reproduce el experimento citado en los documentos del proyecto:
  1. Construye el conjunto a nivel de HOST: maliciosos de abuse.ch (ThreatFox + URLhaus), PhishTank (90 días) y
     TweetFeed, sin IPs ni plataformas de doble uso; no maliciosos = top 50.000 de Tranco sin choques con los
     registrables maliciosos y sin doble uso.
  2. Calcula rasgos léxicos del host (no usa fuente, reportero, etiquetas ni nada que un dominio desconocido no tendría).
  3. Parte en entrenamiento y test por DOMINIO REGISTRABLE (todos los hosts de un registrable caen en el mismo lado).
  4. Curva de aprendizaje: entrena con 100, 300, 1.000, 3.000, 10.000 y todos los registros y mide en el test.
  5. Generalización entre familias: entrena sin una fuente y prueba en ella (más los no maliciosos del test).

Sin red y sin claves: solo lee los CSV de --data-dir. Los cargadores y la lista de doble uso se importan de
cargadores_corregidos.py (que debe estar en la misma carpeta). Necesita tldextract (con su lista de sufijos incluida,
sin descargas); sin él los registrables serían distintos y los resultados no coincidirían.

Uso:
    python ensayo_aprendizaje.py --data-dir ../data/raw
    python ensayo_aprendizaje.py --data-dir ../data/raw --semilla 1 --salida resultados_ensayo/

Parámetros del experimento original que NO figuraban en los documentos (valores por defecto de este script):
  - Modelo: HistGradientBoostingClassifier(max_iter=200, learning_rate=0.1, random_state=<semilla de la repetición>);
    el resto, valores por defecto de scikit-learn (31 hojas máx., min_samples_leaf=20, sin pesos de clase...).
    El parámetro early_stopping='auto' solo se activa con más de 10.000 muestras de entrenamiento, es decir, solo en la
    fila «todos» (reserva un 10 % con la misma semilla; por eso su desviación es ~0).
  - Partición: GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=<semilla>) sobre el dominio registrable.
  - Curva: 3 repeticiones por tamaño; cada una submuestrea el entrenamiento con RandomState(semilla + i), sin reemplazo,
    manteniendo la proporción natural de clases. Se informa la media y la desviación (ddof=0). «Maliciosos aprox.» es el
    nº de maliciosos de la última repetición.
  - Rasgos (51): longitud del host, nº de etiquetas, longitud y nº de niveles del subdominio, longitud del dominio, fracción
    de dígitos, guiones, entropía de Shannon (sobre el dominio, sin sufijo), fracción de vocales (aeiou), racha de dígitos más
    larga del host y longitud del sufijo, más 40 indicadores one-hot de los 40 sufijos (TLD) más frecuentes. Los demás
    sufijos solo cuentan en «longitud del sufijo». Los 40 sufijos se eligen sobre TODO el conjunto (incluido el test): usa
    nombres, no etiquetas, pero es una pequeña filtración de información que conviene conocer.
  - Generalización: el test incluye TODOS los hosts de la familia excluida (estén o no en el lado de entrenamiento de la
    partición) más los no maliciosos del test; si dos familias comparten registrable, el de la otra puede estar en el
    entrenamiento.
"""
import argparse
import math
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))

import numpy as np
import pandas as pd

from cargadores_corregidos import (DOBLE_USO, es_doble_uso, es_ip, load_phishtank, load_threatfox, load_tranco,
                                   load_tweetfeed, load_urlhaus, registrable)

FAMILIAS = ("phishtank", "abusech", "tweetfeed")
TAMANOS = (100, 300, 1_000, 3_000, 10_000)  # y, además, todos los registros de entrenamiento
HIPERPARAMETROS = {"max_iter": 200, "learning_rate": 0.1}
N_TLD = 40


# ----------------------------------------------------------------------------- utilidades
def versiones() -> dict:
    import sklearn
    try:
        import tldextract
        v_tld = tldextract.__version__
    except ImportError:
        v_tld = "NO INSTALADO"
    return {"python": sys.version.split()[0], "scikit-learn": sklearn.__version__, "pandas": pd.__version__,
            "numpy": np.__version__, "tldextract": v_tld}


def crear_extractor():
    try:
        import tldextract
    except ImportError:
        sys.exit("Falta tldextract: pip install tldextract (sin él los registrables serían distintos y los "
                 "resultados no coincidirían con los documentados).")
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # lista de sufijos incluida: sin red


def host_de(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


# ----------------------------------------------------------------------------- conjunto
def construir_conjunto(data_dir: Path, top_n: int, excluir_registrable_vacio: bool):
    """Devuelve (df, resumen). df: host, y (1 malicioso, 0 no), fam, reg (dominio registrable)."""
    tf = load_threatfox(data_dir / "threatfox.csv")
    uh = load_urlhaus(data_dir / "urlhaus.csv")
    pt = load_phishtank(data_dir / "verified_online.csv")
    exclusive = data_dir / "exclusive.csv"
    tw = load_tweetfeed(data_dir / "month.csv", exclusive if exclusive.exists() else None)
    tr = load_tranco(data_dir / "top-1m.csv")

    tw_hosts = pd.concat([tw.loc[tw["type"] == "url", "host"], tw.loc[(tw["type"] == "domain") & ~tw["derivado"], "value_norm"]])
    pools = {  # el orden importa: un host repetido se asigna a la primera familia
        "abusech": pd.concat([uh["url"].map(host_de), tf.loc[tf["ioc_type"] == "domain", "ioc"].str.lower(),
                              tf.loc[tf["ioc_type"] == "url", "ioc"].map(host_de)]),
        "phishtank": pt.loc[pt["reciente"], "host"],
        "tweetfeed": tw_hosts,
    }
    filas = []
    for fam, serie in pools.items():
        s = serie.dropna().astype(str).str.lower()
        s = s[(s != "") & ~s.map(es_ip) & ~s.map(es_doble_uso)].drop_duplicates()
        filas += [(h, 1, fam) for h in s]
    mal = pd.DataFrame(filas, columns=["host", "y", "fam"]).drop_duplicates("host")
    mal["reg"] = mal["host"].map(registrable)
    mal = mal[~mal["reg"].map(es_doble_uso) & (mal["reg"] != "")]

    bt = tr.head(top_n).copy()
    bt["reg"] = bt["domain"].map(registrable)
    bt = bt[~bt["reg"].isin(set(mal["reg"])) & ~bt["domain"].map(es_doble_uso)]
    vacios = int((bt["reg"] == "").sum())
    if excluir_registrable_vacio:  # criterio del notebook: los sufijos públicos (p. ej. bet.br) quedan fuera
        bt = bt[bt["reg"] != ""]
    ben = pd.DataFrame({"host": bt["domain"].values, "y": 0, "fam": "tranco", "reg": bt["reg"].values})
    df = pd.concat([mal, ben], ignore_index=True)

    g = mal.groupby("reg").size()
    resumen = {
        "maliciosos_hosts": len(mal), "maliciosos_registrables": int(mal["reg"].nunique()),
        "maliciosos_por_familia": mal["fam"].value_counts().to_dict(),
        "no_maliciosos": len(ben), "no_maliciosos_con_registrable_vacio": vacios,
        "registrables_con_mas_de_10_hosts": int((g > 10).sum()), "hosts_en_ellos": int(g[g > 10].sum()),
        "doble_uso_entradas": len(DOBLE_USO),
    }
    return df, resumen


# ----------------------------------------------------------------------------- rasgos
def entropia(s: str) -> float:
    c, n = Counter(s), len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values()) if n else 0.0


def matriz_rasgos(hosts: pd.Series, ext) -> pd.DataFrame:
    sufijos = [ext(h).suffix for h in hosts]
    top = [t for t, _ in Counter(sufijos).most_common(N_TLD)]
    filas = []
    for h, suf in zip(hosts, sufijos):
        e = ext(h)
        lab, sub = e.domain, e.subdomain
        f = {"len": len(h), "n_lab": h.count(".") + 1, "sub_len": len(sub), "sub_n": (sub.count(".") + 1) if sub else 0,
             "lab_len": len(lab), "dig": sum(c.isdigit() for c in lab) / max(1, len(lab)), "hy": lab.count("-"),
             "ent": entropia(lab), "vow": sum(c in "aeiou" for c in lab) / max(1, len(lab)),
             "maxdig": max([len(x) for x in re.findall(r"\d+", h)] or [0]), "tldlen": len(suf)}
        for t in top:
            f["tld_" + t] = int(suf == t)
        filas.append(f)
    return pd.DataFrame(filas)


# ----------------------------------------------------------------------------- modelo y evaluación
def evaluar(X, y, idx_train, idx_test, semilla):
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.metrics import average_precision_score, roc_auc_score
    m = HistGradientBoostingClassifier(random_state=semilla, **HIPERPARAMETROS).fit(X.iloc[idx_train], y[idx_train])
    p = m.predict_proba(X.iloc[idx_test])[:, 1]
    return average_precision_score(y[idx_test], p), roc_auc_score(y[idx_test], p)


def curva_aprendizaje(X, y, tri, tei, semilla, repeticiones):
    filas = []
    for n in list(TAMANOS) + [len(tri)]:
        aps, aucs, sel = [], [], tri
        for i in range(repeticiones):
            rng = np.random.RandomState(semilla + i)
            sel = rng.choice(tri, size=min(n, len(tri)), replace=False)
            if y[sel].min() == y[sel].max():  # una sola clase: no se puede entrenar
                continue
            a, b = evaluar(X, y, sel, tei, semilla + i)
            aps.append(a)
            aucs.append(b)
        filas.append({"n_entrenamiento": min(n, len(tri)), "maliciosos_aprox": int(y[sel].sum()),
                      "pr_auc_media": np.mean(aps), "pr_auc_desv": np.std(aps), "roc_auc_media": np.mean(aucs),
                      "repeticiones": len(aps)})
    return pd.DataFrame(filas)


def generalizacion_familias(df, X, y, tri, tei, semilla):
    fam = df["fam"].to_numpy()
    en_test = np.zeros(len(df), dtype=bool)
    en_test[tei] = True
    filas = []
    for fuera in FAMILIAS:
        tr_idx = tri[fam[tri] != fuera]
        te_idx = np.flatnonzero((fam == fuera) | ((fam == "tranco") & en_test))
        a, b = evaluar(X, y, tr_idx, te_idx, semilla)
        filas.append({"familia_fuera": fuera, "maliciosos_test": int(y[te_idx].sum()), "base_pr_auc": y[te_idx].mean(),
                      "pr_auc": a, "roc_auc": b})
    return pd.DataFrame(filas)


# ----------------------------------------------------------------------------- main
def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data-dir", type=Path, default=Path("../data/raw"), help="carpeta con los CSV de las fuentes")
    p.add_argument("--semilla", type=int, default=0, help="semilla de la partición y base de las repeticiones (0 reproduce el original)")
    p.add_argument("--tamano-test", type=float, default=0.2, help="fracción de dominios registrables reservada para test")
    p.add_argument("--repeticiones", type=int, default=3, help="repeticiones por tamaño en la curva")
    p.add_argument("--top-tranco", type=int, default=50_000, help="no maliciosos: primeros N dominios de Tranco")
    p.add_argument("--excluir-registrable-vacio", action="store_true",
                   help="excluir los dominios de Tranco sin registrable (sufijos públicos como bet.br): criterio del notebook")
    p.add_argument("--salida", type=Path, default=None, help="carpeta donde guardar las tablas en CSV (opcional)")
    a = p.parse_args()

    if not a.data_dir.is_dir():
        sys.exit(f"No existe la carpeta de datos: {a.data_dir}")
    from sklearn.model_selection import GroupShuffleSplit

    ext = crear_extractor()
    v = versiones()
    print("Versiones:", " | ".join(f"{k} {x}" for k, x in v.items()))
    print(f"Parámetros: semilla={a.semilla} | test={a.tamano_test:.0%} de los registrables | repeticiones={a.repeticiones} | "
          f"modelo=HistGradientBoostingClassifier({HIPERPARAMETROS}) | top Tranco={a.top_tranco:,} | "
          f"excluir registrable vacío={a.excluir_registrable_vacio}")

    df, resumen = construir_conjunto(a.data_dir, a.top_tranco, a.excluir_registrable_vacio)
    print(f"\nCONJUNTO: {resumen['maliciosos_hosts']:,} maliciosos ({resumen['maliciosos_registrables']:,} registrables únicos) "
          f"y {resumen['no_maliciosos']:,} no maliciosos")
    print(f"  maliciosos por familia: {resumen['maliciosos_por_familia']}")
    print(f"  registrables con >10 hosts: {resumen['registrables_con_mas_de_10_hosts']} ({resumen['hosts_en_ellos']} hosts) | "
          f"no maliciosos con registrable vacío: {resumen['no_maliciosos_con_registrable_vacio']} | entradas en DOBLE_USO: {resumen['doble_uso_entradas']}")

    X = matriz_rasgos(df["host"], ext)
    y = df["y"].to_numpy()
    tri, tei = next(GroupShuffleSplit(n_splits=1, test_size=a.tamano_test, random_state=a.semilla).split(X, y, df["reg"].to_numpy()))
    print(f"\nPARTICIÓN por dominio registrable: {len(tri):,} para entrenar y {len(tei):,} para test "
          f"(prevalencia de maliciosos en el test: {y[tei].mean():.3f}; rasgos: {X.shape[1]})")

    curva = curva_aprendizaje(X, y, tri, tei, a.semilla, a.repeticiones)
    print("\nCURVA DE APRENDIZAJE (proporción natural de clases)")
    for _, f in curva.iterrows():
        print(f"  n_train={int(f.n_entrenamiento):6d} (≈{int(f.maliciosos_aprox):5d} maliciosos) | "
              f"PR-AUC {f.pr_auc_media:.3f} ±{f.pr_auc_desv:.3f} | ROC-AUC {f.roc_auc_media:.3f}")

    gen = generalizacion_familias(df, X, y, tri, tei, a.semilla)
    print("\nGENERALIZACIÓN POR FAMILIA (entrena sin la familia; test = esa familia + no maliciosos del test)")
    for _, f in gen.iterrows():
        print(f"  fuera {f.familia_fuera:10s}: test maliciosos {int(f.maliciosos_test):5d} | PR-AUC {f.pr_auc:.3f} "
              f"(base {f.base_pr_auc:.2f}) | ROC-AUC {f.roc_auc:.3f}")

    if a.salida is not None:
        a.salida.mkdir(parents=True, exist_ok=True)
        curva.round(4).to_csv(a.salida / "curva_aprendizaje.csv", index=False)
        gen.round(4).to_csv(a.salida / "generalizacion_por_familia.csv", index=False)
        pd.DataFrame([{**{k: x for k, x in resumen.items() if k != "maliciosos_por_familia"},
                       **{f"maliciosos_{k}": x for k, x in resumen["maliciosos_por_familia"].items()},
                       "n_entrenamiento": len(tri), "n_test": len(tei), "prevalencia_test": round(float(y[tei].mean()), 4),
                       "semilla": a.semilla, "tamano_test": a.tamano_test, **{f"version_{k}": x for k, x in v.items()}}]
                     ).to_csv(a.salida / "resumen_conjunto.csv", index=False)
        print(f"\nTablas guardadas en {a.salida}/")


if __name__ == "__main__":
    main()
