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
loaders.py (que debe estar en la misma carpeta). Necesita tldextract (con su lista de sufijos incluida, sin
descargas); sin él los registrables serían distintos y los resultados no coincidirían.

Uso:
    python learning_trial.py --data-dir ../data/raw
    python learning_trial.py --data-dir ../data/raw --seed 1 --output trial_results/

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

from loaders import (DUAL_USE, is_dual_use, is_ip, load_phishtank, load_threatfox, load_tranco, load_tweetfeed,
                     load_urlhaus, registered_domain)

FAMILIES = ("phishtank", "abusech", "tweetfeed")
SIZES = (100, 300, 1_000, 3_000, 10_000)  # y, además, todos los registros de entrenamiento
HYPERPARAMS = {"max_iter": 200, "learning_rate": 0.1}
N_TLD = 40


# ----------------------------------------------------------------------------- utilidades
def versions() -> dict:
    import sklearn
    try:
        import tldextract
        v_tld = tldextract.__version__
    except ImportError:
        v_tld = "NOT INSTALLED"
    return {"python": sys.version.split()[0], "scikit-learn": sklearn.__version__, "pandas": pd.__version__,
            "numpy": np.__version__, "tldextract": v_tld}


def make_extractor():
    try:
        import tldextract
    except ImportError:
        sys.exit("Missing tldextract: pip install tldextract (without it the registered domains would differ and the "
                 "results would not match the documented ones).")
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # lista de sufijos incluida: sin red


def host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


# ----------------------------------------------------------------------------- conjunto
def build_dataset(data_dir: Path, top_n: int, exclude_empty_registered: bool):
    """Devuelve (df, summary). df: host, y (1 malicioso, 0 no), fam, reg (dominio registrable)."""
    tf = load_threatfox(data_dir / "threatfox.csv")
    uh = load_urlhaus(data_dir / "urlhaus.csv")
    pt = load_phishtank(data_dir / "verified_online.csv")
    exclusive = data_dir / "exclusive.csv"
    tw = load_tweetfeed(data_dir / "month.csv", exclusive if exclusive.exists() else None)
    tr = load_tranco(data_dir / "top-1m.csv")

    tw_hosts = pd.concat([tw.loc[tw["type"] == "url", "host"], tw.loc[(tw["type"] == "domain") & ~tw["derived"], "value_norm"]])
    pools = {  # el orden importa: un host repetido se asigna a la primera familia
        "abusech": pd.concat([uh["url"].map(host_of), tf.loc[tf["ioc_type"] == "domain", "ioc"].str.lower(),
                              tf.loc[tf["ioc_type"] == "url", "ioc"].map(host_of)]),
        "phishtank": pt.loc[pt["recent"], "host"],
        "tweetfeed": tw_hosts,
    }
    rows = []
    for fam, series in pools.items():
        s = series.dropna().astype(str).str.lower()
        s = s[(s != "") & ~s.map(is_ip) & ~s.map(is_dual_use)].drop_duplicates()
        rows += [(h, 1, fam) for h in s]
    mal = pd.DataFrame(rows, columns=["host", "y", "fam"]).drop_duplicates("host")
    mal["reg"] = mal["host"].map(registered_domain)
    mal = mal[~mal["reg"].map(is_dual_use) & (mal["reg"] != "")]

    bt = tr.head(top_n).copy()
    bt["reg"] = bt["domain"].map(registered_domain)
    bt = bt[~bt["reg"].isin(set(mal["reg"])) & ~bt["domain"].map(is_dual_use)]
    empty = int((bt["reg"] == "").sum())
    if exclude_empty_registered:  # criterio antiguo del notebook: los sufijos públicos (p. ej. bet.br) quedan fuera
        bt = bt[bt["reg"] != ""]
    ben = pd.DataFrame({"host": bt["domain"].values, "y": 0, "fam": "tranco", "reg": bt["reg"].values})
    df = pd.concat([mal, ben], ignore_index=True)

    g = mal.groupby("reg").size()
    summary = {
        "malicious_hosts": len(mal), "malicious_registered": int(mal["reg"].nunique()),
        "malicious_by_family": mal["fam"].value_counts().to_dict(),
        "benign": len(ben), "benign_empty_registered": empty,
        "registered_with_over_10_hosts": int((g > 10).sum()), "hosts_in_them": int(g[g > 10].sum()),
        "dual_use_entries": len(DUAL_USE),
    }
    return df, summary


# ----------------------------------------------------------------------------- rasgos
def entropy(s: str) -> float:
    c, n = Counter(s), len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values()) if n else 0.0


def feature_matrix(hosts: pd.Series, ext) -> pd.DataFrame:
    suffixes = [ext(h).suffix for h in hosts]
    top = [t for t, _ in Counter(suffixes).most_common(N_TLD)]
    rows = []
    for h, suf in zip(hosts, suffixes):
        e = ext(h)
        lab, sub = e.domain, e.subdomain
        f = {"len": len(h), "n_lab": h.count(".") + 1, "sub_len": len(sub), "sub_n": (sub.count(".") + 1) if sub else 0,
             "lab_len": len(lab), "dig": sum(c.isdigit() for c in lab) / max(1, len(lab)), "hy": lab.count("-"),
             "ent": entropy(lab), "vow": sum(c in "aeiou" for c in lab) / max(1, len(lab)),
             "maxdig": max([len(x) for x in re.findall(r"\d+", h)] or [0]), "tldlen": len(suf)}
        for t in top:
            f["tld_" + t] = int(suf == t)
        rows.append(f)
    return pd.DataFrame(rows)


# ----------------------------------------------------------------------------- modelo y evaluación
def evaluate(X, y, idx_train, idx_test, seed):
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.metrics import average_precision_score, roc_auc_score
    m = HistGradientBoostingClassifier(random_state=seed, **HYPERPARAMS).fit(X.iloc[idx_train], y[idx_train])
    p = m.predict_proba(X.iloc[idx_test])[:, 1]
    return average_precision_score(y[idx_test], p), roc_auc_score(y[idx_test], p)


def learning_curve(X, y, tri, tei, seed, repetitions):
    rows = []
    for n in list(SIZES) + [len(tri)]:
        aps, aucs, sel = [], [], tri
        for i in range(repetitions):
            rng = np.random.RandomState(seed + i)
            sel = rng.choice(tri, size=min(n, len(tri)), replace=False)
            if y[sel].min() == y[sel].max():  # una sola clase: no se puede entrenar
                continue
            a, b = evaluate(X, y, sel, tei, seed + i)
            aps.append(a)
            aucs.append(b)
        rows.append({"n_train": min(n, len(tri)), "malicious_approx": int(y[sel].sum()),
                     "pr_auc_mean": np.mean(aps), "pr_auc_std": np.std(aps), "roc_auc_mean": np.mean(aucs),
                     "repetitions": len(aps)})
    return pd.DataFrame(rows)


def family_generalization(df, X, y, tri, tei, seed):
    fam = df["fam"].to_numpy()
    in_test = np.zeros(len(df), dtype=bool)
    in_test[tei] = True
    rows = []
    for left_out in FAMILIES:
        tr_idx = tri[fam[tri] != left_out]
        te_idx = np.flatnonzero((fam == left_out) | ((fam == "tranco") & in_test))
        a, b = evaluate(X, y, tr_idx, te_idx, seed)
        rows.append({"family_left_out": left_out, "malicious_test": int(y[te_idx].sum()), "pr_auc_baseline": y[te_idx].mean(),
                     "pr_auc": a, "roc_auc": b})
    return pd.DataFrame(rows)


# ----------------------------------------------------------------------------- main
def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data-dir", type=Path, default=Path("../data/raw"), help="folder with the source CSV files")
    p.add_argument("--seed", type=int, default=0, help="split seed and base of the repetitions (0 reproduces the original)")
    p.add_argument("--test-size", type=float, default=0.2, help="fraction of registered domains held out for test")
    p.add_argument("--repetitions", type=int, default=3, help="repetitions per size in the curve")
    p.add_argument("--tranco-top", type=int, default=50_000, help="benign class: first N Tranco domains")
    p.add_argument("--exclude-empty-registered", action="store_true",
                   help="drop Tranco domains without a registered domain (public suffixes such as bet.br): old notebook criterion")
    p.add_argument("--output", type=Path, default=None, help="folder to save the tables as CSV (optional)")
    a = p.parse_args()

    if not a.data_dir.is_dir():
        sys.exit(f"Data folder not found: {a.data_dir}")
    from sklearn.model_selection import GroupShuffleSplit

    ext = make_extractor()
    v = versions()
    print("Versions:", " | ".join(f"{k} {x}" for k, x in v.items()))
    print(f"Parameters: seed={a.seed} | test={a.test_size:.0%} of registered domains | repetitions={a.repetitions} | "
          f"model=HistGradientBoostingClassifier({HYPERPARAMS}) | Tranco top={a.tranco_top:,} | "
          f"exclude empty registered={a.exclude_empty_registered}")

    df, s = build_dataset(a.data_dir, a.tranco_top, a.exclude_empty_registered)
    print(f"\nDATASET: {s['malicious_hosts']:,} malicious ({s['malicious_registered']:,} unique registered domains) "
          f"and {s['benign']:,} benign")
    print(f"  malicious by family: {s['malicious_by_family']}")
    print(f"  registered domains with >10 hosts: {s['registered_with_over_10_hosts']} ({s['hosts_in_them']} hosts) | "
          f"benign with empty registered domain: {s['benign_empty_registered']} | DUAL_USE entries: {s['dual_use_entries']}")

    X = feature_matrix(df["host"], ext)
    y = df["y"].to_numpy()
    tri, tei = next(GroupShuffleSplit(n_splits=1, test_size=a.test_size, random_state=a.seed).split(X, y, df["reg"].to_numpy()))
    print(f"\nSPLIT by registered domain: {len(tri):,} for training and {len(tei):,} for test "
          f"(malicious prevalence in test: {y[tei].mean():.3f}; features: {X.shape[1]})")

    curve = learning_curve(X, y, tri, tei, a.seed, a.repetitions)
    print("\nLEARNING CURVE (natural class ratio)")
    for _, f in curve.iterrows():
        print(f"  n_train={int(f.n_train):6d} (≈{int(f.malicious_approx):5d} malicious) | "
              f"PR-AUC {f.pr_auc_mean:.3f} ±{f.pr_auc_std:.3f} | ROC-AUC {f.roc_auc_mean:.3f}")

    gen = family_generalization(df, X, y, tri, tei, a.seed)
    print("\nGENERALIZATION BY FAMILY (train without the family; test = that family + benign test hosts)")
    for _, f in gen.iterrows():
        print(f"  without {f.family_left_out:10s}: malicious in test {int(f.malicious_test):5d} | PR-AUC {f.pr_auc:.3f} "
              f"(baseline {f.pr_auc_baseline:.2f}) | ROC-AUC {f.roc_auc:.3f}")

    if a.output is not None:
        a.output.mkdir(parents=True, exist_ok=True)
        curve.round(4).to_csv(a.output / "learning_curve.csv", index=False)
        gen.round(4).to_csv(a.output / "family_generalization.csv", index=False)
        pd.DataFrame([{**{k: x for k, x in s.items() if k != "malicious_by_family"},
                       **{f"malicious_{k}": x for k, x in s["malicious_by_family"].items()},
                       "n_train": len(tri), "n_test": len(tei), "test_prevalence": round(float(y[tei].mean()), 4),
                       "seed": a.seed, "test_size": a.test_size, **{f"version_{k}": x for k, x in v.items()}}]
                     ).to_csv(a.output / "dataset_summary.csv", index=False)
        print(f"\nTables saved in {a.output}/")


if __name__ == "__main__":
    main()
