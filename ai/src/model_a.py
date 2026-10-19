#!/usr/bin/env python3
"""Modelo A de VeriThreat: probabilidad de que un dominio (host) sea malicioso a partir de rasgos léxicos.

Entrena con la base de datos (lo que acumula la ingesta) y la clase no maliciosa de Tranco, evalúa de tres formas y
guarda una versión reproducible:

  Datos      Maliciosos: hosts de los indicadores `domain` y `url` (sin IPs ni plataformas de doble uso), con su
             primera fecha de aparición y la familia de la fuente que lo vio primero. No maliciosos: top N de Tranco
             sin choques con los registrables maliciosos ni doble uso (los sufijos públicos sin registrable se
             mantienen: criterio de la decisión 6 de CLAUDE.md).
  Rasgos     11 léxicos del host + one-hot de los TLD más frecuentes, elegidos SOLO con los datos de entrenamiento
             (el ensayo de aprendizaje los elegía con todo el conjunto: pequeña filtración corregida aquí).
  Campañas   Cada dominio registrable pesa lo mismo en total, aunque tenga muchos subdominios; los pesos se
             reescalan para mantener la proporción de clases.
  Evaluación (1) partición por dominio registrable, con y sin ponderar; (2) por tiempo: el 20 % más reciente de cada
             familia como test, sin registrables compartidos con el entrenamiento; (3) dejando fuera una familia.
  Final      Se entrena con todos los datos, sin calibrar (Platt no mejoró el Brier). La probabilidad es relativa a
             la proporción de maliciosos del entrenamiento: úsese como ordenación, no como riesgo real.
  Salida     ai/models/model_a/<versión>/: model.joblib, metrics.json, params.json y training_hosts.csv (lista exacta
             y en su orden, con su sha256 en params). Se registra en la tabla model_version; --activate la marca como
             activa. Como la base de datos crece cada hora, --from-hosts reconstruye exactamente una versión anterior.

Uso:
    python model_a.py --data-dir ../data/raw                 # evalúa, entrena y registra (inactiva)
    python model_a.py --data-dir ../data/raw --activate      # además, la marca como versión activa
    python model_a.py --data-dir ../data/raw --no-register   # sin escribir en la base de datos
    python model_a.py --from-hosts ../models/model_a/<versión>/training_hosts.csv --output-dir /tmp/repro

Para puntuar hosts desde otro módulo (paso 5):  load_artifact(ruta) y score_hosts(artefacto, hosts).
"""
import argparse
import hashlib
import json
import math
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from loaders import is_dual_use, is_ip, load_tranco, registered_domain, to_punycode  # noqa: E402

MODEL_NAME = "model_a"
HYPERPARAMS = {"max_iter": 200, "learning_rate": 0.1}
N_TLD = 40
TEST_FRACTION = 0.2
FAMILIES = ("abuse.ch", "phishtank", "tweetfeed")
MODELS_DIR = Path(__file__).resolve().parent.parent / "models" / MODEL_NAME

SQL_MALICIOUS = """
SELECT i.type, i.value, src.family, s.seen_at
FROM sighting s
JOIN indicator i ON i.id = s.indicator_id
JOIN source src  ON src.code = s.source
WHERE i.type IN ('domain', 'url')"""


# ----------------------------------------------------------------------------- rasgos
_EXT = None


def _extractor():
    global _EXT
    if _EXT is None:
        import tldextract
        _EXT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # lista de sufijos incluida: sin red
    return _EXT


def entropy(s: str) -> float:
    c, n = Counter(s), len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values()) if n else 0.0


def lexical_features(hosts) -> pd.DataFrame:
    """Rasgos calculables para un dominio desconocido (decisión 7 de CLAUDE.md), más el sufijo para el one-hot."""
    ext = _extractor()
    rows = []
    for h in hosts:
        e = ext(h)
        lab, sub, suf = e.domain, e.subdomain, e.suffix
        rows.append({"len": len(h), "n_lab": h.count(".") + 1, "sub_len": len(sub),
                     "sub_n": (sub.count(".") + 1) if sub else 0, "lab_len": len(lab),
                     "dig": sum(c.isdigit() for c in lab) / max(1, len(lab)), "hy": lab.count("-"),
                     "ent": entropy(lab), "vow": sum(c in "aeiou" for c in lab) / max(1, len(lab)),
                     "maxdig": max([len(x) for x in re.findall(r"\d+", h)] or [0]), "tldlen": len(suf), "_suffix": suf})
    return pd.DataFrame(rows)


def fit_tlds(base: pd.DataFrame) -> list:
    return [t for t, _ in Counter(base["_suffix"]).most_common(N_TLD)]


def to_matrix(base: pd.DataFrame, tlds: list) -> pd.DataFrame:
    X = base.drop(columns="_suffix").copy()
    for t in tlds:
        X["tld_" + t] = (base["_suffix"] == t).astype(int)
    return X


# ----------------------------------------------------------------------------- datos
def _host(typ: str, value: str) -> str:
    if typ == "domain":
        return value
    return to_punycode((urlparse(value).hostname or "").lower())


def malicious_hosts(conn) -> pd.DataFrame:
    """Un registro por host malicioso: host, reg, family (de la observación más antigua), first_seen."""
    df = pd.DataFrame(conn.execute(SQL_MALICIOUS).fetchall(), columns=["type", "value", "family", "seen_at"])
    df["host"] = [_host(t, v) for t, v in zip(df["type"], df["value"])]
    df = df[(df["host"] != "") & ~df["host"].map(is_ip) & ~df["host"].map(is_dual_use)]
    df["seen_at"] = pd.to_datetime(df["seen_at"], utc=True)
    df = df.sort_values(["seen_at", "family"]).drop_duplicates("host")  # la primera observación decide la familia
    df["reg"] = df["host"].map(registered_domain)
    df = df[(df["reg"] != "") & ~df["reg"].map(is_dual_use)]
    return df[["host", "reg", "family", "seen_at"]].rename(columns={"seen_at": "first_seen"}).reset_index(drop=True)


def benign_hosts(tranco_path: Path, top_n: int, malicious_regs: set) -> pd.DataFrame:
    tr = load_tranco(tranco_path).head(top_n)
    tr["reg"] = tr["domain"].map(registered_domain)
    tr = tr[~tr["reg"].isin(malicious_regs - {""}) & ~tr["domain"].map(is_dual_use)]
    return pd.DataFrame({"host": tr["domain"].values, "reg": tr["reg"].values, "family": "tranco", "first_seen": pd.NaT})


def _with_groups(df: pd.DataFrame) -> pd.DataFrame:
    df["group"] = df["reg"].where(df["reg"] != "", df["host"])  # un sufijo público sin registrable es su propio grupo
    return df


def build_dataset(conn, tranco_path: Path, top_n: int) -> pd.DataFrame:
    mal = malicious_hosts(conn).assign(y=1)
    ben = benign_hosts(tranco_path, top_n, set(mal["reg"])).assign(y=0)
    ben = ben[~ben["host"].isin(set(mal["host"]))]
    return _with_groups(pd.concat([mal, ben], ignore_index=True))


def dataset_from_hosts(path: Path) -> pd.DataFrame:
    """Reconstruye exactamente el conjunto de una versión anterior a partir de su training_hosts.csv."""
    df = pd.read_csv(path, dtype={"host": str, "reg": str, "family": str}, keep_default_na=False)
    df["first_seen"] = pd.to_datetime(df["first_seen"].replace("", None), utc=True)
    df["y"] = df["y"].astype(int)
    return _with_groups(df)  # el fichero conserva el orden original (la parada temprana del modelo depende de él)


def campaign_weights(df: pd.DataFrame) -> np.ndarray:
    """Cada registrable pesa lo mismo en total; se reescala por clase para conservar la proporción de clases."""
    w = 1.0 / df.groupby("group")["host"].transform("size").to_numpy(dtype=float)
    y = df["y"].to_numpy()
    for c in (0, 1):
        m = y == c
        w[m] *= m.sum() / w[m].sum()
    return w


# ----------------------------------------------------------------------------- modelo y evaluación
def group_split(groups: np.ndarray, test_size: float, seed: int):
    from sklearn.model_selection import GroupShuffleSplit
    return next(GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed).split(groups, groups=groups))


def fit_model(df_train: pd.DataFrame, base_train: pd.DataFrame, seed: int, weighted: bool):
    from sklearn.ensemble import HistGradientBoostingClassifier
    tlds = fit_tlds(base_train)
    w = campaign_weights(df_train) if weighted else None
    m = HistGradientBoostingClassifier(random_state=seed, **HYPERPARAMS)
    m.fit(to_matrix(base_train, tlds), df_train["y"].to_numpy(), sample_weight=w)
    return m, tlds


def metrics(y: np.ndarray, p: np.ndarray) -> dict:
    from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score
    return {"n": int(len(y)), "malicious": int(y.sum()), "prevalence": round(float(y.mean()), 4),
            "pr_auc": round(float(average_precision_score(y, p)), 4), "roc_auc": round(float(roc_auc_score(y, p)), 4),
            "brier": round(float(brier_score_loss(y, p)), 4)}


def evaluate(df: pd.DataFrame, base: pd.DataFrame, tri: np.ndarray, tei: np.ndarray, seed: int, weighted: bool) -> dict:
    m, tlds = fit_model(df.iloc[tri], base.iloc[tri], seed, weighted)
    p = m.predict_proba(to_matrix(base.iloc[tei], tlds))[:, 1]
    return metrics(df["y"].to_numpy()[tei], p)


def temporal_split(df: pd.DataFrame, benign_test: np.ndarray) -> tuple:
    """Test = el 20 % más reciente de cada familia + los no maliciosos de benign_test; se quitan del entrenamiento los
    registrables que aparezcan en el test."""
    test = np.zeros(len(df), dtype=bool)
    test[benign_test] = True
    for fam in FAMILIES:
        seen = df.loc[df["family"] == fam, "first_seen"]
        if len(seen):
            cut = seen.quantile(1 - TEST_FRACTION)
            test[seen.index[(seen > cut).to_numpy()]] = True
    test_groups = set(df.loc[test, "group"])
    train = ~test & ~df["group"].isin(test_groups).to_numpy()
    cutoffs = {fam: str(df.loc[(df["family"] == fam) & test, "first_seen"].min()) for fam in FAMILIES}
    return np.flatnonzero(train), np.flatnonzero(test), cutoffs


def run_evaluations(df: pd.DataFrame, base: pd.DataFrame, seed: int) -> dict:
    groups = df["group"].to_numpy()
    tri, tei = group_split(groups, TEST_FRACTION, seed)
    out = {"by_registered_domain": {"weighted": evaluate(df, base, tri, tei, seed, True),
                                    "unweighted": evaluate(df, base, tri, tei, seed, False)}}
    benign_test = tei[df["y"].to_numpy()[tei] == 0]
    ttr, tte, cutoffs = temporal_split(df, benign_test)
    out["temporal"] = {**evaluate(df, base, ttr, tte, seed, True), "test_from": cutoffs,
                       "train_size": int(len(ttr))}
    fam = df["family"].to_numpy()
    in_test = np.zeros(len(df), dtype=bool)
    in_test[tei] = True
    out["family_left_out"] = {}
    for f in FAMILIES:
        tr_idx = tri[fam[tri] != f]
        te_idx = np.flatnonzero((fam == f) | ((fam == "tranco") & in_test))
        out["family_left_out"][f] = evaluate(df, base, tr_idx, te_idx, seed, True)
    return out


def train_final(df: pd.DataFrame, base: pd.DataFrame, seed: int) -> tuple:
    """Entrena con todos los datos. Sin calibración: Platt no mejoró el Brier (0,0878 → 0,0878, 19-10-2026), y
    calibrar obligaba a reservar un 20 % de los datos."""
    return fit_model(df, base, seed, True)


# ----------------------------------------------------------------------------- artefacto y puntuación
def load_artifact(path) -> dict:
    import joblib
    return joblib.load(path)


def score_hosts(artifact: dict, hosts) -> np.ndarray:
    """p_malicioso para cada host (dominio en minúsculas, punycode). Ordenación, no probabilidad real."""
    base = lexical_features(list(hosts))
    return artifact["model"].predict_proba(to_matrix(base, artifact["tlds"]))[:, 1]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def versions() -> dict:
    import sklearn
    import tldextract
    return {"python": sys.version.split()[0], "scikit-learn": sklearn.__version__, "pandas": pd.__version__,
            "numpy": np.__version__, "tldextract": tldextract.__version__}


def register(conn, version: str, trained_at: datetime, artifact_sha: str, params: dict, metrics_: dict, activate: bool):
    with conn.transaction():
        if activate:
            conn.execute("UPDATE model_version SET active = false WHERE name = %s AND active", (MODEL_NAME,))
        conn.execute("INSERT INTO model_version (name, version, trained_at, artifact_sha256, params, metrics, active) "
                     "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                     (MODEL_NAME, version, trained_at, artifact_sha, json.dumps(params), json.dumps(metrics_), activate))


# ----------------------------------------------------------------------------- main
def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data-dir", type=Path, default=Path("../data/raw"), help="folder with top-1m.csv (Tranco)")
    p.add_argument("--tranco-top", type=int, default=50_000)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--output-dir", type=Path, default=MODELS_DIR)
    p.add_argument("--activate", action="store_true", help="mark the new version as the active one")
    p.add_argument("--no-register", action="store_true", help="do not write the version to the database")
    p.add_argument("--from-hosts", type=Path, default=None,
                   help="rebuild the exact dataset of a previous version from its training_hosts.csv (implies --no-register)")
    a = p.parse_args()

    import joblib
    from contextlib import nullcontext
    from load_db import connect
    trained_at = datetime.now(timezone.utc).replace(microsecond=0)
    version = trained_at.strftime("%Y%m%dT%H%M%SZ")
    register_it = not (a.no_register or a.from_hosts)
    with (connect() if (register_it or a.from_hosts is None) else nullcontext()) as conn:
        if a.from_hosts:
            df = dataset_from_hosts(a.from_hosts)
        else:
            df = build_dataset(conn, a.data_dir / "top-1m.csv", a.tranco_top)
        mal = df[df["y"] == 1]
        print(f"DATASET: {len(mal):,} malicious hosts ({mal['reg'].nunique():,} registered domains) and "
              f"{int((df['y'] == 0).sum()):,} benign | by family: {mal['family'].value_counts().to_dict()}")
        print(f"  first_seen: {mal['first_seen'].min()} → {mal['first_seen'].max()}")
        base = lexical_features(df["host"])

        ev = run_evaluations(df, base, a.seed)
        r, u = ev["by_registered_domain"]["weighted"], ev["by_registered_domain"]["unweighted"]
        print(f"\nBY REGISTERED DOMAIN (test {r['n']:,}, prevalence {r['prevalence']:.3f})")
        print(f"  campaign-weighted  PR-AUC {r['pr_auc']:.3f} | ROC-AUC {r['roc_auc']:.3f}")
        print(f"  unweighted         PR-AUC {u['pr_auc']:.3f} | ROC-AUC {u['roc_auc']:.3f}")
        t = ev["temporal"]
        print(f"TEMPORAL (newest 20% per family; test {t['n']:,}, prevalence {t['prevalence']:.3f}) "
              f"PR-AUC {t['pr_auc']:.3f} | ROC-AUC {t['roc_auc']:.3f}")
        print(f"  test from: {t['test_from']}")
        for f, x in ev["family_left_out"].items():
            print(f"WITHOUT {f:10s} (malicious in test {x['malicious']:,}, baseline {x['prevalence']:.2f}) "
                  f"PR-AUC {x['pr_auc']:.3f} | ROC-AUC {x['roc_auc']:.3f}")

        model, tlds = train_final(df, base, a.seed)

        out = a.output_dir / version
        out.mkdir(parents=True, exist_ok=True)
        # Orden original de las filas: --from-hosts lo necesita para reproducir exactamente el entrenamiento
        df[["host", "reg", "family", "first_seen", "y"]].to_csv(out / "training_hosts.csv", index=False)
        joblib.dump({"model": model, "tlds": tlds, "version": version, "hyperparams": HYPERPARAMS}, out / "model.joblib")
        params = {"hyperparams": HYPERPARAMS, "seed": a.seed, "n_tld": N_TLD, "test_fraction": TEST_FRACTION,
                  "tranco_top": a.tranco_top, "training_hosts_sha256": sha256_file(out / "training_hosts.csv"),
                  "n_malicious": int(len(mal)), "n_benign": int((df["y"] == 0).sum()),
                  "first_seen_range": [str(mal["first_seen"].min()), str(mal["first_seen"].max())],
                  "campaign_weighting": "1/hosts per registered domain, rescaled per class",
                  "calibration": "none (Platt did not improve the Brier score)",
                  "rebuilt_from": str(a.from_hosts) if a.from_hosts else None, "versions": versions()}
        if not a.from_hosts:
            params["tranco_sha256"] = sha256_file(a.data_dir / "top-1m.csv")
        (out / "params.json").write_text(json.dumps(params, indent=2), encoding="utf-8")
        (out / "metrics.json").write_text(json.dumps(ev, indent=2), encoding="utf-8")
        artifact_sha = sha256_file(out / "model.joblib")
        print(f"\nFINAL MODEL trained on {len(df):,} hosts. Saved to {out} (model sha256 {artifact_sha[:12]}…)")
        if register_it:
            register(conn, version, trained_at, artifact_sha, params, ev, a.activate)
            print(f"Registered as {MODEL_NAME} {version}" + (" (active)" if a.activate else " (inactive)"))


if __name__ == "__main__":
    main()
