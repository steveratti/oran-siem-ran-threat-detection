#!/usr/bin/env python3
"""
Scenario C repetitions: the SPL/MLTK pipeline of the paper, repeated over several seeded
4% training samples, with the same scikit-learn estimator that MLTK's RandomForestClassifier wraps.

Input: CSV exported from Splunk (index=external_iot_ddos_validation) with the fields
  id_ue, timestamp, mob_pattern, label, mac_*, phy_*

Steps (as in the paper):
  - train patterns static/pedestrian/car, test patterns bus/train
  - per UE, sorted by timestamp, rolling window of the last W=10 reports (current included)
    -> mean and sample std of 7 KPIs (= SPL streamstats window=10 ... by id_ue), std NaN -> 0
    (computed separately on the train and on the test set, as the two SPL queries do)
  - 4% random sample of the training set, seeded per repetition
  - RandomForest(n_estimators=100, max_depth=15, min_samples_split=5)
  - feature sets: baseline (11), extended (16), proposed (16 + 14 windowed)
  - tasks: 8-class and binary (attack vs benign)

Usage:
  python3 scenario_c_repeat.py scenario_c_export.csv --seeds 10 --jobs 4
"""
import argparse, sys, time
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score, accuracy_score
from scipy import stats

BASE = ["mac_dl_cqi", "mac_dl_mcs", "phy_ul_mcs", "phy_ul_pusch_sinr", "phy_ul_pucch_sinr",
        "mac_ul_brate", "mac_dl_brate", "mac_ul_ok", "mac_dl_ok", "mac_ul_nok", "mac_dl_nok"]
EXTRA = ["mac_ul_bsr", "mac_dl_buffer", "mac_phr", "phy_ul_pusch_rssi", "mac_nof_tti"]
WIN_K = ["mac_ul_brate", "mac_dl_brate", "mac_ul_ok", "mac_dl_ok", "mac_ul_nok", "mac_dl_buffer", "phy_ul_mcs"]
TRAIN_PAT = ["static", "pedestrian", "car"]
TEST_PAT = ["bus", "train"]
BENIGN_HINTS = ("iot", "mqtt", "voip", "sipp", "web", "youtube", "video", "benign")


def windowed(df, w=10):
    df = df.sort_values(["id_ue", "timestamp"], kind="mergesort").copy()
    g = df.groupby("id_ue", sort=False)
    names = []
    for k in WIN_K:
        m = g[k].rolling(w, min_periods=1).mean().reset_index(level=0, drop=True)
        s = g[k].rolling(w, min_periods=2).std(ddof=1).reset_index(level=0, drop=True)
        df[k + "_m10"] = m
        df[k + "_s10"] = s.fillna(0.0)
        names += [k + "_m10", k + "_s10"]
    return df, names


def ci95(x):
    x = np.asarray(x, float)
    if len(x) < 2:
        return (np.nan, np.nan)
    h = stats.t.ppf(0.975, len(x) - 1) * x.std(ddof=1) / np.sqrt(len(x))
    return (x.mean() - h, x.mean() + h)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--seeds", type=int, default=10)
    ap.add_argument("--rho", type=float, default=0.04)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--out", default="scenario_c_repeat_results.csv")
    ap.add_argument("--tasks", default="multi,binary", help="multi,binary or binary only")
    a = ap.parse_args()

    t0 = time.time()
    need = ["id_ue", "timestamp", "mob_pattern", "label"] + BASE + EXTRA
    with open(a.csv, encoding="latin-1") as fh:
        head = fh.readline()
    sep = ";" if head.count(";") > head.count(",") else ","
    d = pd.read_csv(a.csv, sep=sep, low_memory=False, encoding="latin-1",
                    usecols=lambda c: c.strip() in need)
    d.columns = d.columns.str.strip()
    miss = [c for c in need if c not in d.columns]
    if miss:
        sys.exit(f"missing columns: {miss}")
    d = d[d.label.notna() & d.mob_pattern.notna()]
    for c in BASE + EXTRA + ["timestamp"]:
        d[c] = pd.to_numeric(d[c], errors="coerce")
    d = d.dropna(subset=BASE + EXTRA + ["timestamp"])
    d["mob_pattern"] = d.mob_pattern.astype(str).str.lower()
    print(f"{len(d):,} labelled records; labels: {d.label.value_counts().to_dict()}")
    print(f"mobility patterns: {d.mob_pattern.value_counts().to_dict()}")
    benign = sorted({l for l in d.label.unique() if any(h in str(l).lower() for h in BENIGN_HINTS)})
    print(f"benign classes (binary task): {benign}")

    tr, wnames = windowed(d[d.mob_pattern.isin(TRAIN_PAT)])
    te, _ = windowed(d[d.mob_pattern.isin(TEST_PAT)])
    print(f"train {len(tr):,}  test {len(te):,}  (load + features {time.time()-t0:.0f} s)")
    sets = {"baseline": BASE, "extended": BASE + EXTRA, "proposed": BASE + EXTRA + wnames}
    yte_multi = te.label.values
    yte_bin = np.where(te.label.isin(benign), "benign", "attack")

    rows = []
    for s in range(a.seeds):
        rng = np.random.default_rng(s)
        sample = tr[rng.random(len(tr)) < a.rho]          # same sample for the three feature sets
        ytr_multi = sample.label.values
        ytr_bin = np.where(sample.label.isin(benign), "benign", "attack")
        for name, feats in sets.items():
            for task, ytr, yte in (("multi", ytr_multi, yte_multi), ("binary", ytr_bin, yte_bin)):
                if task not in a.tasks.split(","):
                    continue
                rf = RandomForestClassifier(n_estimators=100, max_depth=15, min_samples_split=5,
                                            random_state=s, n_jobs=a.jobs)
                rf.fit(sample[feats].values, ytr)
                p = rf.predict(te[feats].values)
                r = dict(seed=s, features=name, task=task, n_train=len(sample),
                         macro_f1=f1_score(yte, p, average="macro"), accuracy=accuracy_score(yte, p))
                if task == "binary":
                    r["attack_f1"] = f1_score(yte, p, pos_label="attack")
                else:
                    for c, f in zip(sorted(set(yte)), f1_score(yte, p, average=None, labels=sorted(set(yte)))):
                        r["f1_" + str(c)] = f
                rows.append(r)
        print(f"seed {s} done ({time.time()-t0:.0f} s): " + ", ".join(
            f"{x['features']}/{x['task']} {x['macro_f1']:.3f}" for x in rows if x['seed'] == s))
    R = pd.DataFrame(rows)
    R.to_csv(a.out, index=False)

    print("\nMean +- std over seeds, 95% CI of the mean:")
    for task in [t for t in ("multi", "binary") if t in a.tasks.split(",")]:
        for name in sets:
            x = R[(R.task == task) & (R.features == name)]
            for m in (["macro_f1", "accuracy"] + (["attack_f1"] if task == "binary" else [])):
                lo, hi = ci95(x[m])
                print(f"  {task:6s} {name:9s} {m:10s} {x[m].mean():.3f} +- {x[m].std(ddof=1):.3f}  [{lo:.3f}, {hi:.3f}]")
    print("\nPaired differences over seeds (same training sample):")
    for task in [t for t in ("multi", "binary") if t in a.tasks.split(",")]:
        piv = R[R.task == task].pivot(index="seed", columns="features", values="macro_f1")
        for x, y in (("proposed", "baseline"), ("extended", "baseline"), ("proposed", "extended")):
            dlt = piv[x] - piv[y]
            p = stats.wilcoxon(dlt).pvalue if len(dlt) >= 6 and dlt.abs().sum() > 0 else np.nan
            lo, hi = ci95(dlt)
            print(f"  {task:6s} {x} - {y}: {dlt.mean():+.3f} [{lo:+.3f}, {hi:+.3f}], "
                  f"{(dlt > 0).sum()}/{len(dlt)} seeds positive, Wilcoxon p={p:.4f}")
    print(f"\nresults per seed -> {a.out}   (total {time.time()-t0:.0f} s)")


if __name__ == "__main__":
    main()
