#!/usr/bin/env python3
"""Jamming rule on the raw KPM files: transfer of the Scenario B threshold (N_al = 11, k = 1) to the
triage deployment, and the effect of the tuning pool (5 control runs vs 20 jammer-free runs).
Run in the folder that holds the full_* run folders and anomaly_eval.py."""
import glob, os, re
import numpy as np, pandas as pd
import anomaly_eval as A
GAMMA = -12.0
def low_counts(run):
    parts = []
    for f in glob.glob(os.path.join(run, "cu-cp-cell-*.txt")):
        if int(re.findall(r"cell-(\d+)", f)[0]) == 1:
            continue
        d = A.read(f); col = A.pick(d, "L3 serving SINR")
        if col is None:
            continue
        uecol = "UE (imsi)" if "UE (imsi)" in d.columns else "ueImsiComplete"
        ok = pd.to_numeric(d["timestamp"], errors="coerce").notna()
        ts = d.loc[ok, "timestamp"].str.strip().str.split(".").str[0].astype("int64")
        parts.append(pd.DataFrame({"t": (ts - ts.min() + 50).values,
                                   "ue": pd.to_numeric(d.loc[ok, uecol], errors="coerce").values,
                                   "v": pd.to_numeric(d.loc[ok, col], errors="coerce").values}).dropna())
    x = pd.concat(parts).groupby(["t", "ue"], as_index=False).v.max()
    x["w"] = (x.t // 1000).astype(int)
    c = x.assign(low=x.v < GAMMA).groupby("w").low.sum()
    return c.reindex(range(0, int(x.w.max()) + 1), fill_value=0)
runs = {}
for r in sorted(glob.glob("full_*_r*")):
    m = re.match(r"full_(ctrl|a5|a10|a20|j50)_r(\d+)$", r)
    if m and os.path.isfile(r + "/done"):
        runs[r] = (m.group(1), int(m.group(2)))
C = {r: low_counts(r) for r in runs}
first = lambda c, N, K: (lambda h: None if h.empty else int(h.index[0]))(c.rolling(K).min()[lambda s: s >= N])
test = lambda conds: [r for r, (c, s) in runs.items() if s >= 6 and c in conds]
print("Scenario B threshold N_al = 11, k = 1 on this deployment: jamming alarms in",
      sum(first(C[r], 11, 1) is not None for r in test(["ctrl"])), "of", len(test(["ctrl"])), "test control runs")
pools = {"5 control runs": [r for r, (c, s) in runs.items() if c == "ctrl" and s <= 5],
         "20 jammer-free runs": [r for r, (c, s) in runs.items() if c != "j50" and s <= 5]}
for K in (1, 3, 5, 10):
    for name, T in pools.items():
        N = int(max(C[r].rolling(K).min().max() for r in T)) + 1
        print(f"k={K:2d} tuned on {name:20s} N_al={N:3d}  jammer detected {sum(first(C[r], N, K) is not None for r in test(['j50']))}/25"
              f"  control false {sum(first(C[r], N, K) is not None for r in test(['ctrl']))}/25"
              f"  flood-run false {sum(first(C[r], N, K) is not None for r in test(['a5', 'a10', 'a20']))}/75")
