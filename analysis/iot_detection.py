#!/usr/bin/env python3
"""Scenario D: per-UE persistence rule with transferred, refitted and class-aware thresholds (asset lookup)."""
import numpy as np, pandas as pd
START = 10
D = pd.read_csv("scenarioD_splunk.csv", usecols=["run", "cond", "seed", "t_ms", "ue_id", "pdcp_thr_kbps", "attacker"])
cls = pd.read_csv("iot_assets.csv").set_index("ue_id").dev_class
D["w"] = (D.t_ms // 1000).astype(int)
meta = D.groupby("run")[["cond", "seed"]].first()
att = D.groupby(["run", "ue_id"]).attacker.max()
F = D.groupby(["run", "ue_id", "w"]).pdcp_thr_kbps.mean().dropna()
tune = meta[(meta.cond == "iotc") & (meta.seed <= 5)].index
test = meta[meta.seed >= 6]
print("runs:", meta.groupby("cond").size().to_dict(), " test runs:", test.groupby("cond").size().to_dict())
def rmin(K):
    return F.groupby(level=[0, 1], group_keys=False).apply(lambda g: g.rolling(K).min())
for K in (3, 10):
    m = rmin(K).dropna()
    mt = m[m.index.get_level_values("run").isin(tune)]
    c_t = cls.reindex(mt.index.get_level_values("ue_id")).values
    th_g = mt.max() + 1e-6
    th = {"mobile": mt[c_t == "mobile"].max() + 1e-6, "iot": mt[c_t == "iot"].max() + 1e-6}
    rules = {"global, Scenario A theta (4812.16)": lambda c: 4812.16,
             f"global, refitted ({th_g:.2f})": lambda c: th_g,
             f"class-aware (mobile {th['mobile']:.2f}, IoT {th['iot']:.2f})": lambda c: th[c]}
    print(f"\n===== persistence k = {K} s, thresholds fitted on {len(tune)} IoT control tuning runs (seeds 1-5) =====")
    mm = m[m.index.get_level_values("run").isin(test.index)].reset_index(name="mk")
    mm["cls"] = cls.reindex(mm.ue_id).values
    mm["att"] = [att.get((r, u), 0) for r, u in zip(mm.run, mm.ue_id)]
    n_vic = int(sum(att.get((r, u), 0) for r in test.index for u in cls.index))
    for name, f in rules.items():
        hit = mm[mm.mk > mm.cls.map(f)]
        first = hit.groupby(["run", "ue_id", "cls", "att"]).w.min().reset_index()
        tp = first[(first.att == 1) & (first.w >= START)]
        fp = first[first.att == 0]
        print(f"  {name:45s} victims detected {len(tp):2d}/{n_vic}  (time after start median {(tp.w + 1 - START).median()}, max {(tp.w + 1 - START).max()})"
              f" | false alarms: IoT {int((fp.cls == 'iot').sum())}, mobile {int((fp.cls == 'mobile').sum())} UE-runs")
v = D[(D.attacker == 1) & (D.w >= START + 1)].groupby("run").pdcp_thr_kbps.mean()
print("\nvictim PDCP throughput after the start, per run [kb/s]: median", round(v.median(), 1), "min", round(v.min(), 1), "max", round(v.max(), 1))
b = D[(D.cond == "iotc")].assign(cls=lambda x: cls.reindex(x.ue_id).values).groupby("cls").pdcp_thr_kbps.max()
print("largest 50 ms PDCP throughput in control runs, per class [kb/s]:", b.round(1).to_dict())
