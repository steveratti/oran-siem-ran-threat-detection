#!/usr/bin/env python3
"""Jamming rule alone for k = 1, 3, 5, 10 (Table: jamming rule in the triage deployment)."""
import os, numpy as np, pandas as pd
WARM, GAMMA = 10, -12.0
use = ["run", "cond", "seed", "t_ms", "ue_id", "pdcp_thr_kbps", "sinr_db"]
D = pd.concat([pd.read_csv(f, usecols=use) for f in ("scenarioA_splunk.csv", "scenarioJ_splunk.csv")])
D["w"] = (D.t_ms // 1000).astype(int)
print("events:", D.groupby("cond").size().to_dict(), " runs:", D.run.nunique())
meta = D.groupby("run")[["cond", "seed"]].first()
F = D.groupby(["run", "ue_id", "w"]).pdcp_thr_kbps.mean().dropna()      # SPL: stats avg(pdcp_thr_kbps) by run ue_id _time
F = F[F.index.get_level_values("w") >= WARM]
J = D.assign(low=(D.sinr_db < GAMMA).astype(int)).groupby(["run", "w"]).low.sum()   # SPL: eval low=if(sinr_db<-12,1,0) | stats sum(low)
def rmin(s, K):
    return s.groupby(level=list(range(s.index.nlevels - 1)), group_keys=False).apply(lambda g: g.rolling(K).min())
def first_alarm(m, th, by):
    hit = m[m > th].reset_index()
    return hit.groupby(by).w.min() if len(hit) else pd.Series(dtype=float)
truth = {"ctrl": "normal", "a5": "flood", "a10": "flood", "a20": "flood", "j50": "jamming"}
tune_ctrl = meta[(meta.cond == "ctrl") & (meta.seed <= 5)].index
tune_free = meta[(meta.cond != "j50") & (meta.seed <= 5)].index
test = meta[meta.seed >= 6]
print("\nJamming rule alone (test seeds 6-30), N_al fitted on the 20 jammer-free tuning runs:")
print(" K  N_al  j50 detected  ctrl false  flood-run false  j50 alarm time [s] median / max")
for K in (1, 3, 5, 10):
    mj = rmin(J, K)
    N = int(mj[mj.index.get_level_values("run").isin(tune_free)].max()) + 1
    tj = first_alarm(mj, N - 0.5, "run")
    det = lambda conds: sum(r in tj.index for r in test[test.cond.isin(conds)].index)
    tt = tj.reindex(test[test.cond == "j50"].index).dropna() + 1
    print(f"{K:2d}  {N:4d}     {det(['j50']):2d}/25        {det(['ctrl']):2d}/25        {det(['a5','a10','a20']):2d}/75          {tt.median():.1f} / {tt.max():.0f}")
for K in (3, 10):
    mf = rmin(F, K); mj = rmin(J, K)
    TH = mf[mf.index.get_level_values("run").isin(tune_ctrl)].max() + 1e-6
    N = int(mj[mj.index.get_level_values("run").isin(tune_free)].max()) + 1
    tf = first_alarm(mf, TH, "run"); tj = first_alarm(mj, N - 0.5, "run")
    R = test.copy()
    R["t_flood"] = tf.reindex(R.index) + 1; R["t_jam"] = tj.reindex(R.index) + 1
    R["truth"] = R.cond.map(truth)
    R["decision"] = np.select([R.t_flood.notna() & R.t_jam.notna(), R.t_jam.notna(), R.t_flood.notna()],
                              ["jamming+flood", "jamming", "flood"], "normal")
    R.to_csv(f"triage_csv_K{K}.csv")
    print(f"\n===== TRIAGE K = {K} s: flood theta = {TH:.1f} kb/s (5 ctrl tuning runs), jamming N_al = {N} (20 jammer-free tuning runs) =====")
    print(pd.crosstab(R.cond, R.decision).to_string())
    print(f"correct run-level decisions: {(R.decision == R.truth).sum()}/{len(R)}")
    print("alarm time [s], flood runs (flood from 10 s): median", R[R.truth == "flood"].t_flood.median(), "max", R[R.truth == "flood"].t_flood.max(),
          "| jammer runs (jammer from 0 s): median", R[R.cond == "j50"].t_jam.median(), "max", R[R.cond == "j50"].t_jam.max())
    print("wrong:"); print(R[R.decision != R.truth][["cond", "decision", "t_flood", "t_jam"]].to_string())
    if os.path.isfile(f"triage_final_K{K}.csv"):
        P = pd.read_csv(f"triage_final_K{K}.csv").set_index("run")
        print("runs whose decision differs from the raw-file computation:", int((P.decision.reindex(R.index) != R.decision).sum()))
