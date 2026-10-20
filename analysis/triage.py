#!/usr/bin/env python3
"""Joint triage (flood rule per UE + jamming rule per run, same persistence k), Section V of the paper.
Reads scenarioA_splunk.csv, scenarioJ_splunk.csv, scenarioAJ_splunk.csv; thresholds fitted on seeds 1-5 only."""
import numpy as np, pandas as pd
WARM, GAMMA, START = 10, -12.0, 10
use = ["run", "cond", "seed", "t_ms", "ue_id", "pdcp_thr_kbps", "sinr_db", "attacker"]
D = pd.concat([pd.read_csv(f, usecols=use) for f in ("scenarioA_splunk.csv", "scenarioJ_splunk.csv", "scenarioAJ_splunk.csv")])
D["w"] = (D.t_ms // 1000).astype(int)
print("events:", D.groupby("cond").size().to_dict())
meta = D.groupby("run")[["cond", "seed"]].first()
att = D.groupby(["run", "ue_id"]).attacker.max()
F = D.groupby(["run", "ue_id", "w"]).pdcp_thr_kbps.mean().dropna()
Fw = F[F.index.get_level_values("w") >= WARM]
J = D.assign(low=(D.sinr_db < GAMMA).astype(int)).groupby(["run", "w"]).low.sum()
def rmin(s, K):
    return s.groupby(level=list(range(s.index.nlevels - 1)), group_keys=False).apply(lambda g: g.rolling(K).min())
truth = {"ctrl": "normal", "a5": "flood", "a10": "flood", "a20": "flood", "j50": "jamming", "a10j50": "jamming+flood"}
tune_ctrl = meta[(meta.cond == "ctrl") & (meta.seed <= 5)].index
tune_free = meta[(~meta.cond.isin(["j50", "a10j50"])) & (meta.seed <= 5)].index
test = meta[meta.seed >= 6]
for K in (3, 10):
    mf = rmin(Fw, K); mj = rmin(J, K)
    TH = mf[mf.index.get_level_values("run").isin(tune_ctrl)].max() + 1e-6
    N = int(mj[mj.index.get_level_values("run").isin(tune_free)].max()) + 1
    hf = mf[mf > TH].reset_index(); hj = mj[mj >= N].reset_index()
    tf = hf.groupby("run").w.min(); tj = hj.groupby("run").w.min()
    R = test.copy()
    R["t_flood"] = tf.reindex(R.index) + 1; R["t_jam"] = tj.reindex(R.index) + 1
    R["truth"] = R.cond.map(truth)
    R["decision"] = np.select([R.t_flood.notna() & R.t_jam.notna(), R.t_jam.notna(), R.t_flood.notna()],
                              ["jamming+flood", "jamming", "flood"], "normal")
    R.to_csv(f"triage2_K{K}.csv")
    print(f"\n===== TRIAGE K = {K} s: theta = {TH:.2f} kb/s, N_al = {N} (same tuning runs as before) =====")
    print(pd.crosstab(R.cond, R.decision).to_string())
    print("correct, all runs:", int((R.decision == R.truth).sum()), "/", len(R),
          "| without a10j50:", int((R[R.cond != "a10j50"].decision == R[R.cond != "a10j50"].truth).sum()), "/", int((R.cond != "a10j50").sum()))
    x = R[R.cond == "a10j50"]
    print("a10j50: flood alarm in", int(x.t_flood.notna().sum()), "| jamming alarm in", int(x.t_jam.notna().sum()), "of", len(x),
          "| t_flood median/max", x.t_flood.median(), x.t_flood.max(), "| t_jam median/max", x.t_jam.median(), x.t_jam.max())
    # per-UE: which UEs raise the flood alarm (from the flood start on for flooded UEs)
    ue = hf.groupby(["run", "ue_id"]).w.min().rename("w_alarm").reset_index()
    ue["attacker"] = [att.get((r, u), 0) for r, u in zip(ue.run, ue.ue_id)]
    for c in [c for c in ("a10", "a10j50") if c in set(test.cond)]:
        runs = test[test.cond == c].index
        n_att = int(sum(att.get((r, u), 0) for r in runs for u in D[D.run == r].ue_id.unique()))
        u = ue[ue.run.isin(runs)]
        tp = u[(u.attacker == 1) & (u.w_alarm >= START)]
        print(f"  {c}: flooded UEs flagged {len(tp)}/{n_att} (time after start median {(tp.w_alarm + 1 - START).median()}), "
              f"benign UEs flagged {int((u.attacker == 0).sum())}")
# does the jammer reduce what the flooded UEs receive?
A2 = D[(D.w >= START + 1) & (D.attacker == 1) & D.cond.isin(["a10", "a10j50"])].groupby(["cond", "run"]).pdcp_thr_kbps.mean().groupby("cond").median()
print("\nmedian per-run mean PDCP throughput of the flooded UEs after the start [kb/s]:", A2.round(0).to_dict())
