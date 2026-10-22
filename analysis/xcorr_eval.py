#!/usr/bin/env python3
"""Scenario E: RAN-only, IT-only and correlated detection, offline counterpart of spl/xcorr_*.spl.
Usage: in the folder with the files written by xcorr_convert.py: python3 <repo>/analysis/xcorr_eval.py"""
# Cross-layer (RAN-IT) correlation in the SIEM: offline counterpart of the SPL searches.
# Rules are fitted ONLY on control runs of seeds 1-5; all results are on seeds 6-15.
import warnings; warnings.filterwarnings("ignore")
import numpy as np, pandas as pd
from scipy.stats import beta
START, WARM, GAMMA = 10, 10, -12.0
P_SCAN = 15   # Zeek default Scan::port_scan_threshold (unique ports of one scanner on one victim host)
EXT = "2.0.0.2"
R = pd.read_csv("xcorr_ran.csv", usecols=["run", "cond", "seed", "t_ms", "ue_id", "pdcp_thr_kbps", "sinr_db", "cell"])
I = pd.read_csv("xcorr_it.csv")
B = pd.read_csv("xcorr_ueip.csv")
T = pd.read_csv("xcorr_truth.csv")
CLS = pd.read_csv("xcorr_assets.csv").set_index("ue_id").dev_class
KNOWN = set(pd.read_csv("known_services.csv").query("trusted == 1").ip)
R["w"] = (R.t_ms // 1000).astype(int); I["w"] = I.t_s.astype(int)
meta = R.groupby("run")[["cond", "seed"]].first()
dep = lambda c: "iot" if c.startswith("iot") else "ue"
meta["dep"] = meta.cond.map(dep)
ip2imsi = {(r.run, r.ue_ip): r.imsi for r in B.itertuples()}
imsi2ip = {(r.run, r.imsi): r.ue_ip for r in B.itertuples()}
role = {(r.run, r.imsi): r.role for r in T.itertuples()}
tune_ctrl = meta[meta.cond.isin(["ctrl", "iotc"]) & (meta.seed <= 5)].index
tune_nojam = meta[meta.cond.isin(["ctrl", "a10", "scan", "iotc", "iotbv"]) & (meta.seed <= 5)].index
test = meta[meta.seed >= 6].copy()
print("runs per condition (all / test):", meta.cond.value_counts().to_dict(), "/", test.cond.value_counts().to_dict())

def cp(k, n):   # exact 95% Clopper-Pearson interval
    lo = 0.0 if k == 0 else beta.ppf(0.025, k, n - k + 1)
    hi = 1.0 if k == n else beta.ppf(0.975, k + 1, n - k)
    return f"{k}/{n} [{100*lo:.1f}, {100*hi:.1f}]%"

def rmin(s, K, fill=None):
    """rolling minimum over K consecutive 1 s windows within each group (last index level = w)"""
    lv = list(range(s.index.nlevels - 1)); out = []
    for key, g in s.groupby(level=lv):
        g = g.droplevel(lv).sort_index()
        if fill is not None:
            g = g.reindex(range(g.index.min(), max(g.index.max(), 0) + 1), fill_value=fill)
        r = g.rolling(K).min().dropna()
        key = key if isinstance(key, tuple) else (key,)
        r.index = pd.MultiIndex.from_tuples([key + (w,) for w in r.index], names=s.index.names)
        out.append(r)
    return pd.concat(out)

# ---------- features ----------
Fr = R.groupby(["run", "ue_id", "w"]).pdcp_thr_kbps.mean().dropna()                       # RAN: PDCP per UE
Jr = R.assign(low=(R.sinr_db < GAMMA).astype(int)).groupby(["run", "w"]).low.sum()           # RAN: low-SINR reports per run
CELL = R.dropna(subset=["cell"]).groupby(["run", "ue_id", "w"]).cell.agg(lambda c: c.mode().iloc[0])
SINR = R.groupby(["run", "ue_id", "w"]).sinr_db.mean()
DL = I[I.direction == "dl"].groupby(["run", "dst_ip", "src_ip", "w"]).bytes.sum() * 8 / 1000  # IT: kb/s per source -> UE
UL = I[I.direction == "ul"].groupby(["run", "src_ip", "w"]).bytes.sum() * 8 / 1000           # IT: uplink kb/s per UE
IBY = {r: g for r, g in I.groupby("run")}
PT = I[(I.direction == "ul") & (I.proto == 17)].groupby(["run", "src_ip", "dst_ip", "w"]).dst_port.nunique()  # IT: distinct ports per victim

def cls_of_ip(run, ip):
    return CLS.get(ip2imsi.get((run, ip), -1), "mobile")

def fit(m, cls_fun):   # largest value in the tuning control runs (w >= WARM), per device class
    x = m[m.index.get_level_values("run").isin(tune_ctrl) & (m.index.get_level_values("w") >= WARM)]
    c = np.array([cls_fun(k) for k in x.index])
    # a class without any traffic of this kind in the control runs gets threshold 0 (any traffic is anomalous)
    return {k: (float(x[c == k].max()) if (c == k).any() else 0.0) + 1e-6 for k in ("mobile", "iot")}

rows = []
for K in (3, 10):
    mF = rmin(Fr, K); mJ = rmin(Jr, K)
    mD = rmin(DL, K, fill=0.0); mU = rmin(UL, K, fill=0.0); mP = rmin(PT, K, fill=0)
    thF = fit(mF, lambda k: CLS.get(k[1], "mobile"))
    thD = fit(mD, lambda k: cls_of_ip(k[0], k[1]))
    thU = fit(mU, lambda k: cls_of_ip(k[0], k[1]))
    xP = mP[mP.index.get_level_values("run").isin(tune_ctrl) & (mP.index.get_level_values("w") >= WARM)]
    P_fit = int(xP.max()) if len(xP) else 0
    P = P_SCAN
    xJ = mJ[mJ.index.get_level_values("run").isin(tune_nojam)]
    NJ = {d: int(xJ[[meta.dep[r] == d for r in xJ.index.get_level_values("run")]].max()) + 1 for d in ("ue", "iot")}
    print(f"\n================ persistence k = {K} s ================")
    print("thresholds (fitted on control runs, seeds 1-5): RAN PDCP", {k: round(v, 1) for k, v in thF.items()},
          "| IT DL per source", {k: round(v, 1) for k, v in thD.items()}, "| IT UL", {k: round(v, 1) for k, v in thU.items()},
          "| IT distinct ports P =", P, f"(largest in control runs: {P_fit})", "| RAN low-SINR count N =", NJ)
    sel = lambda m: m[m.index.get_level_values("run").isin(test.index) & (m.index.get_level_values("w") >= WARM)]
    # ---- RAN-side alarms ----
    a = sel(mF).reset_index(name="v"); a["cls"] = a.ue_id.map(lambda u: CLS.get(u, "mobile"))
    ranF = a[a.v > a.cls.map(thF)].groupby(["run", "ue_id"]).w.min().reset_index()
    a = sel(mJ).reset_index(name="v"); a["dep"] = a.run.map(meta.dep)
    ranJ = a[a.v >= a.dep.map(NJ)].groupby("run").w.min()
    # ---- IT-side alarms ----
    a = sel(mD).reset_index(name="v"); a["cls"] = [cls_of_ip(r, ip) for r, ip in zip(a.run, a.dst_ip)]
    itD = a[a.v > a.cls.map(thD)].groupby(["run", "dst_ip", "src_ip"]).w.min().reset_index()
    a = sel(mU).reset_index(name="v"); a["cls"] = [cls_of_ip(r, ip) for r, ip in zip(a.run, a.src_ip)]
    itU = a[a.v > a.cls.map(thU)].groupby(["run", "src_ip"]).w.min().reset_index()
    a = sel(mP).reset_index(name="v")
    itS = a[a.v >= P].groupby(["run", "src_ip"]).w.min().reset_index()
    # ---- correlation ----
    def top_source(run, imsi, w):   # source with most bytes to the UE in the K alarm windows
        ip = imsi2ip.get((run, imsi)); Ir = IBY[run]
        x = Ir[(Ir.dst_ip == ip) & (Ir.w > w - K) & (Ir.w <= w)].groupby("src_ip").bytes.sum()
        return (x.idxmax(), x.max() / x.sum()) if len(x) else (None, np.nan)
    def where(run, imsi, w):        # serving cell and SINR of the UE in the K alarm windows (from RAN)
        c = CELL.loc[run, imsi] if (run, imsi) in CELL.index else pd.Series(dtype=float)
        c = c[(c.index > w - K) & (c.index <= w)]
        s = SINR.loc[run, imsi] if (run, imsi) in SINR.index else pd.Series(dtype=float)
        s = s[(s.index > w - K) & (s.index <= w)]
        return (int(c.mode().iloc[0]) if len(c) else None, round(float(s.mean()), 1) if s.notna().any() else None)
    ranF["role"] = [role.get((r, u), "none") for r, u in zip(ranF.run, ranF.ue_id)]
    src = [top_source(r, u, w) for r, u, w in zip(ranF.run, ranF.ue_id, ranF.w)]
    ranF["src"] = [s for s, _ in src]; ranF["share"] = [x for _, x in src]
    ranF["suppressed"] = ranF.src.isin(KNOWN)
    itU["imsi"] = [ip2imsi.get((r, ip)) for r, ip in zip(itU.run, itU.src_ip)]
    itS["imsi"] = [ip2imsi.get((r, ip)) for r, ip in zip(itS.run, itS.src_ip)]
    for d in (itU, itS):
        d["role"] = [role.get((r, u), "none") for r, u in zip(d.run, d.imsi)]
        d["cls"] = d.imsi.map(lambda u: CLS.get(u, "mobile"))
        loc = [where(r, u, w) for r, u, w in zip(d.run, d.imsi, d.w)]
        d["cell"] = [c for c, _ in loc]; d["sinr"] = [s for _, s in loc]
    itD["imsi"] = [ip2imsi.get((r, ip)) for r, ip in zip(itD.run, itD.dst_ip)]
    itD["suppressed"] = itD.src_ip.isin(KNOWN)   # allow-listed operator service
    itD["role"] = [role.get((r, u), "none") for r, u in zip(itD.run, itD.imsi)]
    # ---- per-attack outcome: RAN only / IT only / correlated ----
    tt = T[T.run.isin(test.index)]
    print("\nper attacked entity (test seeds 6-15): detected by RAN | detected by IT | correlated: source / IMSI / cell")
    for rl in ("flood_target", "bot", "scanner", "jammer"):
        g = tt[tt.role == rl]; n = len(g)
        if n == 0:
            continue
        if rl == "jammer":
            dr = sum(r in ranJ.index for r in g.run)
            di = sum(((itD.run == r) & (itD.role == "none") & (itD.src_ip == EXT)).any() for r in g.run)
            print(f"  jammer        n={n:3d}  RAN {cp(dr, n)} | IT (external source on a non-target UE) {di}/{n} -> classified radio-layer in {dr - min(dr, di)}/{n}")
            continue
        k_r = g.apply(lambda x: ((ranF.run == x.run) & (ranF.ue_id == x.imsi) & (ranF.w >= START)).any(), axis=1).sum()
        k_d = g.apply(lambda x: ((itD.run == x.run) & (itD.imsi == x.imsi)).any(), axis=1).sum()
        k_u = g.apply(lambda x: ((itU.run == x.run) & (itU.imsi == x.imsi)).any(), axis=1).sum()
        k_s = g.apply(lambda x: ((itS.run == x.run) & (itS.imsi == x.imsi)).any(), axis=1).sum()
        if rl == "flood_target":
            hit = ranF[(ranF.role == rl) & (ranF.w >= START)]
            hit = hit.merge(g[["run", "imsi"]], left_on=["run", "ue_id"], right_on=["run", "imsi"])
            attr = int((hit.src == EXT).sum())
            byc = g.assign(cls=g.imsi.map(lambda u: CLS.get(u, "mobile"))).groupby("cls").size().to_dict()
            print(f"  flood target  n={n:3d} {byc}  RAN {cp(k_r, n)} | IT {cp(k_d, n)} | source {EXT} named for {attr}/{len(hit)} RAN alarms "
                  f"(median byte share {hit.share.median():.2f}), median time {(hit.w + 1 - START).median()} s")
        else:
            d = itU if rl == "bot" else itS
            h = d[d.role == rl]
            print(f"  {rl:13s} n={n:3d}  RAN {cp(k_r, n)} | IT {'UL volume' if rl == 'bot' else 'port rule'} {cp(k_u if rl == 'bot' else k_s, n)} | "
                  f"IMSI resolved {h.imsi.notna().sum()}/{len(h)}, class {h.cls.value_counts().to_dict()}, cell known {h.cell.notna().sum()}/{len(h)}, "
                  f"median time {(h.w + 1 - START).median()} s, cells {h.cell.value_counts().to_dict()}")
    # ---- false alarms on test runs ----
    n_ue = R[R.run.isin(test.index)].groupby("run").ue_id.nunique().sum()
    fpR = ranF[ranF.role == "none"]; fpD = itD[itD.role == "none"]; fpU = itU[itU.role == "none"]; fpS = itS[itS.role == "none"]
    jamfree = test[~test.cond.isin(["j50", "a10j50"])].index
    print(f"\nfalse alarms (test): RAN flood {len(fpR)} UE-runs of {n_ue} (after allow-list correlation: {int((~fpR.suppressed).sum())}; "
          f"sources {fpR.src.value_counts().to_dict()}) | IT DL {len(fpD)} (after allow-list: {int((~fpD.suppressed).sum())}) | IT UL {len(fpU)} | IT ports {len(fpS)} | "
          f"RAN jamming {cp(int(ranJ.index.isin(jamfree).sum()), len(jamfree))} of jammer-free runs")
    # ---- run-level triage: RAN only vs IT only vs correlated ----
    truth = {"ctrl": set(), "a10": {"flood"}, "j50": {"jam"}, "a10j50": {"jam", "flood"}, "iotc": set(),
             "iotbv": {"flood", "bot"}, "scan": {"scan"}}
    out = []
    for r, x in test.iterrows():
        fr = ranF[(ranF.run == r)]; fr_c = fr[~fr.suppressed]
        ran = ({"flood"} if len(fr) else set()) | ({"jam"} if r in ranJ.index else set())
        dI = itD[(itD.run == r) & ~itD.suppressed]
        itl = ({"flood"} if len(dI) else set()) | \
              ({"bot"} if ((itU.run == r) & (itU.cls == "iot")).any() else set()) | \
              ({"scan"} if (itS.run == r).any() else set())
        cor = ({"flood"} if (len(fr_c) or len(dI)) else set()) | ({"jam"} if r in ranJ.index else set()) | \
              (itl - {"flood"})
        out.append((r, x.cond, truth[x.cond], ran, itl, cor))
    D = pd.DataFrame(out, columns=["run", "cond", "truth", "ran_only", "it_only", "correlated"])
    print("\nrun-level triage (exact label set correct), test runs:")
    for c in ["ran_only", "it_only", "correlated"]:
        ok = D[c] == D.truth
        print(f"  {c:11s} {int(ok.sum())}/{len(D)}  per condition:", D.assign(ok=ok).groupby("cond").ok.sum().astype(int).to_dict())
    D.assign(**{c: D[c].map(lambda s: "+".join(sorted(s)) or "normal") for c in ["truth", "ran_only", "it_only", "correlated"]}).to_csv(f"xcorr_triage_K{K}.csv", index=False)
    rows.append((K, D))
# ---- offered (IT) vs delivered (RAN) traffic for the flooded UEs, with and without the jammer ----
off = I[(I.direction == "dl") & (I.w >= START + 1)].groupby(["run", "dst_ip"]).bytes.sum() * 8 / 1000
dl = R[R.w >= START + 1].groupby(["run", "ue_id", "w"]).pdcp_thr_kbps.mean().groupby(["run", "ue_id"]).sum()
x = T[T.role == "flood_target"].copy()
x["offered"] = [off.get((r, imsi2ip.get((r, u))), np.nan) for r, u in zip(x.run, x.imsi)]
x["delivered"] = [dl.get((r, u), np.nan) for r, u in zip(x.run, x.imsi)]
x["ratio"] = x.delivered / x.offered
print("\ndelivered (RAN PDCP) / offered (IT flow) for flooded UEs, median per condition:", x.groupby("cond").ratio.median().round(3).to_dict())
