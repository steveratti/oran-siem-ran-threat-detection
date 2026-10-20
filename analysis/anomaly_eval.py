#!/usr/bin/env python3
"""
Scenario A (resource-exhaustion UE): per-UE detection from E2 KPM, as the SIEM would do it.

Per run it reads the E2 KPM files (cu-up: PDCP throughput / volume / delay, du: RLC buffer,
cu-cp: L3 serving SINR) and anomaly.txt (ground truth), builds 1 s windows per UE, and
applies a persistence rule:   a UE is flagged when KPI > theta for k consecutive windows.

theta and k are fitted ONLY on the attack-free control runs of the tuning seeds (no false
alarm allowed there); everything is then evaluated on the test seeds.

Usage (in ~/anomaly_runs):
  python3 anomaly_eval.py --prefix full --train 1-5 --test 6-30
  python3 anomaly_eval.py --prefix pilot --train 1-1 --test 1-1      (only to check it runs)
"""
import argparse, glob, os, re, sys, warnings
warnings.filterwarnings("ignore")
import numpy as np
import pandas as pd

KPIS = {  # name -> (file kind, column prefix, direction: +1 = high is anomalous, -1 = low)
    "pdcp_thr_kbps": ("cu-up", "DRB.PdcpSduBitRateDl.UEID", +1),
    "pdcp_vol":      ("cu-up", "DRB.PdcpSduVolumeDl_Filter.UEID", +1),
    "pdcp_delay_ms": ("cu-up", "DRB.PdcpSduDelayDl.UEID", +1),
    "rlc_buffer":    ("du",    "DRB.BufferSize.Qos.UEID", +1),
    "sinr_db":       ("cu-cp", "L3 serving SINR", -1),
}


def read(f):
    d = pd.read_csv(f, index_col=False, encoding="latin-1", dtype={"timestamp": str})
    d.columns = d.columns.str.strip()
    return d.loc[:, ~d.columns.str.startswith("Unnamed")]


def pick(d, prefix):
    cands = [c for c in d.columns if c.startswith(prefix)
             and not (prefix == "L3 serving SINR" and "3gpp" in c)]
    if not cands:
        return None
    return max(cands, key=lambda c: pd.to_numeric(d[c], errors="coerce").notna().sum())


def load_run(run):
    frames = []
    for kpi, (kind, prefix, _) in KPIS.items():
        parts = []
        for f in glob.glob(os.path.join(run, f"{kind}-cell-*.txt")):
            if int(re.findall(r"cell-(\d+)", f)[0]) == 1 and kind != "cu-up":
                continue
            d = read(f)
            col = pick(d, prefix)
            if col is None:
                continue
            uecol = "UE (imsi)" if kind == "cu-cp" and "UE (imsi)" in d.columns else "ueImsiComplete"
            # timestamps are ms with a large, file-specific offset (up to ~2e18): keep them as
            # exact integers and convert to simulation time = ts - first ts of the file + 50 ms
            ts = pd.to_numeric(d["timestamp"], errors="coerce", downcast=None)
            ok = ts.notna()
            ts_int = d.loc[ok, "timestamp"].str.strip().str.split(".").str[0].astype("int64")
            x = pd.DataFrame({"t_ms": (ts_int - ts_int.min() + 50).values,
                              "ue": pd.to_numeric(d.loc[ok, uecol], errors="coerce").values,
                              "v": pd.to_numeric(d.loc[ok, col], errors="coerce").values}).dropna()
            parts.append(x)
        if not parts:
            continue
        x = pd.concat(parts)
        x = x.groupby(["t_ms", "ue"], as_index=False)["v"].max()   # same report in several files
        x["w"] = (x["t_ms"] // 1000).astype(int)
        frames.append(x.groupby(["ue", "w"])["v"].mean().rename(kpi))
    win = pd.concat(frames, axis=1).reset_index()
    gt = pd.read_csv(os.path.join(run, "anomaly.txt"))
    return win, gt


def runs(prefix, cond, seeds):
    a, b = (int(v) for v in seeds.split("-"))
    out = []
    for s in range(a, b + 1):
        r = f"{prefix}_{cond}_r{s}"
        if os.path.isfile(os.path.join(r, "done")):
            out.append((s, r))
    return out


def first_alarm(series, theta, k, sign):
    """first window index at which the last k windows all exceed theta, else None"""
    above = (sign * series.values > sign * theta).astype(int)
    if k > 1:
        run_len = np.convolve(above, np.ones(k, int), "valid")
        hits = np.where(run_len == k)[0]
        return None if len(hits) == 0 else series.index[hits[0] + k - 1]
    hits = np.where(above == 1)[0]
    return None if len(hits) == 0 else series.index[hits[0]]


def evaluate(data, kpi, theta, k, sign, start_w):
    """per-UE outcome over a list of (seed, win, gt, anomaly_on)"""
    rows = []
    for seed, win, gt, on in data:
        for ue, g in win.groupby("ue"):
            s = g.set_index("w")[kpi].dropna().sort_index()
            if s.empty:
                continue
            info = gt[gt.imsi == ue]
            att = int(info.attacker.iloc[0]) if len(info) else 0
            prof = info.profile.iloc[0] if len(info) else "?"
            if att and on:
                # attacked UE: only an alarm raised from the attack start on counts as a detection
                fa = first_alarm(s[s.index >= start_w], theta, k, sign)
                rows.append(dict(seed=seed, ue=ue, attacker=1, profile=prof, alarm=fa is not None,
                                 ttd=(fa - start_w + 1) if fa is not None else np.nan))
            else:
                fa = first_alarm(s, theta, k, sign)    # any alarm on a benign UE is a false alarm
                rows.append(dict(seed=seed, ue=ue, attacker=0, profile=prof, alarm=fa is not None,
                                 ttd=np.nan))
    return pd.DataFrame(rows)


def tune(ctrl_data, kpi, sign, ks=(1, 2, 3, 5)):
    """smallest theta per k with zero alarms on the tuning control runs"""
    vals = pd.concat([w[kpi] for _, w, _, _ in ctrl_data]).dropna()
    if vals.empty:
        return {}
    out = {}
    for k in ks:
        # the k-window running min (max for sign<0) must stay below theta in every UE trace
        worst = []
        for _, win, _, _ in ctrl_data:
            for _, g in win.groupby("ue"):
                s = sign * g.set_index("w")[kpi].dropna().sort_index()
                if len(s) >= k:
                    worst.append(s.rolling(k).min().max())
        if worst:
            out[k] = sign * (max(worst) + 1e-9)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prefix", default="full")
    ap.add_argument("--train", default="1-5")
    ap.add_argument("--test", default="6-30")
    ap.add_argument("--start", type=float, default=None, help="attack start [s] (default: from anomaly.txt)")
    a = ap.parse_args()

    conds = sorted({re.match(rf"{a.prefix}_(\w+?)_r\d+$", os.path.basename(p)).group(1)
                    for p in glob.glob(f"{a.prefix}_*_r*") if re.match(rf"{a.prefix}_(\w+?)_r\d+$", os.path.basename(p))})
    if "ctrl" not in conds:
        sys.exit("no control runs found")
    cache = {}

    def get(cond, seeds):
        out = []
        for s, r in runs(a.prefix, cond, seeds):
            if r not in cache:
                cache[r] = load_run(r)
            win, gt = cache[r]
            out.append((s, win, gt, 0 if cond == "ctrl" else 1))
        return out

    tr_ctrl = get("ctrl", a.train)
    te_ctrl = get("ctrl", a.test)
    if not tr_ctrl:
        sys.exit("no finished tuning control runs")
    start = a.start if a.start is not None else float(tr_ctrl[0][2].attack_start_s.iloc[0])
    start_w = int(start)
    print(f"tuning control runs: {len(tr_ctrl)}, test control runs: {len(te_ctrl)}, attack start {start} s")

    summary = []
    for kpi, (_, _, sign) in KPIS.items():
        if kpi not in tr_ctrl[0][1].columns:
            continue
        th = tune(tr_ctrl, kpi, sign)
        if not th:
            continue
        # choose k: the smallest k whose threshold is still finite; report all k for k in th
        for k, theta in th.items():
            fp_ctrl = evaluate(te_ctrl, kpi, theta, k, sign, start_w)
            for cond in [c for c in conds if c != "ctrl"]:
                te = get(cond, a.test)
                if not te:
                    continue
                r = evaluate(te, kpi, theta, k, sign, start_w)
                att = r[r.attacker == 1]
                ben = r[r.attacker == 0]
                tp = int(att.alarm.sum()); fn = int((~att.alarm).sum())
                fp = int(ben.alarm.sum()); heavy = ben[ben.profile == "heavy"]
                prec = tp / (tp + fp) if tp + fp else np.nan
                rec = tp / (tp + fn) if tp + fn else np.nan
                f1 = 2 * prec * rec / (prec + rec) if prec and rec and not np.isnan(prec) else 0.0
                summary.append(dict(kpi=kpi, k=k, theta=round(theta, 2), cond=cond, runs=len(te),
                                    recall=round(rec, 3), precision=round(prec, 3) if not np.isnan(prec) else np.nan,
                                    f1=round(f1, 3), fp_benign=fp, fp_heavy=int(heavy.alarm.sum()),
                                    n_heavy=len(heavy), fp_ctrl_ues=int(fp_ctrl.alarm.sum()),
                                    ctrl_ues=len(fp_ctrl), ttd_med_s=att.ttd.median(), ttd_max_s=att.ttd.max()))
    S = pd.DataFrame(summary)
    pd.set_option("display.width", 200)
    S.to_csv(f"anomaly_eval_{a.prefix}.csv", index=False)
    if S.empty:
        print("nothing to report"); return
    print("\nPer KPI, persistence k windows of 1 s, theta fitted on tuning controls (zero alarms there):\n")
    print(S.to_string(index=False))

    # collateral damage: benign UEs in attack runs vs the same seed's control run
    print("\nCollateral effect on benign UEs after the attack start (attack run minus paired control run, median over UEs):")
    for cond in [c for c in conds if c != "ctrl"]:
        diffs = []
        for s, win, gt, _ in get(cond, a.test):
            c = [x for x in te_ctrl if x[0] == s]
            if not c:
                continue
            cw = c[0][1]
            ben = gt[gt.attacker == 0].imsi
            A = win[(win.w >= start_w) & win.ue.isin(ben)].groupby("ue")[["pdcp_delay_ms", "pdcp_thr_kbps"]].mean()
            B = cw[(cw.w >= start_w) & cw.ue.isin(ben)].groupby("ue")[["pdcp_delay_ms", "pdcp_thr_kbps"]].mean()
            diffs.append((A - B).dropna())
        if diffs:
            D = pd.concat(diffs)
            print(f"  {cond}: delay {D.pdcp_delay_ms.median():+.1f} ms (P90 {D.pdcp_delay_ms.quantile(.9):+.1f}), "
                  f"throughput {D.pdcp_thr_kbps.median():+.0f} kb/s, n={len(D)} benign UE-runs")


if __name__ == "__main__":
    main()
