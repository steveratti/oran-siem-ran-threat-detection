#!/usr/bin/env python3
"""Scenario E: convert the x_* run folders (E2 KPM logs, it_flows.txt, ue_ip.txt, ground truth) into the Splunk inputs.
Usage: cd <folder with the x_* run folders> && python3 <repo>/analysis/xcorr_convert.py"""
# Converts the x_* runs into the Splunk inputs of the cross-layer (RAN-IT) correlation:
#   xcorr_ran.csv     RAN events: one UE and one E2 report (PDCP thr, RLC buffer, serving L3 SINR, serving cell)
#   xcorr_it.csv      IT events: one 1 s flow record at the core-network boundary (src, dst, ports, bytes)
#   xcorr_ueip.csv    IMSI <-> UE IP binding per run (core-network session log)      -> Splunk lookup
#   xcorr_assets.csv  device class per IMSI (mobile / iot)                            -> Splunk lookup
#   known_services.csv  operator allow-list of external services (1.0.0.2 content server) -> Splunk lookup
#   xcorr_truth.csv   ground truth per run and IMSI (not used by the rules)
import glob, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pandas as pd
import anomaly_eval as A
BASE = pd.Timestamp("2026-10-22T00:00:00")
KP = {k: A.KPIS[k] for k in ("pdcp_thr_kbps", "rlc_buffer", "sinr_db")}
def tstr(td):
    return (BASE + td).dt.strftime("%Y-%m-%dT%H:%M:%S.%f").str[:-3] + "Z"
ran, it, ipb, truth, iot_imsi = [], [], [], [], set()
runs = sorted(r for r in glob.glob("x_*_r*") if os.path.isfile(r + "/done"))
for run in runs:
    m = re.match(r"x_(\w+?)_r(\d+)$", run); cond, seed = m.group(1), int(m.group(2))
    cols = []
    for kpi, (kind, prefix, _) in KP.items():
        parts = []
        for f in glob.glob(f"{run}/{kind}-cell-*.txt"):
            c = int(re.findall(r"cell-(\d+)", f)[0])
            if c == 1 and kind != "cu-up":
                continue
            d = A.read(f); col = A.pick(d, prefix)
            if col is None:
                continue
            uec = "UE (imsi)" if kind == "cu-cp" and "UE (imsi)" in d.columns else "ueImsiComplete"
            ok = pd.to_numeric(d["timestamp"], errors="coerce").notna()
            ts = d.loc[ok, "timestamp"].str.strip().str.split(".").str[0].astype("int64")
            x = pd.DataFrame({"t_ms": ((ts - ts.min() + 50) // 50 * 50).values,
                              "ue_id": pd.to_numeric(d.loc[ok, uec], errors="coerce").values,
                              kpi: pd.to_numeric(d.loc[ok, col], errors="coerce").values}).dropna()
            if kind == "cu-cp":
                x["cell"] = c
            parts.append(x)
        if not parts:
            continue
        x = pd.concat(parts)
        if kpi == "sinr_db":   # serving cell = the cell whose CU-CP file reports the highest serving SINR
            x = x.sort_values(kpi).drop_duplicates(["t_ms", "ue_id"], keep="last").set_index(["t_ms", "ue_id"])
            cols.append(x[[kpi, "cell"]])
        else:
            cols.append(x.groupby(["t_ms", "ue_id"])[kpi].max())
    df = pd.concat(cols, axis=1).reset_index()
    df["ue_id"] = df.ue_id.astype(int)
    df.insert(0, "time", tstr(pd.to_timedelta(df.t_ms, unit="ms")))
    df.insert(1, "run", run); df.insert(2, "cond", cond); df.insert(3, "seed", seed)
    ran.append(df)
    f = pd.read_csv(run + "/it_flows.txt")
    f.insert(0, "time", tstr(pd.to_timedelta(f.t_s, unit="s")))
    f.insert(1, "run", run); f.insert(2, "cond", cond); f.insert(3, "seed", seed)
    f["direction"] = ["ul" if s.startswith("7.") else "dl" for s in f.src_ip]
    it.append(f)
    b = pd.read_csv(run + "/ue_ip.txt"); b.insert(0, "run", run); ipb.append(b)
    if os.path.isfile(run + "/iot.txt"):
        t = pd.read_csv(run + "/iot.txt"); iot_imsi |= set(t.imsi)
        on = cond == "iotbv"
        for r in t.itertuples():
            if on and r.bot == 1:
                truth.append((run, cond, seed, r.imsi, "bot"))
            if on and r.victim == 1:
                truth.append((run, cond, seed, r.imsi, "flood_target"))
    if os.path.isfile(run + "/anomaly.txt") and cond in ("a10", "a10j50"):
        g = pd.read_csv(run + "/anomaly.txt")
        for u in g.imsi[g.attacker == 1]:
            truth.append((run, cond, seed, u, "flood_target"))
    if cond in ("j50", "a10j50"):
        truth.append((run, cond, seed, -1, "jammer"))
    if os.path.isfile(run + "/scan.txt"):
        s = pd.read_csv(run + "/scan.txt")
        if s.scan_on.iloc[0] == 1:
            truth.append((run, cond, seed, int(s.imsi.iloc[0]), "scanner"))
    print("ok", run, len(df), "RAN events,", len(f), "flow records")
R = pd.concat(ran).round(3); R.to_csv("xcorr_ran.csv", index=False)
I = pd.concat(it); I.to_csv("xcorr_it.csv", index=False)
B = pd.concat(ipb); B.to_csv("xcorr_ueip.csv", index=False)
pd.DataFrame(truth, columns=["run", "cond", "seed", "imsi", "role"]).to_csv("xcorr_truth.csv", index=False)
pd.DataFrame({"ue_id": sorted(R.ue_id.unique())}).assign(
    dev_class=lambda x: ["iot" if u in iot_imsi else "mobile" for u in x.ue_id]).to_csv("xcorr_assets.csv", index=False)
pd.DataFrame({"ip": ["1.0.0.2"], "service": ["operator content server"], "trusted": [1]}).to_csv("known_services.csv", index=False)
print("runs:", R.groupby("cond").run.nunique().to_dict())
print("wrote xcorr_ran.csv", len(R), "| xcorr_it.csv", len(I), "| xcorr_ueip.csv", len(B), "| xcorr_truth.csv, xcorr_assets.csv, known_services.csv")
