#!/usr/bin/env python3
"""
Convert ns-O-RAN E2 KPM logs (one folder per run) into the event CSV indexed in Splunk.

One event = one UE and one 50 ms E2 report, with the PDCP throughput / volume / delay (CU-UP),
the RLC buffer (DU) and the serving-cell L3 SINR (CU-CP), plus run, condition, seed and ground truth.

  Scenario A / triage runs (anomaly.txt):   attacker = flooded UE (0 in control and jammer-only runs)
  Scenario D runs (iot.txt):                attacker = targeted IoT device in iotv runs; also writes iot_assets.csv

Usage (in the folder that holds the run folders and anomaly_eval.py):
  python3 convert_runs.py --glob "full_ctrl_r*" "full_a5_r*" "full_a10_r*" "full_a20_r*" --out scenarioA_splunk.csv
  python3 convert_runs.py --glob "full_j50_r*" --out scenarioJ_splunk.csv
  python3 convert_runs.py --glob "full_a10j50_r*" --out scenarioAJ_splunk.csv
  python3 convert_runs.py --glob "full_iotc_r*" "full_iotv_r*" --out scenarioD_splunk.csv --base 2026-10-21
"""
import argparse, glob, os, re
from datetime import datetime, timedelta, timezone
import pandas as pd
import anomaly_eval as A

ap = argparse.ArgumentParser()
ap.add_argument("--glob", nargs="+", required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--base", default="2026-10-20", help="date used as event time origin (UTC)")
a = ap.parse_args()
BASE = datetime.fromisoformat(a.base).replace(tzinfo=timezone.utc)

out, iot_sets = [], set()
for run in sorted(r for g in a.glob for r in glob.glob(g)):
    if not os.path.isfile(run + "/done"):
        continue
    m = re.match(r"full_(\w+?)_r(\d+)$", os.path.basename(run)); cond, seed = m.group(1), int(m.group(2))
    cols = []
    for kpi, (kind, prefix, _) in A.KPIS.items():
        parts = []
        for f in glob.glob(f"{run}/{kind}-cell-*.txt"):
            if f.endswith("-cell-1.txt") and kind != "cu-up":
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
            parts.append(x)
        if parts:
            cols.append(pd.concat(parts).groupby(["t_ms", "ue_id"])[kpi].max())
    df = pd.concat(cols, axis=1).reset_index()
    if os.path.isfile(run + "/iot.txt"):                       # Scenario D
        it = pd.read_csv(run + "/iot.txt")
        iot_sets.add(tuple(sorted(it.imsi)))
        df["ue_id"] = df["ue_id"].astype(int)
        vic = set(it.imsi[it.victim == 1]) if cond == "iotv" else set()
        df["attacker"] = df.ue_id.isin(vic).astype(int)
    else:                                                      # Scenario A, jammer and triage runs
        gt = pd.read_csv(run + "/anomaly.txt")
        df = df.merge(gt[["imsi", "attacker", "profile"]].rename(columns={"imsi": "ue_id"}), on="ue_id", how="left")
        flood_on = cond not in ("ctrl", "j50")
        df["attacker"] = df["attacker"].fillna(0).astype(int) * (1 if flood_on else 0)
        df["ue_id"] = df["ue_id"].astype(int)
    df.insert(0, "time", [(BASE + timedelta(milliseconds=int(t))).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" for t in df.t_ms])
    df.insert(1, "run", os.path.basename(run)); df.insert(2, "cond", cond); df.insert(3, "seed", seed)
    out.append(df)
    print("ok", run, len(df))
D = pd.concat(out).round(3)
D.to_csv(a.out, index=False)
print("wrote", a.out, len(D), "events,", D.run.nunique(), "runs")
if iot_sets:
    assert len(iot_sets) == 1, "IoT IMSIs differ between runs"
    iot = set(next(iter(iot_sets)))
    pd.DataFrame({"ue_id": sorted(D.ue_id.unique())}).assign(
        dev_class=lambda x: ["iot" if u in iot else "mobile" for u in x.ue_id]).to_csv("iot_assets.csv", index=False)
    print("wrote iot_assets.csv")
