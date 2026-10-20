#!/usr/bin/env python3
"""Replay test runs through the Splunk HEC at the 50 ms reporting rate (streaming latency).
env: HEC_URL (https://<host>:8088), HEC_TOKEN, optional HEC_INDEX, RUNS, SRC. Then run spl/hec_latency.spl in Splunk."""
import os, ssl, json, time, threading, urllib.request
import pandas as pd
HEC = os.environ["HEC_URL"]; TOKEN = os.environ["HEC_TOKEN"]
INDEX = os.environ.get("HEC_INDEX", "hec_latency")
RUNS = os.environ.get("RUNS", "full_a10j50_r6,full_a10j50_r7,full_a10j50_r8").split(",")
SRC = os.environ.get("SRC", "scenarioAJ_splunk.csv")
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE
def post(payload):
    req = urllib.request.Request(HEC + "/services/collector/event", data=payload.encode(),
                                 headers={"Authorization": "Splunk " + TOKEN}, method="POST")
    with urllib.request.urlopen(req, context=CTX, timeout=30) as r:
        return r.read().decode()
D = pd.read_csv(SRC, usecols=["run", "t_ms", "ue_id", "pdcp_thr_kbps", "sinr_db"])
print("HEC:", post(json.dumps({"event": {"check": 1}, "index": INDEX, "sourcetype": "_json"})))
for run in RUNS:
    E = D[D.run == run].sort_values("t_ms")
    tag = f"{run}_lat{int(time.time())}"
    ticks = [(t, g.drop(columns="run").to_dict("records")) for t, g in E.groupby("t_ms")]
    t0 = time.time() + 1.0
    late, n = [], 0
    for t, recs in ticks:
        due = t0 + t / 1000.0
        dt = due - time.time()
        if dt > 0:
            time.sleep(dt)
        now = time.time()
        post("".join(json.dumps({"time": now, "index": INDEX, "sourcetype": "_json",
                                 "event": dict({k: v for k, v in r.items() if v == v}, run=tag, sent=round(now, 3))}) for r in recs))
        late.append(time.time() - due); n += len(recs)
    s = pd.Series(late) * 1000
    print(f"{tag}: {n} events in {len(ticks)} posts over {ticks[-1][0]/1000:.1f} s; "
          f"post finished after its due time: median {s.median():.1f} ms, p95 {s.quantile(.95):.1f} ms, max {s.max():.1f} ms")
print("done - now run the SPL in Splunk")
