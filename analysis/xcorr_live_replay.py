#!/usr/bin/env python3
"""Scenario E: real-time replay of the test runs of seeds 6-8 through the Splunk HEC (env HEC_TOKEN, HEC_URL).
Then run spl/xcorr_live.spl."""
# Real-time replay of Scenario E test runs (seeds 6-8, all 7 conditions = 21 runs, streamed concurrently)
# through the Splunk HEC: each RAN report is posted at its 50 ms reporting time, each IT flow record at the
# end of its 1 s bin (as a flow exporter would). One HTTPS post per 50 ms tick carries the events of all runs.
import os, json, ssl, time, urllib.request
import pandas as pd, numpy as np
URL = os.environ.get("HEC_URL", "https://127.0.0.1:8088") + "/services/collector/event"; TOK = os.environ["HEC_TOKEN"]
ctx = ssl._create_unverified_context()
SEEDS = (6, 7, 8)
def post(body):
    req = urllib.request.Request(URL, data=body.encode(), headers={"Authorization": "Splunk " + TOK})
    for i in range(5):
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
                return r.status
        except Exception as e:
            print("retry", i, e); time.sleep(0.2)
    raise SystemExit("HEC failed")
R = pd.read_csv("xcorr_ran.csv"); R = R[R.seed.isin(SEEDS)].drop(columns=["time"])
I = pd.read_csv("xcorr_it.csv"); I = I[I.seed.isin(SEEDS)].drop(columns=["time"])
R["t_send"] = R.t_ms / 1000.0; R["src"] = "live_ran"
I["t_send"] = I.t_s + 1.0;     I["src"] = "live_it"
E = pd.concat([R, I], ignore_index=True)
E["tick"] = np.round(E.t_send / 0.05).astype(int)
ticks = [(t, g.drop(columns=["tick", "t_send"]).to_dict("records")) for t, g in E.groupby("tick")]
print(f"{E.run.nunique()} runs, {len(R)} RAN events + {len(I)} flow records, {len(ticks)} posts over {ticks[-1][0]*0.05:.1f} s")
T0 = time.time() + 3.0
late, n = [], 0
for t, recs in ticks:
    due = T0 + t * 0.05
    d = due - time.time()
    if d > 0:
        time.sleep(d)
    now = time.time()
    lines = []
    for r in recs:
        src = r.pop("src")
        ev = {k: v for k, v in r.items() if v == v}
        # columns present in only one event type become float after the concat: restore integers
        ev = {k: (int(v) if isinstance(v, float) and v.is_integer() and k not in ("pdcp_thr_kbps", "rlc_buffer", "sinr_db") else v)
              for k, v in ev.items()}
        ev.update(orig_run=ev["run"], run="live_" + ev["run"], sent=round(now, 3), sched=round(due, 3), t0=round(T0, 3))
        lines.append(json.dumps({"time": round(now, 3), "index": "xcorr_ran", "sourcetype": "_json", "source": src, "event": ev}))
    post("\n".join(lines))
    late.append(time.time() - due); n += len(recs)
    if t % 200 == 0:
        print(f"\r{t*0.05:5.1f} s sent, {n} events", end="", flush=True)
s = pd.Series(late) * 1000
print(f"\ndone: {n} events in {len(ticks)} posts; post finished after its due time: median {s.median():.1f} ms, "
      f"p95 {s.quantile(.95):.1f} ms, max {s.max():.1f} ms; T0 = {T0:.3f}")
