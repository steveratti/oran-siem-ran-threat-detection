# SIEM-Based Monitoring of O-RAN: An Agent/Forwarder xApp Architecture for RAN Threat Detection

Code, Splunk SPL searches and processed data for the paper

S. A. Ratti et al., "SIEM-Based Monitoring of O-RAN: An Agent/Forwarder xApp Architecture for RAN Threat Detection", under review.

An Agent/Forwarder xApp on the Near-RT RIC selects E2 KPM fields, normalizes them into JSON events and
forwards them to Splunk through the HTTP Event Collector (HEC). All detection runs in Splunk (SPL and MLTK).
This repository contains everything needed to reproduce the simulated scenarios and the SIEM-side results.

## Scenarios

| Scenario | What | Runs (tuning / test) | Index | Data here |
|---|---|---|---|---|
| A | Downlink flood (5, 10, 20 Mb/s) towards two of ten UEs, from t = 10 s | 30 per rate + 30 paired controls (seeds 1-5 / 6-30), 60 s | `scenario_a` | `data/scenarioA_splunk.csv.gz` |
| B | Constant downlink jammer, 40/50/60 dBm EIRP, near gNB 3 | 30 per power + 30 controls | `jammer_full` | in the jammer dataset repository (see below) |
| Triage | Jammer (50 dBm) alone and together with the 10 Mb/s flood, in the Scenario A deployment | 30 + 30 (same seeds) | `scenario_a` | `data/scenarioJ_splunk.csv.gz`, `data/scenarioAJ_splunk.csv.gz` |
| C | Network-layer attacks on an over-the-air LTE testbed | public dataset, see below | `external_iot_ddos_validation` | not redistributed |
| D | Ten static IoT devices: 0.5 Mb/s downlink flood towards two of them; uplink botnet pilot | 15 + 15 paired controls (seeds 1-5 / 6-15), 30 s | `scenario_d` | `data/scenarioD_splunk.csv.gz`, `data/iot_assets.csv` |
| HEC | Three triage runs replayed through the HEC at the 50 ms reporting rate | seeds 6-8 | `hec_latency` | `analysis/hec_replay.py` |
| E | RAN-IT correlation: RAN events + core-network flow records (PGW/SGi), IMSI-IP binding, asset list, allow-list. Conditions: no attack, 10 Mb/s flood, 50 dBm jammer, both, UDP port scan (60 s); IoT control, IoT botnet + IoT flood (30 s). Flood source / botnet target: external host 2.0.0.2 | 7 conditions x 15 seeds (1-5 / 6-15) | `xcorr_ran` (both event types, `source=xcorr_ran.csv` / `xcorr_it.csv`) | `data/xcorr_ran.csv.gz`, `data/xcorr_it.csv.gz`, `data/xcorr_*.csv`, `data/known_services.csv` |
| E live | 21 test runs of Scenario E (seeds 6-8) streamed concurrently in real time: RAN reports at their 50 ms instants, flow records at the end of their 1 s bin | seeds 6-8 | `xcorr_ran` (`source=live_ran` / `live_it`) | `analysis/xcorr_live_replay.py` |

Evaluation protocol: thresholds are fitted only on attack-free (or jammer-free) runs of seeds 1-5;
all reported results use the held-out seeds. Attack and control runs with the same seed share every random draw.

## Repository layout

```
simulation/   ns-3 scenario files (ns-O-RAN, mmwave-LENA-oran, ns-3.42) and the run script
analysis/     conversion of the E2 KPM logs to Splunk events, and offline re-implementations of every SPL result
spl/          the SPL searches used in Splunk
data/         processed event CSVs (gzip) and result tables
```

## 1. Simulation

Requires ns-O-RAN (`mmwave-LENA-oran`, ns-3.42) built in the optimized profile. Copy the files of `simulation/`
into `scratch/` and build:

```
./ns3 build scenario_anomaly_ue scenario_iot_botnet scenario_xcorr_ue scenario_xcorr_iot scenario_xcorr_scan
```

Each run writes the E2 KPM logs (`--enableE2FileLogging=1`) and its ground truth (`anomaly.txt`, `jammer.txt`, `iot.txt`)
into its own folder. Examples (one run each; the paper uses `--RngRun` 1-30, or 1-15 for Scenario D):

```
# Scenario A: flood of 10 Mb/s from t = 10 s (control run: --anomalyOn=0)
scenario_anomaly_ue --RngRun=7 --anomalyOn=1 --attackRateMbps=10 --attackStart=10 --simTime=60 --enableE2FileLogging=1 --enableTraces=0
# Triage: jammer alone, and jammer + flood
scenario_anomaly_ue --RngRun=7 --anomalyOn=0 --jammerOn=1 --jammerPowerDbm=50 --attackStart=10 --simTime=60 --enableE2FileLogging=1 --enableTraces=0
scenario_anomaly_ue --RngRun=7 --anomalyOn=1 --attackRateMbps=10 --attackStart=10 --jammerOn=1 --jammerPowerDbm=50 --simTime=60 --enableE2FileLogging=1 --enableTraces=0
# Scenario D: flood towards two IoT devices (control: --victimOn=0); botnet pilot: --botOn=1
scenario_iot_botnet --RngRun=7 --anomalyOn=0 --victimOn=1 --victimStart=10 --simTime=30 --enableE2FileLogging=1 --enableTraces=0
# Scenario E (also writes it_flows.txt and ue_ip.txt): flood, jammer, port scan, IoT botnet + IoT flood
scenario_xcorr_ue   --RngRun=7 --anomalyOn=1 --jammerOn=1 --jammerPowerDbm=50 --attackRateMbps=10 --attackStart=10 --simTime=60 --enableE2FileLogging=1 --enableTraces=0
scenario_xcorr_scan --RngRun=7 --anomalyOn=0 --jammerOn=0 --scanOn=1 --scanStart=10 --simTime=60 --enableE2FileLogging=1 --enableTraces=0
scenario_xcorr_iot  --RngRun=7 --anomalyOn=0 --botOn=1 --victimOn=1 --botStart=10 --victimStart=10 --simTime=30 --enableE2FileLogging=1 --enableTraces=0
```

`simulation/run_xcorr.sh` and `simulation/run_scan.sh` run the 105 runs of Scenario E (folders `x_<condition>_r<seed>`).
The Scenario E files add to the Scenario A/D deployments an external host (2.0.0.2) on its own link to the PGW, a flow log
at the PGW (`it_flows.txt`: per second and per source, destination, protocol and ports, bytes and packets) and the
IMSI-IP binding (`ue_ip.txt`); the port scan sends a 40 B UDP probe every 10 ms to consecutive ports of 2.0.0.2.

Run folders are named `full_<condition>_r<seed>` (conditions `ctrl`, `a5`, `a10`, `a20`, `j50`, `a10j50`, `iotc`, `iotv`).
The raw run folders (E2 KPM logs) are archived separately (see *Raw data*).

## 2. Events for Splunk

```
cd <folder with the run folders>; cp <repo>/analysis/*.py .
python3 convert_runs.py --glob "full_ctrl_r*" "full_a5_r*" "full_a10_r*" "full_a20_r*" --out scenarioA_splunk.csv
python3 convert_runs.py --glob "full_j50_r*" --out scenarioJ_splunk.csv
python3 convert_runs.py --glob "full_a10j50_r*" --out scenarioAJ_splunk.csv
python3 convert_runs.py --glob "full_iotc_r*" "full_iotv_r*" --out scenarioD_splunk.csv --base 2026-10-21
```

One event = one UE and one 50 ms report (DU/CU-UP period); the CU-CP reports the L3 SINR every 100 ms, so `sinr_db` is filled in every second event. Columns: `time` (event time), `run`, `cond`, `seed`, `t_ms` (simulation time),
`ue_id` (IMSI), `pdcp_thr_kbps`, `pdcp_vol`, `pdcp_delay_ms`, `rlc_buffer`, `sinr_db` (serving-cell L3 SINR),
`attacker` (ground truth: flooded UE / targeted IoT device), `profile` (benign traffic profile, Scenario A).

In Splunk: *Add Data → Upload*, source type `csv`, timestamp field `time`, format `%Y-%m-%dT%H:%M:%S.%3NZ`, time zone GMT;
`scenarioA`, `scenarioJ` and `scenarioAJ` into index `scenario_a`, `scenarioD` into `scenario_d`.
Upload `iot_assets.csv` as a lookup table file (*Settings → Lookups → Lookup table files*).

Scenario E: `cd <folder with the x_* runs> && python3 <repo>/analysis/xcorr_convert.py` writes `xcorr_ran.csv`,
`xcorr_it.csv` and the lookups `xcorr_ueip.csv`, `xcorr_assets.csv`, `known_services.csv` (and the ground truth
`xcorr_truth.csv`, used only for scoring). The paper posted both event files to the index `xcorr_ran` through the HEC
(`sourcetype=_json`, `source` = file name); the four lookups go into `etc/apps/search/lookups`.

## 3. Detection

The searches are in `spl/`. Every SPL result of the paper has an offline counterpart in `analysis/`:

| Result | SPL | Offline |
|---|---|---|
| Scenario A, per-UE detection | `spl/scenario_a_persistence.spl` | `analysis/anomaly_eval.py --prefix full --train 1-5 --test 6-30` |
| Joint triage incl. simultaneous attacks | `spl/triage.spl` | `analysis/triage.py` |
| Jamming rule vs persistence k | — | `analysis/triage_jamming_k.py` |
| Threshold transfer from Scenario B | — | `analysis/jamming_threshold_transfer.py` (raw KPM files) |
| Scenario D (IoT) | `spl/scenario_d_iot.spl` | `analysis/iot_detection.py` |
| Scenario C repetitions | — | `analysis/scenario_c_repeat.py <export.csv> --seeds 10` |
| HEC streaming latency | `spl/hec_latency.spl` | `analysis/hec_replay.py` (sender) |
| Scenario E: RAN only / IT only / correlated, triage | `spl/xcorr_botnet.spl`, `spl/xcorr_scan.spl`, `spl/xcorr_flood_attribution.spl` | `analysis/xcorr_eval.py` |
| Scenario E on a real-time stream (21 concurrent runs) | `spl/xcorr_live.spl` | `analysis/xcorr_live_replay.py` (sender) |

## External data

* Scenario B: O-RAN Jammer Detection and Geolocation Dataset, https://github.com/steveratti/oran-jammer-detection-geolocation-dataset (Release v2.0).
* Scenario C: B. M. Xavier et al., "Performance Measurement Dataset for Open RAN with User Mobility and Security Threats", Computer Networks 253 (2024) 110710; data: Mendeley Data, doi:10.17632/t2rzh9y4mp.1.

## Raw data

The raw run folders (E2 KPM logs of all runs, several GB) are archived on Zenodo: *DOI to be added*.

## License

Code: MIT (see `LICENSE`). Data in `data/`: CC BY 4.0.

## Citation

If you use this code or data, please cite the paper above (under review; the full reference will be added when it is published).
