#!/bin/bash
# Runs the anomaly scenario for many seeds in parallel.
#   pilot : 1 seed, 3 conditions, 15 s simulated time  (checks that everything works)
#   full  : 30 seeds, 3 conditions, 60 s simulated time
# Usage:  NS3_DIR=~/ns-O-RAN-flexric/mmwave-LENA-oran ./run_anomaly.sh pilot
# Optional: OUT=~/anomaly_runs  JOBS=18
# Finished runs are skipped, so the script can simply be started again after a stop.
NS3_DIR=${NS3_DIR:?set NS3_DIR to the ns-3 folder (the one that contains ./ns3)}
OUT=${OUT:-$HOME/anomaly_runs}
JOBS=${JOBS:-18}
MODE=${1:-pilot}
BIN=$(ls "$NS3_DIR"/build/scratch/*scenario_anomaly_ue*-default 2>/dev/null | head -1)
[ -n "$BIN" ] || BIN=$(ls "$NS3_DIR"/build/scratch/*scenario_anomaly_ue* 2>/dev/null | grep -v '\.o$' | head -1)
if [ ! -x "$BIN" ]; then
  echo "Binary not found. Build first:  cd $NS3_DIR && ./ns3 build scenario_anomaly_ue"; exit 1
fi
if [ "$MODE" = pilot ]; then SIM=15; START=5; SEEDS="1"; else SIM=60; START=10; SEEDS=$(seq 1 30); fi
mkdir -p "$OUT"
LIST="$OUT/jobs_$MODE.txt"
: > "$LIST"
for s in $SEEDS; do
  echo "ctrl 0 20 $s"  >> "$LIST"     # control: same seed, flood not started
  echo "a5 1 5 $s"     >> "$LIST"     # 5 Mb/s flood  (close to a heavy benign user)
  echo "a20 1 20 $s"   >> "$LIST"     # 20 Mb/s flood
done
run_one() {
  name=$1; on=$2; rate=$3; seed=$4
  d="$OUT/${MODE}_${name}_r${seed}"
  [ -f "$d/done" ] && return 0
  mkdir -p "$d" && cd "$d" || return 1
  start=$(date +%s)
  "$BIN" --RngRun=$seed --anomalyOn=$on --attackRateMbps=$rate --attackStart=$START \
         --simTime=$SIM --enableE2FileLogging=1 --enableTraces=0 > log.txt 2>&1
  rc=$?
  echo "exit=$rc wall_s=$(( $(date +%s) - start ))" >> log.txt
  [ $rc -eq 0 ] && touch done
  echo "$(date +%H:%M) $(basename "$d") exit=$rc"
}
export -f run_one; export BIN OUT SIM START MODE
echo "Binary: $BIN"
echo "Jobs: $(wc -l < "$LIST")  parallel: $JOBS  output: $OUT"
xargs -P "$JOBS" -L 1 bash -c 'run_one "$@"' _ < "$LIST"
echo "Finished: $(ls -d "$OUT"/${MODE}_*/done 2>/dev/null | wc -l) of $(wc -l < "$LIST")"
