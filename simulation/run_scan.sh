#!/bin/bash
while pgrep -f run_xcorr.sh > /dev/null; do sleep 60; done
BIN=$(ls ~/ns-O-RAN-flexric/mmwave-LENA-oran/build/scratch/*scenario_xcorr_scan*-optimized); OUT=~/xcorr_runs
run_one(){ s=$1; d=$OUT/x_scan_r$s; [ -f $d/done ] && return 0; mkdir -p $d && cd $d || return 1; t=$(date +%s)
  $BIN --RngRun=$s --anomalyOn=0 --jammerOn=0 --scanOn=1 --scanStart=10 --simTime=60 --enableE2FileLogging=1 --enableTraces=0 > log.txt 2>&1
  rc=$?; echo "exit=$rc wall_s=$(( $(date +%s)-t ))" >> log.txt; [ $rc -eq 0 ] && touch done; echo "$(date +%H:%M) x_scan_r$s exit=$rc"; }
export -f run_one; export BIN OUT
seq 1 15 | xargs -P 15 -I{} bash -c 'run_one {}'
echo "SCAN KHATAM: $(ls $OUT/x_scan_*/done | wc -l)/15"
