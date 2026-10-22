#!/bin/bash
B=~/ns-O-RAN-flexric/mmwave-LENA-oran/build/scratch
UE=$(ls $B/*scenario_xcorr_ue*-optimized); IOT=$(ls $B/*scenario_xcorr_iot*-optimized)
OUT=~/xcorr_runs; JOBS=${JOBS:-18}; mkdir -p $OUT; L=$OUT/jobs.txt; : > $L
C="--enableE2FileLogging=1 --enableTraces=0"
for s in $(seq 1 15); do
  echo "x_ctrl_r$s   $UE --RngRun=$s --anomalyOn=0 --jammerOn=0 --attackRateMbps=10 --attackStart=10 --simTime=60 $C" >> $L
  echo "x_a10_r$s    $UE --RngRun=$s --anomalyOn=1 --jammerOn=0 --attackRateMbps=10 --attackStart=10 --simTime=60 $C" >> $L
  echo "x_j50_r$s    $UE --RngRun=$s --anomalyOn=0 --jammerOn=1 --jammerPowerDbm=50 --attackRateMbps=10 --attackStart=10 --simTime=60 $C" >> $L
  echo "x_a10j50_r$s $UE --RngRun=$s --anomalyOn=1 --jammerOn=1 --jammerPowerDbm=50 --attackRateMbps=10 --attackStart=10 --simTime=60 $C" >> $L
  echo "x_iotc_r$s   $IOT --RngRun=$s --anomalyOn=0 --botOn=0 --victimOn=0 --botStart=10 --victimStart=10 --simTime=30 $C" >> $L
  echo "x_iotbv_r$s  $IOT --RngRun=$s --anomalyOn=0 --botOn=1 --victimOn=1 --botStart=10 --victimStart=10 --simTime=30 $C" >> $L
done
run_one(){ name=$1; shift; d=$OUT/$name; [ -f $d/done ] && return 0; mkdir -p $d && cd $d || return 1
  t=$(date +%s); "$@" > log.txt 2>&1; rc=$?; echo "exit=$rc wall_s=$(( $(date +%s)-t ))" >> log.txt
  [ $rc -eq 0 ] && touch done; echo "$(date +%H:%M) $name exit=$rc"; }
export -f run_one; export OUT
xargs -P $JOBS -L 1 bash -c 'run_one "$@"' _ < $L
echo "SAB KHATAM: $(ls $OUT/x_*/done 2>/dev/null | wc -l) / $(wc -l < $L)"
