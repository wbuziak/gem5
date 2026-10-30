#!/bin/sh

export MEMORY=$1
export CONFIG=$2

benchmarks="
   blackscholes
   canneal
   fluidanimate
   dedup
   streamcluster
   microbenchmark
"

for curr in $benchmarks; do
  echo ""
  echo "=========================="
  echo ""
  echo "Running $curr:"
  echo "  SECURITY CONFIGURATION: $MEMORY"
  echo "  METADATA CACHE SIZE:    4 KiB"
  echo "  CONFIG FILE:            $2"
  echo ""
  echo "=========================="
  echo ""
  sh run.sh $curr simlarge 4KiB $MEMORY $CONFIG
done

echo "Finished running all tests"

