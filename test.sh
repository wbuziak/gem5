#!/bin/sh

export BENCHMARK=$1

configs="
  configurable
  hashing_only
  encryption_only
  integrity_tree
  hashing+encryption
  hashing+integrity
  encryption+integrity
  full_security
  no_security
  "

for curr in $configs; do
  echo "Running $BENCHMARK on $curr"
  sh run.sh $BENCHMARK simlarge 4KiB $curr x86-parsec-configurable.py
done

echo "Finished running all tests"
