#!/bin/sh

export BENCHMARK=$1

configs="
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
  echo ""
  echo "Running $BENCHMARK:"
  echo "  SECURITY CONFIGURATION: $curr"
  echo "  METADATA CACHE SIZE:    4 KiB"
  echo "  CONFIG FILE:            x86-parsec-configurable.py"
  sh run.sh $BENCHMARK simlarge 4KiB $curr x86-parsec-configurable.py
done

echo "Finished running all tests"
