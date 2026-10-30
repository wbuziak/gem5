#!/bin/sh

export BENCHMARK=$1

configs="
  no_security
  hashing_only
  encryption_only
  hashing+encryption
  full_security
  "

for curr in $configs; do
  echo ""
  echo "=========================="
  echo ""
  echo "Running $BENCHMARK:"
  echo "  SECURITY CONFIGURATION: $curr"
  echo "  METADATA CACHE SIZE:    4 KiB"
  echo "  CONFIG FILE:            x86-parsec-configurable.py"
  echo ""
  echo "=========================="
  echo ""
  sh run.sh $BENCHMARK simlarge 4KiB $curr riscv-parsec.py
done

echo "Finished running all tests"
