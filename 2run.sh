#!/bin/sh

export CUR_DIR=$(pwd)
export BMK=$1 # benchmark
export BMK2=$2
export SIZE=$3 # simulation size (simlarge, simsmall)
export META_SIZE=$4 # metadata cache size
export NAME=$5 # memory module name (configurable / non-secure / MCX)
export MEMORY=$6
export CONFIG=$7 # architecture / name / mem-module we are testing (config file)

# redirect the stats to a folder with the following naming convention
RESULTS_DIR=$CUR_DIR/results/$NAME/$MEMORY/$BMK-$SIZE/$CONFIG-$META_SIZE

./build/RISCV/gem5.opt -d $RESULTS_DIR configs/example/gem5_library/$CONFIG --benchmark $BMK --benchmark2 $BMK2 --size $SIZE --metadata_cache_size $META_SIZE --memory configurable --l3_size 256KiB --mcx_policy never 2>&1 | tee $RESULTS_DIR/output.txt

# save the config file
cp configs/example/gem5_library/$CONFIG $RESULTS_DIR/
