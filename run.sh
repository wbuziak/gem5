#!/bin/sh

export CUR_DIR=$(pwd)
export BMK=$1 # benchmark
export SIZE=$2 # simulation size (simlarge, simsmall)
export META_SIZE=$3 # metadata cache size
export MEMORY=$4 # memory module name (configurable / non-secure / MCX)
export CONFIG=$5 # architecture / name / mem-module we are testing (config file)

# redirect the stats to a folder with the following naming convention
RESULTS_DIR=$CUR_DIR/results/$MEMORY/$BMK-$SIZE/$CONFIG-$META_SIZE

$CUR_DIR/build/X86/gem5.opt -d $RESULTS_DIR $CUR_DIR/configs/example/gem5_library/$CONFIG --benchmark $BMK --size $SIZE --metadata_cache_size $META_SIZE --memory $MEMORY --l3_size 256KiB --mcx_policy never

# save the config file
cp $CUR_DIR/configs/example/gem5_library/$CONFIG $RESULTS_DIR/
