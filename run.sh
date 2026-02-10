#!/bin/sh

export CUR_DIR=$(pwd)
export BMK=$1
export SIZE=$2
export MCX=$3
export META_SIZE=$4
export LLC_SIZE=$5

RESULTS_DIR=$CUR_DIR/results/$BMK-$SIZE/$MCX-$META_SIZE-$LLC_SIZE

$CUR_DIR/build/X86/gem5.opt -d $RESULTS_DIR $CUR_DIR/configs/example/gem5_library/x86-parsec-mcx_v3.py --benchmark $BMK --size $SIZE --metadata_cache_size $META_SIZE --l3_size $LLC_SIZE --mcx_policy $MCX --cache_mac


