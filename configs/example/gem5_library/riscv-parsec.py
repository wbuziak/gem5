# Copyright (c) 2021 The Regents of the University of California.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met: redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer;
# redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution;
# neither the name of the copyright holders nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
Script to run GAPBS benchmarks with gem5. The script expects the
benchmark program and the simulation size to run. The input is in the format
<benchmark_prog> <size> <synthetic>
The system is fixed with 2 CPU cores, MESI Two Level system cache and 3 GiB
DDR4 memory. It uses the x86 board.

This script will count the total number of instructions executed
in the ROI. It also tracks how much wallclock and simulated time.

Usage:
------

```
scons build/X86/gem5.opt
./build/X86/gem5.opt \
    configs/example/gem5_library/x86-gabps-benchmarks.py \
    --benchmark <benchmark_name> \
    --synthetic <synthetic> \
    --size <simulation_size/graph_name>
```
"""

import argparse
import sys
import time
import os

import m5
from m5.objects import Root

from gem5.coherence_protocol import CoherenceProtocol
from gem5.components.cachehierarchies.classic.private_l1_shared_l2_cache_hierarchy import (
    PrivateL1SharedL2CacheHierarchy,
)
from gem5.components.boards.riscv_board import RiscvBoard
from gem5.components.memory.secure_ddr4 import IntegrityTreeProtectedMemory
from gem5.components.memory.secure_ddr4 import ConfigurableMemory
from gem5.components.memory.secure_ddr4 import DirectEncryptedMemory
from gem5.components.memory import DualChannelDDR4_2400
from gem5.components.processors.cpu_types import CPUTypes
from gem5.components.processors.simple_switchable_processor import (
    SimpleSwitchableProcessor,
)

from gem5.resources.resource import (
    KernelResource,
    DiskImageResource,
    BootloaderResource
)

from gem5.isas import ISA
from gem5.simulate.exit_event import ExitEvent
from gem5.simulate.simulator import Simulator
from gem5.utils.requires import requires


benchmark_choices = [
    "blackscholes",
    "bodytrack",
    "canneal",
    "dedup",
    "facesim",
    "ferret",
    "fluidanimate",
    "freqmine",
    "raytrace",
    "streamcluster",
    "swaptions",
    "vips",
    "x264",
    "microbenchmark",
]

# Memory module choices

memory_choices = [
    "configurable", # configurability based on ePMP security
    "hashing_only",
    "encryption_only",
    "hashing+encryption",
    "full_security", # should be identical to integrity_tree
    "no_security",
    "mcx",
    "DDR4", # Regular DDR4 module from gem5
]

# Following are the input size.

size_choices = ["simsmall", "simmedium", "simlarge"]

parser = argparse.ArgumentParser(
    description="An example configuration script to run the npb benchmarks."
)

# The arguments accepted are the benchmark name and the simulation size.

parser.add_argument(
    "--benchmark",
    type=str,
    required=True,
    help="Input the benchmark program to execute.",
    choices=benchmark_choices,
)

parser.add_argument(
    "--memory",
    type=str,
    required=True,
    help="Input the memory module to run.",
    choices=memory_choices,
)

parser.add_argument(
    "--size",
    type=str,
    required=True,
    help="Simulation size the benchmark program.",
    choices=size_choices,
)

parser.add_argument(
    "--metadata_cache_size",
    type=str,
    required=False,
    help="Metadata cache size (power of 2 in kB or MB)",
    default="64kB",
)

parser.add_argument(
    "--no_metadata_cache",
    action="store_true",
    help="When specified, the input will not use a metadata cache \
          even when --metadata_cache_size is specified",
)

parser.add_argument(
    "--arity",
    type=int,
    required=False,
    help="Integrity tree arity (i.e., how many children share a parent)",
    default=8,
)

parser.add_argument(
    "--encryption_latency",
    type=int,
    required=False,
    default=53,
    help="Input the encryption latency.",
)

parser.add_argument(
    "--cache_mac",
    action="store_true",
    help="Should MACs be stored?",
    default=False,
)

parser.add_argument(
    "--eager_fetch",
    action="store_true",
    help="Should tree nodes be fetched upon miss detection?",
    default=False,
)

parser.add_argument(
    "--no_bonsai",
    action="store_true",
    help="Should the integrity tree implement a merkle tree over \
            data instead of counters?",
    default=False,
)

parser.add_argument(
    "--l3_size",
    type=str,
    required=True,
    default="1MB",
    help="L3 size for MCX",
)

parser.add_argument(
    "--mcx_policy",
    type=str,
    required=True,
    default="never",
    choices=[
        "insecure",
        "never",
        "always",
        "counter",
        "hotspot",
        "read-write",
        "approx-ancestors",
        "approx-ancestors-v2",
        "l3-hitrate",
    ],
    help="MCX policy",
)

args = parser.parse_args()

# helper for parsec command
def get_parsec_workload_cmd(
    benchmark: str, size: str = "simsmall", threads: int = 4
) -> str:
    """Generates robust POSIX guest OS shell scripts for PARSEC 3.0 benchmarks

    on RISC-V gem5 full-system simulations with explicit dynamic linking.
    """
    parsec_root = "/home/gem5/parsec-benchmark"
    hooks_lib = (
        f"{parsec_root}/pkgs/libs/hooks/inst/riscv64-linux.gcc-hooks/lib"
    )

    # Added /usr/lib/riscv64-linux-gnu to resolve libstdc++.so.6
    lib_paths = f"{hooks_lib}:/usr/lib/riscv64-linux-gnu:/lib:/usr/lib"

    cmds = [
        "#!/bin/sh",
        f"export LD_LIBRARY_PATH={lib_paths}:$LD_LIBRARY_PATH",
        "echo '=== LD_LIBRARY_PATH ==='",
        "echo $LD_LIBRARY_PATH",
    ]

    # Helper wrapper to print dynamic dependencies and capture standard error
    def wrap_run(bin_path: str, run_cmd: str) -> list[str]:
        return [
            f"echo '=== LDD CHECK FOR {bin_path} ==='",
            f"ldd {bin_path} 2>/dev/null || true",
            f"echo '=== EXECUTING: {run_cmd} ==='",
            f"{run_cmd} 2>/tmp/err.log || {{ echo 'EXECUTION FAILED:'; cat /tmp/err.log; m5 exit; }}",
        ]

    # 1. DEDUP (Kernel)
    if benchmark == "dedup":
        bin_path = f"{parsec_root}/pkgs/kernels/dedup/inst/riscv64-linux.gcc-hooks/bin/dedup"
        run_cmd = f"{bin_path} -c -p -v -t {threads} -i /tmp/dedup_run/media.dat -o /tmp/dedup_run/output.ddp"
        cmds.extend([
            "mkdir -p /tmp/dedup_run",
            "dd if=/dev/urandom of=/tmp/dedup_run/media.dat bs=1M count=10 2>/dev/null",
        ])
        cmds.extend(wrap_run(bin_path, run_cmd))

    # 2. CANNEAL (Kernel)
    elif benchmark == "canneal":
        bin_path = f"{parsec_root}/pkgs/kernels/canneal/inst/riscv64-linux.gcc-hooks/bin/canneal"
        inputs_dir = f"{parsec_root}/pkgs/kernels/canneal/inputs"
        input_map = {
            "test": ("100.nets", "100", "300", "2"),
            "simsmall": ("100000.nets", "100", "300", "2"),
            "simmedium": ("200000.nets", "15000", "2000", "32"),
            "simlarge": ("400000.nets", "15000", "2000", "32"),
        }
        target_netlist, swaps, temp, steps = input_map.get(
            size, ("100000.nets", "100", "300", "2")
        )

        cmds.extend([
            "mkdir -p /tmp/canneal_run",
            f'NETLIST="{inputs_dir}/{target_netlist}"',
            f'if [ ! -f "$NETLIST" ]; then NETLIST=$(ls {inputs_dir}/*.nets 2>/dev/null | tail -n 1); fi',
            'if [ -z "$NETLIST" ] || [ ! -f "$NETLIST" ]; then '
            'NETLIST="/tmp/canneal_run/test.nets"; '
            'echo "100 50" > "$NETLIST"; '
            "i=0; while [ $i -lt 50 ]; do echo \"1 $i $((i+1))\" >> \"$NETLIST\"; i=$((i+1)); done; "
            "fi",
        ])
        run_cmd = f'{bin_path} {threads} {swaps} {temp} "$NETLIST" {steps}'
        cmds.extend(wrap_run(bin_path, run_cmd))

    # 3. BODYTRACK (App)
    elif benchmark == "bodytrack":
        bin_path = f"{parsec_root}/pkgs/apps/bodytrack/inst/riscv64-linux.gcc-hooks/bin/bodytrack"
        inputs_dir = f"{parsec_root}/pkgs/apps/bodytrack/inputs"
        input_map = {
            "test": ("4", "1", "100", "5", "0"),
            "simsmall": ("4", "1", "1000", "5", "0"),
            "simmedium": ("4", "2", "2000", "5", "0"),
            "simlarge": ("4", "4", "4000", "5", "0"),
        }
        cams, frames, particles, layers, mode = input_map.get(
            size, ("4", "1", "1000", "5", "0")
        )

        cmds.extend([
            "mkdir -p /tmp/bt_run",
            'SEQ_DIR=""',
            f'for d in "{inputs_dir}"/* "{inputs_dir}"; do '
            'if [ -d "$d/CALIB" ]; then SEQ_DIR="$d"; break; fi; done',
            'if [ -z "$SEQ_DIR" ]; then echo "ERROR: Bodytrack CALIB directory missing"; m5 exit; fi',
        ])
        run_cmd = f'{bin_path} "$SEQ_DIR" {cams} {frames} {particles} {layers} {threads} {mode}'
        cmds.extend(wrap_run(bin_path, run_cmd))

    # 4. STREAMCLUSTER (Kernel)
    elif benchmark == "streamcluster":
        bin_path = f"{parsec_root}/pkgs/kernels/streamcluster/inst/riscv64-linux.gcc-hooks/bin/streamcluster"
        input_map = {
            "test": ("10", "20", "32", "10", "10", "1000"),
            "simsmall": ("10", "20", "32", "4096", "4096", "1000"),
            "simmedium": ("10", "20", "32", "8192", "8192", "1000"),
            "simlarge": ("10", "20", "64", "65536", "65536", "1000"),
        }
        k1, k2, dim, npoints, chunk, clusters = input_map.get(
            size, ("10", "20", "32", "4096", "4096", "1000")
        )

        cmds.append("mkdir -p /tmp/sc_run")
        run_cmd = f"{bin_path} {k1} {k2} {dim} {npoints} {chunk} {clusters} none /tmp/sc_run/output.txt {threads}"
        cmds.extend(wrap_run(bin_path, run_cmd))

    # 5. FLUIDANIMATE (App)
    elif benchmark == "fluidanimate":
        bin_path = f"{parsec_root}/pkgs/apps/fluidanimate/inst/riscv64-linux.gcc-hooks/bin/fluidanimate"
        inputs_dir = f"{parsec_root}/pkgs/apps/fluidanimate/inputs"
        input_map = {
            "test": ("in_15K.fluid", "5"),
            "simsmall": ("in_35K.fluid", "5"),
            "simmedium": ("in_100K.fluid", "15"),
            "simlarge": ("in_300K.fluid", "500"),
        }
        target_fluid, frames = input_map.get(size, ("in_35K.fluid", "5"))

        cmds.extend([
            "mkdir -p /tmp/fluid_run",
            f'FLUID_INPUT="{inputs_dir}/{target_fluid}"',
            f'if [ ! -f "$FLUID_INPUT" ]; then FLUID_INPUT=$(ls {inputs_dir}/*.fluid 2>/dev/null | tail -n 1); fi',
            'if [ -z "$FLUID_INPUT" ] || [ ! -f "$FLUID_INPUT" ]; then echo "ERROR: No .fluid input file found"; m5 exit; fi',
        ])
        run_cmd = f'{bin_path} {threads} {frames} "$FLUID_INPUT" /tmp/fluid_run/fluid.out'
        cmds.extend(wrap_run(bin_path, run_cmd))

    # 6. BLACKSCHOLES (App)
    elif benchmark == "blackscholes":
        bin_path = f"{parsec_root}/pkgs/apps/blackscholes/inst/riscv64-linux.gcc-hooks/bin/blackscholes"
        inputs_dir = f"{parsec_root}/pkgs/apps/blackscholes/inputs"
        input_map = {
            "test": "in_16.txt",
            "simsmall": "in_4K.txt",
            "simmedium": "in_16K.txt",
            "simlarge": "in_64K.txt",
        }
        txt_name = input_map.get(size, "in_4K.txt")

        cmds.extend([
            "mkdir -p /tmp/bs_run",
            f'INPUT_PATH="{inputs_dir}/{txt_name}"',
            f'if [ ! -f "$INPUT_PATH" ]; then INPUT_PATH=$(ls {inputs_dir}/*.txt 2>/dev/null | tail -n 1); fi',
            'if [ -z "$INPUT_PATH" ] || [ ! -f "$INPUT_PATH" ]; then '
            'INPUT_PATH="/tmp/bs_run/in_100.txt"; '
            'echo "100" > "$INPUT_PATH"; '
            "i=0; while [ $i -lt 100 ]; do echo \"100.0 100.0 0.05 0.10 0.20 1.0 P 0.0 0.0\" >> \"$INPUT_PATH\"; i=$((i+1)); done; "
            "fi",
        ])
        run_cmd = f'{bin_path} {threads} "$INPUT_PATH" /tmp/bs_run/prices.txt'
        cmds.extend(wrap_run(bin_path, run_cmd))

    else:
        raise ValueError(f"Unsupported benchmark '{benchmark}'")

    cmds.append("echo '=== BENCHMARK COMPLETED SUCCESSFULLY ==='")
    cmds.append("m5 exit")
    return "\n".join(cmds)

cache_hierarchy = PrivateL1SharedL2CacheHierarchy(
    l1d_size="32KiB",
    l1i_size="32KiB",
    l2_size="128KiB",
)

# Assign memory module

if (args.memory == "integrity_tree"):
    memory = IntegrityTreeProtectedMemory(
        size="16GiB",
        latency=args.encryption_latency,
        cache=not args.no_metadata_cache,
        cache_size=args.metadata_cache_size,
        arity=args.arity,
        cache_mac=args.cache_mac,
        eager_fetch=args.eager_fetch,
        bonsai=not args.no_bonsai,
        #l3_cache_size=args.l3_size,
        #protocol=args.mcx_policy,
    )
elif (args.memory == "mcx"):
    memory = MCXSecureMemory(
        size="16GiB",
        latency=args.encryption_latency,
        cache=not args.no_metadata_cache,
        metadata_cache_size=args.metadata_cache_size,
        arity=args.arity,
        cache_mac=args.cache_mac,
        eager_fetch=args.eager_fetch,
        bonsai=not args.no_bonsai,
        l3_cache_size=args.l3_size,
        protocol=args.mcx_policy,
    )
elif (args.memory == "DDR4"):
    memory =DualChannelDDR4_2400(
        size="16GiB",
    )
else: # Any kind of configurable memory uses the configurable module
    # Creating secure flag
    secure_flag = 0 # no security
    if (args.memory == "hashing_only"): secure_flag = 1
    elif (args.memory == "encryption_only"): secure_flag = 2
    elif (args.memory == "hashing+encryption"): secure_flag = 3
    elif (args.memory == "full_security" or args.memory == "configurable"): secure_flag = 7
    elif (args.memory == "no_security"): secure_flag = 0
    else:
      print(f"Incorrect memory module: {args.memory}")
      exit

    print(f"\nRunning memory module: {args.memory}\n  secure_flag: {secure_flag}\n\n")

    memory = ConfigurableMemory(
        size="16GiB",
        latency=args.encryption_latency,
        cache=not args.no_metadata_cache,
        cache_size=args.metadata_cache_size,
        arity=args.arity,
        cache_mac=args.cache_mac,
        eager_fetch=args.eager_fetch,
        bonsai=not args.no_bonsai,
        secure=secure_flag,
        #l3_cache_size=args.l3_size,
        #protocol=args.mcx_policy,
    )


# Here we setup the processor. This is a special switchable processor in which
# a starting core type and a switch core type must be specified. Once a
# configuration is instantiated a user may call `processor.switch()` to switch
# from the starting core types to the switch core types. In this simulation
# we start with KVM cores to simulate the OS boot, then switch to the Timing
# cores for the command we wish to run after boot.

processor = SimpleSwitchableProcessor(
    starting_core_type=CPUTypes.ATOMIC,
    switch_core_type=CPUTypes.O3,
    isa=ISA.RISCV,
    num_cores=4,
)

# Here we setup the board. The X86Board allows for Full-System X86 simulations

board = RiscvBoard(
    clk_freq="3GHz",
    processor=processor,
    memory=memory,
    cache_hierarchy=cache_hierarchy,
)

# Here we set the FS workload, i.e., gapbs benchmark program
# After simulation has ended you may inspect
# `m5out/system.pc.com_1.device` to the stdout, if any.

# After the system boots, we execute the benchmark program and wait till the
# ROI `workbegin` annotation is reached. We start collecting the number of
# committed instructions till ROI ends (marked by `workend`). We then finish
# executing the rest of the benchmark.

# micro-benchmark command
if (args.benchmark == "microbenchmark"):
    command = (
        f"cd;"
        f"cd repos/microbenchmark;"
        f"./bin/micro 500000000 536870900;"  
        f"sleep 5;"
        f"m5 exit;"
    )
    #command = """
    #  cd ~/repos/microbenchmark
    #  mkdir -p tmp
    #  ./bin/micro 500000000 536870900 > tmp/bg_out.log 2>&1 & 
    #  BG_PID=$!
    #  ./bin/micro 500000000 536870900 > tmp/fg_out.log 2>&1
    #  wait $BG_PID
    #  sleep 5
    #  m5 exit
    #""" # background process w/ '&' operator
else:
# parsec command
    command = get_parsec_workload_cmd(
        benchmark=args.benchmark,
        size=args.size,
        threads=4
    )

board.set_kernel_disk_workload(
    bootloader=BootloaderResource(
        local_path=os.getcwd() + "/fs_files/riscv-bootloader-opensbi-1.3.1"
    ),
    kernel=KernelResource(
        local_path=os.getcwd() + "/fs_files/linux-6.5.5"
    ),
    # The x86-parsec image will be automatically downloaded to the
    # `~/.cache/gem5` directory if not already present.
    disk_image=DiskImageResource(
        local_path=os.getcwd() + "/fs_files/riscv-ubuntu-22.04"
    ),
    readfile_contents=command,
)

# functions to handle different exit events during the simuation
def handle_workbegin():
    print("Done booting Linux")
    print("Resetting stats at the start of ROI!")
    processor.switch()
    m5.stats.reset()
    simulator.schedule_max_insts(125000000) # 500 million instructions
    yield False


def handle_workend():
    print()
    print("Benchmark finished")
    print("Dump stats at the end of the ROI!")
    m5.stats.dump()
    print()
    yield True

def handle_max_insts():
    print()
    print("Maximum instructions reached")
    print("Dump stats at the end of the ROI!")
    m5.stats.dump()
    print()
    yield True

simulator = Simulator(
    board=board,
    on_exit_event={
        ExitEvent.WORKBEGIN: handle_workbegin(),
        ExitEvent.WORKEND: handle_workend(),
        ExitEvent.MAX_INSTS: handle_max_insts(),
    },
)

# We maintain the wall clock time.

globalStart = time.time()

print("Running the simulation")

m5.stats.reset()

# We start the simulation
simulator.run()

print("All simulation events were successful.")

# We print the final simulation statistics.
print()
print("Performance statistics:")
roi_ticks = simulator.get_roi_ticks()
if roi_ticks:
    print("Simulated time in ROI: " + str(roi_ticks[0]))
else:
    print("Simulated time in ROI: N/A (Simulation exited before ROI completed)")
