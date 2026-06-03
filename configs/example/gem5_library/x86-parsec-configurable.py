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
Script to run PARSEC benchmarks with gem5.
The script expects a benchmark program name and the simulation
size. The system is fixed with 2 CPU cores, MESI Two Level system
cache and 3 GiB DDR4 memory. It uses the x86 board.

This script will count the total number of instructions executed
in the ROI. It also tracks how much wallclock and simulated time.

Usage:
------

```
scons build/X86/gem5.opt
./build/X86/gem5.opt \
    configs/example/gem5_library/x86-parsec-benchmarks.py \
    --benchmark <benchmark_name> \
    --size <simulation_size>
```
"""
import argparse
import os
import time

import m5
from m5.objects import Root

from gem5.coherence_protocol import CoherenceProtocol
from gem5.components.boards.x86_board import X86Board
from gem5.components.memory.secure_ddr4 import MCXSecureMemory
from gem5.components.memory.secure_ddr4 import IntegrityTreeProtectedMemory
from gem5.components.memory.multi_channel import DualChannelDDR4_2400
from gem5.components.processors.cpu_types import CPUTypes
from gem5.components.processors.simple_switchable_processor import (
    SimpleSwitchableProcessor,
)
from gem5.isas import ISA
from gem5.resources.resource import obtain_resource
from gem5.resources.resource import KernelResource
from gem5.resources.resource import DiskImageResource
from gem5.simulate.exit_event import ExitEvent
from gem5.simulate.simulator import Simulator
from gem5.utils.requires import requires

# Following are the list of benchmark programs for parsec.

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
]

# Memory module choices

memory_choices = [
    "configurable",
    "integrity_tree",
    "no_security",
    "mcx",
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

# Setting up all the fixed system parameters here
# Caches: MESI Two Level Cache Hierarchy

from gem5.components.cachehierarchies.classic.private_l1_shared_l2_cache_hierarchy import (
    PrivateL1SharedL2CacheHierarchy,
)

# Memory: Dual Channel DDR4 2400 DRAM device.
# The X86 board only supports 3 GiB of main memory.


cache_hierarchy = PrivateL1SharedL2CacheHierarchy(
    l1d_size="32KiB",
    l1i_size="32KiB",
    l2_size="128KiB",
)

print(f"\nRunning memory module: {args.memory}\n")

if (args.memory == "configurable"):
    memory = ConfigurableMemory(
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
elif (args.memory == "integrity_tree"):
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
else:
    memory =DualChannelDDR4_2400( 
        size="16GiB",
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
    isa=ISA.X86,
    num_cores=4,
)

# for proc in processor.start:
#     proc.core.usePerf = False

# Here we setup the board. The X86Board allows for Full-System X86 simulations

board = X86Board(
    clk_freq="3GHz",
    processor=processor,
    memory=memory,
    cache_hierarchy=cache_hierarchy,
)

# Here we set the FS workload, i.e., parsec benchmark
# After simulation has ended you may inspect
# `m5out/system.pc.com_1.device` to the stdout, if any.

# After the system boots, we execute the benchmark program and wait till the
# ROI `workbegin` annotation is reached (m5_work_begin()). We start collecting
# the number of committed instructions till ROI ends (marked by `workend`).
# We then finish executing the rest of the benchmark.

# Also, we sleep the system for some time so that the output is printed
# properly.


command = (
    f"cd /home/gem5/parsec-benchmark;"
    + "source env.sh;"
    + f"parsecmgmt -a run -p {args.benchmark} -c gcc-hooks -i {args.size}         -n 4;"
    + "sleep 5;"
    + "m5 exit;"
)

board.set_kernel_disk_workload(
    # The x86 linux kernel will be automatically downloaded to the
    # `~/.cache/gem5` directory if not already present.
    # PARSEC benchamarks were tested with kernel version 4.19.83
    #kernel=KernelResource(
    #    local_path=os.getcwd() + "/fs_files/vmlinux-4.19.83"
    #),
    kernel=KernelResource(
        local_path=os.getcwd() + "/fs_files/vmlinux-5.2.3"
    ),
    # The x86-parsec image will be automatically downloaded to the
    # `~/.cache/gem5` directory if not already present.
    disk_image=DiskImageResource(
        local_path=os.getcwd() + "/fs_files/parsec.img"
    ),
    readfile_contents=command,
)


# functions to handle different exit events during the simuation
def handle_workbegin():
    print("Done booting Linux")
    print("Resetting stats at the start of ROI!")
    m5.stats.reset()
    processor.switch()
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

print("Simulated time in ROI: " + (str(simulator.get_roi_ticks()[0])))
print(
    "Ran a total of", simulator.get_current_tick() / 1e12, "simulated seconds"
)
print(
    "Total wallclock time: %.2fs, %.2f min"
    % (time.time() - globalStart, (time.time() - globalStart) / 60)
)
