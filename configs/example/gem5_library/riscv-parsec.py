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
import base64

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
from socket import gethostname


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
    "--benchmark2",
    type=str,
    required=False,
    help="2nd benchmark",
    choices=benchmark_choices,
)

parser.add_argument(
    "--memory2",
    type=str,
    required=False,
    help="Which security protocol for 2nd benchmark.",
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
    elif (args.memory == "full_security"): secure_flag = 7
    elif (args.memory == "no_security" or args.memory == "configurable"): secure_flag = 0
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
    bmarks = [args.benchmark]
    if args.benchmark2:
        bmarks.append(args.benchmark2)

    payloads = {}
    guest_args_map = {}
<<<<<<< Updated upstream
    bm_types = {} # Track whether the benchmark is an app or a kernel
=======
    bm_types = {}  # Tracks whether the benchmark is an 'app' or 'kernel' for the tar extraction
>>>>>>> Stashed changes

    hostname = gethostname()
    PARSEC_DIR = "/home/wbuziak/repos/gem5/parsec-benchmark"

    for bm in bmarks:
<<<<<<< Updated upstream
        # 1. Locate the binary
        app_path = os.path.join(PARSEC_DIR, "pkgs", "apps", bm, "inst", "aarch64-linux.riscv-hooks", "bin", bm)
        kernel_path = os.path.join(PARSEC_DIR, "pkgs", "kernels", bm, "inst", "aarch64-linux.riscv-hooks", "bin", bm)
=======
        # 1. Locate the binary and determine its type
        if "iris-arm-server" in hostname:
            app_path = os.path.join(PARSEC_DIR, "pkgs", "apps", bm, "inst", "aarch64-linux.riscv-hooks", "bin", bm)
            kernel_path = os.path.join(PARSEC_DIR, "pkgs", "kernels", bm, "inst", "aarch64-linux.riscv-hooks", "bin", bm)

            if os.path.isfile(app_path):
                WORKLOAD_PATH = app_path
                bm_types[bm] = "apps"
            elif os.path.isfile(kernel_path):
                WORKLOAD_PATH = kernel_path
                bm_types[bm] = "kernels"
            else:
                WORKLOAD_PATH = ""
        else:
            WORKLOAD_PATH = os.path.join(PARSEC_DIR, bm)
            # Fallback check if it's an app or kernel on other hosts
            if os.path.exists(os.path.join(PARSEC_DIR, "pkgs", "kernels", bm)):
                bm_types[bm] = "kernels"
            else:
                bm_types[bm] = "apps"
>>>>>>> Stashed changes

        # Check both apps and kernels directories
        if os.path.isfile(app_path):
            WORKLOAD_PATH = app_path
            bm_types[bm] = "apps"
        elif os.path.isfile(kernel_path):
            WORKLOAD_PATH = kernel_path
            bm_types[bm] = "kernels"
        else:
            print(f"Host binary not found for {bm}. Checked apps and kernels.")
            sys.exit(1)

        # 2. Base64 Encode
        with open(WORKLOAD_PATH, "rb") as f:
            payloads[bm] = base64.b64encode(f.read()).decode("ascii")

<<<<<<< Updated upstream
        # 3. Setup arguments based on workload and size
=======
        # 3. Setup arguments based on the specific benchmark
>>>>>>> Stashed changes
        if bm == "blackscholes":
            input_map = {"simsmall": "in_4K.txt", "simmedium": "in_16K.txt", "simlarge": "in_64K.txt"}
            input_file = input_map.get(args.size, "in_4K.txt")
            guest_args_map[bm] = f"4 {input_file} prices.txt"
<<<<<<< Updated upstream

        elif bm == "streamcluster":
            # args: k1 k2 d dim chunksize clustersize infile outfile nthreads
=======
            
        elif bm == "dedup":
            # dedup args: -c (compress) -p (profiling) -v (verbose) -t <threads> -i <infile> -o <outfile>
            # The input tarball always extracts a file named 'media.dat' regardless of sim size.
            guest_args_map[bm] = "-c -p -v -t 4 -i media.dat -o output.dat.ddp"
            
        elif bm == "streamcluster":
>>>>>>> Stashed changes
            input_map = {
                "simsmall": "10 20 32 4096 4096 1000 none output.txt 4",
                "simmedium": "10 20 64 8192 8192 1000 none output.txt 4",
                "simlarge": "10 20 128 16384 16384 1000 none output.txt 4"
            }
            guest_args_map[bm] = input_map.get(args.size, "10 20 32 4096 4096 1000 none output.txt 4")
<<<<<<< Updated upstream

        elif bm == "dedup":
            # args: -c (compress) -p (profiling) -v (verbose) -t <threads> -i <infile> -o <outfile>
            # PARSEC's input_*.tar extracts 'media.dat' for all sizes; only the file size changes.
            guest_args_map[bm] = "-c -p -v -t 4 -i media.dat -o output.dat.ddp"

=======
            
>>>>>>> Stashed changes
        else:
            guest_args_map[bm] = "4" # Fallback

    # 4. Construct Guest Execution Command
    command = "echo 'Boot complete, updating binaries!'\n"

<<<<<<< Updated upstream
    # Unpack both binaries via Base64 decoding
=======
    # Unpack both binaries
>>>>>>> Stashed changes
    for i, bm in enumerate(bmarks):
        command += (
            f"cat << 'B64EOF{i}' | base64 -d > /root/exec_{bm}\n"
            f"{payloads[bm]}\n"
            f"B64EOF{i}\n"
            f"chmod +x /root/exec_{bm}\n"
        )

    # Launch both benchmarks in the background
    for i, bm in enumerate(bmarks):
<<<<<<< Updated upstream
        bm_type = bm_types[bm] # Dynamically grab "apps" or "kernels"
        command += (
            f"mkdir -p /root/run_{bm}\n"
            f"cd /root/run_{bm}\n"
            # Note: This assumes /home/wbuziak/... is mounted in your guest OS via m5 virtio 9p.
=======
        bm_type = bm_types.get(bm, "apps") # Dynamically inject 'apps' or 'kernels'
        command += (
            f"mkdir -p /root/run_{bm}\n"
            f"cd /root/run_{bm}\n"
>>>>>>> Stashed changes
            f"tar -xf {PARSEC_DIR}/pkgs/{bm_type}/{bm}/inputs/input_{args.size}.tar\n"
            f"/root/exec_{bm} {guest_args_map[bm]} &\n"
            f"PID{i}=$!\n"
        )

    # Wait for both to finish
    for i in range(len(bmarks)):
        command += f"wait $PID{i}\n"
<<<<<<< Updated upstream

command += "echo 'All benchmarks exited'\nm5 exit\n"

=======

    command += "echo 'All benchmarks exited'\nm5 exit\n"

>>>>>>> Stashed changes
board.set_kernel_disk_workload(
    bootloader=BootloaderResource(local_path=os.getcwd() + "/fs_files/riscv-bootloader-opensbi-1.3.1"),
    kernel=KernelResource(local_path=os.getcwd() + "/fs_files/linux-6.5.5"),
    disk_image=DiskImageResource(local_path=os.getcwd() + "/fs_files/riscv-ubuntu-22.04"),
    readfile_contents=command,
<<<<<<< Updated upstream
) 
=======
)
>>>>>>> Stashed changes

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

def handle_exit():
    print("Done booting Linux")
    print("Resetting stats at the start of ROI!")
    processor.switch()
    m5.stats.reset()
    simulator.schedule_max_insts(125000000) # 500 million instructions
    yield False

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
        ExitEvent.EXIT: handle_exit(),
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
