"""
Full-system config for the concurrent skip list on CXL device memory.

Mode is "operations" by default

The guest prints one CSV row on stdout. Run once with --mode header to get
the column names.

```
./build/X86/gem5.opt --outdir=m5out_skiplist_8t_random \
    configs/example/gem5_library/x86-cxl-skiplist-test.py \
    --threads 8 --preload 32000 --ops 20000 \
    --ins 25 --rem 25 --con 50 --element-space 1000000 --policy random
```
"""

import argparse
import base64
import os
import sys
from socket import gethostname

import m5
from gem5.components.boards.x86_board import X86Board
from gem5.components.cachehierarchies.classic.no_cache import NoCache
from gem5.components.cachehierarchies.classic.private_l1_cache_hierarchy import (
    PrivateL1CacheHierarchy,
)
from gem5.components.memory.cxl_memory import CXLmemory
from gem5.components.memory.dram_interfaces.ddr3 import DDR3_1600_8x8
from gem5.components.memory.dram_interfaces.ddr4 import DDR4_2400_8x8
from gem5.components.memory.dram_interfaces.ddr5 import DDR5_8400_4x8
from gem5.components.processors.cpu_types import CPUTypes
from gem5.components.processors.simple_switchable_processor import (
    SimpleSwitchableProcessor,
)
from gem5.isas import ISA
from gem5.resources.resource import DiskImageResource, KernelResource
from gem5.simulate.exit_event import ExitEvent
from gem5.simulate.simulator import Simulator
from gem5.utils.requires import requires

requires(isa_required=ISA.X86)

parser = argparse.ArgumentParser(description="Skip list on CXL device memory")
parser.add_argument("--threads", type=int, default=4)

# "operations" gives every policy the same work and measures the time
# "time" gives every policy the same time and measures the work
parser.add_argument(
    "--mode",
    default="operations",
    choices=["operations", "time", "header"],
)
parser.add_argument("--ins", type=int, default=25, help="insert percent")
parser.add_argument("--rem", type=int, default=25, help="remove percent")
parser.add_argument("--con", type=int, default=50, help="contains percent")
parser.add_argument("--preload", type=int, default=32000)
parser.add_argument("--element-space", type=int, default=1000000)
parser.add_argument("--ops", type=int, default=20000, help="operations per thread")
parser.add_argument("--seconds", type=int, default=10, help="only used by time modes")

# Fixed so two policies draw the same keys and the comparison is apples to
# apples. Vary it to get a different stream.
parser.add_argument("--seed", type=int, default=12345, help="guest RNG seed")

# Workload keys are skewed by default (zipf)
parser.add_argument(
    "--key-dist",
    default="zipfian",
    choices=["zipfian", "uniform"],
    help="distribution the workload keys are drawn from",
)
parser.add_argument(
    "--zipf-alpha", type=float, default=1.0, help="zipf skew, larger is steeper"
)

# Hot keys are scattered across the keyspace by default (YCBS)
parser.add_argument(
    "--no-scramble",
    action="store_true",
    help="leave zipf hot keys contiguous at the bottom of the keyspace",
)

# What to cache.
parser.add_argument(
    "--cache",
    default="none",
    choices=["none", "l1"],
    help="cache hierarchy: no caches, L1I",
)
parser.add_argument("--l1i-size", default="32KiB")
parser.add_argument("--l1d-size", default="512B")

# Which device the allocator puts each object on. See DevicePolicy.hh.
parser.add_argument(
    "--policy",
    default="speed",
    choices=["random", "mirakuru", "speed"],
)

# Round-trip link latency to each device, in nanoseconds, fastest first
# This separates memory tiers (instead of DDR5/4/3)
parser.add_argument(
    "--device-latency",
    type=int,
    nargs=3,
    default=[100, 200, 400],  # TODO: Play with these values
    metavar=("DEV0", "DEV1", "DEV2"),
    help="round-trip link latency of each device in ns, fastest first",
)

# Which DRAM sits behind each device.
parser.add_argument(
    "--dram",
    default="uniform",
    choices=["uniform", "mixed"],
    help="uniform: the same part everywhere, so the tiers differ by link "
    "latency alone. mixed: DDR5/DDR4/DDR3, which differ in bandwidth",
)

# For some reason we need extra cores (more cores than threads)
# FIX: 6 extra cores works surprisingly well
parser.add_argument(
    "--extra-cores",
    type=int,
    default=6,
    help="cores beyond --threads, for the main thread and the kernel",
)
args = parser.parse_args()

# The first three are the devices the guest claims, and DEVICE_SIZES in
# tests/SkipListTest.cc must match them: 180, 52 and 50 + 80 = 130 MiB
#
# The fourth is GUEST_MARGIN, which the guest deliberately leaves unclaimed for the OS, the zipf table, etc.
sizes = ["180MiB", "52MiB", "50MiB", "80MiB"]

# "uniform" - differ by link latency alone
# "mixed" - differ by link latency and device type
if args.dram == "mixed":
    memory = [
        DDR5_8400_4x8(),
        DDR4_2400_8x8(),
        DDR3_1600_8x8(),
        DDR3_1600_8x8(),
    ]
else:
    memory = [DDR4_2400_8x8() for _ in sizes]  # "uniform" ddr4 devices

# The margin is the program's own heap, so imitate local mem by 0 latency
latencies = list(args.device_latency) + [0]  # Different link latencies
# latencies = [25, 25, 25, 25] # NOTE: What I had before

cxl_mem = CXLmemory(
    memory=memory,
    sizes=sizes,
    strategy="speed",
    frag_perc=0,
    frag_seed=47,
    cxl_latency=latencies,
)


processor = SimpleSwitchableProcessor(
    starting_core_type=CPUTypes.ATOMIC,
    switch_core_type=CPUTypes.TIMING,
    isa=ISA.X86,
    num_cores=args.threads + args.extra_cores,
)

if args.cache == "l1":
    cache_hierarchy = PrivateL1CacheHierarchy(
        l1i_size=args.l1i_size, l1d_size=args.l1d_size
    )
else:
    cache_hierarchy = NoCache()

board = X86Board(
    clk_freq="3GHz",
    processor=processor,
    memory=cxl_mem,
    cache_hierarchy=cache_hierarchy,
)

# Get the binary path (depends on a machine where I'm running this)
hostname = gethostname()
if hostname.startswith("Vadym"):
    BIN_DIR = "/Users/vadymmusiienko/Work/Research/microtests/bin"
elif hostname == "pcal03":
    BIN_DIR = "/home/vmmv2023/SURP/microtests/bin"
elif "SLURM_JOB_ID" in os.environ or hostname == "sagehen.hpc.pomona.edu":
    BIN_DIR = "/rhome/vmmv2023/SURP/microtests/bin"
else:
    print("Not one of the configured machines! (pcal|hpc|local mac)")
    assert False

WORKLOAD_PATH = os.path.join(BIN_DIR, "SkipListTest")

# Same cache layout obtain_resource() would have used
# so an already populated ~/.cache/gem5 just works
# Explicit paths because the cluster has no internet to download from
RESOURCE_DIR = os.environ.get("GEM5_RESOURCE_DIR", os.path.expanduser("~/.cache/gem5"))
KERNEL_PATH = os.path.join(RESOURCE_DIR, "x86-linux-kernel-5.4.49-1.0.0")
DISK_IMAGE_PATH = os.path.join(RESOURCE_DIR, "x86-ubuntu-18.04-img-1.0.0")

for path in (KERNEL_PATH, DISK_IMAGE_PATH):
    if not os.path.isfile(path):
        print(f"Full-system resource not found: {path}")
        assert False

# READ IN THE BINARY
with open(WORKLOAD_PATH, "rb") as f:
    payload = base64.b64encode(f.read()).decode("ascii")

# NOTE: SkipList Tester takes 9 positional args in this order
# NOTE: policy is an additional argument for cxl skiplist only
GUEST_ARGS = (
    f"{args.threads} {args.mode} {args.ins} {args.rem} {args.con} "
    f"{args.preload} {args.element_space} {args.ops} {args.seconds} "
    f"--{args.policy} --seed {args.seed} "
    f"--{args.key_dist} --zipf-alpha {args.zipf_alpha}"
    f"{' --no-scramble' if args.no_scramble else ''}"
)

# Execute any commands on the disk image
my_commands = (
    "echo 'Boot complete, updating the binary!'\n"
    "cat << 'B64EOF' | base64 -d > /root/executable\n"
    f"{payload}\n"
    "B64EOF\n"
    "chmod +x /root/executable\n"
    # No marker here. Both ROI markers come from inside the binary now, so
    # that boot, the device claim and the whole preload stay on the ATOMIC
    # cores. The binary switches to TIMING only once every worker has
    # finished preloading, and exits again after it writes its CSV row
    f"/root/executable {GUEST_ARGS}\n"
    'echo "skiplist exit $?"\n'
    "m5 exit\n"  # safety net if the binary dies before its own ROI-end exit
)

board.set_kernel_disk_workload(
    kernel=KernelResource(local_path=KERNEL_PATH),
    disk_image=DiskImageResource(local_path=DISK_IMAGE_PATH, root_partition="1"),
    readfile_contents=my_commands,
)

print("Full-System mode")


# Both markers come from inside the workload: the first once preload is done, the second after the CSV row is written
def roi_start() -> bool:
    print("ROI start: preload done, switching to TIMING cores and resetting stats")
    processor.switch()
    m5.stats.reset()
    return False


def roi_end() -> bool:
    print("ROI end: dumping stats")
    m5.stats.dump()
    return True


simulator = Simulator(
    board=board,
    on_exit_event={ExitEvent.EXIT: [roi_start, roi_end]},
)

print(
    f"skip list: {args.threads} threads, {args.mode}, {args.policy}, "
    f"seed {args.seed}, keys {args.key_dist}"
    f"{f' alpha {args.zipf_alpha}' if args.key_dist == 'zipfian' else ''}"
    f"{' unscrambled' if args.no_scramble else ''}, cache {args.cache}, "
    f"sizes {sizes}, dram {args.dram}, link latency {args.device_latency} ns"
)
simulator.run()
