# Copyright (c) 2012, 2014, 2017-2019, 2021 Arm Limited
# All rights reserved
#
# The license below extends only to copyright in the software and shall
# not be construed as granting a license to any other intellectual
# property including but not limited to intellectual property relating
# to a hardware implementation of the functionality of the software
# licensed hereunder.  You may use the software subject to the license
# terms below provided that you ensure that this notice is replicated
# unmodified and in its entirety in all distributions of the software,
# modified or unmodified, in source code or in binary form.
#
# Copyright (c) 2002-2005 The Regents of The University of Michigan
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
#
# Author: Samuel Thomas, Brown University (2025)


""" a ddr4 module with secure memory enabled """

from typing import (
    List,
    Optional,
    Sequence,
    Tuple,
)

from m5.objects import (
    MAC,
    MCX,
    AddrRange,
    Cache,
    CounterModeEncryption,
    DirectEncryption,
    IntegrityTree,
    L2XBar,
    MemCtrl,
    Port,
    StridePrefetcher,
)
from m5.util.convert import toMemorySize

from ...utils.override import overrides
from ..boards.abstract_board import AbstractBoard
from ..cachehierarchies.classic.caches.l1dcache import L1DCache
from .abstract_memory_system import AbstractMemorySystem
from .dram_interfaces.ddr4 import DDR4_2400_8x8


class SecureDDR4(AbstractMemorySystem):
    """A class that implements secure memory using SimpleMemory"""

    def __init__(
        self,
        secure_memory_class,
        latency: int,
        size: str,
        arity: int = 8,
        cache: bool = True,
        cache_size: str = "64KiB",
        ch: bool = False,
        ef: bool = True,
        bonsai: bool = True,
        l3_size: str = "1MB",
        protocol: str = "never",
    ):
        """
        :param latency: the average request to response latency
        :param bandwidth: combined read and write bandwidth
        :param size: size of the memory
        """

        super().__init__()

        if toMemorySize(size) > toMemorySize("3GiB"):
            assert size[-3:] == "GiB"
            #assert secure_memory_class == MCX
            remaining_size = str(int(size[:-3]) - 3) + "GiB"
            self._dram = [
                    DDR4_2400_8x8(device_size = "3GiB"),
                    DDR4_2400_8x8(device_size = remaining_size),
            ]
            self.mem_ctrl = [
                    MemCtrl(dram=self._dram[0]),
                    MemCtrl(dram=self._dram[1]),
            ]
        else:
            self._dram = [DDR4_2400_8x8(device_size=size)]
            self.mem_ctrl = [MemCtrl(dram=self._dram[0])]

        self._size = toMemorySize(size)

        if secure_memory_class == DirectEncryption:
            self.secure_memory = DirectEncryption(latency=latency)
        else:
            if secure_memory_class == CounterModeEncryption:
                self.secure_memory = CounterModeEncryption(
                    latency=latency, arity=arity
                )
            elif secure_memory_class == MAC:
                self.secure_memory = MAC(
                    latency=latency, counter_arity=arity, cache_mac=ch
                )
            elif secure_memory_class == IntegrityTree:
                self.secure_memory = IntegrityTree(
                    latency=latency,
                    tree_arity=arity,
                    cache_mac=ch,
                    eager_fetch=ef,
                    bonsai=bonsai,
                )
            elif secure_memory_class == MCX:
                self.secure_memory = MCX(
                    latency=latency,
                    tree_arity=arity,
                    cache_mac=ch,
                    eager_fetch=ef,
                    bonsai=bonsai,
                    protocol=protocol,
                    print_llc_stats=cache_size == "64KiB" and l3_size == "256KiB",
                )

            self.metadata_cache = L1DCache(size=cache_size)
            self.secure_memory.metadata_request_port = (
                self.metadata_cache.cpu_side
            )
            self.secure_memory.metadata_response_port = (
                self.metadata_cache.mem_side
            )

        # Check that we actually want an L3 cache before building it
        if secure_memory_class == MCX:
            # Only build if size is not 'none' and greater than 0 bytes
            if str(l3_size).lower() != "none" and toMemorySize(str(l3_size)) > 0:

                class L3Cache(Cache):
                    def __init__(
                        self,
                    ):
                        super().__init__()
                        self.size = l3_size
                        self.assoc = 64
                        self.tag_latency = 32
                        self.data_latency = 32
                        self.response_latency = 1
                        self.mshrs = 50
                        self.tgts_per_mshr = 16
                        self.writeback_clean = False
                        self.clusivity = "mostly_incl"
                        self.prefetcher = StridePrefetcher()

                self.secure_memory.l3 = L3Cache()
                self.secure_memory.l3_request_port = self.secure_memory.l3.cpu_side
                self.secure_memory.l3_response_port = (
                    self.secure_memory.l3.mem_side
                )
            else:
                # SHORT-CIRCUIT: Tie the L3 ports together to bypass
                self.secure_memory.l3_request_port = self.secure_memory.l3_response_port
#        if secure_memory_class == MCX:
#
#            class L3Cache(Cache):
#                def __init__(
#                    self,
#                ):
#                    super().__init__()
#                    self.size = l3_size
#                    self.assoc = 64
#                    self.tag_latency = 32
#                    self.data_latency = 32
#                    self.response_latency = 1
#                    self.mshrs = 50
#                    self.tgts_per_mshr = 16
#                    self.writeback_clean = False
#                    self.clusivity = "mostly_incl"
#                    self.prefetcher = StridePrefetcher()
#
#            self.secure_memory.l3 = L3Cache()
#            self.secure_memory.l3_request_port = self.secure_memory.l3.cpu_side
#            self.secure_memory.l3_response_port = (
#                self.secure_memory.l3.mem_side
#            )

        self.to_mem = L2XBar()
        self.secure_memory.mem_side = self.to_mem.cpu_side_ports
        for ctrl in self.mem_ctrl:
            self.to_mem.mem_side_ports = ctrl.port

    @overrides(AbstractMemorySystem)
    def incorporate_memory(self, board: AbstractBoard) -> None:
        pass

    @overrides(AbstractMemorySystem)
    def get_mem_ports(self) -> Sequence[Tuple[AddrRange, Port]]:
        to_return = [ (self._dram[0].range, self.secure_memory.cpu_side0) ]
        #to_return = [ (self._dram[0].range, self.secure_memory.cpu_side ) ]

        if len(self.mem_ctrl) > 1:
            assert len(self.mem_ctrl) == 2
            to_return.append(( self._dram[1].range, self.secure_memory.cpu_side1 ))

        return to_return

    @overrides(AbstractMemorySystem)
    def get_memory_controllers(self) -> List[MemCtrl]:
        return self.mem_ctrl

    @overrides(AbstractMemorySystem)
    def get_size(self) -> int:
        return self._size

    @overrides(AbstractMemorySystem)
    def set_memory_range(self, ranges: List[AddrRange]) -> None:
        if len(ranges) != 1:
            # raise Exception(
            #     "Secure memory controller requires a single "
            #     "range which matches the memory's size. Too naughty for words!"
            # )
            assert len(ranges) == 2
            self._dram[0].range = ranges[0]
            self._dram[1].range = ranges[1]
        else:
            self._dram[0].range = ranges[0]


def DirectEncryptedMemory(
    size: Optional[str] = "32MB", latency: Optional[int] = 53
) -> AbstractMemorySystem:
    # latency is the number of cycles to do AES encryption
    return SecureDDR4(DirectEncryption, size=size, latency=latency)


def CounterModeEncryptedMemory(
    size: Optional[str] = "32MB",
    latency: Optional[int] = 53,
    arity: Optional[int] = 64,
    cache: Optional[bool] = True,
    cache_size: Optional[str] = "64KiB",
) -> AbstractMemorySystem:
    # arity describes counter arity (number of data blocks per counter block)
    return SecureDDR4(
        CounterModeEncryption,
        size=size,
        latency=latency,
        arity=arity,
        cache=cache,
        cache_size=cache_size,
    )


def MACProtectedMemory(
    size: Optional[str] = "32MB",
    latency: Optional[int] = 53,
    arity: Optional[int] = 64,
    cache: Optional[bool] = True,
    cache_size: Optional[str] = "64KiB",
    cache_mac: Optional[bool] = False,
) -> AbstractMemorySystem:
    # arity describes counter arity (number of data blocks per counter block)
    return SecureDDR4(
        MAC,
        size=size,
        latency=latency,
        arity=arity,
        cache=cache,
        cache_size=cache_size,
        ch=cache_mac,
    )


def IntegrityTreeProtectedMemory(
    size: Optional[str] = "32MB",
    latency: Optional[int] = 53,
    arity: Optional[int] = 64,
    cache: Optional[bool] = True,
    cache_size: Optional[str] = "64KiB",
    cache_mac: Optional[bool] = False,
    eager_fetch: Optional[bool] = True,
    bonsai: Optional[bool] = True,
) -> AbstractMemorySystem:
    # arity describes counter arity (number of data blocks per counter block)
    return SecureDDR4(
        IntegrityTree,
        size=size,
        latency=latency,
        arity=arity,
        cache=cache,
        cache_size=cache_size,
        ch=cache_mac,
        ef=eager_fetch,
        bonsai=bonsai,
    )


def MCXSecureMemory(
    size: Optional[str] = "32MB",
    latency: Optional[int] = 53,
    arity: Optional[int] = 64,
    cache: Optional[bool] = True,
    metadata_cache_size: Optional[str] = "64KiB",
    cache_mac: Optional[bool] = False,
    eager_fetch: Optional[bool] = True,
    bonsai: Optional[bool] = True,
    l3_cache_size: Optional[str] = "1MB",
    protocol: Optional[str] = "never",
) -> AbstractMemorySystem:
    # arity describes counter arity (number of data blocks per counter block)
    return SecureDDR4(
        MCX,
        size=size,
        latency=latency,
        arity=arity,
        cache=cache,
        cache_size=metadata_cache_size,
        ch=cache_mac,
        ef=eager_fetch,
        bonsai=bonsai,
        l3_size=l3_cache_size,
        protocol=protocol,
    )
