/*
 * Copyright (c) 2012, 2014, 2017-2019, 2021 Arm Limited
 * All rights reserved
 *
 * The license below extends only to copyright in the software and shall
 * not be construed as granting a license to any other intellectual
 * property including but not limited to intellectual property relating
 * to a hardware implementation of the functionality of the software
 * licensed hereunder.  You may use the software subject to the license
 * terms below provided that you ensure that this notice is replicated
 * unmodified and in its entirety in all distributions of the software,
 * modified or unmodified, in source code or in binary form.
 *
 * Copyright (c) 2002-2005 The Regents of The University of Michigan
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer;
 * redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution;
 * neither the name of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: Samuel Thomas, Brown University (2025)
 */

#include <cmath>
#include "mem/secure_memory/mcx.hh"
#include "mem/cache/tags/base_set_assoc.hh"

namespace gem5::memory {

  MCX::MCX(const MCXParams *p)
    : SimObject(*p),
    cpu_port0(p->name + ".cpu_side0", this),
    cpu_port1(p->name + ".cpu_side1", this),
    mem_port(p->name + ".mem_side", this),
    metadata_request_port(p->name + ".metadata_request_port", this),
    metadata_response_port(p->name + ".metadata_response_port", this),
    l3_request_port(p->name + ".l3_request_port", this),
    l3_response_port(p->name + ".l3_response_port", this),
    cipher_latency(p->latency * 1000), // accounts for 1GHz CPU clock
    xor_latency(1000), // accounts for 1GHz CPU clock
    hash_latency(p->hash_latency * 1000), // accounts for 1GHz CPU clock
    tree_arity(p->tree_arity),
    counter_arity(p->counter_arity),
    mac_arity(p->mac_arity),
    use_metadata_cache(p->cache),
    cache_mac(p->cache_mac),
    eager_fetch(p->eager_fetch),
    bonsai(p->bonsai),
    hotspot_level(p->hotspot_level),
    access_buffer_size(p->access_buffer_size),
    hot_pct(p->hot_pct),
    recent_accesses_buffer_size(64),
    distance_level(1), // root by default
    recent_l3_accesses_buffer_size(1024),
    recent_l3_hits(0),
    protocol(p->protocol),
    requests_handled(0),
    metadata_in_llc(0),
    print_llc_stats(p->print_llc_stats),
    cipherEvent([this] { cipherEngine(); }, name()),
    macEvent([this] { macEngine(); }, name()),
    parallelReadRespondEvent([this] { respondParallelRead(); }, name()),
    metadataRespondEvent([this] { respondMetadataCache(); }, name()),
    l3RespondEvent([this] { respondL3Cache(); }, name()),
    stats(*this)
    {
    }

  void
    MCX::startup()
    {
      // assert(mem_port.getAddrRanges().size() == 1);

      Addr start = mem_port.getAddrRanges().front().start();
      Addr end = mem_port.getAddrRanges().back().end();

      uint64_t mac_bytes = (end - start) / mac_arity;
      uint64_t level_items;
      if (bonsai) {
        level_items = ((end - start) / counter_arity) / BLOCK_SIZE;
      } else {
        level_items = mac_bytes / BLOCK_SIZE;
      }

      Addr level_start = end + mac_bytes;
      // assert(bonsai);

      // setup integrity levels
      // [ mac_start, root addr, L2 start, ..., counter start, data start]

      integrity_levels.push_back(start); // data

      while (level_items) {
        integrity_levels.push_front(level_start); // tree levels
        level_start += (level_items * BLOCK_SIZE);
        level_items /= tree_arity;
      }

      integrity_levels.push_front(end); // mac

      integrity_levels.shrink_to_fit(); // C++ data structures... meh :/


      // setup frequencies vector
      int nodes_at_level = pow(8, hotspot_level - 1);
      for (int i = 0; i < nodes_at_level; i++) {
        frequencies.push_back(0);
      }
    }

  Port&
    MCX::getPort(const std::string &if_name, PortID idx)
    {
      if (if_name == "mem_side") {
        return mem_port;
      } else if (if_name == "cpu_side0") {
        return cpu_port0;
      } else if (if_name == "cpu_side1") {
        return cpu_port1;
      } else if (if_name == "metadata_request_port") {
        return metadata_request_port;
      } else if (if_name == "metadata_response_port") {
        return metadata_response_port;
      } else if (if_name == "l3_request_port") {
        return l3_request_port;
      } else if (if_name == "l3_response_port") {
        return l3_response_port;
      }

      return SimObject::getPort(if_name, idx);
    }

  int
    MCX::getSubtree(PacketPtr pkt)
    {
      for (int i = 1; i < integrity_levels.size() - 1; i++) {
        if (pkt->getAddr() >= integrity_levels[i]) {
          if (i < hotspot_level) {
            return -1;
          }

          uint64_t nodes_at_hotspot_level = (integrity_levels[hotspot_level - 1] - integrity_levels[hotspot_level] - BLOCK_SIZE) / BLOCK_SIZE;
          uint64_t region_size = (integrity_levels[i - 1] - integrity_levels[i] - BLOCK_SIZE) / nodes_at_hotspot_level;

          return (pkt->getAddr() - integrity_levels[i]) / region_size / BLOCK_SIZE;
        }
      }

      // assert(false); // triggered when cache_mac set to true
      return -1;
    }

  void
    MCX::sendMetadataToCache(PacketPtr pkt)
    {
      stats.metadata_requests++;

      if (protocol == "never") {
        metadata_request_port.sendPacket(pkt);
      } else if (protocol == "always") {
        stats.metadata_requests_llc++;
        l3_request_port.sendPacket(pkt);
      } else if (protocol == "counter") {
        if (isCounter(pkt->getAddr())) {
          metadata_request_port.sendPacket(pkt);
        } else {
          stats.metadata_requests_llc++;
          l3_request_port.sendPacket(pkt);
        }
      } else if (protocol == "read-write") {
        for (auto it = pending_reads.begin();
            it != pending_reads.end();
            it++)
        {
          Addr pending_addr = it->first;
          Addr parent_addr = calculateCounterAddress(pending_addr);
          while (parent_addr != integrity_levels[1]) {
            if (parent_addr == pkt->getAddr()) {
              // the current metadata has a read waiting for it
              metadata_request_port.sendPacket(pkt);
              return;
            }

            parent_addr = calculateParentAddress(parent_addr);
          }
        }

        for (auto it = awaiting_counter.begin();
            it != awaiting_counter.end();
            it++)
        {
          Addr pending_addr = (*it)->getAddr();
          Addr parent_addr = calculateCounterAddress(pending_addr);
          while (parent_addr != integrity_levels[1]) {
            if ((*it)->isRead() && parent_addr == pkt->getAddr()) {
              // the current metadata has a read waiting for it
              metadata_request_port.sendPacket(pkt);
              return;
            }

            parent_addr = calculateParentAddress(parent_addr);
          }
        }

        // there is no read depending on this metadata
        stats.metadata_requests_llc++;
        l3_request_port.sendPacket(pkt);
      } else if (protocol == "approx-ancestors") {
        for (int i = 1; i < integrity_levels.size() - 1; i++) {
          if (pkt->getAddr() >= integrity_levels[i] && i == distance_level) {
            metadata_request_port.sendPacket(pkt);
            return;
          }
        }

        stats.metadata_requests_llc++;
        l3_request_port.sendPacket(pkt);
      } else if (protocol == "approx-ancestors-v2") {
        for (int i = 1; i < integrity_levels.size() - 1; i++) {
          if (pkt->getAddr() >= integrity_levels[i] && i >= distance_level) {
            metadata_request_port.sendPacket(pkt);
            return;
          }
        }

        stats.metadata_requests_llc++;
        l3_request_port.sendPacket(pkt);
      } else if (protocol == "hotspot") {
        int subtree_idx = getSubtree(pkt);
        if (subtree_idx != -1 && frequencies[subtree_idx] > (access_buffer_size * hot_pct / 100)) {
          metadata_request_port.sendPacket(pkt);
        } else {
          stats.metadata_requests_llc++;
          l3_request_port.sendPacket(pkt);
        }
      } else if (protocol == "l3-hitrate") {
        // if the data hit rate is BAD, then send metadata there bc utilization is poor
        if (!isCounter(pkt->getAddr()) && ((recent_l3_hits * 100) / recent_l3_accesses_buffer_size) < 50) {
          stats.metadata_requests_llc++;
          l3_request_port.sendPacket(pkt);
        } else {
          metadata_request_port.sendPacket(pkt);
        }
      } else {
        assert(false);
      }
    }

  bool
    MCX::isMetadata(Addr addr)
    {
      return addr >= integrity_levels[0];
    }

  bool
    MCX::isMac(Addr addr)
    {
      assert(integrity_levels.size() >= 3);
      return isMetadata(addr) &&
        addr < integrity_levels[integrity_levels.size() - 2];
    }

  bool
    MCX::isCounter(Addr addr)
    {
      assert(integrity_levels.size() >= 4);
      return isMetadata(addr) && !isMac(addr) &&
        addr < integrity_levels[integrity_levels.size() - 3];
    }

  Addr
    MCX::calculateMacAddress(Addr data_address)
    {
      // get the memory size from the memory device
      AddrRangeList ranges = mem_port.getAddrRanges();
      // assert(ranges.size() == 1);

      Addr start = ranges.front().start();
      Addr end = ranges.back().end();

      uint64_t word_idx = (data_address - start) / BLOCK_SIZE;
      uint64_t mac_idx = word_idx / mac_arity;

      return (mac_idx * BLOCK_SIZE) + end;
    }

  Addr
    MCX::calculateCounterAddress(Addr data_address)
    {
      // get the memory size from the memory device
      AddrRangeList ranges = mem_port.getAddrRanges();
      // assert(ranges.size() == 1);

      Addr start = ranges.front().start();
      Addr end = ranges.back().end();

      uint64_t mac_bytes = (end - start) / mac_arity;

      uint64_t word_idx = (data_address - start) / BLOCK_SIZE;
      uint64_t counter_idx = word_idx / counter_arity;

      Addr addr = (counter_idx * BLOCK_SIZE) + end + mac_bytes;
      assert(isMetadata(addr) && !isMac(addr));
      assert(addr % BLOCK_SIZE == 0);

      return addr;
    }

  Addr
    MCX::calculateParentAddress(Addr meta_addr)
    {
      // note: with kvm, some of the first cache state is weird
      Addr addr = meta_addr;
      if (addr % BLOCK_SIZE) {
        addr -= (addr % BLOCK_SIZE);
      }

      assert(isMetadata(meta_addr));

      // get the memory size from the memory device
      AddrRangeList ranges = mem_port.getAddrRanges();
      // assert(ranges.size() == 1);

      assert(integrity_levels.size() >= 3); // mac, counter, data
      if (bonsai) {
        for (int i = 1; // start with the root
            i <= integrity_levels.size() - 2; // stop at the counters
            i++)
        {
          if (meta_addr >= integrity_levels[i]) {
            // the address belongs to this level
            // we better not be trying to compute the parent of the root
            assert(i != 1);

            uint64_t index_at_level = (meta_addr - integrity_levels[i]) /
              BLOCK_SIZE;
            uint64_t index = index_at_level / tree_arity;

            Addr addr = integrity_levels[i - 1] + (index * BLOCK_SIZE);
            if (i - 1 == 1) {
              return integrity_levels[i - 1];
            } else {
              return addr;
            }
          }
        }
      } else if (isMac(meta_addr)) {
        assert(!bonsai);

        uint64_t index_at_level = (meta_addr - integrity_levels[0]) /
          BLOCK_SIZE;
        uint64_t index = index_at_level / tree_arity;

        // [ ..., MT leaves, counter, data ]
        Addr addr = integrity_levels[integrity_levels.size() - 3] +
          (index * BLOCK_SIZE);
        return addr;
      } else {
        assert(integrity_levels.size() >= 4); // mac, tree, counter, data

        for (int i = 1; // start with the root
            i <= integrity_levels.size() - 3; // stop at the MT leaves
            i++)
        {
          if (meta_addr >= integrity_levels[i]) {
            // the address belongs to this level
            // we better not be trying to compute the parent of the root
            assert(i != 1);

            uint64_t index_at_level =
              (meta_addr - integrity_levels[i]) / BLOCK_SIZE;
            uint64_t index = index_at_level / tree_arity;

            Addr addr = integrity_levels[i - 1] + (index * BLOCK_SIZE);
            if (i - 1 == 1) {
              return integrity_levels[i - 1];
            } else {
              return addr;
            }
          }
        }
      }

      assert(false); // we should never get here
      return (Addr) -1;
    }

  bool
    MCX::handleRequest(PacketPtr pkt)
    {
      if (cipher_queue.size() == max_cipher_size) {
        return false;
      }

      requests_handled++;
      // dump metadata in llc?
      if (print_llc_stats && requests_handled % 50000 == 0) {
        std::cout << requests_handled << "," << metadata_in_llc << std::endl;
      }

      // log frequency
      Addr start = mem_port.getAddrRanges().front().start();
      Addr end = mem_port.getAddrRanges().back().end();
      assert(pkt->getAddr() >= start && pkt->getAddr() < end);

      // determine which subtree pkt belongs to for frequency tracking
      Addr counter_addr = calculateCounterAddress(pkt->getAddr());

      Addr counter_start = integrity_levels[integrity_levels.size() - 2];
      Addr counter_end = integrity_levels[integrity_levels.size() - 3];
      uint64_t counter_size = counter_end - counter_start;

      Addr hotspot_start = integrity_levels[hotspot_level];
      Addr hotspot_end = integrity_levels[hotspot_level - 1];
      uint64_t hotspot_level_size = hotspot_end - hotspot_start;

      uint64_t nodes_at_hotspot_level = hotspot_level_size / BLOCK_SIZE;
      uint64_t region_size = counter_size / nodes_at_hotspot_level;

      int subtree_idx = (counter_addr - counter_start) / region_size / BLOCK_SIZE;
      frequencies[subtree_idx]++;

      access_circle_buffer.push_back(subtree_idx);

      if (access_circle_buffer.size() > access_buffer_size) {
        int to_remove_idx = access_circle_buffer.front();
        frequencies[to_remove_idx]--;
        assert(frequencies[to_remove_idx] >= 0);
        access_circle_buffer.pop_front();
        access_circle_buffer.shrink_to_fit();
      }

      // for ancestor approximation
      recent_accesses_buffer.push_back(pkt->getAddr());
      if (recent_accesses_buffer.size() > recent_accesses_buffer_size) {
        recent_accesses_buffer.pop_front(); recent_accesses_buffer.shrink_to_fit(); // do we need to shrink_to_fit?
      }

      if (recent_accesses_buffer.size() > 1) {
        auto it = recent_accesses_buffer.begin();
        Addr prev_addr = *it;
        uint64_t total_distances = 0;
        for (; it != recent_accesses_buffer.end(); it++) {
          Addr addr = *it;
          total_distances += abs(prev_addr - addr);
        }

        total_distances /= recent_accesses_buffer.size();

       distance_level = integrity_levels.size() - 1;
        Addr region_size = 4096;
        while (region_size < total_distances && distance_level > 1) {
          distance_level--;
          region_size *= tree_arity;
        }
      }

      // create request for associated metadata
      RequestPtr req = std::make_shared<Request>(counter_addr, BLOCK_SIZE, 0, 0);
      PacketPtr counter_pkt = Packet::createRead(req);

      if (pkt->isWrite()) {
        // need to fetch encryption counter prior to encryption
        awaiting_counter.emplace(pkt);
      } else {
        assert(pkt->isRead());

        if (!parallelReadAndWrite(pkt)) {
          // if the encryption counter comes back first, tell it who we are
          bool success;
          std::tie(std::ignore, success) = pending_reads.emplace(
              pkt->getAddr(), 1
              );

          if (!success) {
            pending_reads[pkt->getAddr()]++;
          }

          // reads are sent to memory and decrypted on response
          //mem_port.sendPacket(pkt);

          // request the mac as well
          //Addr mac_addr = calculateMacAddress(pkt->getAddr());
          //RequestPtr req = std::make_shared<Request>(
          //    mac_addr, BLOCK_SIZE, 0, 0
          //    );
          //PacketPtr mac_pkt = Packet::createRead(req);

          // send mac to memory
          //mac_pkt->allocate();

          //if (use_metadata_cache && cache_mac) {
            // metadata_request_port.sendPacket(mac_pkt);
          //  sendMetadataToCache(mac_pkt);
          //} else {
          //  mem_port.sendPacket(mac_pkt);

          //  if (!bonsai) {
          //    bool success;
          //    std::tie(std::ignore, success) =
          //      needs_authentication.emplace(mac_addr, 1);

          //    if (!success) {
          //      needs_authentication[mac_addr]++;
          //    }
          //  }
          //}
          else {
            delete counter_pkt;
            return true;
          }
        }
      }

      // send counter request to memory
      counter_pkt->allocate();
      if (use_metadata_cache) {
        // metadata_request_port.sendPacket(counter_pkt);
        sendMetadataToCache(counter_pkt);
      } else {
        mem_port.sendPacket(counter_pkt);
      }

      // stat accounting
      stats.requests_processed++;

      return true;
    }

  void
    MCX::handleMetadataCacheMiss(PacketPtr pkt)
    {
      assert(pkt->isRead());
      assert(isMetadata(pkt->getAddr()));
      assert(!isMac(pkt->getAddr()) || cache_mac);

      stats.metadata_misses++;

      if (!isMac(pkt->getAddr()) && pkt->getAddr() < integrity_levels[1]) {
        // this is a tree node, we need to track the miss
        if ((!isMac(pkt->getAddr()) && !isCounter(pkt->getAddr())) ||
            (bonsai && isCounter(pkt->getAddr())) ||
            (!bonsai && isMac(pkt->getAddr())))
        {
          bool success;
          std::tie(std::ignore, success) = needs_authentication.emplace(
              pkt->getAddr(), 1
              );

          if (!success) {
            needs_authentication[pkt->getAddr()]++;
          }
        }
      }

      if (eager_fetch && pkt->getAddr() < integrity_levels[1]) {
        Addr parent_addr = calculateParentAddress(pkt->getAddr());
        RequestPtr req = std::make_shared<Request>(
            parent_addr, BLOCK_SIZE, 0, 0
            );
        PacketPtr parent_pkt = Packet::createRead(req);

        // send to cache
        assert(use_metadata_cache);
        parent_pkt->allocate();
        // metadata_request_port.sendPacket(parent_pkt);
        sendMetadataToCache(parent_pkt);
      }
    }

  bool
    MCX::handleResponse(PacketPtr pkt)
    {
      assert(pkt->isResponse());

      if (pkt->isRead() && !parallelReadAndWrite(pkt)) {
        // check if the counter has returned
        auto ctr_found = counter_fetched.find(pkt->getAddr());
        if (ctr_found != counter_fetched.end()) {
          // we are all set to start the decryption procedure
          if (!initiateCipher(pkt)) {
            return false;
          } else {
            assert(awaiting_counter.find(pkt) == awaiting_counter.end());
          }

          // cipher has happened, we don't need to track
          ctr_found->second--;
          if (ctr_found->second == 0) {
            counter_fetched.erase(pkt->getAddr());
          }
        } else {
          // the counter hasn't returned from memory yet...
          // when the counter returns, tell it to initiate the cipher
          bool success;
          std::tie(std::ignore, success) = awaiting_counter.emplace(pkt);
          assert(success);
        }

        auto mac_found = mac_fetched.find(pkt->getAddr());
        if (mac_found != mac_fetched.end()) {
          // we are all set to start the authentication procedure
          if (!initiateMac(pkt)) {
            return false;
          } else {
            assert(awaiting_mac.find(pkt) == awaiting_mac.end());
          }

          // mac has happended, we don't need to track
          mac_found->second--;
          if (mac_found->second == 0) {
            mac_fetched.erase(pkt->getAddr());
          }
        } else {
          // the mac hasn't returned from memory yet...
          // when the mac returns, tell it to initiate the authentication
          bool success;
          std::tie(std::ignore, success) = awaiting_mac.emplace(pkt);
          assert(success);
        }

        assert(pending_reads.find(pkt->getAddr()) != pending_reads.end());
        pending_reads[pkt->getAddr()]--;

        if (pending_reads[pkt->getAddr()] == 0) {
          pending_reads.erase(pkt->getAddr());
        }
      } else if (pkt->isRead()) {
        // cleanup handled by parallelReadAndWrite... do nothing!
      } else {
        assert(pkt->isWrite());

        // write responses are just sent to the processor
        assert(awaiting_counter.find(pkt) == awaiting_counter.end());
        l3_response_port.sendPacket(pkt);
      }

      // stat accounting
      stats.responses_processed++;

      return true;
    }

  bool
    MCX::processCounterResponse(PacketPtr pkt)
    {
      return initiateCipher(pkt);
    }

  bool
    MCX::handleCounterResponse(PacketPtr pkt)
    {
      // check for data that uses this counter
      for (auto it = pending_reads.begin();
          it != pending_reads.end();
          ++it)
      {
        if (calculateCounterAddress(it->first) == pkt->getAddr()) {
          // move address and count from pending to fetched
          counter_fetched.emplace(it->first, it->second);
        }
      }

      // check for data that has already returned and is waiting on this counter
      for (auto it = awaiting_counter.begin();
          it != awaiting_counter.end();)
      {
        if (calculateCounterAddress((*it)->getAddr()) == pkt->getAddr()) {
          // something was waiting on this counter to do the cipher
          // try sending it for en/decryption
          if (!initiateCipher(*it)) {
            // the queue was full, move to pending state (with priority)
            pending_cipher.push_back((PacketPtr) *it);
          }

          // if the packet is a write, we need the counter to compute the MAC
          if ((*it)->isWrite()) {
            // not sure who will trigger retry event if this fails
            assert((*it)->isRequest());
            assert(initiateMac(*it));
          }

          // only if read and counter not fetched first
          it = awaiting_counter.erase(it);
          continue;
        }

        ++it;
      }

      // we no longer need the encryption counter
      delete pkt;

      return true;
    }

  bool
    MCX::handleTreeResponse(PacketPtr pkt)
    {
      if (needs_authentication.find(pkt->getAddr()) !=
          needs_authentication.end())
      {
        // check if our parent has already returned
        Addr parent_addr = calculateParentAddress(pkt->getAddr());
        bool authenticated = false;
        for (auto it = awaiting_child.begin();
            it != awaiting_child.end();
            ++it)
        {
          if (parent_addr == (*it)->getAddr()) {
            assert(!authenticated);
            initiateMac(pkt);
            authenticated = true;

            // remove from authentication structure
            assert(needs_authentication.find(pkt->getAddr()) !=
                needs_authentication.end());
            needs_authentication[pkt->getAddr()]--;
            if (needs_authentication[pkt->getAddr()] == 0) {
              needs_authentication.erase(pkt->getAddr());
            }

            // if nothing is waiting on us, we can remove and continue
            bool pending_dependents = false;
            for (auto _it = needs_authentication.begin();
                _it != needs_authentication.end();
                ++_it)
            {
              if (calculateParentAddress(_it->first) ==
                  (*it)->getAddr())
              {
                pending_dependents = true;
              }
            }

            if (!pending_dependents) {
              delete *it; // avoid memory leak for trusted parent
              awaiting_child.erase(it);
            }

            break;
          }
        }

        // the metadata is untrusted
        if (!authenticated) {
          pending_authentication.emplace(pkt);

          if (!eager_fetch) {
            RequestPtr req = std::make_shared<Request>(
                parent_addr, BLOCK_SIZE, 0, 0
                );
            PacketPtr parent_pkt = Packet::createRead(req);

            // send to cache
            parent_pkt->allocate();
            if (use_metadata_cache) {
              // metadata_request_port.sendPacket(parent_pkt);
              sendMetadataToCache(parent_pkt);
            } else {
              mem_port.sendPacket(parent_pkt);
            }
          }
        }
      } else {
        // we are trusted, authenticate anything that depends on us
        bool child_authenticated = false;
        for (auto it = pending_authentication.begin();
            it != pending_authentication.end();)
        {
          if (calculateParentAddress((*it)->getAddr()) == pkt->getAddr()) {
            // authenticate the child node
            assert((*it)->isWrite() || (*it)->isResponse());
            initiateMac(*it);
            child_authenticated = true;

            // remove from both authentication structures
            if (needs_authentication.find((*it)->getAddr()) !=
                needs_authentication.end())
            {
              needs_authentication[(*it)->getAddr()]--;
              if (needs_authentication[(*it)->getAddr()] == 0) {
                // note: there's a chance that this structure gets
                // incremented before the pkt responds from memory and
                // it gets stuck here bc the authenticator finished b4
                // got back... check here if we deadlock --> we do :-)
                needs_authentication.erase((*it)->getAddr());
              }
            }

            it = pending_authentication.erase(it);
            continue;
          }

          ++it;
        }

        if (isCounter(pkt->getAddr())) {
          assert(bonsai);
          assert(handleCounterResponse(pkt));
        } else if (isMac(pkt->getAddr())) {
          assert(!bonsai);
          assert(handleMacResponse(pkt));
        } else {
          if (pkt->isRead() && !child_authenticated) {
            awaiting_child.emplace(pkt);
          } else {
            delete pkt;
          }
        }
      }

      return true;
    }

  bool
    MCX::handleMacResponse(PacketPtr pkt)
    {
      // check for data that uses this counter
      for (auto it = pending_reads.begin();
          it != pending_reads.end();
          ++it)
      {
        if (calculateMacAddress(it->first) == pkt->getAddr()) {
          // move address and count from pending to fetched
          mac_fetched.emplace(it->first, it->second);
        }
      }

      // check for data that has already returned and is waiting on this counter
      for (auto it = awaiting_mac.begin();
          it != awaiting_mac.end();)
      {
        if (calculateMacAddress((*it)->getAddr()) == pkt->getAddr()) {
          // something was waiti on this counter to do the cipher
          // try sending it for en/decryption
          if (!initiateMac(*it)) {
            // the queue was full, move to pending state (with priority)
            pending_mac.push_back((PacketPtr) *it);
          } else {
            // only if read and mac not fetched first
            it = awaiting_mac.erase(it);
            continue;
          }
        }

        ++it;
      }

      // we no longer need the encryption counter
      delete pkt;

      return true;
    }

  bool
    MCX::initiateCipher(PacketPtr pkt)
    {
      // need to decrypt the data prior to sending to processor
      if (cipher_queue.size() == max_cipher_size) {
        return false;
      }

      // queue can only process one element per cycle (but pipelined) so
      // ready time is the current time + order in queue + latency
      Tick finish_time;
      if (!isCounter(pkt->getAddr())) {
        if ((xor_queue.size() * 1000) >= xor_latency) {
          finish_time = curTick() + (xor_queue.size() * 1000);
        } else {
          finish_time = curTick() + xor_latency;
        }

        xor_queue.push_back(
            std::pair<PacketPtr, Tick>(pkt, finish_time)
            );
      } else {
        if ((cipher_queue.size() * 1000) >= cipher_latency) {
          finish_time = curTick() + (cipher_queue.size() * 1000);
        } else {
          finish_time = curTick() + cipher_latency;
        }

        cipher_queue.push_back(
            std::pair<PacketPtr, Tick>(pkt, finish_time)
            );
      }

      // if something is already in the cipher queue, it will
      // reschedule itself
      if (!cipherEvent.scheduled()) {
        // schedule for when the first item in the queue can cipher
        finish_time = finish_time < curTick() ? curTick() : finish_time;
        schedule(cipherEvent, finish_time);
      }

      return true;
    }

  bool
    MCX::initiateMac(PacketPtr pkt)
    {
      // need to decrypt the data prior to sending to processor
      if (hashing_queue.size() == max_mac_size) {
        return false;
      }

      // queue can only process one element per cycle (but pipelined) so
      // ready time is the current time + order in queue + latency
      Tick finish_time;
      if (hashing_queue.size() >= hash_latency) {
        finish_time = curTick() + hashing_queue.size();
      } else {
        finish_time = curTick() + hash_latency;
      }

      hashing_queue.push_back(
          std::pair<PacketPtr, Tick>(pkt, finish_time)
          );

      // if something is already in the cipher queue, it will
      // reschedule itself
      if (!macEvent.scheduled()) {
        // schedule for when the first item in the queue can cipher
        schedule(macEvent, hashing_queue.front().second);
      }

      return true;
    }

  void
    MCX::updateTree(PacketPtr pkt)
    {
      // data is encrypted and MAC is computed
      // send all three to memory
      // addrs
      Addr ctr_addr = calculateCounterAddress(pkt->getAddr());
      Addr mac_addr = calculateMacAddress(pkt->getAddr());

      mem_port.sendPacket(pkt); // send data to memory

      RequestPtr ctr_req = std::make_shared<Request>(ctr_addr, BLOCK_SIZE, 0, 0);
      PacketPtr counter_pkt = Packet::createWrite(ctr_req);
      counter_pkt->allocate();

      if (use_metadata_cache) {
        // send counter to the cache
        // metadata_request_port.sendPacket(counter_pkt);
        sendMetadataToCache(counter_pkt);
      } else {
        mem_port.sendPacket(counter_pkt); // send counter to memory
      }
      
      // make parent packets
      Addr addr = bonsai ? ctr_addr : mac_addr;
      do {
        addr = calculateParentAddress(addr);

        RequestPtr req = std::make_shared<Request>(addr, BLOCK_SIZE, 0, 0);
        PacketPtr pkt = Packet::createWrite(req);
        pkt->allocate();

        if (use_metadata_cache) {
          // send tree node to the cache
          // metadata_request_port.sendPacket(pkt);
          sendMetadataToCache(pkt);
        } else {
          mem_port.sendPacket(pkt); // send tree node to memory
        }
      } while (addr != integrity_levels[1]);

      // make mac packet
      RequestPtr mac_req = std::make_shared<Request>(mac_addr, BLOCK_SIZE, 0, 0);
      PacketPtr mac_pkt = Packet::createWrite(mac_req);
      mac_pkt->allocate();

      if (use_metadata_cache && cache_mac) {
        // metadata_request_port.sendPacket(mac_pkt); // send counter to the cache
        sendMetadataToCache(mac_pkt);
      } else {
        mem_port.sendPacket(mac_pkt); // send counter to memory
      }
    }

  void
    MCX::cipherEngine()
    {
      assert(!(cipher_queue.empty() && xor_queue.empty()));

      PacketPtr pkt;
      if (!cipher_queue.empty() &&
          (xor_queue.empty() ||
           cipher_queue.front().second < xor_queue.front().second))
      {
        pkt = cipher_queue.front().first;
        cipher_queue.pop_front();
      } else {
        assert(!xor_queue.empty());
        pkt = xor_queue.front().first;
        xor_queue.pop_front();
      }

      if (isCounter(pkt->getAddr())) {
        if (bonsai) {
          handleTreeResponse(pkt); // checks if data is trusted first
        } else {
          handleCounterResponse(pkt);
        }
      } else {
        // try to process data
        auto mac_it = std::find(hashed_packets.begin(),
            hashed_packets.end(), pkt);
        if (mac_it != hashed_packets.end()) {
          // the data has already been ciphered
          if (pkt->isWrite()) {
            assert(pkt->isRequest());
            updateTree(pkt);
          } else {
            assert(pkt->isRead() && pkt->isResponse());

            // respond to the processor
            assert(awaiting_counter.find(pkt) == awaiting_counter.end());
            l3_response_port.sendPacket(pkt);
          }

          // make sure that the ciphered packet is removed
          hashed_packets.erase(mac_it);
        } else {
          // not done with cipher
          assert(awaiting_counter.find(pkt) == awaiting_counter.end());
          ciphered_packets.push_back(pkt);
        }
      }

      // schedule the next encryption/decryption when it is read to be executed
      if (!(cipher_queue.empty() && xor_queue.empty()) &&
          !cipherEvent.scheduled())
      {
        Tick next_tick;
        if (!cipher_queue.empty() &&
            (xor_queue.empty() ||
             cipher_queue.front().second < xor_queue.front().second))
        {
          next_tick = cipher_queue.front().second;
        } else {
          assert(!xor_queue.empty());
          next_tick = xor_queue.front().second;
        }

        next_tick = next_tick < curTick() ? curTick() : next_tick;
        schedule(cipherEvent, next_tick);
      }
    }

  void
    MCX::macEngine()
    {
      assert(!hashing_queue.empty());

      PacketPtr pkt = hashing_queue.front().first;
      hashing_queue.pop_front();

      if (isMetadata(pkt->getAddr())) {
        handleTreeResponse(pkt);
      } else {
        // try to process data
        auto cipher_it = std::find(ciphered_packets.begin(),
            ciphered_packets.end(), pkt);
        if (cipher_it != ciphered_packets.end()) {
          // the data has already been ciphered
          if (pkt->isWrite()) {
            assert(pkt->isRequest());
            updateTree(pkt);
          } else {
            assert(pkt->isRead() && pkt->isResponse());

            // respond to the processor
            assert(awaiting_counter.find(pkt) == awaiting_counter.end());
            l3_response_port.sendPacket(pkt);
          }

          ciphered_packets.erase(cipher_it);
        } else {
          // not done with cipher
          hashed_packets.push_back(pkt);
        }
      }

      // schedule the next encryption/decryption when it is read to be executed
      if (!hashing_queue.empty() && !macEvent.scheduled()) {
        schedule(macEvent, hashing_queue.front().second);
      }
    }

  bool
    MCX::parallelReadAndWrite(PacketPtr pkt)
    {
      bool found = false;

      // check if we are currently trying to write this data to memory
      // if so, get state from pending packet as it is more up-to-date
      // (traverse back to front to get most recent version if multiple
      // pending writes)
      // our counter is now useless to us... we found plain-text data
      for (auto it = cipher_queue.rbegin();
          it != cipher_queue.rend();
          ++it)
      {
        if (it->first->getAddr() == pkt->getAddr() &&
            it->first->getSize() == pkt->getSize())
        {
          // set data to packet from pending write
          uint8_t data[pkt->getSize()]; // 64B (word size)
          it->first->writeData(data);
          pkt->setData(data);

          if (pkt->needsResponse()) {
            pkt->makeResponse();
            found_reads.push_back(pkt);

            // respond to processor in same clock cycle
            if (!parallelReadRespondEvent.scheduled()) {
              schedule(parallelReadRespondEvent, curTick());
            }
          }

          found = true;
        }
      }

      for (auto it = awaiting_counter.rbegin();
          it != awaiting_counter.rend();
          ++it)
      {
        if ((*it)->getAddr() == pkt->getAddr() &&
            (*it)->getSize() == pkt->getSize())
        {
          // set data to packet from pending write
          uint8_t data[pkt->getSize()]; // 64B (word size)
          (*it)->writeData(data);
          pkt->setData(data);

          if (pkt->needsResponse()) {
            pkt->makeResponse();
            found_reads.push_back(pkt);

            // respond to processor in same clock cycle
            if (!parallelReadRespondEvent.scheduled()) {
              schedule(parallelReadRespondEvent, curTick());
            }
          }

          found = true;
        }
      }

      if (found) {
        if (pending_reads.find(pkt->getAddr()) != pending_reads.end()) {
          pending_reads[pkt->getAddr()]--;

          if (pending_reads[pkt->getAddr()] == 0) {
            pending_reads.erase(pkt->getAddr());
          }
        } else if (counter_fetched.find(pkt->getAddr()) !=
            counter_fetched.end())
        {
          counter_fetched[pkt->getAddr()]--;

          if (counter_fetched[pkt->getAddr()] == 0) {
            counter_fetched.erase(pkt->getAddr());
          }
        }
      }

      return found;
    }

  void
    MCX::respondParallelRead()
    {
      assert(!found_reads.empty());

      PacketPtr pkt = found_reads.front();
      found_reads.pop_front();

      assert(awaiting_counter.find(pkt) == awaiting_counter.end());
      l3_response_port.sendPacket(pkt);

      if (!found_reads.empty() && !parallelReadRespondEvent.scheduled()) {
        schedule(parallelReadRespondEvent, curTick());
      }
    }

  void
    MCX::respondMetadataCache()
    {
      assert(!metadata_response_queue.empty());
      PacketPtr to_send = metadata_response_queue.front();
      metadata_response_port.sendPacket(to_send);
      metadata_response_queue.pop_front();

      // do this again if the queue is not empty
      if (!metadata_response_queue.empty() &&
          !metadataRespondEvent.scheduled())
      {
        schedule(metadataRespondEvent, curTick());
      }
    }

  void
    MCX::respondL3Cache()
    {
      assert(!l3_response_queue.empty());
      PacketPtr to_send = l3_response_queue.front();
      l3_response_port.sendPacket(to_send);
      l3_response_queue.pop_front();

      // do this again if the queue is not empty
      if (!l3_response_queue.empty() &&
          !l3RespondEvent.scheduled())
      {
        schedule(l3RespondEvent, curTick());
      }
    }

  // port function definitions
  bool
    MCX::CpuSidePort::recvTimingReq(PacketPtr pkt)
    {
      if (!(pkt->isRead() || pkt->isWrite())) {
        assert(false);
      }

      // some accounting
      BaseSetAssoc *l3_tags = (BaseSetAssoc *) SimObject::find("board.memory.secure_memory.l3.tags"); // hack!
      assert(l3_tags != nullptr);
      Cycles c;
      bool hit = l3_tags->accessBlock(pkt, c) != nullptr;

      if (hit) {
        parent->recent_l3_hits++;
      }

      parent->recent_l3_accesses_buffer.push_back(hit);

      if (parent->recent_l3_accesses_buffer.size() > parent->recent_l3_accesses_buffer_size) {
        if (parent->recent_l3_accesses_buffer.front()) {
          parent->recent_l3_hits--;
        }

        parent->recent_l3_accesses_buffer.pop_front();
        parent->recent_l3_accesses_buffer.shrink_to_fit();
      }

      parent->l3_request_port.sendPacket(pkt);

      return true;
    }

  void
    MCX::CpuSidePort::recvRespRetry()
    {
      assert(!blocked_packets.empty());

      PacketPtr to_send = blocked_packets.front();
      if (sendTimingResp(to_send)) {
        blocked_packets.pop_front();
      }
    }

  void
    MCX::CpuSidePort::sendPacket(PacketPtr pkt)
    {
      blocked_packets.push_back(pkt);
      PacketPtr to_send = blocked_packets.front();

      if (sendTimingResp(to_send)) {
        // if this fails, the retry logic is implemented in recvRespRetry
        blocked_packets.pop_front();
      }

      if (!parent->pending_cipher.empty()) {
        // first, serve the packets that were blocked by the encryption counter
        PacketPtr blocked_enc_pkt = parent->pending_cipher.front();
        assert(parent->initiateCipher(blocked_enc_pkt));
        parent->pending_cipher.pop_front();
      } else if (!parent->mem_port.blocked_responses.empty()) {
        // serve the memory responses next
        PacketPtr blocked_mem_pkt = parent->mem_port.blocked_responses.front();
        assert(parent->handleResponse(blocked_mem_pkt)); // we should succeed
        parent->mem_port.blocked_responses.pop_front();
      } else if (need_retry) {
        // handle pending requests from processor
        sendRetryReq();
        need_retry--;
      }
    }

  bool
    MCX::MemSidePort::recvTimingResp(PacketPtr pkt)
    {
      if (parent->protocol == "insecure") {
        assert(!parent->isMetadata(pkt->getAddr()));
        parent->l3_response_port.sendPacket(pkt);
        return true;
      }

      // assert(getAddrRanges().size() == 1);

      bool is_metadata = parent->isMetadata(pkt->getAddr());
      if (is_metadata) {
         bool is_mac = parent->isMac(pkt->getAddr());
         if (!is_mac || (is_mac && parent->cache_mac)) {
          // this is a tree node
          if (parent->use_metadata_cache) {
            if (parent->awaiting_mc_resp.find(pkt->getAddr()) != parent->awaiting_mc_resp.end()) {
              parent->awaiting_mc_resp[pkt->getAddr()]--;
              if (parent->awaiting_mc_resp[pkt->getAddr()] == 0) {
                parent->awaiting_mc_resp.erase(pkt->getAddr());
              }

              parent->metadata_response_port.sendPacket(pkt);
            } else {
              assert(parent->awaiting_l3_resp.find(pkt->getAddr()) != parent->awaiting_l3_resp.end());
              parent->awaiting_l3_resp[pkt->getAddr()]--;
              if (parent->awaiting_l3_resp[pkt->getAddr()] == 0) {
                parent->awaiting_l3_resp.erase(pkt->getAddr());
              }

              parent->l3_response_port.sendPacket(pkt);
            }
          } else if (parent->bonsai) {
            assert(parent->handleTreeResponse(pkt));
          } else {
            assert(parent->processCounterResponse(pkt));
          }
        } else {
          // this is a mac
          if (parent->cache_mac) {
            assert(false); // cached macs handled above
            parent->metadata_response_port.sendPacket(pkt);
          } else if (!parent->bonsai) {
            assert(parent->handleTreeResponse(pkt));
          } else {
            assert(parent->handleMacResponse(pkt));
          }
        }
      } else if (!parent->handleResponse(pkt)) {
        blocked_responses.push_back(pkt); // data
      }

      return true;
    }

  void
    MCX::MemSidePort::recvReqRetry()
    {
      while (!blocked_packets.empty() &&
          sendTimingReq(blocked_packets.front()))
      {
        blocked_packets.pop_front();
      }
    }

  void
    MCX::MemSidePort::sendPacket(PacketPtr pkt)
    {
      if (!sendTimingReq(pkt)) {
        blocked_packets.push_back(pkt);
      }
    }

  bool
    MCX::MetadataRequestPort::recvTimingResp(PacketPtr pkt)
    {
      // check if returned value is a hit (i.e., doesn't need authentication)
      assert(parent->isMetadata(pkt->getAddr()));
      if (parent->needs_authentication.find(pkt->getAddr()) ==
          parent->needs_authentication.end())
      {
        // we hit in the cache!
        parent->metadata_cache_hit_addrs.emplace(pkt->getAddr());
      }

      if (parent->isMac(pkt->getAddr())) {
        assert(parent->cache_mac);
        if (parent->bonsai) {
          return parent->handleMacResponse(pkt);
        } else {
          return parent->handleTreeResponse(pkt);
        }
      } else if (parent->isCounter(pkt->getAddr())) {
        return parent->processCounterResponse(pkt);
      } else {
        return parent->handleTreeResponse(pkt);
      }
    }

  void
    MCX::MetadataRequestPort::recvReqRetry()
    {
      while (!blocked_packets.empty() &&
          sendTimingReq(blocked_packets.front()))
      {
        blocked_packets.pop_front();
      }
    }

  void
    MCX::MetadataRequestPort::sendPacket(PacketPtr pkt)
    {
      assert(pkt->isRequest());
      assert(!parent->isMac(pkt->getAddr()) || parent->cache_mac);

      if (!sendTimingReq(pkt)) {
        blocked_packets.push_back(pkt);
      }
    }

  bool
    MCX::MetadataResponsePort::recvTimingReq(PacketPtr pkt)
    {
      assert(pkt->isRequest());

      if (pkt->isRead() || pkt->isWrite()) {
        // handle miss --> untrusted access
        if (!(pkt->isWriteback() || pkt->isEviction())) {
          if (pkt->needsResponse()) {
            bool success;
            std::tie(std::ignore, success) =
              parent->awaiting_mc_resp.emplace(pkt->getAddr(), 1);

            if (!success) {
              parent->awaiting_mc_resp[pkt->getAddr()]++;
            }
          }

          parent->handleMetadataCacheMiss(pkt);
        } else {
          // let's do a little accounting
          if (parent->metadata_cache_hit_addrs.erase(pkt->getAddr())) {
            parent->stats.used_mc_metadata_blocks++;
          } else {
            parent->stats.unused_mc_metadata_blocks++;
          }
        }

        parent->mem_port.sendPacket(pkt);
      } else {
        if (pkt->needsResponse()) {
          pkt->makeResponse();
          parent->metadata_response_queue.push_back(pkt);

          if (!parent->metadataRespondEvent.scheduled()) {
            // note, response cannot happen in the same call stack
            // so that the cache can finish managing its state
            parent->schedule(parent->metadataRespondEvent, curTick());
          }
        } else {
          delete pkt;
        }
      }

      return true;
    }

  void
    MCX::MetadataResponsePort::sendPacket(PacketPtr pkt)
    {
      assert(pkt->isResponse());
      if (!sendTimingResp(pkt)) {
        blocked_packets.push_back(pkt);
        need_retry++;
      }
    }

  bool
    MCX::L3RequestPort::recvTimingResp(PacketPtr pkt)
    {
      // check if returned value is a hit (i.e., doesn't need authentication)
      if (parent->isMetadata(pkt->getAddr()) &&
          parent->needs_authentication.find(pkt->getAddr()) ==
          parent->needs_authentication.end())
      {
        // we hit in the cache!
        parent->llc_hit_addrs.emplace(pkt->getAddr());
      }

      if (parent->isMetadata(pkt->getAddr())) {
        if (parent->isMac(pkt->getAddr())) {
          assert(parent->cache_mac);
          if (parent->bonsai) {
            return parent->handleMacResponse(pkt);
          } else {
            return parent->handleTreeResponse(pkt);
          }
        } else if (parent->isCounter(pkt->getAddr())) {
          return parent->processCounterResponse(pkt);
        } else {
          return parent->handleTreeResponse(pkt);
        }
      } else {
        AddrRangeList ranges = parent->mem_port.getAddrRanges();

        if (pkt->getAddr() > ranges.front().end()) {
          parent->cpu_port1.sendPacket(pkt);

          if (parent->cpu_port0.need_retry) {
            // handle pending requests from processor
            parent->cpu_port0.sendRetryReq();
            parent->cpu_port0.need_retry--;
          }
        } else {
          assert(pkt->getAddr() < ranges.front().end());
          parent->cpu_port0.sendPacket(pkt);

          if (parent->cpu_port1.need_retry) {
            // handle pending requests from processor
            parent->cpu_port1.sendRetryReq();
            parent->cpu_port1.need_retry--;
          }
        }
      }

      return true;
    }

  void
    MCX::L3RequestPort::recvReqRetry()
    {
      while (!blocked_packets.empty() &&
          sendTimingReq(blocked_packets.front()))
      {
        blocked_packets.pop_front();
      }
    }

  void
    MCX::L3RequestPort::sendPacket(PacketPtr pkt)
    {
      if (!sendTimingReq(pkt)) {
        blocked_packets.push_back(pkt);
      }
    }

  bool
    MCX::L3ResponsePort::recvTimingReq(PacketPtr pkt)
    {
      // for stats counting
      if (pkt->isEviction() && parent->isMetadata(pkt->getAddr())) {
        parent->metadata_in_llc--;

        if (parent->llc_hit_addrs.erase(pkt->getAddr())) {
          parent->stats.used_llc_metadata_blocks++;
        } else {
          parent->stats.unused_llc_metadata_blocks++;
        }
      }

      if (pkt->isRead() || pkt->isWrite()) {
        if (parent->isMetadata(pkt->getAddr())) {
          if (pkt->needsResponse()) {
            bool success;
            std::tie(std::ignore, success) =
              parent->awaiting_l3_resp.emplace(pkt->getAddr(), 1);

            if (!success) {
              parent->awaiting_l3_resp[pkt->getAddr()]++;
            }

            parent->handleMetadataCacheMiss(pkt);
            parent->stats.metadata_misses_llc++;
          }

          parent->mem_port.sendPacket(pkt);

          return true;
        } else if (parent->protocol == "insecure") {
          parent->mem_port.sendPacket(pkt);
          return true;
        }

        return parent->handleRequest(pkt);
      } else {
        if (pkt->needsResponse()) {
          pkt->makeResponse();
          parent->l3_response_queue.push_back(pkt);

          if (!parent->l3RespondEvent.scheduled()) {
            // note, response cannot happen in the same call stack
            // so that the cache can finish managing its state
            parent->schedule(parent->l3RespondEvent, curTick());
          }
        } else {
          delete pkt;
        }
      }

      return true;
    }

  void
    MCX::L3ResponsePort::sendPacket(PacketPtr pkt)
    {
      assert(pkt->isResponse());
      if (!sendTimingResp(pkt)) {
        blocked_packets.push_back(pkt);
        need_retry++;
      } else {
        if (parent->isMetadata(pkt->getAddr())) {
          parent->metadata_in_llc++;
        }
      }
    }

  // stats function definition
  MCX::MCXStats::MCXStats(MCX &s)
    : statistics::Group(&s), s(s),
    ADD_STAT(requests_processed, statistics::units::Count::get(),
        "number of handled requests from the processor side"),
    ADD_STAT(responses_processed, statistics::units::Count::get(),
        "number of memory responses that we've handled"),
    ADD_STAT(metadata_requests, statistics::units::Count::get(),
        "number of memory responses that we've handled"),
    ADD_STAT(metadata_requests_llc, statistics::units::Count::get(),
        "number of memory responses that we've handled"),
    ADD_STAT(metadata_misses, statistics::units::Count::get(),
        "number of memory responses that we've handled"),
    ADD_STAT(metadata_misses_llc, statistics::units::Count::get(),
        "number of memory responses that we've handled"),
    ADD_STAT(used_mc_metadata_blocks, statistics::units::Count::get(),
        "number of evicted blocks from the metdata cache that had hit prior to eviction"),
    ADD_STAT(unused_mc_metadata_blocks, statistics::units::Count::get(),
        "number of evicted blocks from the metadata cache that have not hit prior to eviction"),
    ADD_STAT(used_llc_metadata_blocks, statistics::units::Count::get(),
        "number of evicted metadata blocks from the llc that had hit prior to eviction"),
    ADD_STAT(unused_llc_metadata_blocks, statistics::units::Count::get(),
        "number of evicted metadata blocks from the llc that had not hit prior to eviction")
  {
  }

  void
    MCX::MCXStats::regStats()
    {
      statistics::Group::regStats();
    }

}; // namespace gem5::memory

gem5::memory::MCX *
gem5::MCXParams::create() const
{
  return new gem5::memory::MCX(this);
}
