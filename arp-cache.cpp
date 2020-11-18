/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router
{

  //////////////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////
  // IMPLEMENT THIS METHOD
  void
  ArpCache::periodicCheckArpRequestsAndCacheEntries()
  {
    // FILL THIS IN

    // Find the invaild entries
    std::list<std::shared_ptr<ArpEntry>> inValidEntries;
    for (auto &entry : m_cacheEntries)
    {
      if (!entry->isValid)
      {
        inValidEntries.push_back(entry);
      }
    }

    // Remove them
    for (auto &entry : inValidEntries)
    {
      m_cacheEntries.remove(entry);
    }

    // Deal with arpRequest
    std::list<std::shared_ptr<ArpRequest>> temp_arpRequests;
    while (!m_arpRequests.empty())
    {
      std::shared_ptr<ArpRequest> temp = m_arpRequests.front();
      m_arpRequests.pop_front();
      if (handle_arpreq(temp))
      {
        temp_arpRequests.push_back(temp);
      }
    }
    while (!temp_arpRequests.empty())
    {
      m_arpRequests.push_back(temp_arpRequests.front());
      temp_arpRequests.pop_front();
    }
  }

  bool
  ArpCache::handle_arpreq(const std::shared_ptr<ArpRequest> &req)
  {
    time_point now = steady_clock::now(); // Get the current time
    if (now - (req->timeSent) > seconds(1))
    {
      if (req->nTimesSent >= 5)
      {
        // TODO: Send icmp host unreachable to source
        std::cerr << "Remove numout arp_req." << std::endl;
        std::cerr << std::endl;
        for (auto &pending_packet : req->packets)
        {
          // This line will cause deadlock, so I have to delete the lock.
          // Because send packet must call ArpCache::lookup(),
          // but at the same time
          // ArpCache::tick() has been called
          // m_router.sendICMPPacket(pending_packet.packet, DESTINATION_HOST_UNREACHABLE);
          // So I use multi-thread
          m_router.addWaitingPacket(pending_packet.packet);
        }
        return false;
      }
      else
      {
        // First get router interface
        RoutingTableEntry entry = m_router.getRoutingTable().lookup(req->ip);
        const Interface *iface = m_router.findIfaceByName(entry.ifName);
        if (!iface)
        {
          std::cerr << "When sending ARP request, can't find out interface! Remove it!" << std::endl;
          std::cerr << std::endl;
        }
        else
        {
          // Ethernet header
          ethernet_hdr ehdr;
          std::memset(ehdr.ether_dhost, 255, ETHER_ADDR_LEN);
          std::memcpy(ehdr.ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
          ehdr.ether_type = htons(ethertype_arp);
          // ARP header
          arp_hdr ahdr;
          ahdr.arp_hrd = htons(arp_hrd_ethernet);
          ahdr.arp_pro = htons(ethertype_ip);
          ahdr.arp_hln = 0x06;
          ahdr.arp_pln = 0x04;
          ahdr.arp_op = htons(arp_op_request);
          std::memcpy(ahdr.arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
          ahdr.arp_sip = iface->ip;
          std::memset(ahdr.arp_tha, 0, ETHER_ADDR_LEN);
          ahdr.arp_tip = req->ip;
          // Packet
          Buffer packet(sizeof(ethernet_hdr) + sizeof(arp_hdr));
          std::memcpy(packet.data(), &ehdr, sizeof(ethernet_hdr));
          std::memcpy(packet.data() + sizeof(ethernet_hdr), &ahdr, sizeof(arp_hdr));
          // Send Packet
          // std::cerr << "ARP request is like below: " << std::endl;
          // std::cerr << std::endl;
          // print_hdrs(packet);
          // std::cerr << std::endl;
          m_router.sendPacket(packet, iface->name);
          std::cerr << "Send ARP request to interface " << iface->name
                    // << "(" << ipToString(iface->ip) << "): " << macToString(iface->addr)
                    // << " to find " << ipToString(req->ip)
                    << "." << std::endl;
          std::cerr << std::endl;
        }
        // Update req info
        req->timeSent = steady_clock::now();
        req->nTimesSent++;
      }
    }
    return true;
  } // namespace simple_router
  //////////////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////

  // You should not need to touch the rest of this code.

  ArpCache::ArpCache(SimpleRouter &router)
      : m_router(router), m_shouldStop(false), m_tickerThread(std::bind(&ArpCache::ticker, this))
  {
  }

  ArpCache::~ArpCache()
  {
    m_shouldStop = true;
    m_tickerThread.join();
  }

  std::shared_ptr<ArpEntry>
  ArpCache::lookup(uint32_t ip)
  {
    std::lock_guard<std::mutex> lock(m_mutex);

    for (const auto &entry : m_cacheEntries)
    {
      if (entry->isValid && entry->ip == ip)
      {
        return entry;
      }
    }

    return nullptr;
  }

  std::shared_ptr<ArpRequest>
  ArpCache::queueRequest(uint32_t ip, const Buffer &packet, const std::string &iface)
  {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                                [ip](const std::shared_ptr<ArpRequest> &request) {
                                  return (request->ip == ip);
                                });

    if (request == m_arpRequests.end())
    {
      request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
    }

    // Add the packet to the list of packets for this request
    (*request)->packets.push_back({packet, iface});
    return *request;
  }

  void ArpCache::removeRequest(const std::shared_ptr<ArpRequest> &entry)
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_arpRequests.remove(entry);
  }

  std::shared_ptr<ArpRequest>
  ArpCache::insertArpEntry(const Buffer &mac, uint32_t ip)
  {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto entry = std::make_shared<ArpEntry>();
    entry->mac = mac;
    entry->ip = ip;
    entry->timeAdded = steady_clock::now();
    entry->isValid = true;
    m_cacheEntries.push_back(entry);

    auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                                [ip](const std::shared_ptr<ArpRequest> &request) {
                                  return (request->ip == ip);
                                });
    if (request != m_arpRequests.end())
    {
      return *request;
    }
    else
    {
      return nullptr;
    }
  }

  void ArpCache::clear()
  {
    std::lock_guard<std::mutex> lock(m_mutex);

    m_cacheEntries.clear();
    m_arpRequests.clear();
  }

  void ArpCache::ticker()
  {
    while (!m_shouldStop)
    {
      std::this_thread::sleep_for(std::chrono::seconds(1));

      {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto now = steady_clock::now();

        for (auto &entry : m_cacheEntries)
        {
          if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO))
          {
            entry->isValid = false;
          }
        }

        periodicCheckArpRequestsAndCacheEntries();
      }
    }
  }

  std::ostream &
  operator<<(std::ostream &os, const ArpCache &cache)
  {
    std::lock_guard<std::mutex> lock(cache.m_mutex);

    os << "\nMAC            IP         AGE                       VALID\n"
       << "-----------------------------------------------------------\n";

    auto now = steady_clock::now();
    for (const auto &entry : cache.m_cacheEntries)
    {

      os << macToString(entry->mac) << "   "
         << ipToString(entry->ip) << "   "
         << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
         << entry->isValid
         << "\n";
    }
    os << std::endl;
    return os;
  }

} // namespace simple_router
