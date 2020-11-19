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

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router
{

  //////////////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////
  // IMPLEMENT THIS METHOD
  void
  SimpleRouter::handlePacket(const Buffer &packet, const std::string &inIface)
  {
    // std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

    const Interface *iface = findIfaceByName(inIface);
    if (iface == nullptr)
    {
      std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
      return;
    }

    // std::cerr << getRoutingTable() << std::endl;

    // FILL THIS IN

    // Print headers
    // print_hdrs(packet);
    // std::cerr << std::endl;

    // Get ethernet header info
    ethernet_hdr ehdr;
    std::memcpy(&ehdr, packet.data(), sizeof(ethernet_hdr));
    // print_hdr_eth((uint8_t *)&ehdr);
    // std::cerr << std::endl;

    // Get dest MAC
    Buffer destMac(ETHER_ADDR_LEN);
    std::memcpy(destMac.data(), ehdr.ether_dhost, ETHER_ADDR_LEN);

    // Assert destMac
    if (macToString(destMac) == "ff:ff:ff:ff:ff:ff" || macToString(destMac) == macToString(iface->addr))
    {
      if (ntohs(ehdr.ether_type) == ethertype_arp)
      {
        // Handle arp packet
        // std::cerr << "It's ARP frame from " << inIface
        // << ": " << macToString(iface->addr)
        // << "." << std::endl;
        // std::cerr << std::endl;
        handleARPPacket(packet, inIface);
      }
      else if (ntohs(ehdr.ether_type) == ethertype_ip)
      {
        // std::cerr << "It's IP frame from " << inIface
        // << ": " << macToString(iface->addr)
        // << "." << std::endl;
        // std::cerr << std::endl;
        handleIPPacket(packet, inIface);
      }
      else
      {
        // Ignore frames other than ARP and IPV4
        std::cerr << "Ignore frames other than ARP and IPV4." << std::endl;
        std::cerr << std::endl;
      }
    }
    else
    {
      // Ignore wrong destMac
    }
  } // namespace simple_router

  void
  SimpleRouter::handleARPPacket(const Buffer &packet, const std::string &inIface)
  {
    // Get ARP packet header info
    arp_hdr ahdr;
    std::memcpy(&ahdr, packet.data() + sizeof(ethernet_hdr), sizeof(arp_hdr));
    // print_hdr_arp((uint8_t *)&ahdr);
    // std::cerr << std::endl;

    if (ntohs(ahdr.arp_op) == arp_op_request)
    // ARP Request
    {
      // Get interface in router by ip
      // std::cerr << "It's ARP request." << std::endl;
      // std::cerr << std::endl;
      const Interface *iface = findIfaceByIp(ahdr.arp_tip);

      if (iface != nullptr)
      {
        // ARP Reply header
        arp_hdr ahdr_rep;
        ahdr_rep.arp_hrd = htons(arp_hrd_ethernet);
        ahdr_rep.arp_pro = htons(ethertype_ip);
        ahdr_rep.arp_hln = 0x06;
        ahdr_rep.arp_pln = 0x04;
        ahdr_rep.arp_op = htons(arp_op_reply);
        std::memcpy(ahdr_rep.arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
        ahdr_rep.arp_sip = iface->ip;
        std::memcpy(ahdr_rep.arp_tha, ahdr.arp_sha, ETHER_ADDR_LEN);
        ahdr_rep.arp_tip = ahdr.arp_sip;

        // Ethernet header
        ethernet_hdr ehdr;
        std::memcpy(ehdr.ether_dhost, ahdr.arp_sha, ETHER_ADDR_LEN);
        std::memcpy(ehdr.ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
        ehdr.ether_type = htons(ethertype_arp);

        // Packet
        Buffer reply_packet(sizeof(arp_hdr) + sizeof(ethernet_hdr));
        std::memcpy(reply_packet.data(), &ehdr, sizeof(ethernet_hdr));
        std::memcpy(reply_packet.data() + sizeof(ethernet_hdr), &ahdr_rep, sizeof(arp_hdr));
        // Output information
        // std::cerr << "I reply it with packet of size " << reply_packet.size() << " below." << std::endl;
        // std::cerr << std::endl;
        // print_hdrs(reply_packet);
        // std::cerr << std::endl;
        // Send reply
        sendPacket(reply_packet, iface->name);
        // std::cerr << "Send reply packet to interface" << iface->name
        // << ": " << macToString(iface->addr)
        // << "." << std::endl;
        // std::cerr << std::endl;
      }
    }
    else if (ntohs(ahdr.arp_op) == arp_op_reply)
    // ARP Reply
    {
      // std::cerr << "It's ARP reply." << std::endl;
      // std::cerr << std::endl;

      // Insert arp cache
      Buffer mac_address(ETHER_ADDR_LEN);
      std::memcpy(mac_address.data(), ahdr.arp_sha, ETHER_ADDR_LEN);
      std::shared_ptr<ArpRequest> arp_req = m_arp.insertArpEntry(mac_address, ahdr.arp_sip);

      // Deal with queue packets
      if (arp_req)
      {
        // int num = 0;
        for (auto &pending_packet : arp_req->packets)
        {
          // std::cerr << "Send queuing packet " << ++num << "." << std::endl;
          // std::cerr << std::endl;
          // Add dest mac address
          std::memcpy(pending_packet.packet.data(), ahdr.arp_sha, ETHER_ADDR_LEN);
          sendPacket(pending_packet.packet, pending_packet.iface);
        }
        m_arp.removeRequest(arp_req);
      }
    }
    else
    {
      // Ignore others
      std::cerr << "It's neither a arp request nor a arp reply." << std::endl;
      std::cerr << std::endl;
    }
  }

  void
  SimpleRouter::handleIPPacket(const Buffer &packet, const std::string &inIface)
  {
    // If less than the minimum length of an IP packet
    if (packet.size() - sizeof(ethernet_hdr) < sizeof(ip_hdr))
    {
      // Wrong length, but a proper ICMP error response is NOT required for this
      std::cerr << "IP packet has wrong length, discard it." << std::endl;
      std::cerr << std::endl;
      return;
    }

    // Get IP packet header info
    ip_hdr ihdr;
    std::memcpy(&ihdr, packet.data() + sizeof(ethernet_hdr), sizeof(ihdr));
    // print_hdr_ip((uint8_t *)&ihdr);
    // std::cerr << std::endl;

    // If checksum wrong
    if (cksum(&ihdr, sizeof(ip_hdr)) != 0xffff)
    {
      // Wrong checksum, but a proper ICMP error response is NOT required for this
      std::cerr << "IP packet has wrong checksum, discard it." << std::endl;
      std::cerr << std::endl;
      return;
    }

    // Judge if destined to router
    const Interface *iface = findIfaceByIp(ihdr.ip_dst);
    if (iface != NULL)
    {
      // Destined to router
      // std::cerr << "IP packet is destined to router." << std::endl;
      // std::cerr << std::endl;

      // Judge ip payload
      if (ihdr.ip_p == ip_protocol_icmp)
      {
        // Get ICMP info
        const icmp_hdr *icmphdr;
        auto icmp_packet_length = packet.size() - sizeof(ethernet_hdr) - sizeof(ip_hdr);
        icmphdr = (icmp_hdr *)(packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));

        // Checksum
        if (cksum(icmphdr, icmp_packet_length) != 0xffff)
        {
          // A proper ICMP response not required in this project
          std::cerr << "ICMP packet has wrong checksum, discard it." << std::endl;
          std::cerr << std::endl;
          return;
        }

        // ECHO message
        if (icmphdr->icmp_type == 8)
        {
          sendICMPPacket(packet, ECHO_REPLY_MESSAGE);
        }
        else
        {
          // Ignore others
          std::cerr << "Discard ICMP packet other than ECHO message." << std::endl;
          std::cerr << std::endl;
        }
      }
      else
      {
        // UDP or TCP packet
        sendICMPPacket(packet, DESTINATION_PORT_UNREACHABLE);
      }
    }
    else
    {
      // Not desnined to router
      // std::cerr << "IP packet is not destined to router. Forward it." << std::endl;
      // std::cerr << std::endl;

      // Decrease TTL
      if (--ihdr.ip_ttl <= 0)
      {
        // Time Exceeded
        // std::cerr << "IP packet time exceeded. Reply ICMP message." << std::endl;
        // std::cerr << std::endl;
        sendICMPPacket(packet, TIME_EXCEEDED);
        return;
      }

      // Recompute checksum
      ihdr.ip_sum = 0;
      ihdr.ip_sum = cksum(&ihdr, sizeof(ihdr));

      // Forward it
      Buffer forward_packet(packet);
      std::memcpy(forward_packet.data() + sizeof(ethernet_hdr), &ihdr, sizeof(ip_hdr));
      forwardPacket(forward_packet);
    }
  }

  void
  SimpleRouter::sendICMPPacket(const Buffer &packet, ICMPTYPE type)
  {
    // IP header
    ip_hdr ihdr;
    std::memcpy(&ihdr, packet.data() + sizeof(ethernet_hdr), sizeof(ip_hdr));

    // IP reply header
    ip_hdr ihdr_reply;
    std::memcpy(&ihdr_reply, &ihdr, sizeof(ip_hdr));

    // ICMP reply header
    icmp_hdr *icmphdr_reply;

    // ICMP_T3 header
    icmp_t3_hdr icmpt3hdr_reply;

    // RouteTable entry
    RoutingTableEntry entry;

    // IP length
    int length;

    // Interface
    const Interface *iface;

    // Switch TYPE
    switch (type)
    {
    case ECHO_MESSAGE:
      break;

    case ECHO_REPLY_MESSAGE:
      // Info
      // std::cerr << "Echo Reply. Send ICMP packet." << std::endl;
      // std::cerr << std::endl;

      {
        // Packet length != sizeof(icmp_hdr)
        auto icmp_packet_length = packet.size() - sizeof(ethernet_hdr) - sizeof(ip_hdr);

        // ICMP reeply header info
        Buffer icmphdr_reply_buffer(icmp_packet_length);
        std::memcpy(icmphdr_reply_buffer.data(), packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr), icmp_packet_length);
        icmphdr_reply = (icmp_hdr *)icmphdr_reply_buffer.data();
        icmphdr_reply->icmp_type = 0;
        icmphdr_reply->icmp_code = 0;
        icmphdr_reply->icmp_sum = 0;
        icmphdr_reply->icmp_sum = cksum(icmphdr_reply, icmp_packet_length);

        // IP reply header info
        ihdr_reply.ip_sum = 0;
        ihdr_reply.ip_p = ip_protocol_icmp;
        ihdr_reply.ip_ttl = 64;
        ihdr_reply.ip_dst = ihdr.ip_src;
        ihdr_reply.ip_src = ihdr.ip_dst;
        ihdr_reply.ip_sum = cksum(&ihdr_reply, sizeof(ip_hdr));

        // Forward packet
        Buffer forward_packet(packet.size());
        std::memcpy(forward_packet.data() + sizeof(ethernet_hdr), &ihdr_reply, sizeof(ip_hdr));
        std::memcpy(forward_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr), icmphdr_reply, icmp_packet_length);
        // print_hdr_ip((uint8_t *)&ihdr_reply);
        // print_hdr_icmp((uint8_t *)icmphdr_reply);
        // std::cerr << std::endl;
        forwardPacket(forward_packet);
      }
      break;

    case TIME_EXCEEDED:
    case DESTINATION_HOST_UNREACHABLE:
    case DESTINATION_PORT_UNREACHABLE:
      // Info
      /*
      if (type == TIME_EXCEEDED)
      {
        std::cerr << "Time exceeded. ";
      }
      else if (type == DESTINATION_HOST_UNREACHABLE)
      {
        std::cerr << "Destination host unreachable. ";
      }
      else
      {
        std::cerr << "Destination port unreachable. ";
      }
      std::cerr << "Send ICMP packet." << std::endl;
      std::cerr << std::endl;
      */

      // ICMP reply header info
      std::memset(&icmpt3hdr_reply, 0, sizeof(icmp_t3_hdr));
      // ICMP_TYPE
      if (type == TIME_EXCEEDED)
      {
        icmpt3hdr_reply.icmp_type = 11; // Time exceeded
      }
      else
      {
        icmpt3hdr_reply.icmp_type = 3; // Destination host or port unreachable
      }
      // ICMP_CODE
      if (type == TIME_EXCEEDED)
      {
        icmpt3hdr_reply.icmp_code = 0; // Time exceeded
      }
      else if (type == DESTINATION_HOST_UNREACHABLE)
      {
        icmpt3hdr_reply.icmp_code = 1; // Destination host unreachable
      }
      else
      {
        icmpt3hdr_reply.icmp_code = 3; // Destination port unreachable
      }
      length = packet.size() - sizeof(ethernet_hdr);
      length = length < ICMP_DATA_SIZE ? length : ICMP_DATA_SIZE;
      std::memcpy(icmpt3hdr_reply.data, packet.data() + sizeof(ethernet_hdr), length);
      icmpt3hdr_reply.icmp_sum = cksum(&icmpt3hdr_reply, sizeof(icmp_t3_hdr));

      // IP reply header info
      ihdr_reply.ip_sum = 0;
      ihdr_reply.ip_p = ip_protocol_icmp;
      ihdr_reply.ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
      ihdr_reply.ip_ttl = 64;
      ihdr_reply.ip_dst = ihdr.ip_src;

      // Iterface
      entry = m_routingTable.lookup(ihdr_reply.ip_dst);
      iface = findIfaceByName(entry.ifName);
      if (iface)
      {
        ihdr_reply.ip_src = iface->ip;
        ihdr_reply.ip_sum = cksum(&ihdr_reply, sizeof(ip_hdr));

        // Forward packet
        Buffer forward_packet(sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
        std::memcpy(forward_packet.data() + sizeof(ethernet_hdr), &ihdr_reply, sizeof(ip_hdr));
        std::memcpy(forward_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr), &icmpt3hdr_reply, sizeof(icmp_t3_hdr));
        // print_hdr_ip((uint8_t *)&ihdr_reply);
        // print_hdr_icmp((uint8_t *)&icmpt3hdr_reply);
        // std::cerr << std::endl;
        forwardPacket(forward_packet);
      }
      else
      {
        // Error finding inferface
        std::cerr << "When sending ICMP packet back, can't find interface." << std::endl;
        std::cerr << std::endl;
      }
      break;
    default:
      break;
    }
  }

  // Forward IP packet
  void
  SimpleRouter::forwardPacket(Buffer &packet)
  {
    // Get IP packet header info
    ip_hdr ihdr;
    std::memcpy(&ihdr, packet.data() + sizeof(ethernet_hdr), sizeof(ihdr));

    // Forward it
    RoutingTableEntry entry = m_routingTable.lookup(ihdr.ip_dst);
    const Interface *outIface = findIfaceByName(entry.ifName);

    // Out interFace
    if (outIface)
    {
      // std::cerr << "Should forward it to interface " << outIface->name
      // << "(" << ipToString(outIface->ip) << "): "
      // << macToString(outIface->addr)
      // << "." << std::endl;
      // std::cerr << std::endl;

      // Ethernet header
      ethernet_hdr ehdr;
      std::memcpy(ehdr.ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
      ehdr.ether_type = htons(ethertype_ip);

      // Get ARP cache
      uint32_t lookupAddress = entry.mask && ((entry.dest & entry.mask) == (outIface->ip & entry.mask))
                                   ? ihdr.ip_dst
                                   : entry.gw;
      std::shared_ptr<ArpEntry> arp_entry = m_arp.lookup(lookupAddress);
      if (!arp_entry)
      // Can't find ARP map
      {
        // Info
        // std::cerr << "Destination mac address unknown. Queue it." << std::endl;
        // std::cerr << std::endl;

        // Queue the reply
        std::memcpy(packet.data(), &ehdr, sizeof(ethernet_hdr));
        std::shared_ptr<ArpRequest> arp_req = m_arp.queueRequest(lookupAddress, packet, outIface->name);

        // Handle ARP request
        if (!m_arp.handle_arpreq(arp_req))
        {
          // Numout
          m_arp.removeRequest(arp_req);
        }
      }
      else
      // Send it
      {
        // Info
        // std::cerr << "Destination mac address known. Send it." << std::endl;
        // std::cerr << std::endl;

        // Send it
        memcpy(ehdr.ether_dhost, arp_entry->mac.data(), ETHER_ADDR_LEN);
        std::memcpy(packet.data(), &ehdr, sizeof(ethernet_hdr));
        // print_hdrs(forward_packet);
        // std::cerr << std::endl;
        sendPacket(packet, outIface->name);
        // std::cerr << "Send it to interface " << outIface->name
        // << "." << std::endl;
        // std::cerr << std::endl;
      }
    }
    else
    {
      // Can't find interface
      std::cerr << "Can't find interface " << entry.ifName << std::endl;
      std::cerr << std::endl;
    }
  }

  void
  SimpleRouter::addWaitingPacket(const Buffer &packet)
  {
    m_waitingPackets.push_back(packet);
    // std::cerr << "Now waiting packets size = " << m_waitingPackets.size() << "." << std::endl;
    // std::cerr << std::endl;
  }

  void
  SimpleRouter::ticker()
  {
    while (!m_shouldStop)
    {
      // Sending interval
      std::this_thread::sleep_for(std::chrono::milliseconds(10));

      // Send waiting packet
      if (!m_waitingPackets.empty())
      {
        sendICMPPacket(m_waitingPackets.front(), DESTINATION_HOST_UNREACHABLE);
        m_waitingPackets.pop_front();
      }
    }
  }
  //////////////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////

  // You should not need to touch the rest of this code.
  SimpleRouter::SimpleRouter()
      : m_shouldStop(false),
        m_tickerThread(std::bind(&SimpleRouter::ticker, this)),
        m_arp(*this)
  {
  }

  SimpleRouter::~SimpleRouter()
  {
    m_shouldStop = true;
    m_tickerThread.join();
  }

  void SimpleRouter::sendPacket(const Buffer &packet, const std::string &outIface)
  {
    m_pox->begin_sendPacket(packet, outIface);
  }

  bool SimpleRouter::loadRoutingTable(const std::string &rtConfig)
  {
    return m_routingTable.load(rtConfig);
  }

  void SimpleRouter::loadIfconfig(const std::string &ifconfig)
  {
    std::ifstream iff(ifconfig.c_str());
    std::string line;
    while (std::getline(iff, line))
    {
      std::istringstream ifLine(line);
      std::string iface, ip;
      ifLine >> iface >> ip;

      in_addr ip_addr;
      if (inet_aton(ip.c_str(), &ip_addr) == 0)
      {
        throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
      }

      m_ifNameToIpMap[iface] = ip_addr.s_addr;
    }
  }

  void SimpleRouter::printIfaces(std::ostream &os)
  {
    if (m_ifaces.empty())
    {
      os << " Interface list empty " << std::endl;
      return;
    }

    for (const auto &iface : m_ifaces)
    {
      os << iface << "\n";
    }
    os.flush();
  }

  const Interface *
  SimpleRouter::findIfaceByIp(uint32_t ip) const
  {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip](const Interface &iface) {
      return iface.ip == ip;
    });

    if (iface == m_ifaces.end())
    {
      return nullptr;
    }

    return &*iface;
  }

  const Interface *
  SimpleRouter::findIfaceByMac(const Buffer &mac) const
  {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac](const Interface &iface) {
      return iface.addr == mac;
    });

    if (iface == m_ifaces.end())
    {
      return nullptr;
    }

    return &*iface;
  }

  const Interface *
  SimpleRouter::findIfaceByName(const std::string &name) const
  {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name](const Interface &iface) {
      return iface.name == name;
    });

    if (iface == m_ifaces.end())
    {
      return nullptr;
    }

    return &*iface;
  }

  void SimpleRouter::reset(const pox::Ifaces &ports)
  {
    std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

    m_arp.clear();
    m_ifaces.clear();

    for (const auto &iface : ports)
    {
      auto ip = m_ifNameToIpMap.find(iface.name);
      if (ip == m_ifNameToIpMap.end())
      {
        std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
        continue;
      }

      m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
    }

    printIfaces(std::cerr);
  }

} // namespace simple_router
