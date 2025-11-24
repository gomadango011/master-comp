/*
 * Copyright (c) 2009 IITP RAS
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Based on
 *      NS-2 AODV model developed by the CMU/MONARCH group and optimized and
 *      tuned by Samir Das and Mahesh Marina, University of Cincinnati;
 *
 *      AODV-UU implementation by Erik Nordström of Uppsala University
 *      https://web.archive.org/web/20100527072022/http://core.it.uu.se/core/index.php/AODV-UU
 *
 * Authors: Elena Buchatskaia <borovkovaes@iitp.ru>
 *          Pavel Boyko <boyko@iitp.ru>
 */

#include "aodv-routing-protocol.h"

#include "ns3/adhoc-wifi-mac.h"
#include "ns3/boolean.h"
#include "ns3/inet-socket-address.h"
#include "ns3/log.h"
#include "ns3/pointer.h"
#include "ns3/random-variable-stream.h"
#include "ns3/string.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/udp-header.h"
#include "ns3/udp-l4-protocol.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/wifi-mpdu.h"
#include "ns3/wifi-net-device.h"
#include "ns3/icmpv4-l4-protocol.h"


#include <algorithm>
#include <limits>

#undef NS_LOG_APPEND_CONTEXT
#define NS_LOG_APPEND_CONTEXT                                                                      \
    if (m_ipv4)                                                                                    \
    {                                                                                              \
        std::clog << "[node " << m_ipv4->GetObject<Node>()->GetId() << "] ";                       \
    }

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("AodvRoutingProtocol");

namespace aodv
{
NS_OBJECT_ENSURE_REGISTERED(RoutingProtocol);

/// UDP Port for AODV control traffic
const uint32_t RoutingProtocol::AODV_PORT = 654;

/**
 * @ingroup aodv
 * @brief Tag used by AODV implementation
 */
class DeferredRouteOutputTag : public Tag
{
  public:
    /**
     * @brief Constructor
     * @param o the output interface
     */
    DeferredRouteOutputTag(int32_t o = -1)
        : Tag(),
          m_oif(o)
    {
    }

    /**
     * @brief Get the type ID.
     * @return the object TypeId
     */
    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::aodv::DeferredRouteOutputTag")
                                .SetParent<Tag>()
                                .SetGroupName("Aodv")
                                .AddConstructor<DeferredRouteOutputTag>();
        return tid;
    }

    TypeId GetInstanceTypeId() const override
    {
        return GetTypeId();
    }

    /**
     * @brief Get the output interface
     * @return the output interface
     */
    int32_t GetInterface() const
    {
        return m_oif;
    }

    /**
     * @brief Set the output interface
     * @param oif the output interface
     */
    void SetInterface(int32_t oif)
    {
        m_oif = oif;
    }

    uint32_t GetSerializedSize() const override
    {
        return sizeof(int32_t);
    }

    void Serialize(TagBuffer i) const override
    {
        i.WriteU32(m_oif);
    }

    void Deserialize(TagBuffer i) override
    {
        m_oif = i.ReadU32();
    }

    void Print(std::ostream& os) const override
    {
        os << "DeferredRouteOutputTag: output interface = " << m_oif;
    }

  private:
    /// Positive if output device is fixed in RouteOutput
    int32_t m_oif;
};

NS_OBJECT_ENSURE_REGISTERED(DeferredRouteOutputTag);

//-----------------------------------------------------------------------------
RoutingProtocol::RoutingProtocol()
    : m_rreqRetries(2),
      m_ttlStart(1),
      m_ttlIncrement(2),
      m_ttlThreshold(7),
      m_timeoutBuffer(2),
      m_rreqRateLimit(10),
      m_rerrRateLimit(10),
      m_activeRouteTimeout(Seconds(3)),
      m_netDiameter(35),
      m_nodeTraversalTime(MilliSeconds(40)),  //1ホップの平均通信時間
      m_netTraversalTime(Time((2 * m_netDiameter) * m_nodeTraversalTime)),
      m_pathDiscoveryTime(Time(2 * m_netTraversalTime)),
      m_myRouteTimeout(Time(2 * std::max(m_pathDiscoveryTime, m_activeRouteTimeout))),
      m_helloInterval(Seconds(1)),
      m_allowedHelloLoss(2),
      m_deletePeriod(Time(5 * std::max(m_activeRouteTimeout, m_helloInterval))),
      m_nextHopWait(m_nodeTraversalTime + MilliSeconds(10)),
      m_blackListTimeout(Time(m_rreqRetries * m_netTraversalTime)),
      m_maxQueueLen(64),
      m_maxQueueTime(Seconds(30)),
      m_destinationOnly(false),
      m_gratuitousReply(true),
      m_enableHello(false),
      m_routingTable(m_deletePeriod),
      m_queue(m_maxQueueLen, m_maxQueueTime),
      m_requestId(0),
      m_seqNo(0),
      m_rreqIdCache(m_pathDiscoveryTime),
      m_dpd(m_pathDiscoveryTime),
      m_nb(m_helloInterval),
      m_rreqCount(0),
      m_rerrCount(0),
      m_whNeighborThreshold(1.2f), //隣接ノード比率のしきい値を初期化
      m_sendBlocked(false),
      m_step3ReplyWaitTime(3*m_nodeTraversalTime),
      m_htimer(Timer::CANCEL_ON_DESTROY),
      m_rreqRateLimitTimer(Timer::CANCEL_ON_DESTROY),
      m_rerrRateLimitTimer(Timer::CANCEL_ON_DESTROY),
      m_lastBcastTime()
{
    m_nb.SetCallback(MakeCallback(&RoutingProtocol::SendRerrWhenBreaksLinkToNextHop, this));
}

TypeId
RoutingProtocol::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::aodv::RoutingProtocol")
            .SetParent<Ipv4RoutingProtocol>()
            .SetGroupName("Aodv")
            .AddConstructor<RoutingProtocol>()
            .AddAttribute("HelloInterval",
                          "HELLO messages emission interval.",
                          TimeValue(Seconds(1)),
                          MakeTimeAccessor(&RoutingProtocol::m_helloInterval),
                          MakeTimeChecker())
            .AddAttribute("TtlStart",
                          "Initial TTL value for RREQ.",
                          UintegerValue(1),
                          MakeUintegerAccessor(&RoutingProtocol::m_ttlStart),
                          MakeUintegerChecker<uint16_t>())
            .AddAttribute("TtlIncrement",
                          "TTL increment for each attempt using the expanding ring search for RREQ "
                          "dissemination.",
                          UintegerValue(2),
                          MakeUintegerAccessor(&RoutingProtocol::m_ttlIncrement),
                          MakeUintegerChecker<uint16_t>())
            .AddAttribute("TtlThreshold",
                          "Maximum TTL value for expanding ring search, TTL = NetDiameter is used "
                          "beyond this value.",
                          UintegerValue(7),
                          MakeUintegerAccessor(&RoutingProtocol::m_ttlThreshold),
                          MakeUintegerChecker<uint16_t>())
            .AddAttribute("TimeoutBuffer",
                          "Provide a buffer for the timeout.",
                          UintegerValue(2),
                          MakeUintegerAccessor(&RoutingProtocol::m_timeoutBuffer),
                          MakeUintegerChecker<uint16_t>())
            .AddAttribute("RreqRetries",
                          "Maximum number of retransmissions of RREQ to discover a route",
                          UintegerValue(2),
                          MakeUintegerAccessor(&RoutingProtocol::m_rreqRetries),
                          MakeUintegerChecker<uint32_t>())
            .AddAttribute("RreqRateLimit",
                          "Maximum number of RREQ per second.",
                          UintegerValue(10),
                          MakeUintegerAccessor(&RoutingProtocol::m_rreqRateLimit),
                          MakeUintegerChecker<uint32_t>())
            .AddAttribute("RerrRateLimit",
                          "Maximum number of RERR per second.",
                          UintegerValue(10),
                          MakeUintegerAccessor(&RoutingProtocol::m_rerrRateLimit),
                          MakeUintegerChecker<uint32_t>())
            .AddAttribute("NodeTraversalTime",
                          "Conservative estimate of the average one hop traversal time for packets "
                          "and should include "
                          "queuing delays, interrupt processing times and transfer times.",
                          TimeValue(MilliSeconds(40)),
                          MakeTimeAccessor(&RoutingProtocol::m_nodeTraversalTime),
                          MakeTimeChecker())
            .AddAttribute(
                "NextHopWait",
                "Period of our waiting for the neighbour's RREP_ACK = 10 ms + NodeTraversalTime",
                TimeValue(MilliSeconds(50)),
                MakeTimeAccessor(&RoutingProtocol::m_nextHopWait),
                MakeTimeChecker())
            .AddAttribute("ActiveRouteTimeout",
                          "Period of time during which the route is considered to be valid",
                          TimeValue(Seconds(3)),
                          MakeTimeAccessor(&RoutingProtocol::m_activeRouteTimeout),
                          MakeTimeChecker())
            .AddAttribute("MyRouteTimeout",
                          "Value of lifetime field in RREP generating by this node = 2 * "
                          "max(ActiveRouteTimeout, PathDiscoveryTime)",
                          TimeValue(Seconds(11.2)),
                          MakeTimeAccessor(&RoutingProtocol::m_myRouteTimeout),
                          MakeTimeChecker())
            .AddAttribute("BlackListTimeout",
                          "Time for which the node is put into the blacklist = RreqRetries * "
                          "NetTraversalTime",
                          TimeValue(Seconds(5.6)),
                          MakeTimeAccessor(&RoutingProtocol::m_blackListTimeout),
                          MakeTimeChecker())
            .AddAttribute("DeletePeriod",
                          "DeletePeriod is intended to provide an upper bound on the time for "
                          "which an upstream node A "
                          "can have a neighbor B as an active next hop for destination D, while B "
                          "has invalidated the route to D."
                          " = 5 * max (HelloInterval, ActiveRouteTimeout)",
                          TimeValue(Seconds(15)),
                          MakeTimeAccessor(&RoutingProtocol::m_deletePeriod),
                          MakeTimeChecker())
            .AddAttribute("NetDiameter",
                          "Net diameter measures the maximum possible number of hops between two "
                          "nodes in the network",
                          UintegerValue(35),
                          MakeUintegerAccessor(&RoutingProtocol::m_netDiameter),
                          MakeUintegerChecker<uint32_t>())
            .AddAttribute(
                "NetTraversalTime",
                "Estimate of the average net traversal time = 2 * NodeTraversalTime * NetDiameter",
                TimeValue(Seconds(2.8)),
                MakeTimeAccessor(&RoutingProtocol::m_netTraversalTime),
                MakeTimeChecker())
            .AddAttribute(
                "PathDiscoveryTime",
                "Estimate of maximum time needed to find route in network = 2 * NetTraversalTime",
                TimeValue(Seconds(5.6)),
                MakeTimeAccessor(&RoutingProtocol::m_pathDiscoveryTime),
                MakeTimeChecker())
            .AddAttribute("MaxQueueLen",
                          "Maximum number of packets that we allow a routing protocol to buffer.",
                          UintegerValue(64),
                          MakeUintegerAccessor(&RoutingProtocol::SetMaxQueueLen,
                                               &RoutingProtocol::GetMaxQueueLen),
                          MakeUintegerChecker<uint32_t>())
            .AddAttribute("MaxQueueTime",
                          "Maximum time packets can be queued (in seconds)",
                          TimeValue(Seconds(30)),
                          MakeTimeAccessor(&RoutingProtocol::SetMaxQueueTime,
                                           &RoutingProtocol::GetMaxQueueTime),
                          MakeTimeChecker())
            .AddAttribute("AllowedHelloLoss",
                          "Number of hello messages which may be loss for valid link.",
                          UintegerValue(2),
                          MakeUintegerAccessor(&RoutingProtocol::m_allowedHelloLoss),
                          MakeUintegerChecker<uint16_t>())
            .AddAttribute("GratuitousReply",
                          "Indicates whether a gratuitous RREP should be unicast to the node "
                          "originated route discovery.",
                          BooleanValue(true),
                          MakeBooleanAccessor(&RoutingProtocol::SetGratuitousReplyFlag,
                                              &RoutingProtocol::GetGratuitousReplyFlag),
                          MakeBooleanChecker())
            .AddAttribute("DestinationOnly",
                          "Indicates only the destination may respond to this RREQ.",
                          BooleanValue(false),
                          MakeBooleanAccessor(&RoutingProtocol::SetDestinationOnlyFlag,
                                              &RoutingProtocol::GetDestinationOnlyFlag),
                          MakeBooleanChecker())
            .AddAttribute("EnableHello",
                          "Indicates whether a hello messages enable.",
                          BooleanValue(true),
                          MakeBooleanAccessor(&RoutingProtocol::SetHelloEnable,
                                              &RoutingProtocol::GetHelloEnable),
                          MakeBooleanChecker())
            .AddAttribute("EnableBroadcast",
                          "Indicates whether a broadcast data packets forwarding enable.",
                          BooleanValue(true),
                          MakeBooleanAccessor(&RoutingProtocol::SetBroadcastEnable,
                                              &RoutingProtocol::GetBroadcastEnable),
                          MakeBooleanChecker())
            .AddAttribute("UniformRv",
                          "Access to the underlying UniformRandomVariable",
                          StringValue("ns3::UniformRandomVariable"),
                          MakePointerAccessor(&RoutingProtocol::m_uniformRandomVariable),
                          MakePointerChecker<UniformRandomVariable>());
    return tid;
}

void
RoutingProtocol::SetMaxQueueLen(uint32_t len)
{
    m_maxQueueLen = len;
    m_queue.SetMaxQueueLen(len);
}

void
RoutingProtocol::SetMaxQueueTime(Time t)
{
    m_maxQueueTime = t;
    m_queue.SetQueueTimeout(t);
}

RoutingProtocol::~RoutingProtocol()
{
}

void
RoutingProtocol::DoDispose()
{
    m_ipv4 = nullptr;
    for (auto iter = m_socketAddresses.begin(); iter != m_socketAddresses.end(); iter++)
    {
        iter->first->Close();
    }
    m_socketAddresses.clear();
    for (auto iter = m_socketSubnetBroadcastAddresses.begin();
         iter != m_socketSubnetBroadcastAddresses.end();
         iter++)
    {
        iter->first->Close();
    }
    m_socketSubnetBroadcastAddresses.clear();
    Ipv4RoutingProtocol::DoDispose();
}

void
RoutingProtocol::PrintRoutingTable(Ptr<OutputStreamWrapper> stream, Time::Unit unit) const
{
    *stream->GetStream() << "Node: " << m_ipv4->GetObject<Node>()->GetId()
                         << "; Time: " << Now().As(unit)
                         << ", Local time: " << m_ipv4->GetObject<Node>()->GetLocalTime().As(unit)
                         << ", AODV Routing table" << std::endl;

    m_routingTable.Print(stream, unit);
    *stream->GetStream() << std::endl;
}

int64_t
RoutingProtocol::AssignStreams(int64_t stream)
{
    NS_LOG_FUNCTION(this << stream);
    m_uniformRandomVariable->SetStream(stream);
    return 1;
}

void
RoutingProtocol::Start()
{
    NS_LOG_FUNCTION(this);
    if (m_enableHello)
    {
        m_nb.ScheduleTimer();
    }
    m_rreqRateLimitTimer.SetFunction(&RoutingProtocol::RreqRateLimitTimerExpire, this);
    m_rreqRateLimitTimer.Schedule(Seconds(1));

    m_rerrRateLimitTimer.SetFunction(&RoutingProtocol::RerrRateLimitTimerExpire, this);
    m_rerrRateLimitTimer.Schedule(Seconds(1));

    //ステップ3用のコールバックを設定
    Ptr<NetDevice> dev = m_ipv4->GetNetDevice(1);
    dev->SetPromiscReceiveCallback(MakeCallback(&RoutingProtocol::PromiscSniff, this));
}

Ptr<Ipv4Route>
RoutingProtocol::RouteOutput(Ptr<Packet> p,
                             const Ipv4Header& header,
                             Ptr<NetDevice> oif,
                             Socket::SocketErrno& sockerr)
{
    NS_LOG_FUNCTION(this << header << (oif ? oif->GetIfIndex() : 0));

    // //ステップ3用の通信ブロック処理
    // if (m_sendBlocked)
    // {
    //     NS_LOG_DEBUG("RouteOutputがブロックされました　IPアドレス： " << m_ipv4->GetObject<Node>()->GetId());
    //     return Ptr<Ipv4Route>();
    // }

    if (!p)
    {
        NS_LOG_DEBUG("Packet is == 0");
        return LoopbackRoute(header, oif); // later
    }
    if (m_socketAddresses.empty())
    {
        sockerr = Socket::ERROR_NOROUTETOHOST;
        NS_LOG_LOGIC("No aodv interfaces");
        Ptr<Ipv4Route> route;
        return route;
    }
    sockerr = Socket::ERROR_NOTERROR;
    Ptr<Ipv4Route> route;
    Ipv4Address dst = header.GetDestination();
    RoutingTableEntry rt;
    if (m_routingTable.LookupValidRoute(dst, rt))
    {
        route = rt.GetRoute();
        NS_ASSERT(route);
        NS_LOG_DEBUG("Exist route to " << route->GetDestination() << " from interface "
                                       << route->GetSource());
        if (oif && route->GetOutputDevice() != oif)
        {
            NS_LOG_DEBUG("Output device doesn't match. Dropped.");
            sockerr = Socket::ERROR_NOROUTETOHOST;
            return Ptr<Ipv4Route>();
        }
        UpdateRouteLifeTime(dst, m_activeRouteTimeout);
        UpdateRouteLifeTime(route->GetGateway(), m_activeRouteTimeout);
        return route;
    }

    // Valid route not found, in this case we return loopback.
    // Actual route request will be deferred until packet will be fully formed,
    // routed to loopback, received from loopback and passed to RouteInput (see below)
    uint32_t iif = (oif ? m_ipv4->GetInterfaceForDevice(oif) : -1);
    DeferredRouteOutputTag tag(iif);
    NS_LOG_DEBUG("Valid Route not found");
    if (!p->PeekPacketTag(tag))
    {
        p->AddPacketTag(tag);
    }
    return LoopbackRoute(header, oif);
}

void
RoutingProtocol::DeferredRouteOutput(Ptr<const Packet> p,
                                     const Ipv4Header& header,
                                     UnicastForwardCallback ucb,
                                     ErrorCallback ecb)
{
    NS_LOG_FUNCTION(this << p << header);
    NS_ASSERT(p && p != Ptr<Packet>());

    QueueEntry newEntry(p, header, ucb, ecb);
    bool result = m_queue.Enqueue(newEntry);
    if (result)
    {
        NS_LOG_LOGIC("Add packet " << p->GetUid() << " to queue. Protocol "
                                   << (uint16_t)header.GetProtocol());
        RoutingTableEntry rt;
        bool result = m_routingTable.LookupRoute(header.GetDestination(), rt);
        if (!result || ((rt.GetFlag() != IN_SEARCH) && result))
        {
            NS_LOG_LOGIC("Send new RREQ for outbound packet to " << header.GetDestination());
            SendRequest(header.GetDestination());
        }
    }
}

bool
RoutingProtocol::RouteInput(Ptr<const Packet> p,
                            const Ipv4Header& header,
                            Ptr<const NetDevice> idev,
                            const UnicastForwardCallback& ucb,
                            const MulticastForwardCallback& mcb,
                            const LocalDeliverCallback& lcb,
                            const ErrorCallback& ecb)
{
    NS_LOG_FUNCTION(this << p->GetUid() << header.GetDestination() << idev->GetAddress());
    if (m_socketAddresses.empty())
    {
        NS_LOG_LOGIC("No aodv interfaces");
        return false;
    }
    NS_ASSERT(m_ipv4);
    NS_ASSERT(p);
    // Check if input device supports IP
    NS_ASSERT(m_ipv4->GetInterfaceForDevice(idev) >= 0);
    int32_t iif = m_ipv4->GetInterfaceForDevice(idev);

    Ipv4Address dst = header.GetDestination();
    Ipv4Address origin = header.GetSource();

    // Deferred route request
    if (idev == m_lo)
    {
        DeferredRouteOutputTag tag;
        if (p->PeekPacketTag(tag))
        {
            DeferredRouteOutput(p, header, ucb, ecb);
            return true;
        }
    }

    // Duplicate of own packet
    if (IsMyOwnAddress(origin))
    {
        return true;
    }

    // AODV is not a multicast routing protocol
    if (dst.IsMulticast())
    {
        return false;
    }

    // Broadcast local delivery/forwarding
    for (auto j = m_socketAddresses.begin(); j != m_socketAddresses.end(); ++j)
    {
        Ipv4InterfaceAddress iface = j->second;
        if (m_ipv4->GetInterfaceForAddress(iface.GetLocal()) == iif)
        {
            if (dst == iface.GetBroadcast() || dst.IsBroadcast())
            {
                if (m_dpd.IsDuplicate(p, header))
                {
                    NS_LOG_DEBUG("Duplicated packet " << p->GetUid() << " from " << origin
                                                      << ". Drop.");
                    return true;
                }
                UpdateRouteLifeTime(origin, m_activeRouteTimeout);
                Ptr<Packet> packet = p->Copy();
                if (!lcb.IsNull())
                {
                    NS_LOG_LOGIC("Broadcast local delivery to " << iface.GetLocal());
                    lcb(p, header, iif);
                    // Fall through to additional processing
                }
                else
                {
                    NS_LOG_ERROR("Unable to deliver packet locally due to null callback "
                                 << p->GetUid() << " from " << origin);
                    ecb(p, header, Socket::ERROR_NOROUTETOHOST);
                }
                if (!m_enableBroadcast)
                {
                    return true;
                }
                if (header.GetProtocol() == UdpL4Protocol::PROT_NUMBER)
                {
                    UdpHeader udpHeader;
                    p->PeekHeader(udpHeader);
                    if (udpHeader.GetDestinationPort() == AODV_PORT)
                    {
                        // AODV packets sent in broadcast are already managed
                        return true;
                    }
                }
                if (header.GetTtl() > 1)
                {
                    NS_LOG_LOGIC("Forward broadcast. TTL " << (uint16_t)header.GetTtl());
                    RoutingTableEntry toBroadcast;
                    if (m_routingTable.LookupRoute(dst, toBroadcast))
                    {
                        Ptr<Ipv4Route> route = toBroadcast.GetRoute();
                        ucb(route, packet, header);
                    }
                    else
                    {
                        NS_LOG_DEBUG("No route to forward broadcast. Drop packet " << p->GetUid());
                    }
                }
                else
                {
                    NS_LOG_DEBUG("TTL exceeded. Drop packet " << p->GetUid());
                }
                return true;
            }
        }
    }

    // Unicast local delivery
    if (m_ipv4->IsDestinationAddress(dst, iif))
    {
        UpdateRouteLifeTime(origin, m_activeRouteTimeout);
        RoutingTableEntry toOrigin;
        if (m_routingTable.LookupValidRoute(origin, toOrigin))
        {
            UpdateRouteLifeTime(toOrigin.GetNextHop(), m_activeRouteTimeout);
            m_nb.Update(toOrigin.GetNextHop(), m_activeRouteTimeout);
        }
        if (!lcb.IsNull())
        {
            NS_LOG_LOGIC("Unicast local delivery to " << dst);
            lcb(p, header, iif);
        }
        else
        {
            NS_LOG_ERROR("Unable to deliver packet locally due to null callback "
                         << p->GetUid() << " from " << origin);
            ecb(p, header, Socket::ERROR_NOROUTETOHOST);
        }
        return true;
    }

    // Check if input device supports IP forwarding
    if (!m_ipv4->IsForwarding(iif))
    {
        NS_LOG_LOGIC("Forwarding disabled for this interface");
        ecb(p, header, Socket::ERROR_NOROUTETOHOST);
        return true;
    }

    // Forwarding
    return Forwarding(p, header, ucb, ecb);
}

bool
RoutingProtocol::Forwarding(Ptr<const Packet> p,
                            const Ipv4Header& header,
                            UnicastForwardCallback ucb,
                            ErrorCallback ecb)
{
    NS_LOG_FUNCTION(this);

    // //ステップ3用の通信ブロック処理
    // if (m_sendBlocked)
    // {
    //     NS_LOG_DEBUG("Forwardingがブロックされました　IPアドレス： " << m_ipv4->GetObject<Node>()->GetId());
    //     return false;
    // }
    
    Ipv4Address dst = header.GetDestination();
    Ipv4Address origin = header.GetSource();
    m_routingTable.Purge();
    RoutingTableEntry toDst;
    if (m_routingTable.LookupRoute(dst, toDst))
    {
        if (toDst.GetFlag() == VALID)
        {
            Ptr<Ipv4Route> route = toDst.GetRoute();
            NS_LOG_LOGIC(route->GetSource() << " forwarding to " << dst << " from " << origin
                                            << " packet " << p->GetUid());

            /*
             *  Each time a route is used to forward a data packet, its Active Route
             *  Lifetime field of the source, destination and the next hop on the
             *  path to the destination is updated to be no less than the current
             *  time plus ActiveRouteTimeout.
             */
            UpdateRouteLifeTime(origin, m_activeRouteTimeout);
            UpdateRouteLifeTime(dst, m_activeRouteTimeout);
            UpdateRouteLifeTime(route->GetGateway(), m_activeRouteTimeout);
            /*
             *  Since the route between each originator and destination pair is expected to be
             * symmetric, the Active Route Lifetime for the previous hop, along the reverse path
             * back to the IP source, is also updated to be no less than the current time plus
             * ActiveRouteTimeout
             */
            RoutingTableEntry toOrigin;
            m_routingTable.LookupRoute(origin, toOrigin);
            UpdateRouteLifeTime(toOrigin.GetNextHop(), m_activeRouteTimeout);

            m_nb.Update(route->GetGateway(), m_activeRouteTimeout);
            m_nb.Update(toOrigin.GetNextHop(), m_activeRouteTimeout);

            ucb(route, p, header);
            return true;
        }
        else
        {
            if (toDst.GetValidSeqNo())
            {
                SendRerrWhenNoRouteToForward(dst, toDst.GetSeqNo(), origin);
                NS_LOG_DEBUG("Drop packet " << p->GetUid() << " because no route to forward it.");
                return false;
            }
        }
    }
    NS_LOG_LOGIC("route not found to " << dst << ". Send RERR message.");
    NS_LOG_DEBUG("Drop packet " << p->GetUid() << " because no route to forward it.");
    SendRerrWhenNoRouteToForward(dst, 0, origin);
    return false;
}

void
RoutingProtocol::SetIpv4(Ptr<Ipv4> ipv4)
{
    NS_ASSERT(ipv4);
    NS_ASSERT(!m_ipv4);

    m_ipv4 = ipv4;

    // Create lo route. It is asserted that the only one interface up for now is loopback
    NS_ASSERT(m_ipv4->GetNInterfaces() == 1 &&
              m_ipv4->GetAddress(0, 0).GetLocal() == Ipv4Address("127.0.0.1"));
    m_lo = m_ipv4->GetNetDevice(0);
    NS_ASSERT(m_lo);
    // Remember lo route
    RoutingTableEntry rt(
        /*dev=*/m_lo,
        /*dst=*/Ipv4Address::GetLoopback(),
        /*vSeqNo=*/true,
        /*seqNo=*/0,
        /*iface=*/Ipv4InterfaceAddress(Ipv4Address::GetLoopback(), Ipv4Mask("255.0.0.0")),
        /*hops=*/1,
        /*nextHop=*/Ipv4Address::GetLoopback(),
        /*lifetime=*/Simulator::GetMaximumSimulationTime());
    m_routingTable.AddRoute(rt);

    Simulator::ScheduleNow(&RoutingProtocol::Start, this);
}

void
RoutingProtocol::NotifyInterfaceUp(uint32_t i)
{
    NS_LOG_FUNCTION(this << m_ipv4->GetAddress(i, 0).GetLocal());
    Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol>();
    if (l3->GetNAddresses(i) > 1)
    {
        NS_LOG_WARN("AODV does not work with more then one address per each interface.");
    }
    Ipv4InterfaceAddress iface = l3->GetAddress(i, 0);
    if (iface.GetLocal() == Ipv4Address("127.0.0.1"))
    {
        return;
    }

    // Create a socket to listen only on this interface
    Ptr<Socket> socket = Socket::CreateSocket(GetObject<Node>(), UdpSocketFactory::GetTypeId());
    NS_ASSERT(socket);
    socket->SetRecvCallback(MakeCallback(&RoutingProtocol::RecvAodv, this));
    socket->BindToNetDevice(l3->GetNetDevice(i));
    socket->Bind(InetSocketAddress(iface.GetLocal(), AODV_PORT));
    socket->SetAllowBroadcast(true);
    socket->SetIpRecvTtl(true);
    m_socketAddresses.insert(std::make_pair(socket, iface));

    // create also a subnet broadcast socket
    socket = Socket::CreateSocket(GetObject<Node>(), UdpSocketFactory::GetTypeId());
    NS_ASSERT(socket);
    socket->SetRecvCallback(MakeCallback(&RoutingProtocol::RecvAodv, this));
    socket->BindToNetDevice(l3->GetNetDevice(i));
    socket->Bind(InetSocketAddress(iface.GetBroadcast(), AODV_PORT));
    socket->SetAllowBroadcast(true);
    socket->SetIpRecvTtl(true);
    m_socketSubnetBroadcastAddresses.insert(std::make_pair(socket, iface));

    // Add local broadcast record to the routing table
    Ptr<NetDevice> dev = m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(iface.GetLocal()));
    RoutingTableEntry rt(/*dev=*/dev,
                         /*dst=*/iface.GetBroadcast(),
                         /*vSeqNo=*/true,
                         /*seqNo=*/0,
                         /*iface=*/iface,
                         /*hops=*/1,
                         /*nextHop=*/iface.GetBroadcast(),
                         /*lifetime=*/Simulator::GetMaximumSimulationTime());
    m_routingTable.AddRoute(rt);

    if (l3->GetInterface(i)->GetArpCache())
    {
        m_nb.AddArpCache(l3->GetInterface(i)->GetArpCache());
    }

    // Allow neighbor manager use this interface for layer 2 feedback if possible
    Ptr<WifiNetDevice> wifi = dev->GetObject<WifiNetDevice>();
    if (!wifi)
    {
        return;
    }
    Ptr<WifiMac> mac = wifi->GetMac();
    if (!mac)
    {
        return;
    }

    mac->TraceConnectWithoutContext("DroppedMpdu",
                                    MakeCallback(&RoutingProtocol::NotifyTxError, this));
}

void
RoutingProtocol::NotifyTxError(WifiMacDropReason reason, Ptr<const WifiMpdu> mpdu)
{
    m_nb.GetTxErrorCallback()(mpdu->GetHeader());
}

void
RoutingProtocol::NotifyInterfaceDown(uint32_t i)
{
    NS_LOG_FUNCTION(this << m_ipv4->GetAddress(i, 0).GetLocal());

    // Disable layer 2 link state monitoring (if possible)
    Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol>();
    Ptr<NetDevice> dev = l3->GetNetDevice(i);
    Ptr<WifiNetDevice> wifi = dev->GetObject<WifiNetDevice>();
    if (wifi)
    {
        Ptr<WifiMac> mac = wifi->GetMac()->GetObject<AdhocWifiMac>();
        if (mac)
        {
            mac->TraceDisconnectWithoutContext("DroppedMpdu",
                                               MakeCallback(&RoutingProtocol::NotifyTxError, this));
            m_nb.DelArpCache(l3->GetInterface(i)->GetArpCache());
        }
    }

    // Close socket
    Ptr<Socket> socket = FindSocketWithInterfaceAddress(m_ipv4->GetAddress(i, 0));
    NS_ASSERT(socket);
    socket->Close();
    m_socketAddresses.erase(socket);

    // Close socket
    socket = FindSubnetBroadcastSocketWithInterfaceAddress(m_ipv4->GetAddress(i, 0));
    NS_ASSERT(socket);
    socket->Close();
    m_socketSubnetBroadcastAddresses.erase(socket);

    if (m_socketAddresses.empty())
    {
        NS_LOG_LOGIC("No aodv interfaces");
        m_htimer.Cancel();
        m_nb.Clear();
        m_routingTable.Clear();
        return;
    }
    m_routingTable.DeleteAllRoutesFromInterface(m_ipv4->GetAddress(i, 0));
}

void
RoutingProtocol::NotifyAddAddress(uint32_t i, Ipv4InterfaceAddress address)
{
    NS_LOG_FUNCTION(this << " interface " << i << " address " << address);
    Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol>();
    if (!l3->IsUp(i))
    {
        return;
    }
    if (l3->GetNAddresses(i) == 1)
    {
        Ipv4InterfaceAddress iface = l3->GetAddress(i, 0);
        Ptr<Socket> socket = FindSocketWithInterfaceAddress(iface);
        if (!socket)
        {
            if (iface.GetLocal() == Ipv4Address("127.0.0.1"))
            {
                return;
            }
            // Create a socket to listen only on this interface
            Ptr<Socket> socket =
                Socket::CreateSocket(GetObject<Node>(), UdpSocketFactory::GetTypeId());
            NS_ASSERT(socket);
            socket->SetRecvCallback(MakeCallback(&RoutingProtocol::RecvAodv, this));
            socket->BindToNetDevice(l3->GetNetDevice(i));
            socket->Bind(InetSocketAddress(iface.GetLocal(), AODV_PORT));
            socket->SetAllowBroadcast(true);
            m_socketAddresses.insert(std::make_pair(socket, iface));

            // create also a subnet directed broadcast socket
            socket = Socket::CreateSocket(GetObject<Node>(), UdpSocketFactory::GetTypeId());
            NS_ASSERT(socket);
            socket->SetRecvCallback(MakeCallback(&RoutingProtocol::RecvAodv, this));
            socket->BindToNetDevice(l3->GetNetDevice(i));
            socket->Bind(InetSocketAddress(iface.GetBroadcast(), AODV_PORT));
            socket->SetAllowBroadcast(true);
            socket->SetIpRecvTtl(true);
            m_socketSubnetBroadcastAddresses.insert(std::make_pair(socket, iface));

            // Add local broadcast record to the routing table
            Ptr<NetDevice> dev =
                m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(iface.GetLocal()));
            RoutingTableEntry rt(/*dev=*/dev,
                                 /*dst=*/iface.GetBroadcast(),
                                 /*vSeqNo=*/true,
                                 /*seqNo=*/0,
                                 /*iface=*/iface,
                                 /*hops=*/1,
                                 /*nextHop=*/iface.GetBroadcast(),
                                 /*lifetime=*/Simulator::GetMaximumSimulationTime());
            m_routingTable.AddRoute(rt);
        }
    }
    else
    {
        NS_LOG_LOGIC("AODV does not work with more then one address per each interface. Ignore "
                     "added address");
    }
}

void
RoutingProtocol::NotifyRemoveAddress(uint32_t i, Ipv4InterfaceAddress address)
{
    NS_LOG_FUNCTION(this);
    Ptr<Socket> socket = FindSocketWithInterfaceAddress(address);
    if (socket)
    {
        m_routingTable.DeleteAllRoutesFromInterface(address);
        socket->Close();
        m_socketAddresses.erase(socket);

        Ptr<Socket> unicastSocket = FindSubnetBroadcastSocketWithInterfaceAddress(address);
        if (unicastSocket)
        {
            unicastSocket->Close();
            m_socketAddresses.erase(unicastSocket);
        }

        Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol>();
        if (l3->GetNAddresses(i))
        {
            Ipv4InterfaceAddress iface = l3->GetAddress(i, 0);
            // Create a socket to listen only on this interface
            Ptr<Socket> socket =
                Socket::CreateSocket(GetObject<Node>(), UdpSocketFactory::GetTypeId());
            NS_ASSERT(socket);
            socket->SetRecvCallback(MakeCallback(&RoutingProtocol::RecvAodv, this));
            // Bind to any IP address so that broadcasts can be received
            socket->BindToNetDevice(l3->GetNetDevice(i));
            socket->Bind(InetSocketAddress(iface.GetLocal(), AODV_PORT));
            socket->SetAllowBroadcast(true);
            socket->SetIpRecvTtl(true);
            m_socketAddresses.insert(std::make_pair(socket, iface));

            // create also a unicast socket
            socket = Socket::CreateSocket(GetObject<Node>(), UdpSocketFactory::GetTypeId());
            NS_ASSERT(socket);
            socket->SetRecvCallback(MakeCallback(&RoutingProtocol::RecvAodv, this));
            socket->BindToNetDevice(l3->GetNetDevice(i));
            socket->Bind(InetSocketAddress(iface.GetBroadcast(), AODV_PORT));
            socket->SetAllowBroadcast(true);
            socket->SetIpRecvTtl(true);
            m_socketSubnetBroadcastAddresses.insert(std::make_pair(socket, iface));

            // Add local broadcast record to the routing table
            Ptr<NetDevice> dev =
                m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(iface.GetLocal()));
            RoutingTableEntry rt(/*dev=*/dev,
                                 /*dst=*/iface.GetBroadcast(),
                                 /*vSeqNo=*/true,
                                 /*seqNo=*/0,
                                 /*iface=*/iface,
                                 /*hops=*/1,
                                 /*nextHop=*/iface.GetBroadcast(),
                                 /*lifetime=*/Simulator::GetMaximumSimulationTime());
            m_routingTable.AddRoute(rt);
        }
        if (m_socketAddresses.empty())
        {
            NS_LOG_LOGIC("No aodv interfaces");
            m_htimer.Cancel();
            m_nb.Clear();
            m_routingTable.Clear();
            return;
        }
    }
    else
    {
        NS_LOG_LOGIC("Remove address not participating in AODV operation");
    }
}

bool
RoutingProtocol::IsMyOwnAddress(Ipv4Address src)
{
    NS_LOG_FUNCTION(this << src);
    for (auto j = m_socketAddresses.begin(); j != m_socketAddresses.end(); ++j)
    {
        Ipv4InterfaceAddress iface = j->second;
        if (src == iface.GetLocal())
        {
            return true;
        }
    }
    return false;
}

Ptr<Ipv4Route>
RoutingProtocol::LoopbackRoute(const Ipv4Header& hdr, Ptr<NetDevice> oif) const
{
    NS_LOG_FUNCTION(this << hdr);
    NS_ASSERT(m_lo);
    Ptr<Ipv4Route> rt = Create<Ipv4Route>();
    rt->SetDestination(hdr.GetDestination());
    //
    // Source address selection here is tricky.  The loopback route is
    // returned when AODV does not have a route; this causes the packet
    // to be looped back and handled (cached) in RouteInput() method
    // while a route is found. However, connection-oriented protocols
    // like TCP need to create an endpoint four-tuple (src, src port,
    // dst, dst port) and create a pseudo-header for checksumming.  So,
    // AODV needs to guess correctly what the eventual source address
    // will be.
    //
    // For single interface, single address nodes, this is not a problem.
    // When there are possibly multiple outgoing interfaces, the policy
    // implemented here is to pick the first available AODV interface.
    // If RouteOutput() caller specified an outgoing interface, that
    // further constrains the selection of source address
    //
    auto j = m_socketAddresses.begin();
    if (oif)
    {
        // Iterate to find an address on the oif device
        for (j = m_socketAddresses.begin(); j != m_socketAddresses.end(); ++j)
        {
            Ipv4Address addr = j->second.GetLocal();
            int32_t interface = m_ipv4->GetInterfaceForAddress(addr);
            if (oif == m_ipv4->GetNetDevice(static_cast<uint32_t>(interface)))
            {
                rt->SetSource(addr);
                break;
            }
        }
    }
    else
    {
        rt->SetSource(j->second.GetLocal());
    }
    NS_ASSERT_MSG(rt->GetSource() != Ipv4Address(), "Valid AODV source address not found");
    rt->SetGateway(Ipv4Address("127.0.0.1"));
    rt->SetOutputDevice(m_lo);
    return rt;
}

void
RoutingProtocol::SendRequest(Ipv4Address dst)
{
    NS_LOG_FUNCTION(this << dst);

    // A node SHOULD NOT originate more than RREQ_RATELIMIT RREQ messages per second.
    if (m_rreqCount == m_rreqRateLimit)
    {
        Simulator::Schedule(m_rreqRateLimitTimer.GetDelayLeft() + MicroSeconds(100),
                            &RoutingProtocol::SendRequest,
                            this,
                            dst);
        return;
    }
    else
    {
        m_rreqCount++;
    }
    // Create RREQ header
    RreqHeader rreqHeader;
    rreqHeader.SetDst(dst);

    RoutingTableEntry rt;
    // Using the Hop field in Routing Table to manage the expanding ring search
    uint16_t ttl = m_ttlStart;
    if (m_routingTable.LookupRoute(dst, rt))
    {
        if (rt.GetFlag() != IN_SEARCH)
        {
            ttl = std::min<uint16_t>(rt.GetHop() + m_ttlIncrement, m_netDiameter);
        }
        else
        {
            ttl = rt.GetHop() + m_ttlIncrement;
            if (ttl > m_ttlThreshold)
            {
                ttl = m_netDiameter;
            }
        }
        if (ttl == m_netDiameter)
        {
            rt.IncrementRreqCnt();
        }
        if (rt.GetValidSeqNo())
        {
            rreqHeader.SetDstSeqno(rt.GetSeqNo());
        }
        else
        {
            rreqHeader.SetUnknownSeqno(true);
        }
        rt.SetHop(ttl);
        rt.SetFlag(IN_SEARCH);
        rt.SetLifeTime(m_pathDiscoveryTime);
        m_routingTable.Update(rt);
    }
    else
    {
        rreqHeader.SetUnknownSeqno(true);
        Ptr<NetDevice> dev = nullptr;
        RoutingTableEntry newEntry(/*dev=*/dev,
                                   /*dst=*/dst,
                                   /*vSeqNo=*/false,
                                   /*seqNo=*/0,
                                   /*iface=*/Ipv4InterfaceAddress(),
                                   /*hops=*/ttl,
                                   /*nextHop=*/Ipv4Address(),
                                   /*lifetime=*/m_pathDiscoveryTime);
        // Check if TtlStart == NetDiameter
        if (ttl == m_netDiameter)
        {
            newEntry.IncrementRreqCnt();
        }
        newEntry.SetFlag(IN_SEARCH);
        m_routingTable.AddRoute(newEntry);
    }

    if (m_gratuitousReply)
    {
        rreqHeader.SetGratuitousRrep(true);
    }
    if (m_destinationOnly)
    {
        rreqHeader.SetDestinationOnly(true);
    }

    m_seqNo++;
    rreqHeader.SetOriginSeqno(m_seqNo);
    m_requestId++;
    rreqHeader.SetId(m_requestId);

    // if(Anothorflag)
    // {
    //     Ipv4Address myIP = m_ipv4->GetAddress(1, 0).GetLocal();
    //     NS_LOG_DEBUG("（" << myIP << "）⇨（" << dst << "）検知対象ノード：,（" << exlist.back() << "）の別経路探索用のRREQを送信しようとしています。");

    //     rreqHeader.SetGratuitousRrep(true);
    //     rreqHeader.SetDestinationOnly(true);
    //     rreqHeader.SetAnotherRouteCreateFlag(true);
    //     rreqHeader.SetExcludedList(exlist);
    //     rreqHeader.SetDetectionReqID(messageId);
    // }

    // Send RREQ as subnet directed broadcast from each interface used by aodv
    for (auto j = m_socketAddresses.begin(); j != m_socketAddresses.end(); ++j)
    {
        Ptr<Socket> socket = j->first;
        Ipv4InterfaceAddress iface = j->second;

        rreqHeader.SetOrigin(iface.GetLocal());
        m_rreqIdCache.IsDuplicate(iface.GetLocal(), m_requestId);

        Ptr<Packet> packet = Create<Packet>();
        SocketIpTtlTag tag;
        tag.SetTtl(ttl);
        packet->AddPacketTag(tag);
        packet->AddHeader(rreqHeader);
        TypeHeader tHeader(AODVTYPE_RREQ);
        packet->AddHeader(tHeader);
        // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
        Ipv4Address destination;
        if (iface.GetMask() == Ipv4Mask::GetOnes())
        {
            destination = Ipv4Address("255.255.255.255");
        }
        else
        {
            destination = iface.GetBroadcast();
        }
        NS_LOG_DEBUG("Send RREQ with id " << rreqHeader.GetId() << " to socket");
        m_lastBcastTime = Simulator::Now();
        Simulator::Schedule(MilliSeconds(m_uniformRandomVariable->GetInteger(0, 10)),
                            &RoutingProtocol::SendTo,
                            this,
                            socket,
                            packet,
                            destination);
    }
    ScheduleRreqRetry(dst);
}

void
RoutingProtocol::SendTo(Ptr<Socket> socket, Ptr<Packet> packet, Ipv4Address destination)
{
    //ステップ3の認証パケット、認証応答パケット、送信停止・監視依頼メッセージの場合送信を許可する
    bool forceSend = false;

    // パケットを軽く解析
    Ptr<Packet> p = packet->Copy();
    TypeHeader tHeader;
    if (p->PeekHeader(tHeader))
    {
        uint8_t type = tHeader.Get();

        // Step3 の重要パケットは特例として送信
        if (type == AODVTYPE_AUTH ||
            type == AODVTYPE_AUTHREP ||
            type == AODVTYPE_VSR /* B が送る停止依頼もここに含める */)
        {
            forceSend = true;
            NS_LOG_DEBUG("ステップ3のメッセージの場合、送信を許可する");
        }
    }

    //ステップ3用の通信ブロック処理
    if (m_sendBlocked && !forceSend)
    {
        NS_LOG_DEBUG("SendToがブロックされました　IPアドレス： " << m_ipv4->GetObject<Node>()->GetId());
        return;
    }

    socket->SendTo(packet, 0, InetSocketAddress(destination, AODV_PORT));
}

void
RoutingProtocol::ScheduleRreqRetry(Ipv4Address dst)
{
    NS_LOG_FUNCTION(this << dst);
    if (m_addressReqTimer.find(dst) == m_addressReqTimer.end())
    {
        Timer timer(Timer::CANCEL_ON_DESTROY);
        m_addressReqTimer[dst] = timer;
    }
    m_addressReqTimer[dst].SetFunction(&RoutingProtocol::RouteRequestTimerExpire, this);
    m_addressReqTimer[dst].Cancel();
    m_addressReqTimer[dst].SetArguments(dst);
    RoutingTableEntry rt;
    m_routingTable.LookupRoute(dst, rt);
    Time retry;
    if (rt.GetHop() < m_netDiameter)
    {
        retry = 2 * m_nodeTraversalTime * (rt.GetHop() + m_timeoutBuffer);
    }
    else
    {
        NS_ABORT_MSG_UNLESS(rt.GetRreqCnt() > 0, "Unexpected value for GetRreqCount ()");
        uint16_t backoffFactor = rt.GetRreqCnt() - 1;
        NS_LOG_LOGIC("Applying binary exponential backoff factor " << backoffFactor);
        retry = m_netTraversalTime * (1 << backoffFactor);
    }
    m_addressReqTimer[dst].Schedule(retry);
    NS_LOG_LOGIC("Scheduled RREQ retry in " << retry.As(Time::S));
}

void
RoutingProtocol::RecvAodv(Ptr<Socket> socket)
{
    NS_LOG_FUNCTION(this << socket);
    Address sourceAddress;
    Ptr<Packet> packet = socket->RecvFrom(sourceAddress);
    InetSocketAddress inetSourceAddr = InetSocketAddress::ConvertFrom(sourceAddress);
    Ipv4Address sender = inetSourceAddr.GetIpv4();
    Ipv4Address receiver;

    if (m_socketAddresses.find(socket) != m_socketAddresses.end())
    {
        receiver = m_socketAddresses[socket].GetLocal();
    }
    else if (m_socketSubnetBroadcastAddresses.find(socket) !=
             m_socketSubnetBroadcastAddresses.end())
    {
        receiver = m_socketSubnetBroadcastAddresses[socket].GetLocal();
    }
    else
    {
        NS_ASSERT_MSG(false, "Received a packet from an unknown socket");
    }
    NS_LOG_DEBUG("AODV node " << this << " received a AODV packet from " << sender << " to "
                              << receiver);

    UpdateRouteToNeighbor(sender, receiver);
    TypeHeader tHeader(AODVTYPE_RREQ);
    packet->RemoveHeader(tHeader);
    if (!tHeader.IsValid())
    {
        NS_LOG_DEBUG("AODV message " << packet->GetUid() << " with unknown type received: "
                                     << tHeader.Get() << ". Drop");
        return; // drop
    }
    switch (tHeader.Get())
    {
    case AODVTYPE_RREQ: {
        RecvRequest(packet, receiver, sender);
        break;
    }
    case AODVTYPE_RREP: {
        RecvReply(packet, receiver, sender);
        break;
    }
    case AODVTYPE_RERR: {
        RecvError(packet, sender);
        break;
    }
    case AODVTYPE_RREP_ACK: {
        RecvReplyAck(sender);
        break;
    }
    case AODVTYPE_VSR: {
        RecvVerificationStart(packet, receiver, sender);
        break;
    }
    case AODVTYPE_AUTH: {
        RecvAuthPacket(packet, receiver, sender);
        break;
    }
    case AODVTYPE_AUTHREP: {
        RecvAuthReply(packet, receiver, sender);
        break;
    }
    }
}

bool
RoutingProtocol::UpdateRouteLifeTime(Ipv4Address addr, Time lifetime)
{
    NS_LOG_FUNCTION(this << addr << lifetime);
    RoutingTableEntry rt;
    if (m_routingTable.LookupRoute(addr, rt))
    {
        if (rt.GetFlag() == VALID)
        {
            NS_LOG_DEBUG("Updating VALID route");
            rt.SetRreqCnt(0);
            rt.SetLifeTime(std::max(lifetime, rt.GetLifeTime()));
            m_routingTable.Update(rt);
            return true;
        }
    }
    return false;
}

void
RoutingProtocol::UpdateRouteToNeighbor(Ipv4Address sender, Ipv4Address receiver)
{
    NS_LOG_FUNCTION(this << "sender " << sender << " receiver " << receiver);
    RoutingTableEntry toNeighbor;
    if (!m_routingTable.LookupRoute(sender, toNeighbor))
    {
        Ptr<NetDevice> dev = m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(receiver));
        RoutingTableEntry newEntry(
            /*dev=*/dev,
            /*dst=*/sender,
            /*vSeqNo=*/false,
            /*seqNo=*/0,
            /*iface=*/m_ipv4->GetAddress(m_ipv4->GetInterfaceForAddress(receiver), 0),
            /*hops=*/1,
            /*nextHop=*/sender,
            /*lifetime=*/m_activeRouteTimeout);
        m_routingTable.AddRoute(newEntry);
    }
    else
    {
        Ptr<NetDevice> dev = m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(receiver));
        if (toNeighbor.GetValidSeqNo() && (toNeighbor.GetHop() == 1) &&
            (toNeighbor.GetOutputDevice() == dev))
        {
            toNeighbor.SetLifeTime(std::max(m_activeRouteTimeout, toNeighbor.GetLifeTime()));
        }
        else
        {
            RoutingTableEntry newEntry(
                /*dev=*/dev,
                /*dst=*/sender,
                /*vSeqNo=*/false,
                /*seqNo=*/0,
                /*iface=*/m_ipv4->GetAddress(m_ipv4->GetInterfaceForAddress(receiver), 0),
                /*hops=*/1,
                /*nextHop=*/sender,
                /*lifetime=*/std::max(m_activeRouteTimeout, toNeighbor.GetLifeTime()));
            m_routingTable.Update(newEntry);
        }
    }
}

void
RoutingProtocol::RecvRequest(Ptr<Packet> p, Ipv4Address receiver, Ipv4Address src)
{
    NS_LOG_FUNCTION(this);
    NS_LOG_DEBUG("送信元アドレス：" << src << "からのRREQを　" << receiver << "　が受信");
    RreqHeader rreqHeader;
    p->RemoveHeader(rreqHeader);

    // A node ignores all RREQs received from any node in its blacklist
    RoutingTableEntry toPrev;
    if (m_routingTable.LookupRoute(src, toPrev))
    {
        if (toPrev.IsUnidirectional())
        {
            NS_LOG_DEBUG("Ignoring RREQ from node in blacklist");
            return;
        }
    }

    uint32_t id = rreqHeader.GetId();
    Ipv4Address origin = rreqHeader.GetOrigin();

    /*
     *  Node checks to determine whether it has received a RREQ with the same Originator IP Address
     * and RREQ ID. If such a RREQ has been received, the node silently discards the newly received
     * RREQ.
     */

    //同じIDのRREQを受信した場合は破棄
    if (m_rreqIdCache.IsDuplicate(origin, id))
    {
        NS_LOG_DEBUG("Ignoring RREQ due to duplicate");
        return;
    }

    uint8_t hop = rreqHeader.GetHopCount();
    if(rreqHeader.GetWHForwardFlag() == 1 || rreqHeader.GetWHForwardFlag() == 2)
    {
        NS_LOG_DEBUG("転送フラグが立っているためホップカウントをインクリメントしない");
    }
    else
    {
        NS_LOG_DEBUG("転送フラグが立っていないためホップカウントをインクリメントする");
        hop = hop + 1;
        rreqHeader.SetHopCount(hop);
    }

    //転送されたメッセージを攻撃ノードが受信した場合、メッセージを破棄
    if(rreqHeader.GetWHForwardFlag() == 3)
    {
        NS_LOG_DEBUG("転送されたHelloメッセージを受信しました: " << receiver);

        if(receiver == Ipv4Address("10.0.0.2") || receiver == Ipv4Address("10.0.0.3") ||
        receiver == Ipv4Address("10.1.2.1") || receiver == Ipv4Address("10.1.2.2"))
        {
            NS_LOG_DEBUG("転送後のメッセージを攻撃者が受信しました。" << receiver);
            return;
        }
    }

    

    /*
     *  When the reverse route is created or updated, the following actions on the route are also
     * carried out:
     *  1. the Originator Sequence Number from the RREQ is compared to the corresponding destination
     * sequence number in the route table entry and copied if greater than the existing value there
     *  2. the valid sequence number field is set to true;
     *  3. the next hop in the routing table becomes the node from which the  RREQ was received
     *  4. the hop count is copied from the Hop Count in the RREQ message;
     *  5. the Lifetime is set to be the maximum of (ExistingLifetime, MinimalLifetime), where
     *     MinimalLifetime = current time + 2*NetTraversalTime - 2*HopCount*NodeTraversalTime
     */
    //
    RoutingTableEntry toOrigin;
    if (!m_routingTable.LookupRoute(origin, toOrigin))
    {
        Ptr<NetDevice> dev = m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(receiver));
        RoutingTableEntry newEntry(
            /*dev=*/dev,
            /*dst=*/origin,
            /*vSeqNo=*/true,
            /*seqNo=*/rreqHeader.GetOriginSeqno(),
            /*iface=*/m_ipv4->GetAddress(m_ipv4->GetInterfaceForAddress(receiver), 0),
            /*hops=*/hop,
            /*nextHop=*/src,
            /*lifetime=*/Time(2 * m_netTraversalTime - 2 * hop * m_nodeTraversalTime));
        m_routingTable.AddRoute(newEntry);
    }
    else
    {
        if (toOrigin.GetValidSeqNo())
        {
            if (int32_t(rreqHeader.GetOriginSeqno()) - int32_t(toOrigin.GetSeqNo()) > 0)
            {
                toOrigin.SetSeqNo(rreqHeader.GetOriginSeqno());
            }
        }
        else
        {
            toOrigin.SetSeqNo(rreqHeader.GetOriginSeqno());
        }
        toOrigin.SetValidSeqNo(true);
        toOrigin.SetNextHop(src);
        toOrigin.SetOutputDevice(m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(receiver)));
        toOrigin.SetInterface(m_ipv4->GetAddress(m_ipv4->GetInterfaceForAddress(receiver), 0));
        toOrigin.SetHop(hop);
        toOrigin.SetLifeTime(std::max(Time(2 * m_netTraversalTime - 2 * hop * m_nodeTraversalTime),
                                      toOrigin.GetLifeTime()));
        m_routingTable.Update(toOrigin);
        // m_nb.Update (src, Time (AllowedHelloLoss * HelloInterval));
    }

    RoutingTableEntry toNeighbor;
    if (!m_routingTable.LookupRoute(src, toNeighbor))
    {
        NS_LOG_DEBUG("Neighbor:" << src << " not found in routing table. Creating an entry");
        Ptr<NetDevice> dev = m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(receiver));
        RoutingTableEntry newEntry(dev,
                                   src,
                                   false,
                                   rreqHeader.GetOriginSeqno(),
                                   m_ipv4->GetAddress(m_ipv4->GetInterfaceForAddress(receiver), 0),
                                   1,
                                   src,
                                   m_activeRouteTimeout);
        m_routingTable.AddRoute(newEntry);
    }
    else
    {
        toNeighbor.SetLifeTime(m_activeRouteTimeout);
        toNeighbor.SetValidSeqNo(false);
        toNeighbor.SetSeqNo(rreqHeader.GetOriginSeqno());
        toNeighbor.SetFlag(VALID);
        toNeighbor.SetOutputDevice(m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(receiver)));
        toNeighbor.SetInterface(m_ipv4->GetAddress(m_ipv4->GetInterfaceForAddress(receiver), 0));
        toNeighbor.SetHop(1);
        toNeighbor.SetNextHop(src);
        m_routingTable.Update(toNeighbor);
    }
    m_nb.Update(src, Time(m_allowedHelloLoss * m_helloInterval));

    NS_LOG_LOGIC(receiver << " receive RREQ with hop count "
                          << static_cast<uint32_t>(rreqHeader.GetHopCount()) << " ID "
                          << rreqHeader.GetId() << " to destination " << rreqHeader.GetDst());

    // //別経路作成用のRREQを受信した場合、(1)検知対象ノードもしくは、その隣接ノードがメッセージを受信した場合，メッセージを破棄
    // if(rreqHeader.GetAnotherRouteCreateFlag())
    // {
    //     //排除ノードリスト
    //     std::vector<Ipv4Address> excludedList = rreqHeader.GetExcludedList();
    //     for (auto addr : excludedList)
    //     {
    //         if (addr == receiver)
    //         {
    //             NS_LOG_DEBUG("別経路RREQドロップ: ノード(" << receiver
    //                         << ") は検知対象またはその隣接ノード（ExcludedList内）");
    //             return; // パケットを破棄して終了
    //         }
    //     }
    // }

    //  A node generates a RREP if either:
    //  (i)  it is itself the destination,
    if (IsMyOwnAddress(rreqHeader.GetDst()))
    {
        m_routingTable.LookupRoute(origin, toOrigin);
        NS_LOG_DEBUG("Send reply since I am the destination  ホップ数：" << rreqHeader.GetHopCount());
        SendReply(rreqHeader, toOrigin);
        return;
    }
    /*
     * (ii) or it has an active route to the destination, the destination sequence number in the
     * node's existing route table entry for the destination is valid and greater than or equal to
     * the Destination Sequence Number of the RREQ, and the "destination only" flag is NOT set.
     */
    RoutingTableEntry toDst;
    Ipv4Address dst = rreqHeader.GetDst();
    if (m_routingTable.LookupRoute(dst, toDst))
    {
        /*
         * Drop RREQ, This node RREP will make a loop.
         */
        if (toDst.GetNextHop() == src)
        {
            NS_LOG_DEBUG("Drop RREQ from " << src << ", dest next hop " << toDst.GetNextHop());
            return;
        }
        /*
         * The Destination Sequence number for the requested destination is set to the maximum of
         * the corresponding value received in the RREQ message, and the destination sequence value
         * currently maintained by the node for the requested destination. However, the forwarding
         * node MUST NOT modify its maintained value for the destination sequence number, even if
         * the value received in the incoming RREQ is larger than the value currently maintained by
         * the forwarding node.
         */
        if ((rreqHeader.GetUnknownSeqno() ||
             (int32_t(toDst.GetSeqNo()) - int32_t(rreqHeader.GetDstSeqno()) >= 0)) &&
            toDst.GetValidSeqNo())
        {
            NS_LOG_DEBUG("Send reply by intermediate node ホップ数："<< rreqHeader.GetHopCount());
            // 中継ノードがRREPを送信
            if (!rreqHeader.GetDestinationOnly() && toDst.GetFlag() == VALID)
            {
                m_routingTable.LookupRoute(origin, toOrigin);
                SendReplyByIntermediateNode(toDst, toOrigin, rreqHeader.GetGratuitousRrep());
                //return;
            }
            rreqHeader.SetDstSeqno(toDst.GetSeqNo());
            rreqHeader.SetUnknownSeqno(false);
        }
    }

    SocketIpTtlTag tag;
    p->RemovePacketTag(tag);
    if (tag.GetTtl() < 2)
    {
        NS_LOG_DEBUG("TTL exceeded. Drop RREQ origin " << src << " destination " << dst);
        return;
    }

    //入口側のWHノード受信処理
    if(receiver == Ipv4Address("10.0.0.2") || receiver == Ipv4Address("10.0.0.3"))
    {
        //相方のIPアドレスを設定し、転送フラグを立てる
        Ipv4Address partner;
        if(receiver == Ipv4Address("10.0.0.2"))
        {
            partner = Ipv4Address("10.1.2.2");
            rreqHeader.SetWHForwardFlag(1);

        }else if(receiver == Ipv4Address("10.0.0.3"))
        {
            partner = Ipv4Address("10.1.2.1");
            rreqHeader.SetWHForwardFlag(2);
        }

       //相方にRREQを転送
        NS_LOG_DEBUG("WHノード" << receiver <<"が受信したRREQを相方" << partner << "に転送");
 
        //相方までのルートを取得
        RoutingTableEntry toPartner;
        if(!m_routingTable.LookupRoute(partner, toPartner))
        {
            NS_LOG_DEBUG("相方ノード" << partner << "までのルートが存在しないため転送できません");
            return;
        }else
        {
            NS_LOG_DEBUG("相方ノード" << partner << "までのルートを取得しました");
        }

        Ptr<Packet> packet = Create<Packet>();
        SocketIpTtlTag ttl;
        ttl.SetTtl(tag.GetTtl() - 1);
        packet->AddPacketTag(ttl);
        packet->AddHeader(rreqHeader);
        TypeHeader tHeader(AODVTYPE_RREQ);
        packet->AddHeader(tHeader);
        Ptr<Socket> socket = FindSocketWithInterfaceAddress(toPartner.GetInterface());
        NS_ASSERT(socket);
        socket->SendTo(packet, 0, InetSocketAddress(toPartner.GetNextHop(), AODV_PORT));
        return;
    }

    //出口側の受信処理
    if (rreqHeader.GetWHForwardFlag() == 1 || rreqHeader.GetWHForwardFlag() == 2)
    {
        if(rreqHeader.GetWHForwardFlag() == 1)
        {
            NS_LOG_DEBUG("WH転送フラグ1付きのRREQを受信しました。");

            if(receiver == Ipv4Address("10.1.2.2"))
            {
                NS_LOG_DEBUG("相方ノードに到達しました: " << receiver);
            }else{
                NS_LOG_DEBUG("相方ノード以外がRREQを受信しました: " << receiver);
                return;
            }
        }else{
            NS_LOG_DEBUG("WH転送フラグ2付きのRREQを受信しました。");

            if(receiver == Ipv4Address("10.1.2.1"))
            {
                NS_LOG_DEBUG("相方ノードに到達しました: " << receiver);
            }else{
                NS_LOG_DEBUG("相方ノード以外がRREQを受信しました: " << receiver);
                return;
            }
        }

        rreqHeader.SetWHForwardFlag(3); //転送完了フラグを立てる
    }
    

    

    //受信したノードのIPアドレスが攻撃ノードの場合、RREQフラグを立てて相方に転送
    // if(receiver == Ipv4Address("10.0.0.2"))
    // {
    //     rreqHeader.SetAttackRreq(true);
    //     NS_LOG_DEBUG("Attack RREQ flag set by " << receiver);

    //     Ptr<Packet> packet = Create<Packet>();
    //     SocketIpTtlTag tag;
    //     tag.SetTtl(toOrigin.GetHop());
    //     packet->AddPacketTag(tag);
    //     packet->AddHeader(rrepHeader);
    //     TypeHeader tHeader(AODVTYPE_RREP);
    //     packet->AddHeader(tHeader);
    //     Ptr<Socket> socket = FindSocketWithInterfaceAddress(toOrigin.GetInterface());
    //     NS_ASSERT(socket);
    //     socket->SendTo(packet, 0, InetSocketAddress(toOrigin.GetNextHop(), AODV_PORT));
    // }

    for (auto j = m_socketAddresses.begin(); j != m_socketAddresses.end(); ++j)
    {
        Ptr<Socket> socket = j->first;
        Ipv4InterfaceAddress iface = j->second;
        Ptr<Packet> packet = Create<Packet>();
        SocketIpTtlTag ttl;
        ttl.SetTtl(tag.GetTtl() - 1);
        packet->AddPacketTag(ttl);
        packet->AddHeader(rreqHeader);
        TypeHeader tHeader(AODVTYPE_RREQ);
        packet->AddHeader(tHeader);
        // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
        Ipv4Address destination;
        if (iface.GetMask() == Ipv4Mask::GetOnes())
        {
            destination = Ipv4Address("255.255.255.255");
        }
        else
        {
            destination = iface.GetBroadcast();
        }
        m_lastBcastTime = Simulator::Now();
        Simulator::Schedule(MilliSeconds(m_uniformRandomVariable->GetInteger(0, 10)),
                            &RoutingProtocol::SendTo,
                            this,
                            socket,
                            packet,
                            destination);
    }
}

void
RoutingProtocol::SendReply(const RreqHeader& rreqHeader, const RoutingTableEntry& toOrigin)
{
    NS_LOG_FUNCTION(this << toOrigin.GetDestination());
    /*
     * Destination node MUST increment its own sequence number by one if the sequence number in the
     * RREQ packet is equal to that incremented value. Otherwise, the destination does not change
     * its sequence number before generating the  RREP message.
     */
    if (!rreqHeader.GetUnknownSeqno() && (rreqHeader.GetDstSeqno() == m_seqNo + 1))
    {
        m_seqNo++;
    }
    RrepHeader rrepHeader(/*prefixSize=*/0,
                          /*hopCount=*/0,
                          /*dst=*/rreqHeader.GetDst(),
                          /*dstSeqNo=*/m_seqNo,
                          /*origin=*/toOrigin.GetDestination(),
                          /*lifetime=*/m_myRouteTimeout);

    // //別経路作成用のフラグが立っている場合、RREPにもフラグを立てる
    // if(rreqHeader.GetAnotherRouteCreateFlag())
    // {
    //     rrepHeader.SetAnotherRouteCreateFlag(true);
    //     rrepHeader.SetDetectionReqID(rreqHeader.GetDetectionReqID());
    // }
    
    Ptr<Packet> packet = Create<Packet>();
    SocketIpTtlTag tag;
    tag.SetTtl(toOrigin.GetHop());
    packet->AddPacketTag(tag);
    packet->AddHeader(rrepHeader);
    TypeHeader tHeader(AODVTYPE_RREP);
    packet->AddHeader(tHeader);
    Ptr<Socket> socket = FindSocketWithInterfaceAddress(toOrigin.GetInterface());
    NS_ASSERT(socket);
    socket->SendTo(packet, 0, InetSocketAddress(toOrigin.GetNextHop(), AODV_PORT));
}

void
RoutingProtocol::SendReplyByIntermediateNode(RoutingTableEntry& toDst,
                                             RoutingTableEntry& toOrigin,
                                             bool gratRep)
{
    NS_LOG_FUNCTION(this);
    RrepHeader rrepHeader(/*prefixSize=*/0,
                          /*hopCount=*/toDst.GetHop(),
                          /*dst=*/toDst.GetDestination(),
                          /*dstSeqNo=*/toDst.GetSeqNo(),
                          /*origin=*/toOrigin.GetDestination(),
                          /*lifetime=*/toDst.GetLifeTime());
    /* If the node we received a RREQ for is a neighbor we are
     * probably facing a unidirectional link... Better request a RREP-ack
     */
    if (toDst.GetHop() == 1)
    {
        rrepHeader.SetAckRequired(true);
        RoutingTableEntry toNextHop;
        m_routingTable.LookupRoute(toOrigin.GetNextHop(), toNextHop);
        toNextHop.m_ackTimer.SetFunction(&RoutingProtocol::AckTimerExpire, this);
        toNextHop.m_ackTimer.SetArguments(toNextHop.GetDestination(), m_blackListTimeout);
        toNextHop.m_ackTimer.SetDelay(m_nextHopWait);
    }
    toDst.InsertPrecursor(toOrigin.GetNextHop());
    toOrigin.InsertPrecursor(toDst.GetNextHop());
    m_routingTable.Update(toDst);
    m_routingTable.Update(toOrigin);

    Ptr<Packet> packet = Create<Packet>();
    SocketIpTtlTag tag;
    tag.SetTtl(toOrigin.GetHop());
    packet->AddPacketTag(tag);
    packet->AddHeader(rrepHeader);
    TypeHeader tHeader(AODVTYPE_RREP);
    packet->AddHeader(tHeader);
    Ptr<Socket> socket = FindSocketWithInterfaceAddress(toOrigin.GetInterface());
    NS_ASSERT(socket);
    socket->SendTo(packet, 0, InetSocketAddress(toOrigin.GetNextHop(), AODV_PORT));

    // Generating gratuitous RREPs
    if (gratRep)
    {
        RrepHeader gratRepHeader(/*prefixSize=*/0,
                                 /*hopCount=*/toOrigin.GetHop(),
                                 /*dst=*/toOrigin.GetDestination(),
                                 /*dstSeqNo=*/toOrigin.GetSeqNo(),
                                 /*origin=*/toDst.GetDestination(),
                                 /*lifetime=*/toOrigin.GetLifeTime());
        Ptr<Packet> packetToDst = Create<Packet>();
        SocketIpTtlTag gratTag;
        gratTag.SetTtl(toDst.GetHop());
        packetToDst->AddPacketTag(gratTag);
        packetToDst->AddHeader(gratRepHeader);
        TypeHeader type(AODVTYPE_RREP);
        packetToDst->AddHeader(type);
        Ptr<Socket> socket = FindSocketWithInterfaceAddress(toDst.GetInterface());
        NS_ASSERT(socket);
        NS_LOG_LOGIC("Send gratuitous RREP " << packet->GetUid());
        socket->SendTo(packetToDst, 0, InetSocketAddress(toDst.GetNextHop(), AODV_PORT));
    }
}

void
RoutingProtocol::SendReplyAck(Ipv4Address neighbor)
{
    NS_LOG_FUNCTION(this << " to " << neighbor);
    RrepAckHeader h;
    TypeHeader typeHeader(AODVTYPE_RREP_ACK);
    Ptr<Packet> packet = Create<Packet>();
    SocketIpTtlTag tag;
    tag.SetTtl(1);
    packet->AddPacketTag(tag);
    packet->AddHeader(h);
    packet->AddHeader(typeHeader);
    RoutingTableEntry toNeighbor;
    m_routingTable.LookupRoute(neighbor, toNeighbor);
    Ptr<Socket> socket = FindSocketWithInterfaceAddress(toNeighbor.GetInterface());
    NS_ASSERT(socket);
    socket->SendTo(packet, 0, InetSocketAddress(neighbor, AODV_PORT));
}

void
RoutingProtocol::RecvReply(Ptr<Packet> p, Ipv4Address receiver, Ipv4Address sender)
{
    NS_LOG_FUNCTION(this << " src " << sender);
    RrepHeader rrepHeader;
    p->RemoveHeader(rrepHeader);
    Ipv4Address dst = rrepHeader.GetDst();
    NS_LOG_LOGIC("RREP destination " << dst << " RREP origin " << rrepHeader.GetOrigin());

    uint8_t hop = rrepHeader.GetHopCount();
    // Increment RREQ hop count
    if(rrepHeader.GetWHForwardFlag() == 1 || rrepHeader.GetWHForwardFlag() == 2)
    {
        NS_LOG_DEBUG("転送フラグが立っているためホップカウントをインクリメントしない");
    }
    else
    {
        NS_LOG_DEBUG("転送フラグが立っていないためホップカウントをインクリメントする");
        hop = hop + 1;
        rrepHeader.SetHopCount(hop);
    }

    //転送されたメッセージを攻撃ノードが受信した場合、メッセージを破棄
    if(rrepHeader.GetWHForwardFlag() == 3)
    {
        NS_LOG_DEBUG("転送されたRREPを受信しました: " << receiver);
        
        if(receiver == Ipv4Address("10.0.0.2") || receiver == Ipv4Address("10.0.0.3") ||
        receiver == Ipv4Address("10.1.2.1") || receiver == Ipv4Address("10.1.2.2"))
        {
            NS_LOG_DEBUG("転送後のメッセージを攻撃者が受信しました。" << receiver);
            return;
        }
    }

    // If RREP is Hello message
    if (dst == rrepHeader.GetOrigin())
    {
        ProcessHello(rrepHeader, receiver);
        return;
    }

    NS_LOG_DEBUG("送信元アドレス：" << sender << "からのRREPを　" << receiver << "　が受信");

    /*
     * If the route table entry to the destination is created or updated, then the following actions
     * occur:
     * -  the route is marked as active,
     * -  the destination sequence number is marked as valid,
     * -  the next hop in the route entry is assigned to be the node from which the RREP is
     * received, which is indicated by the source IP address field in the IP header,
     * -  the hop count is set to the value of the hop count from RREP message + 1
     * -  the expiry time is set to the current time plus the value of the Lifetime in the RREP
     * message,
     * -  and the destination sequence number is the Destination Sequence Number in the RREP
     * message.
     */
    Ptr<NetDevice> dev = m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(receiver));
    RoutingTableEntry newEntry(
        /*dev=*/dev,
        /*dst=*/dst,
        /*vSeqNo=*/true,
        /*seqNo=*/rrepHeader.GetDstSeqno(),
        /*iface=*/m_ipv4->GetAddress(m_ipv4->GetInterfaceForAddress(receiver), 0),
        /*hops=*/hop,
        /*nextHop=*/sender,
        /*lifetime=*/rrepHeader.GetLifeTime());
    RoutingTableEntry toDst;

    // 既存のルートエントリが存在するかどうかを確認
    if (m_routingTable.LookupRoute(dst, toDst))
    {
        // 既存のエントリは、次の状況でのみ更新されます。
        if (
            // (i) the sequence number in the routing table is marked as invalid in route table
            // entry.
            (!toDst.GetValidSeqNo()) ||

            // (ii) the Destination Sequence Number in the RREP is greater than the node's copy of
            // the destination sequence number and the known value is valid,
            ((int32_t(rrepHeader.GetDstSeqno()) - int32_t(toDst.GetSeqNo())) > 0) ||

            // (iii) the sequence numbers are the same, but the route is marked as inactive.
            (rrepHeader.GetDstSeqno() == toDst.GetSeqNo() && toDst.GetFlag() != VALID) ||

            // (iv) the sequence numbers are the same, and the New Hop Count is smaller than the
            // hop count in route table entry.
            (rrepHeader.GetDstSeqno() == toDst.GetSeqNo() && hop < toDst.GetHop()))
        {
            m_routingTable.Update(newEntry);
        }
    }
    else
    {
        // この宛先への転送ルートがまだ存在しない場合は作成されます。
        NS_LOG_LOGIC("add new route");
        m_routingTable.AddRoute(newEntry);
    }
    // RREP-ACKメッセージを返信してRREPの受信を確認する
    if (rrepHeader.GetAckRequired())
    {
        SendReplyAck(sender);
        rrepHeader.SetAckRequired(false);
    }

    NS_LOG_LOGIC("receiver " << receiver << " origin " << rrepHeader.GetOrigin());
    if (IsMyOwnAddress(rrepHeader.GetOrigin()))
    {
        NS_LOG_DEBUG("送信元ノードにRREPが到達 " << rrepHeader.GetOrigin());
        if (toDst.GetFlag() == IN_SEARCH)
        {
            m_routingTable.Update(newEntry);
            m_addressReqTimer[dst].Cancel();
            m_addressReqTimer.erase(dst);
        }

        // //受信したRREPが別経路作成用のRREPの場合
        // if(rrepHeader.GetAnotherRouteCreateFlag())
        // {
        //     ProcessCreateAnotherRoutes(rrepHeader);
        // }

        m_routingTable.LookupRoute(dst, toDst);
        SendPacketFromQueue(dst, toDst.GetRoute());
        return;
    }

    RoutingTableEntry toOrigin;
    if (!m_routingTable.LookupRoute(rrepHeader.GetOrigin(), toOrigin) ||
        toOrigin.GetFlag() == IN_SEARCH)
    {
        NS_LOG_DEBUG("RREPの発信元へのルートがありません　" << rrepHeader.GetOrigin());
        return; // Impossible! drop.
    }
    toOrigin.SetLifeTime(std::max(m_activeRouteTimeout, toOrigin.GetLifeTime()));
    m_routingTable.Update(toOrigin);

    // Update information about precursors
    //前駆者　＝　このノードを経由して、宛先へパケットを送っている upstream ノード
    if (m_routingTable.LookupValidRoute(rrepHeader.GetDst(), toDst))
    {
        toDst.InsertPrecursor(toOrigin.GetNextHop());
        m_routingTable.Update(toDst);

        RoutingTableEntry toNextHopToDst;
        m_routingTable.LookupRoute(toDst.GetNextHop(), toNextHopToDst);
        toNextHopToDst.InsertPrecursor(toOrigin.GetNextHop());
        m_routingTable.Update(toNextHopToDst);

        toOrigin.InsertPrecursor(toDst.GetNextHop());
        m_routingTable.Update(toOrigin);

        RoutingTableEntry toNextHopToOrigin;
        m_routingTable.LookupRoute(toOrigin.GetNextHop(), toNextHopToOrigin);
        toNextHopToOrigin.InsertPrecursor(toDst.GetNextHop());
        m_routingTable.Update(toNextHopToOrigin);
    }

    SocketIpTtlTag tag;
    p->RemovePacketTag(tag);
    
    if (tag.GetTtl() < 2)
    {
        NS_LOG_DEBUG("TTL exceeded. Drop RREP destination " << dst << " origin "
                                                            << rrepHeader.GetOrigin());
        return;
    }

    //入口側のWHノード受信処理
    if (receiver == Ipv4Address("10.0.0.2") || receiver == Ipv4Address("10.0.0.3"))
    {
        //相方のIPアドレスを設定し、転送フラグを立てる
        Ipv4Address partner;
        if(receiver == Ipv4Address("10.0.0.2"))
        {
            partner = Ipv4Address("10.1.2.2");
            rrepHeader.SetWHForwardFlag(1);

        }else if(receiver == Ipv4Address("10.0.0.3"))
        {
            partner = Ipv4Address("10.1.2.1");
            rrepHeader.SetWHForwardFlag(2);
        }

        //相方までのルートを取得
        RoutingTableEntry toPartner;
        if(!m_routingTable.LookupRoute(partner, toPartner))
        {
            NS_LOG_DEBUG("相方ノード" << partner << "までのルートが存在しないため転送できません");
            return;
        }else
        {
            NS_LOG_DEBUG("相方ノード" << partner << "までのルートを取得しました");
        }

        //相方にRREPを転送
        NS_LOG_DEBUG("WHノード" << receiver <<"が受信したRREPを相方" << partner << "に転送");

        Ptr<Packet> packet = Create<Packet>();
        SocketIpTtlTag ttl;
        ttl.SetTtl(tag.GetTtl());
        packet->AddPacketTag(ttl);
        packet->AddHeader(rrepHeader);
        TypeHeader tHeader(AODVTYPE_RREP);
        packet->AddHeader(tHeader);
        Ptr<Socket> socket = FindSocketWithInterfaceAddress(toPartner.GetInterface());
        NS_ASSERT(socket);
        socket->SendTo(packet, 0, InetSocketAddress(toPartner.GetNextHop(), AODV_PORT));
        return;
    }

    //出口側の受信処理
    if (rrepHeader.GetWHForwardFlag() == 1 || rrepHeader.GetWHForwardFlag() == 2)
    {
        if(rrepHeader.GetWHForwardFlag() == 1)
        {
            NS_LOG_DEBUG("WH転送フラグ1付きのRREPを受信しました。");

            if(receiver == Ipv4Address("10.1.2.2"))
            {
                NS_LOG_DEBUG("相方ノードに到達しました: " << receiver);
            }else{
                NS_LOG_DEBUG("相方ノード以外がRREPを受信しました: " << receiver);
                return;
            }
        }else{
            NS_LOG_DEBUG("WH転送フラグ2付きのRREPを受信しました。");

            if(receiver == Ipv4Address("10.1.2.1"))
            {
                NS_LOG_DEBUG("相方ノードに到達しました: " << receiver);
            }else{
                NS_LOG_DEBUG("相方ノード以外がRREPを受信しました: " << receiver);
                return;
            }
        }

        rrepHeader.SetWHForwardFlag(3); //転送完了フラグを立てる


    }

    Ptr<Packet> packet = Create<Packet>();
    SocketIpTtlTag ttl;
    ttl.SetTtl(tag.GetTtl() - 1);
    packet->AddPacketTag(ttl);
    packet->AddHeader(rrepHeader);
    TypeHeader tHeader(AODVTYPE_RREP);
    packet->AddHeader(tHeader);
    Ptr<Socket> socket = FindSocketWithInterfaceAddress(toOrigin.GetInterface());
    NS_ASSERT(socket);
    socket->SendTo(packet, 0, InetSocketAddress(toOrigin.GetNextHop(), AODV_PORT));
}

void
RoutingProtocol::RecvReplyAck(Ipv4Address neighbor)
{
    NS_LOG_FUNCTION(this);
    RoutingTableEntry rt;
    if (m_routingTable.LookupRoute(neighbor, rt))
    {
        rt.m_ackTimer.Cancel();
        rt.SetFlag(VALID);
        m_routingTable.Update(rt);
    }
}

// void 
// RoutingProtocol::ProcessCreateAnotherRoutes(const RrepHeader rrepHeader)
// {
//     NS_LOG_FUNCTION(this);

//     Ipv4Address dst = rrepHeader.GetDst();
//     Ipv4Address origin = rrepHeader.GetOrigin();
//     uint8_t hopCount = rrepHeader.GetHopCount();
//     uint32_t messageID = rrepHeader.GetDetectionReqID();

//     NS_LOG_DEBUG("別経路RREP受信処理: origin=" << origin << " dst=" << dst 
//                  << " hop=" << static_cast<int>(hopCount));

//     // 関連する別経路要求を探索
//     bool found = false;
//     bool isSafe = false;
//     DetectionReqEntry* targetEntry = nullptr;
//     for (auto& [id, entry] : m_detectionReqCache)
//     {
//         if (id == messageID)
//         {
//             targetEntry = &entry;
//             found = true;
//             NS_LOG_DEBUG("別経路要求メッセージID：" << messageID <<"が一致しました");
//             // 対象ノードを更新
//             if (std::find(entry.exNeighborList.begin(), entry.exNeighborList.end(), dst) != entry.exNeighborList.end())
//             {
//                 //該当の隣接ノードを発見した場合
//                 entry.hopCountMap[dst] = hopCount;
//                 NS_LOG_DEBUG("更新: " << dst << " のホップ数 = " << int(hopCount));

                

//             }else{
//                 //メッセージIDが一致しているが、該当の隣接ノードが発見できない場合
//                 NS_LOG_DEBUG("メッセージID：" << messageID << "の排他的隣接ノードリストの中に該当のノード：" << dst <<"を発見できませんでした");
                
//             }
//             // ★ 全ノードのホップ数が4以下かチェック
//             isSafe = std::all_of(entry.hopCountMap.begin(),
//                                     entry.hopCountMap.end(),
//                                     [](const auto& kv) { return kv.second <= 4; });
//             break;
//         }
//     }

//     if (!found)
//     {
//         NS_LOG_DEBUG("同じメッセージIDが発見できません。" << messageID);
//         return;
//     }
    
//     if(!(hopCount <= 4))
//     {
//         NS_LOG_DEBUG("排他的隣接ノード：" << dst << "までのホップ数が4より大きいためWHと検知したメッセージを送信");
//         SendDetectionResult(targetEntry, 2, 0); //正常と判定した場合、0, WHと判定した場合1

//     }

    

//     //すべての排他的隣接ノードが4ホップ以下の場合、セーフメッセージを送信
//     if(isSafe)
//     {
//         NS_LOG_DEBUG("すべての別経路が4ホップ以内 → WH攻撃ではない");       

//         SendDetectionResult(targetEntry, 2, 1); //正常と判定した場合、0, WHと判定した場合1
//     }
// }

// //別経路要求メッセージの送信元（検知を開始舌ノード）に判定結果を送信
// void
// RoutingProtocol::SendDetectionResult(DetectionReqEntry* entry, uint8_t stepflag, uint8_t detectionflag)
// {
//     NS_LOG_FUNCTION(this);
    
//     //自身のIPアドレスを特定
//     Ipv4Address selfAddr = m_ipv4->GetAddress(1, 0).GetLocal();

//     DetectionResultHeader detectionresultheader(/*別経路要求用のID*/entry->messageId,
//                                                 /*別経路要求メッセージの送信元*/entry->origin,
//                                                 /*このメッセージの送信ノード*/selfAddr,
//                                                 /*検知対象ノード*/entry->target,
//                                                 /*ステップ 2or3を示すフラグ*/stepflag,
//                                                 /*検知結果を示すフラグ*/detectionflag
//                                                 );
    
//     //別経路要求メッセージの送信元ノードまでのルーチングテーブルを取得
//     RoutingTableEntry toOrigin;
//     if (!m_routingTable.LookupRoute(entry->origin, toOrigin))
//     {
//         NS_LOG_DEBUG("SendDetectionResult: 検知開始ノード "
//                      << entry->origin << " へのルートが存在しません");
//         return;
//     }

//     Ptr<Packet> packet = Create<Packet>();
//     SocketIpTtlTag ttl;
//     ttl.SetTtl(1);
//     packet->AddPacketTag(ttl);
//     packet->AddHeader(detectionresultheader);
//     TypeHeader tHeader(AODVTYPE_DETECTION_RESULT);
//     packet->AddHeader(tHeader);
//     Ptr<Socket> socket = FindSocketWithInterfaceAddress(toOrigin.GetInterface());
//     NS_ASSERT(socket);
//     socket->SendTo(packet, 0, InetSocketAddress(toOrigin.GetNextHop(), AODV_PORT));
//     return;
// }

// //ステップ2の判定結果メッセージを受信した場合の処理
// void
// RoutingProtocol::RecvDetectionResult(Ptr<Packet> p, Ipv4Address receiver, Ipv4Address src)
// {
//     NS_LOG_FUNCTION(this);

//     DetectionResultHeader detectionresultheader;
//     p->RemoveHeader(detectionresultheader);
//     NS_LOG_DEBUG("（" << src << "）⇨（" << receiver <<"）の結果メッセージを受信" 
//         << "メッセージID：" << detectionresultheader.GetAnotherRouteID() 
//         << "検知対象ノード：" << detectionresultheader.GetTarget()
//         << "ステップ：" << detectionresultheader.GetStepFlag()
//         << "判定結果：" << detectionresultheader.GetDetectionFlag());

//     //検知開始ノードが自身のIPアドレスと一致しない場合、メッセージを破棄
//     if(receiver != detectionresultheader.GetOrigin())
//     {
//         NS_LOG_DEBUG("受信した判定結果メッセージの判定開始ノードが自身のIPアドレスと一致しませんでした。自身のIPアドレス："<< receiver << "   メッセージのOrigin：" << detectionresultheader.GetOrigin());
//     }
    
// }

void
RoutingProtocol::ProcessHello(RrepHeader& rrepHeader, Ipv4Address receiver)
{
    NS_LOG_FUNCTION(this << "from " << rrepHeader.GetDst());
    /*
     *  Whenever a node receives a Hello message from a neighbor, the node
     * SHOULD make sure that it has an active route to the neighbor, and
     * create one if necessary.
     * 
     * ノードがネイバーから Hello メッセージを受信するたびに、ノードはネイバーへのアクティブなルートがあることを確認し、必要に応じてルートを作成する必要があります。
     */

    double rB = rrepHeader.GetNeighborRatio();

    //転送後のメッセージを攻撃者が受信した場合
    if(rrepHeader.GetWHForwardFlag() == 3)
    {
        NS_LOG_DEBUG("転送されたHelloメッセージを受信しました: " << receiver <<"送信元：" << rrepHeader.GetDst() << "隣接ノード比率："<< rB);

        if(receiver == Ipv4Address("10.0.0.2") || receiver == Ipv4Address("10.0.0.3") ||
            receiver == Ipv4Address("10.1.2.1") || receiver == Ipv4Address("10.1.2.2"))
        {
            NS_LOG_DEBUG("転送後のメッセージを攻撃者が受信しました。" << receiver);
            return;
        }
    }

    //helloメッセージを処理
    RoutingTableEntry toNeighbor;
    if (!m_routingTable.LookupRoute(rrepHeader.GetDst(), toNeighbor))
    {
        //ルーチングテーブルに存在しない場合、新規作成
        Ptr<NetDevice> dev = m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(receiver));
        RoutingTableEntry newEntry(
            /*dev=*/dev,
            /*dst=*/rrepHeader.GetDst(),
            /*vSeqNo=*/true,
            /*seqNo=*/rrepHeader.GetDstSeqno(),
            /*iface=*/m_ipv4->GetAddress(m_ipv4->GetInterfaceForAddress(receiver), 0),
            /*hops=*/1,
            /*nextHop=*/rrepHeader.GetDst(),
            /*lifetime=*/rrepHeader.GetLifeTime(),
            /*隣接ノードの隣接ノード数*/rrepHeader.GetNeighborCount());
        m_routingTable.AddRoute(newEntry);
    }
    else
    {
        toNeighbor.SetLifeTime(
            std::max(Time(m_allowedHelloLoss * m_helloInterval), toNeighbor.GetLifeTime()));
        toNeighbor.SetSeqNo(rrepHeader.GetDstSeqno());
        toNeighbor.SetValidSeqNo(true);
        toNeighbor.SetFlag(VALID);
        toNeighbor.SetOutputDevice(m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(receiver)));
        toNeighbor.SetInterface(m_ipv4->GetAddress(m_ipv4->GetInterfaceForAddress(receiver), 0));
        toNeighbor.SetHop(1);
        toNeighbor.SetNextHop(rrepHeader.GetDst());
        toNeighbor.SetNeighborCount(rrepHeader.GetNeighborCount());
        m_routingTable.Update(toNeighbor);
    }

    if (m_enableHello)
    {
        m_nb.Update(rrepHeader.GetDst(), Time(m_allowedHelloLoss * m_helloInterval));
    }


    //内部WH攻撃
    //WHノードがHelloメッセージを受信した場合、転送フラグを立てて相方に転送
    //攻撃者がAODVのアドレスでhelloメッセージを受信した場合、フラグを立てて相方に転送
    if(receiver == Ipv4Address("10.0.0.2") || receiver == Ipv4Address("10.0.0.3"))
    {
        //相方のIPアドレスを設定し、転送フラグを立てる
        Ipv4Address partner;
        if(receiver == Ipv4Address("10.0.0.2"))
        {
            partner = Ipv4Address("10.1.2.2");
            rrepHeader.SetWHForwardFlag(1);

        }else if(receiver == Ipv4Address("10.0.0.3"))
        {
            partner = Ipv4Address("10.1.2.1");
            rrepHeader.SetWHForwardFlag(2);
        }

        //相方にhelloメッセージを転送
        NS_LOG_DEBUG("WHノード" << receiver <<"が受信したHelloメッセージを相方" << partner << "に転送");

        //相方までのルートを取得
        RoutingTableEntry toPartner;
        if (!m_routingTable.LookupRoute(partner, toPartner))
        {
            //ルートが存在しない場合、メッセージをドロップ
            NS_LOG_DEBUG("パートナーへのルートがありません。メッセージをドロップします " << partner);
            return;
        }else{
            NS_LOG_DEBUG("パートナーノードへのルートが見つかりました: " << toPartner.GetDestination());
        }

        ForwardHelloToPartner(rrepHeader, toPartner);

        return;
    }

    //転送されたHelloメッセージを受信した場合、受信したノードが相方ノードかどうかを確認し、相方ノードであればメッセージを再ブロードキャスト
    if(rrepHeader.GetWHForwardFlag() == 1 || rrepHeader.GetWHForwardFlag() == 2)
    {
        if(rrepHeader.GetWHForwardFlag() == 1)
        {
            NS_LOG_DEBUG("WH転送フラグ1付きのHelloメッセージを受信しました。");

            if(receiver == Ipv4Address("10.1.2.2"))
            {
                NS_LOG_DEBUG("相方ノードに到達しました: " << receiver);
            }else{
                NS_LOG_DEBUG("相方ノード以外がHelloメッセージを受信しました: " << receiver);
                return;
            }
        }else{
            NS_LOG_DEBUG("WH転送フラグ2付きのHelloメッセージを受信しました。");

            if(receiver == Ipv4Address("10.1.2.1"))
            {
                NS_LOG_DEBUG("相方ノードに到達しました: " << receiver);
            }else{
                NS_LOG_DEBUG("相方ノード以外がHelloメッセージを受信しました: " << receiver);
                return;
            }
        }

        rrepHeader.SetWHForwardFlag(3); //転送完了フラグを立てる

        //転送先で再ブロードキャスト
        for (auto j = m_socketAddresses.begin(); j != m_socketAddresses.end(); ++j)
        {
            Ptr<Socket> socket = j->first;
            Ipv4InterfaceAddress iface = j->second;
            Ptr<Packet> packet = Create<Packet>();
            SocketIpTtlTag ttl;
            ttl.SetTtl(1);
            packet->AddPacketTag(ttl);
            packet->AddHeader(rrepHeader);
            TypeHeader tHeader(AODVTYPE_RREP);
            packet->AddHeader(tHeader);
            // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
            Ipv4Address destination;
            if (iface.GetMask() == Ipv4Mask::GetOnes())
            {
                destination = Ipv4Address("255.255.255.255");
            }else
            {
                destination = iface.GetBroadcast();
            }

            Time jitter = MilliSeconds(m_uniformRandomVariable->GetInteger(0, 10));
            Simulator::Schedule(jitter, &RoutingProtocol::SendTo, this, socket, packet, destination);
        }
        return;
    }

    if(rrepHeader.GetWHForwardFlag() == 0)
    {
    NS_LOG_DEBUG("転送されずにhelloメッセージを受信しました。受診者：" << receiver <<"　送信者：" << rrepHeader.GetDst() << "隣接ノード閾値：" << rB);
    }

    if(rrepHeader.GetWHForwardFlag() == 3)
    {
        NS_LOG_DEBUG("転送されたhelloメッセージを受信しました。受診者：" << receiver <<"　送信者：" << rrepHeader.GetDst() << "隣接ノード閾値：" << rB);
    }
    // =========================================================
    // ここから CREDND ステップ2 用の処理
    // A: receiver (このノード), B: rrepHeader.GetDst()
    // =========================================================

    //自身の隣接ノードリストを取得
    std::set<Ipv4Address> neighborList; //自身の隣接ノードリスト

    for (auto it = m_routingTable.m_ipv4AddressEntry.begin();
    it != m_routingTable.m_ipv4AddressEntry.end(); ++it)
    {
        const RoutingTableEntry& e = it->second;
        if (e.GetHop() == 1 && e.GetFlag() == VALID && e.GetNextHop() != Ipv4Address("127.0.0.1") && e.GetNextHop() != Ipv4Address("10.255.255.255"))
        {
            NS_LOG_UNCOND("隣接ノードのIPアドレス: " << e.GetDestination());
            neighborList.insert(e.GetDestination());
        }
    }

    // ========== 1. 自分(A) の Neighbor Set に sender を追加 ==========

    Ipv4Address myaddr = m_ipv4->GetAddress(1, 0).GetLocal();

    // グラフに自分(A)のエントリがない場合は作成
    if (m_localGraph.find(myaddr) == m_localGraph.end())
    {
        m_localGraph[myaddr] = neighborList;
    }
    else{
        //自身の隣接ノードリストを更新
        m_localGraph[myaddr].clear();
        m_localGraph[myaddr] = neighborList; // = m_nb.GetNeighbors()
    }

    // ----- NB: B の 1-hop 隣接集合（Hello に含まれる neighborList） -----
    std::vector<Ipv4Address> targetNeighborVec = rrepHeader.GetNeighborList();
    std::set<Ipv4Address> NB(targetNeighborVec.begin(), targetNeighborVec.end());

    Ipv4Address helloSender = rrepHeader.GetDst();

    if(m_localGraph.find(helloSender) == m_localGraph.end())
    {
        m_localGraph[helloSender] = NB;
    }else{
        //自身の隣接ノードリストを更新
        m_localGraph[helloSender].clear();
        m_localGraph[helloSender] = NB;
    }

    // sender を自分(A)の隣接リストに追加
    if (std::find(m_localGraph[myaddr].begin(),
                m_localGraph[myaddr].end(),
                helloSender) == m_localGraph[myaddr].end())
    {
        m_localGraph[myaddr].insert(helloSender);
    }

    //受信したhelloパケットの隣接ノード比率が閾値を上回る場合、WH攻撃検知を開始
    if(rB > m_whNeighborThreshold)
    {
        NS_LOG_DEBUG("受信したHelloメッセージの隣接ノード数が閾値を上回りました。WH攻撃検知を開始します。 ノード: " << receiver << "判定対象" << rrepHeader.GetDst()
                        << "隣接ノード比率" << rB);
        
        //排他的隣接ノードリストと共通隣接ノードリストを作成
        std::set<Ipv4Address> exclusiveNeighbors;   //排他的隣接ノードリスト
        std::set<Ipv4Address> commonNeighbors;
        std::vector<Ipv4Address> targetNeighborList = rrepHeader.GetNeighborList(); //検知対象ノードの隣接ノードリスト

        //排他的隣接ノードリストと共通隣接ノードリストを作成
        for (const auto& n : m_localGraph[myaddr])
        {
            // B 自身は EA から除外
            if (n == helloSender)
            {
                continue;
            }
            // NB に含まれていないノードのみ EA に入れる
            if (NB.find(n) == NB.end())
            {
                NS_LOG_DEBUG("判定開始ノード：" << myaddr << "　判定対象ノード：" << helloSender <<
                             "の排他的隣接ノードを追加: " << n);
                exclusiveNeighbors.insert(n);
            }else{
                NS_LOG_DEBUG("判定開始ノード：" << myaddr << "　判定対象ノード：" << helloSender <<
                             "　の共通隣接ノードを追加：" << n);

                commonNeighbors.insert(n);
            }
        }

        // 排他的隣接ノード数が１以下の場合、例外処理を実行
        if (exclusiveNeighbors.size() < 2)
        {
            NS_LOG_DEBUG("排他的隣接ノード数が 2 未満のため、しきい値ベースの検知を開始"
                            << " eA = " << exclusiveNeighbors.size());

            double myNeighborCount = static_cast<double>(neighborList.size());
            double sumNeighborCount = 0.0;  //Aの隣接ノードの隣接ノード数
            uint32_t validNeighborNum = 0;  //Aの隣接ノード数

            for (const auto &n : neighborList)
            {
                RoutingTableEntry nEntry;
                if (m_routingTable.LookupRoute(n, nEntry))
                {
                    // Hello で受け取って RoutingTableEntry に保存している
                    // 「隣接ノード数」を利用する
                    sumNeighborCount += static_cast<double>(nEntry.GetNeighborCount());
                    validNeighborNum++;
                }
            }

            //Aの隣接ノード数 > 0 && Aの隣接ノードの隣接ノード数 > 0の場合、通常通り計算
            double avgNeighborCount = (validNeighborNum > 0 && sumNeighborCount > 0.0)
                                      ? (sumNeighborCount / static_cast<double>(validNeighborNum))
                                      : 0.0;
            //Aの隣接ノードの平均隣接ノード数 > 0 の場合、隣接ノードしきい値を計算
            double rA = (avgNeighborCount > 0.0)
                            ? (myNeighborCount / avgNeighborCount)
                            : 0.0;

            if(rA <= 0.0)
            {
                NS_LOG_DEBUG("判定開始ノードの隣接ノード比率が0以下でした。ステップ3に進みます。");
                StartStep3Detection(myaddr, helloSender, neighborList, NB, commonNeighbors);
            }

            // CREDND の特例ケースのしきい値 (論文では 1.5)
            const double specialRatioThreshold = 1.5;

            NS_LOG_DEBUG("特例ケース判定:"
                         << " A=" << myaddr
                         << " B=" << helloSender
                         << " rA=" << rA
                         << " rB=" << rB
                         << " Th=" << specialRatioThreshold);

            if (rA > specialRatioThreshold && rB > specialRatioThreshold)
            {
                NS_LOG_INFO("隣接比率のみの特例ケースにより、"
                            "ノード " << myaddr << " とノード " << helloSender
                            << " の間にWH攻撃が存在すると判定しました。");
                //ブラックリストに追加
                m_blacklist.insert(helloSender);
                return;

            }else{
                NS_LOG_DEBUG("特例ケース: rA または rB がしきい値以下のため、ステップ3に進みます。");
                StartStep3Detection(myaddr, helloSender, neighborList, NB, commonNeighbors);
                return;
            }
        }

        // ========== 2. sender(B) の neighbor list を保存 ==========
        //vector ⇨ set
        std::set<Ipv4Address> NList(targetNeighborList.begin(), targetNeighborList.end());
        m_localGraph[helloSender] = NList;

        //判定対象ノードの隣接ノードリストの型を変更
        std::set<Ipv4Address> st(targetNeighborList.begin(), targetNeighborList.end());

        int wormholeThreshold = 4;
        for (auto oi : exclusiveNeighbors) {
            for (auto oj : exclusiveNeighbors) {
                if (oi == oj) continue;

                //排他的隣接ノードの別経路を計算
                int hop = CalcHopCountBfs(oi, oj, st);
                NS_LOG_DEBUG("EAノード間のホップ数: oi=" << oi
                                << " oj=" << oj
                                << " hop=" << hop);

                if (hop == -1 || hop >= wormholeThreshold) {
                    NS_LOG_INFO("判定開始ノード：" << receiver << "　判定対象ノード：" << rrepHeader.GetDst() << "　がWH攻撃の影響下にある可能性があります。");
                    
                    //ブラックリストに登録
                    m_blacklist.insert(helloSender);

                    return; // wormhole confirmed
                }
            }
        }

        //ステップ3に移行
        NS_LOG_DEBUG("ステップ2では異常がありませんでした。ステップ3に移行します。");
        StartStep3Detection(myaddr, helloSender, neighborList, NB, commonNeighbors);

    }else{
        NS_LOG_DEBUG("隣接ノード比率が閾値以下のため判定不要　　隣接ノード比率"<< rB << "　　送信元ノード：" << rrepHeader.GetDst());
    }

    return;
}

// //内部WH攻撃 helloメッセージ転送のための再帰的呼び出し
// void
// RoutingProtocol::ProcessHelloAfterRoute(const RrepHeader& rrepHeader,
//                                         Ipv4Address receiver,
//                                         Ipv4Address partner)
// {
//     RoutingTableEntry toPartner;
//     if (!m_routingTable.LookupRoute(partner, toPartner))
//     {
//         NS_LOG_DEBUG("Still no route to partner after retry. Giving up.");
//         return;
//     }

//     NS_LOG_DEBUG("パートナーへのルートを確立しました。保存されたHelloメッセージを転送します。");
//     ForwardHelloToPartner(rrepHeader, toPartner);
// }

//内部WH攻撃 helloメッセージ転送関数
void
RoutingProtocol::ForwardHelloToPartner(const RrepHeader& rrepHeader,
                                       RoutingTableEntry& toPartner)
{
    RrepHeader helloForward = rrepHeader;
    helloForward.SetHopCount(0);

    Ptr<Packet> packet = Create<Packet>();
    SocketIpTtlTag tag;
    tag.SetTtl(1);
    packet->AddPacketTag(tag);
    packet->AddHeader(helloForward);
    TypeHeader tHeader(AODVTYPE_RREP);
    packet->AddHeader(tHeader);

    Ptr<Socket> socket = FindSocketWithInterfaceAddress(toPartner.GetInterface());
    NS_ASSERT(socket);
    socket->SendTo(packet, 0, InetSocketAddress(toPartner.GetNextHop(), AODV_PORT));

    NS_LOG_DEBUG("Forwarded Hello message from " << rrepHeader.GetDst()
                                                 << " to WH partner " << toPartner.GetDestination());
}

int
RoutingProtocol::CalcHopCountBfs(
    const Ipv4Address &src,
    const Ipv4Address &dst,
    const std::set<Ipv4Address> &forbidden)
{
    // キュー：pair(NodeAddress, HopCount)
    std::queue<std::pair<Ipv4Address, int>> q;

    // 訪問済み管理
    std::set<Ipv4Address> visited;

    // 初期化
    q.push(std::make_pair(src, 0));
    visited.insert(src);

    // BFS 開始
    while (!q.empty())
    {
        auto current = q.front();
        q.pop();

        Ipv4Address u = current.first;
        int dist = current.second;

        // ゴール判定
        if (u == dst)
        {
            return dist;
        }

        // ローカルグラフに存在しない場合は次へ
        if (m_localGraph.find(u) == m_localGraph.end())
        {
            continue;
        }

        // 近隣ノードへ展開
        for (const auto &v : m_localGraph[u])
        {
            // 禁止ノードは通さない（CREDND の NB）
            if (forbidden.count(v)) continue;

            // 未訪問なら追加
            if (!visited.count(v))
            {
                visited.insert(v);
                q.push(std::make_pair(v, dist + 1));
            }
        }
    }

    // 到達不能の場合
    return -1;  // unreachable
}

void
RoutingProtocol::StartStep3Detection(Ipv4Address startnode ,Ipv4Address target, const std::set<Ipv4Address> NA, const std::set<Ipv4Address> NB, const std::set<Ipv4Address> commonNeighbors)
{
    NS_LOG_FUNCTION(this);

     // 自身が送信停止中なら retry 関数へ
    if (m_sendBlocked)
    {
        NS_LOG_DEBUG("[Step3] 送信停止中のため StartStep3Detection を延期");
        
        Simulator::Schedule(Seconds(0.05),
                            &RoutingProtocol::StartStep3DetectionRetry,
                            this, startnode, target, NA, NB, commonNeighbors);

        return;
    }
        
    Ipv4Address myaddr = m_ipv4->GetAddress(1,0).GetLocal();

    NS_LOG_INFO("=== Step3 Detection Start ===");
    NS_LOG_INFO("判定開始ノード(A): " << myaddr
                << " 判定対象ノード(B): " << target);

    // -----------------------------
    // 1. 周辺ノードの送信停止と共通隣接ノードに関し依頼を行う（VerificationStart）
    // -----------------------------
    
    for(auto n : NA)
    {
        if (commonNeighbors.count(n) == 0) {

            //ステップ3処理中に送信停止になった場合
            if(m_sendBlocked)
            {
                NS_LOG_DEBUG("ステップ3処理中に送信停止になりました。");
                Simulator::Schedule(Seconds(0.05),
                                    &RoutingProtocol::StartStep3DetectionRetry,
                                    this, startnode, target, NA, NB, commonNeighbors);

                return;
            }

            //判定対象ノードにメッセージを送信する場合
            if(n == target)
            {
                NS_LOG_DEBUG("判定開始ノード：" << myaddr << " が判定対象ノード：" << n << "に送信停止依頼を行います。");
                
                //2 = 判定対象ノードに周辺ノードへ送信停止を依頼する
                SendVs(n, myaddr, target, 2);
                continue;
            }
            NS_LOG_DEBUG("判定開始ノード：" << myaddr << " が判定開始ノードの排他的隣接ノード：" << n << "に送信停止依頼を行います。");

            //0 = 監視のみ
            SendVs(n, myaddr, target, 0);  // ← 非共通ノードだけ
            continue;
        }else{
            //ステップ3処理中に送信停止になった場合
            if(m_sendBlocked)
            {
                NS_LOG_DEBUG("ステップ3処理中に送信停止になりました。");
                Simulator::Schedule(Seconds(0.05),
                                    &RoutingProtocol::StartStep3DetectionRetry,
                                    this, startnode, target, NA, NB, commonNeighbors);

                return;
            }
            
            NS_LOG_DEBUG("判定開始ノード：" << myaddr << " が共通隣接ノード：" << n << "に送信停止と監視依頼を行います。");

            //共通隣接ノードの場合、1 = 送信停止かつ監視依頼を行う
            SendVs(n, myaddr, target, 1);
            continue;
        }
    }

    //判定対象ノードへのルーチングテーブルを取得
    RoutingTableEntry toTarget;
    if (!m_routingTable.LookupRoute(target, toTarget))
    {
        NS_LOG_DEBUG("ステップ3の認証メッセージの判定対象ノード：" << target << "への経路が存在しません。");
    }

    //ステップ3処理中に送信停止になった場合
    if(m_sendBlocked)
    {
        NS_LOG_DEBUG("ステップ3処理中に送信停止になりました。");
        Simulator::Schedule(Seconds(0.05),
                            &RoutingProtocol::StartStep3DetectionRetry,
                            this, startnode, target, NA, NB, commonNeighbors);

        return;
    }

    //認証パケットを送信
    SendAuthPacket(myaddr, target, toTarget);

    return;
}

void
RoutingProtocol::StartStep3DetectionRetry(Ipv4Address A, Ipv4Address B,
                                          std::set<Ipv4Address> NA,
                                          std::set<Ipv4Address> NB,
                                          std::set<Ipv4Address> commonNeighbors)
{
    // まだ送信停止中なら少し遅らせる
    if (m_sendBlocked)
    {
        NS_LOG_DEBUG("[Step3 Retry] Node " << A
                      << " は送信停止中。再試行をスケジュール");
        
        Simulator::Schedule(Seconds(0.05),
                            &RoutingProtocol::StartStep3DetectionRetry,
                            this, A, B, NA, NB, commonNeighbors);

        return;
    }

    // 送信可能になったら Step3Detection を開始
    NS_LOG_DEBUG("[Step3 Retry] 送信可能になったため Step3Detection を開始");
    StartStep3Detection(A, B, NA, NB, commonNeighbors);
}

bool
RoutingProtocol::PromiscSniff(Ptr<NetDevice> dev,
                              Ptr<const Packet> packet,
                              uint16_t protocol,
                              const Address &src,
                              const Address &dst,
                              NetDevice::PacketType type)
{
    // 自分の IP
    Ipv4Address me = m_ipv4->GetAddress(1,0).GetLocal();

    NS_LOG_DEBUG("PromiscSniffが開始されました");

    Ptr<Packet> p = packet->Copy();        // 検知用
    Ptr<Packet> pLog = packet->Copy();     // ログ出力専用（解析に影響させない）


    // ======================================================
    // (1) AODVでなければ終了
    // ======================================================
    // L3 が IPv4 でなければ終了
    if (protocol != Ipv4L3Protocol::PROT_NUMBER)
    {
        return true;
    }

    Ipv4Header ip;
    if (!p->RemoveHeader(ip))
    {
        return true;
    }

    // トランスポートが UDP でなければ終了
    if (ip.GetProtocol() != UdpL4Protocol::PROT_NUMBER)
    {
        return true;
    }

    UdpHeader udp;
    p->RemoveHeader(udp);

    // AODV ポート宛以外なら終了
    if (udp.GetDestinationPort() != AODV_PORT)
    {
        return true;
    }

    // AODV TypeHeader を確認
    TypeHeader tHeader;
    p->PeekHeader(tHeader);

    // AUTH / AUTHREP 以外は Step3 対象外
    if (tHeader.Get() != AODVTYPE_AUTH &&
        tHeader.Get() != AODVTYPE_AUTHREP)
    {
        return true;
    }

    // ======================================================
    // (2) AUTH / AUTHREP の origin/target を読み取る
    // ======================================================
    Ipv4Address origin; // 判定開始ノード A
    Ipv4Address target; // 判定対象ノード B

    // Peek した TypeHeader を実際に消費
    p->RemoveHeader(tHeader);

    if (tHeader.Get() == AODVTYPE_AUTH)
    {
        AuthPacketHeader auth;
        p->RemoveHeader(auth);
        origin = auth.GetOrigin();
        target = auth.GetTarget();
    }
    else if (tHeader.Get() == AODVTYPE_AUTHREP)
    {
        AuthReplyHeader authRep;
        p->RemoveHeader(authRep);
        origin = authRep.GetOrigin();
        target = authRep.GetTarget();
    }

    // ======================================================
    // (3) origin/targetの組み合わせが監視対象か確認
    // ======================================================
    auto itA = m_monitorTable.find(origin);
    if (itA == m_monitorTable.end())
    {
        // この (origin,target) は監視対象外
        return true;
    }

    auto itB = itA->second.find(target);
    if (itB == itA->second.end())
    {
        return true;
    }

    auto &entry = itB->second;

    // 監視モードでなければ何もしない
    if (!entry.monitoring || !entry.isWitness)
    {
        return true;
    }

    // ======================================================
    // (4)  実際の送信者が origin/target か確認(結果を記録)
    // ======================================================
    Ipv4Address ipSender = ip.GetSource();  // 実際の送信元 IP

    if (tHeader.Get() == AODVTYPE_AUTH)
    {
        // 認証メッセージ（A→B）の監視結果
        entry.sawAuth = true;

        if (ipSender == origin)
        {
            // origin 自身が送った AUTH を観測
            entry.authSenderIsOrigin = true;   // ← Step3Entry に追加しておくと便利
            NS_LOG_DEBUG("[Step3][witness=" << me << "] AUTH を origin="
                          << origin << " から直接受信");
        }
        else
        {
            // origin 以外から AUTH が来た → 転送 or 偽装の可能性
            entry.authSenderIsOrigin = false;
            entry.sawForward = true;
            NS_LOG_DEBUG("[Step3][witness=" << me
                          << "] AUTH ヘッダは origin=" << origin
                          << " だが実際の送信者は " << ipSender
                          << " （転送/偽装の可能性）");
        }
    }
    else if (tHeader.Get() == AODVTYPE_AUTHREP)
    {
        // 認証応答メッセージ（B→A）の監視結果
        entry.sawReply = true;

        if (ipSender == target)
        {
            // target 自身が送った AUTHREP
            entry.replySenderIsTarget = true;  // ← Step3Entry に追加
            NS_LOG_DEBUG("[Step3][witness=" << me << "] AUTHREP を target="
                          << target << " から直接受信");
        }
        else
        {
            // target 以外から AUTHREP が来ている → 転送/偽装の可能性
            entry.replySenderIsTarget = false;
            entry.sawForward = true;
            NS_LOG_DEBUG("[Step3][witness=" << me
                          << "] AUTHREP ヘッダは target=" << target
                          << " だが実際の送信者は " << ipSender
                          << " （転送/偽装の可能性）");
        }

        //　判定開始ノードに判定結果を送信し、送信・監視を停止、エントリを削除
        //-1 = WH,  0 = 何も受信していない,  1 = 正常
        int8_t tag = 0;

        if (entry.sawAuth && entry.sawReply && entry.authSenderIsOrigin && entry.replySenderIsTarget)
        {
            tag = 1;        // 正常
        }
        else if (entry.sawForward || !entry.authSenderIsOrigin || !entry.replySenderIsTarget)
        {
            tag = -1;       // 転送疑い＝攻撃
        }
        else
        {
            tag = 0;        // 何も受信していない
        }

        //判定結果を送信（後ほど実装）

        // 送信停止を解除 ・エントリを削除
        entry.pauseTx = false;
        m_monitorTable[origin].erase(target);
        if (m_monitorTable[origin].empty())
        {
            m_monitorTable.erase(origin);
        }

        SendBlocked_Stop_Request();

    }

    //ログ表示用
    Ipv4Header ip2;
    if (!pLog->RemoveHeader(ip2))
    {
        return true;
    }
    uint8_t proto = ip2.GetProtocol();

    if (proto == UdpL4Protocol::PROT_NUMBER)
    {
        UdpHeader udp2;
        pLog->RemoveHeader(udp2);

        if (udp2.GetDestinationPort() == AODV_PORT)
        {
            TypeHeader t2;
            pLog->PeekHeader(t2);

            NS_LOG_INFO("PromiscSniff Log: "
                        << t2.Get()
                        << " src=" << ip2.GetSource()
                        << " dst=" << ip2.GetDestination());
        }
    }

    // // MAC アドレス表示用
    // Mac48Address macSrc = Mac48Address::ConvertFrom(src);
    // Mac48Address macDst = Mac48Address::ConvertFrom(dst);

    // Ipv4Address ipSrc = ip.GetSource();
    // Ipv4Address ipDst = ip.GetDestination();
    // uint8_t proto = ip.GetProtocol();   // TCP / UDP / ICMP / AODV(UDP)

    // // --- (2) パケットタイプ文字列化 ---
    // std::string typeStr;
    // switch (type)
    // {
    // case NetDevice::PACKET_HOST:         typeStr = "HOST(自分宛)"; break;
    // case NetDevice::PACKET_OTHERHOST:    typeStr = "OTHERHOST(他宛)"; break;
    // case NetDevice::PACKET_BROADCAST:    typeStr = "BROADCAST"; break;
    // case NetDevice::PACKET_MULTICAST:    typeStr = "MULTICAST"; break;
    // default: typeStr = "UNKNOWN"; break;
    // }

    // // --- (4) UDP（AODV）か？ ---
    // if (proto == UdpL4Protocol::PROT_NUMBER)
    // {
    //     UdpHeader udp;
    //     pLog->RemoveHeader(udp);

    //     if (udp.GetDestinationPort() == AODV_PORT)
    //     {
    //         // AODV TypeHeader を読む
    //         TypeHeader tHeader;
    //         p->PeekHeader(tHeader);

    //         std::string msg = "UNKNOWN";
    //         switch(tHeader.Get())
    //         {
    //         case AODVTYPE_RREQ:      msg = "RREQ"; break;
    //         case AODVTYPE_RREP:      msg = "RREP"; break;
    //         case AODVTYPE_RERR:      msg = "RERR"; break;
    //         case AODVTYPE_RREP_ACK:  msg = "RREP_ACK"; break;
    //         case AODVTYPE_VSR:       msg = "VSR(監視要求)"; break;
    //         case AODVTYPE_AUTH:      msg = "AUTH"; break;
    //         case AODVTYPE_AUTHREP:   msg = "AUTHREP"; break;
    //         default:                 msg = "AODV_UNKNOWN"; break;
    //         }

    //         NS_LOG_INFO("[Promisc][" << me << "] AODV受信: "
    //                     << msg
    //                     << "  srcIP=" << ipSrc
    //                     << " → dstIP=" << ipDst
    //                     << "  MACsrc=" << macSrc
    //                     << " → MACdst=" << macDst
    //                     << "  frame=" << typeStr);
    //     }
    // }
    return true;
}

//送信停止を解除してよいか確認する関数
void
RoutingProtocol::SendBlocked_Stop_Request()
{
    bool blocked = false;

    for (auto &A_pair : m_monitorTable)
    {
        for (auto &B_pair : A_pair.second)
        {
            const auto &entry = B_pair.second;
            if (entry.pauseTx)
            {
                blocked = true;
                break;
            }
        }
        if (blocked) break;
    }

    m_sendBlocked = blocked;
    
    if(blocked)
    {
        NS_LOG_DEBUG("送信停止を要求しているエントリが存在します。");
        
    }else{
        NS_LOG_DEBUG("送信停止を要求しているエントリが存在しないため、送信停止を終了します。");
    }
}

void
RoutingProtocol::SendAuthPacket(Ipv4Address origin, Ipv4Address target, const RoutingTableEntry &toTarget)
{
    NS_LOG_FUNCTION(this << origin << target);

    NS_LOG_DEBUG("判定開始ノード：" << origin << "が判定対象ノード："<< target << "へ認証メッセージを送信しようとしています。");

    AuthPacketHeader auth(origin, target);

    Ptr<Packet> packet = Create<Packet>();

    // TTL は 1 で十分（A→B だけ届けば良い）
    SocketIpTtlTag ttl;
    ttl.SetTtl(1);
    packet->AddPacketTag(ttl);

    // AuthPacketHeader を追加
    packet->AddHeader(auth);

    //TypeHeader
    TypeHeader tHeader(AODVTYPE_AUTH);
    packet->AddHeader(tHeader);

    Ptr<Socket> socket = FindSocketWithInterfaceAddress(toTarget.GetInterface());
    NS_ASSERT(socket);

    NS_LOG_INFO("SendAuthPacket: A=" << origin
                << " → B=" << target
                << " nextHop=" << toTarget.GetNextHop());

    // socket->SendTo(packet, 0, InetSocketAddress(toTarget.GetNextHop(), AODV_PORT));
    SendTo(socket, packet, toTarget.GetNextHop());
}

//ステップ3　送信停止と監視を要求するメッセージを送信
void
RoutingProtocol::SendVs(Ipv4Address dst, Ipv4Address origin, Ipv4Address target, uint8_t modeFlag)
{
    NS_LOG_FUNCTION(this << dst << origin << target << (uint32_t)modeFlag);

    // VS メッセージヘッダを構築
    VerificationStartHeader vsh(origin, target, dst);
    vsh.SetModeFlag(modeFlag);

    //宛先へのルーチングテーブルを取得
    RoutingTableEntry toDst;
    if (!m_routingTable.LookupRoute(dst, toDst))
    {
        NS_LOG_DEBUG("ステップ3のリクエストの宛先ノード：" << dst << "への経路が存在しません。");
    }

    // AODV 用ソケットから送信
    NS_LOG_INFO("SendVs: 送信先=" << dst
                << "  origin=" << origin
                << "  target=" << target
                << "  modeFlag=" << (uint32_t)modeFlag);

    Ptr<Packet> packet = Create<Packet>();
    SocketIpTtlTag tag;
    tag.SetTtl(1);
    packet->AddPacketTag(tag);
    packet->AddHeader(vsh);
    TypeHeader tHeader(AODVTYPE_VSR);
    packet->AddHeader(tHeader);
    Ptr<Socket> socket = FindSocketWithInterfaceAddress(toDst.GetInterface());
    NS_ASSERT(socket);
    // socket->SendTo(packet, 0, InetSocketAddress(toDst.GetNextHop(), AODV_PORT));
    SendTo(socket, packet, toDst.GetNextHop());
}

void
RoutingProtocol::RecvVerificationStart(Ptr<Packet> p, Ipv4Address receiver, Ipv4Address src)
{
    NS_LOG_FUNCTION(this);

    VerificationStartHeader vsh;
    p->RemoveHeader(vsh);

    Ipv4Address A = vsh.GetOrigin();   // 判定開始ノード
    Ipv4Address B = vsh.GetTarget();   // 判定対象ノード

    uint8_t flag = vsh.GetModeFlag();  // 0:停止, 1:停止+監視, 2:Bのみ通知

    if(flag == 0)
    {
        NS_LOG_DEBUG(receiver << "が送信元：" << src <<"から送信停止要求メッセージを受信しました。");
    }
    if(flag == 1)
    {
        NS_LOG_DEBUG(receiver << "が送信元：" << src <<"から送信停止・監視要求とメッセージを受信しました。");
    }
    if(flag == 2)
    {
        NS_LOG_DEBUG("判定対象ノード：" << receiver << "が送信元：" << src <<"からステップ３の依頼を受信しました。");
    }
    
    // -------------------------------
    // (1) 判定対象ノード B の場合
    // -------------------------------
    if (flag == 2 && receiver == B)
    {
        // B は AUTHREP を返すだけなので監視は不要
        auto &entry = m_monitorTable[A][B];
        entry.isTarget = true;
        entry.monitoring = false;

        NS_LOG_DEBUG("判定対象ノード："<< B << "が送信停止依頼を受信しました");

        //------------------------------------------------------------------
        // (追加処理) B の排他的隣接ノードに送信停止フラグ ModeFlag=0 を送る
        //------------------------------------------------------------------

        // B の隣接ノードリスト
        auto itB = m_localGraph.find(B);
        if (itB == m_localGraph.end())
        {
            NS_LOG_WARN("[Step3] B の隣接ノードリストが存在しません: " << B);
            return;
        }
        const auto &neighborsB = itB->second;

        auto itA = m_localGraph.find(A);
        if (itA == m_localGraph.end())
        {
            NS_LOG_WARN("[Step3] A の隣接ノードリストが存在しません: " << A);
        }
        const auto &neighborsA = itA->second;

        // B の排他的隣接ノード = neighborsB - neighborsA
        std::set<Ipv4Address> exNeighborsB;
        for (auto n : neighborsB)
        {
            if(n == A)
            {
                continue;
            }
            if (neighborsA.count(n) == 0)
            {
                exNeighborsB.insert(n);
            }
        }

        NS_LOG_DEBUG("[Step3] B=" << B << " の排他的隣接ノード数: " 
                      << exNeighborsB.size());

         // 排他的隣接ノードへ ModeFlag=0（送信停止要求）送信
        for (Ipv4Address ex : exNeighborsB)
        {
            SendVs(ex, A, B, 0);   // ModeFlag=0 = 送信停止要求
            NS_LOG_DEBUG("[Step3] B=" << B 
                          << " → 排他的隣接ノード " << ex 
                          << " へ ModeFlag=0(送信停止要請) を送信");
        }

        return;
    }

    // -------------------------------
    // (2) witness（共通隣接ノード）が監視を開始（ModeFlag=1）
    // -------------------------------
    if (flag == 1)
    {
        auto &entry = m_monitorTable[A][B];

        //送信停止
        m_sendBlocked = true;

        entry.isWitness  = true;      // 共通隣接ノード
        entry.monitoring = true;      // PromiscSniff が処理すべき
        entry.pauseTx    = true;      // Step3 中の送信停止

        entry.sawAuth    = false;
        entry.sawForward = false;
        entry.sawReply   = false;

        entry.startTime = Simulator::Now();

        NS_LOG_DEBUG("[Step3] Node " << receiver 
                      << " が witness として監視を開始（A=" 
                      << A << ", B=" << B << "）");

        if (!entry.replyWaitEvent.IsPending())
        {
            entry.replyWaitEvent = Simulator::Schedule(
                m_step3ReplyWaitTime,   // 例：0.15 秒
                &RoutingProtocol::Step3Timeout,  // ← 別関数として実装
                this,
                A,
                B
            );

            NS_LOG_DEBUG("[Step3] witness " << receiver
                        << " が Timeout を予約 (A=" << A 
                        << ", B=" << B << ")");
        }

        return;
    }

    //----------------------------------------------------
    // ModeFlag=0 : 排他的隣接ノードが送信停止（Step3）
    //----------------------------------------------------
    if (flag == 0)
    {
        NS_LOG_DEBUG("[Step3] 排他的隣接ノード " << receiver
                      << " が送信停止要求を受信 (A=" << A << ", B=" << B << ")");

        m_sendBlocked = true;

        // Step3専用のフラグとして扱う
        auto &entry = m_monitorTable[A][B];
        entry.pauseTx = true;

        // ※監視停止はしない。排他的隣接ノードは元々監視者ではない。
        return;
    }

}

void
RoutingProtocol::RecvAuthPacket(Ptr<Packet> p,
                                Ipv4Address receiver,
                                Ipv4Address sender)
{
    NS_LOG_FUNCTION(this);

    AuthPacketHeader auth;
    p->RemoveHeader(auth);

    NS_LOG_DEBUG("判定対象ノード：" << receiver << "が判定開始ノード："<< sender << "からの認証メッセージを受信しました。");

    Ipv4Address A = auth.GetOrigin(); //判定開始ノード
    Ipv4Address B = auth.GetTarget(); //判定対象ノード
    Ipv4Address myadder = m_ipv4->GetAddress(1,0).GetLocal(); //自身のIP

     // ----- (1) witness の監視 -----　共通隣接ノードが認証メッセージを受信した場合の処理（Aからメッセージを正常に送信されているか、フォワーディングされていないか）
    // if (m_monitorTable[A][B].monitoring)
    // {
    //     m_monitorTable[A][B].sawAuth = true;
    //     NS_LOG_DEBUG("Monitor(witness): saw AUTH at " << me);
    // }

    // ----- (2) B（判定対象）だけが Reply を返す -----
    if (myadder == B)
    {
        SendAuthReply(A, B);
    }
}

void
RoutingProtocol::RecvAuthReply(Ptr<Packet> p, Ipv4Address receiver, Ipv4Address sender)
{
    NS_LOG_FUNCTION(this);

    NS_LOG_DEBUG("判定開始ノード：" << receiver << "が判定対象ノード："<< sender << "からの認証返信メッセージを受信しました。");
}

void
RoutingProtocol::SendAuthReply(Ipv4Address origin, Ipv4Address target)
{
    NS_LOG_FUNCTION(this << origin << target);

    NS_LOG_DEBUG("判定対象ノード：" << target << "が判定開始ノード："<< origin << "へ認証返信メッセージを送信しようとしています。");

    // --- 1. AuthReplyHeader 作成 ---
    AuthReplyHeader rep;
    rep.SetOrigin(origin);      // 判定開始ノード
    rep.SetTarget(target);  // 判定対象ノード

    // ルーティングテーブルから A への経路を取得
    RoutingTableEntry toA;
    if (!m_routingTable.LookupRoute(origin, toA))
    {
        NS_LOG_ERROR("SendAuthReply: route to A not found: " << origin);
        return;
    }

    Ptr<Packet> packet = Create<Packet>();
    // TTL は 1 で十分（A→B だけ届けば良い）
    SocketIpTtlTag ttl;
    ttl.SetTtl(1);
    packet->AddPacketTag(ttl);

    // AuthPacketHeader を追加
    packet->AddHeader(rep);

    // まず TypeHeader
    TypeHeader tHeader(AODVTYPE_AUTHREP);
    packet->AddHeader(tHeader);

    Ptr<Socket> socket = FindSocketWithInterfaceAddress(toA.GetInterface());
    NS_ASSERT(socket);

    NS_LOG_INFO("SendAuthPacketReply: 判定開始ノード=" << origin
                << " → 判定対象ノード=" << target
                << " nextHop=" << toA.GetNextHop());

    // socket->SendTo(packet, 0, InetSocketAddress(toA.GetNextHop(), AODV_PORT));
    // ★重要：RoutingProtocol::SendTo() を使う
    SendTo(socket, packet, toA.GetNextHop());
}

void
RoutingProtocol::Step3Timeout(Ipv4Address origin, Ipv4Address target)
{
    auto itA = m_monitorTable.find(origin);
    if (itA == m_monitorTable.end()) return;

    auto itB = itA->second.find(target);
    if (itB == itA->second.end()) return;

    auto &entry = itB->second;

    if(!entry.sawReply)
    {
        if(entry.pauseTx)
        {
            NS_LOG_DEBUG("タイムアウトにより送信停止を終了します。");
        }
        if(entry.monitoring)
        {
            NS_LOG_DEBUG("タイムアウトにより監視モードを終了します。");
        }

        entry.pauseTx = false;

        itA->second.erase(target);
        if (itA->second.empty())
        {
            m_monitorTable.erase(origin);
        }

        SendBlocked_Stop_Request();
    }
}

// //WH攻撃検知用　排他的隣接ノード同士の別経路作成Requestメッセージ送信関数
// void
// RoutingProtocol::SendDetectionReq_to_ExNeighbors(const RrepHeader & rrepHeader, const Ipv4Address receiver)
// {
    
//     NS_LOG_FUNCTION(this);
//     //ここにNeighbor List Requestメッセージの生成と送信コードを追加
//     NS_LOG_DEBUG("排他的隣接ノードを作成し検知対象ノード（" << rrepHeader.GetDst() << "）へ、別経路作成用のRequestメッセージを送信します。");


//     //排他的隣接ノードリストを作成
//     std::vector<Ipv4Address> exclusiveNeighbors;   //排他的隣接ノードリスト
//     std::vector<Ipv4Address> targetNeighborList = rrepHeader.GetNeighborList(); //検知対象ノードの隣接ノードリスト

//     for (auto it = m_routingTable.m_ipv4AddressEntry.begin();
//      it != m_routingTable.m_ipv4AddressEntry.end(); ++it)
//     {
//         const RoutingTableEntry& e = it->second;
//         if (e.GetHop() == 1 && e.GetFlag() == VALID)
//         {
//             //自身の隣接ノードであり、検知対象ノードの隣接ノードではない場合、排他的隣接ノードとしてリストに追加
//             auto result = std::find(targetNeighborList.begin(), targetNeighborList.end(), e.GetDestination());
//             if(result == targetNeighborList.end())
//             {
//                 NS_LOG_DEBUG("排他的隣接ノードを追加: " << e.GetDestination());
//                 exclusiveNeighbors.push_back(e.GetDestination());
//             }
            
//         }
//     }

//     //ノードIDと排他的隣接ノードのリスト、それぞれの隣接ノードの検知結果を保存する構造体を作成

//     uint32_t myid = m_anotherRouteID++;

//     // //排他的隣接ノードに別経路を構築してもらうためのRequestメッセージを送信
//     for(auto it = exclusiveNeighbors.begin(); it != exclusiveNeighbors.end(); ++it)
//     {
//         Ipv4Address exNeighbor = *it;
//         NS_LOG_DEBUG("排他的隣接ノード" << exNeighbor << "に別経路構築用のRequestメッセージを送信します。");

//         DetectionRreqHeader DetectionRreqHeader(
//             /*別経路要求ID*/myid,
//             /*送信元アドレス*/receiver,
//             /*検知対象アドレス*/rrepHeader.GetDst(),
//             /*排他的隣接ノードリスト*/exclusiveNeighbors,
//             /*検知対象ノードの隣接ノードリスト*/targetNeighborList
//         );

//         Ptr<Packet> packet = Create<Packet>();
//         SocketIpTtlTag tag;
//         tag.SetTtl(1);
//         packet->AddPacketTag(tag);
//         packet->AddHeader(DetectionRreqHeader);
//         TypeHeader tHeader(AODVTYPE_DetectionReq);
//         packet->AddHeader(tHeader);

//         // ★ receiver(=この関数を呼んだ時にHelloを受け取った自ノードのIP)のIFで送る
//         int32_t ifIndex = m_ipv4->GetInterfaceForAddress(receiver);
//         if (ifIndex < 0)
//         {
//             NS_LOG_ERROR("No interface found for receiver=" << receiver
//                          << " at node " << m_ipv4->GetObject<Node>()->GetId());
//             continue;
//         }
//         Ipv4InterfaceAddress outIf = m_ipv4->GetAddress(static_cast<uint32_t>(ifIndex), 0);
//         Ptr<Socket> socket = FindSocketWithInterfaceAddress(outIf);

//         //Ptr<Socket> socket = FindSocketWithInterfaceAddress(m_ipv4->GetAddress(m_ipv4->GetInterfaceForAddress(exNeighbor), 0));
//         NS_ASSERT(socket);
//         socket->SendTo(packet, 0, InetSocketAddress(exNeighbor, AODV_PORT));
//     }

// }

// //別経路要求メッセージを受信した場合の処理
// void
// RoutingProtocol::RecvDetectionReq(Ptr<Packet> p, Ipv4Address receiver, Ipv4Address src)
// {
//     NS_LOG_FUNCTION(this);
//     DetectionRreqHeader detectionrq;
//     p->RemoveHeader(detectionrq);
//     NS_LOG_DEBUG("（" << src << "）⇨（" << receiver
//                  << "） 検知対象=" << detectionrq.GetTarget()
//                  << " の別経路要求(DetectionReq)を受信");
//     std::vector<Ipv4Address> excludedList = detectionrq.GetTargetNeighborList();
//     excludedList.push_back(detectionrq.GetTarget());

//     DetectionReqEntry entry;
//     entry.messageId = detectionrq.GetAnotherRouteID();
//     entry.origin = detectionrq.GetOrigin();
//     entry.exNeighborList = detectionrq.GetExneighborList();
//     entry.target = detectionrq.GetTarget();

//     // まず初期状態ではホップ数未計測（例: 255）
//     for (auto addr : entry.exNeighborList)
//     {
//         entry.hopCountMap[addr] = 255;
//     }

//     m_detectionReqCache[entry.messageId] = entry;

//     //自ノード以外の排他的隣接ノードに別経路要求メッセージを送信
//     for(auto dst : detectionrq.GetExneighborList())
//     {
//         if(dst == receiver)
//         {
//             continue;
//         }

//         NS_LOG_DEBUG("EAノード(" << receiver << ") → " << dst
//                      << " に別経路RREQを送信 (SendRequest使用)");

//         // --- 一時的に別経路RREQを構築・送信 ---
//         // SendRequest(dst, /*isAltRoute=*/true, excludedList, entry.messageId);

//     //     // RREQを設定
//     //     //メッセージヘッダを作成
//     //     RreqHeader rreqHeader;
//     //     rreqHeader.SetDstSeqno(0);
//     //     rreqHeader.SetHopCount(0);
//     //     rreqHeader.SetOrigin(receiver);
//     //     rreqHeader.SetGratuitousRrep(false);
//     //     rreqHeader.SetDestinationOnly(true);
//     //     rreqHeader.SetUnknownSeqno(true);
//     //     rreqHeader.SetAnotherRouteCreateFlag(true);
//     //     rreqHeader.SetExcludedList(excludedList);
//     //     rreqHeader.SetDst(dst);
//     //     //RREQIDを設定
//     //     rreqHeader.SetId(m_requestId++);

//     //     Ptr<Packet> packet = Create<Packet>();
//     //     SocketIpTtlTag tag;
//     //     tag.SetTtl(5);
//     //     packet->AddPacketTag(tag);
//     //     packet->AddHeader(rreqHeader);
//     //     TypeHeader tHeader(AODVTYPE_RREQ);
//     //     packet->AddHeader(tHeader);

//     //     //別経路作成用のRREQをブロードキャスト
//     //     for (auto j = m_socketAddresses.begin(); j != m_socketAddresses.end(); ++j)
//     //     {
//     //         Ptr<Socket> socket = j->first;
//     //         Ipv4InterfaceAddress iface = j->second;

//     //         rreqHeader.SetOrigin(iface.GetLocal());
//     //         Ipv4Address destination;
//     //         if (iface.GetMask() == Ipv4Mask::GetOnes())
//     //         {
//     //             destination = Ipv4Address("255.255.255.255");
//     //         }
//     //         else
//     //         {
//     //             destination = iface.GetBroadcast();
//     //         }

//     //         NS_LOG_DEBUG("別経路RREQを送信： " << iface.GetLocal()
//     //                      << " -> " << destination
//     //                      << " (宛先EA=" << dst << ") TTL=5");
            
//     //         //socket->SetIpTtl(5); // ★確実なTTL制御
            
//     //         m_lastBcastTime = Simulator::Now();
//     //         Simulator::Schedule(MilliSeconds(m_uniformRandomVariable->GetInteger(0, 10)),
//     //                         &RoutingProtocol::SendTo,
//     //                         this,
//     //                         socket,
//     //                         packet,
//     //                         destination);
//     //     }
        
//     }
// }

// //内部WH攻撃 helloメッセージ転送関数（中継ノード用）
// void
// RoutingProtocol::ForwardHelloByIntermediateNode(RrepHeader& rrepHeader)
// {
//     Ipv4Address partner;
//     if(rrepHeader.GetWHForwardFlag() == 1)
//     {
//         partner = Ipv4Address("10.0.0.3");
//     }else if(rrepHeader.GetWHForwardFlag() == 2)
//     {
//         partner = Ipv4Address("10.0.0.2");
//     }

//     //相方までのルートを取得
//     RoutingTableEntry toPartner;
//     if (!m_routingTable.LookupRoute(partner, toPartner))
//     {
//         NS_LOG_DEBUG("中継ノードがパートナーへのルートを見つけられません: " << partner);
//         return;
//     }

//     Ptr<Packet> packet = Create<Packet>();
//     SocketIpTtlTag tag;
//     tag.SetTtl(1);
//     packet->AddPacketTag(tag);
//     packet->AddHeader(rrepHeader);
//     TypeHeader tHeader(AODVTYPE_RREP);
//     packet->AddHeader(tHeader);
// }

void
RoutingProtocol::RecvError(Ptr<Packet> p, Ipv4Address src)
{
    NS_LOG_FUNCTION(this << " from " << src);
    RerrHeader rerrHeader;
    p->RemoveHeader(rerrHeader);
    std::map<Ipv4Address, uint32_t> dstWithNextHopSrc;
    std::map<Ipv4Address, uint32_t> unreachable;
    m_routingTable.GetListOfDestinationWithNextHop(src, dstWithNextHopSrc);
    std::pair<Ipv4Address, uint32_t> un;
    while (rerrHeader.RemoveUnDestination(un))
    {
        for (auto i = dstWithNextHopSrc.begin(); i != dstWithNextHopSrc.end(); ++i)
        {
            if (i->first == un.first)
            {
                unreachable.insert(un);
            }
        }
    }

    std::vector<Ipv4Address> precursors;
    for (auto i = unreachable.begin(); i != unreachable.end();)
    {
        if (!rerrHeader.AddUnDestination(i->first, i->second))
        {
            TypeHeader typeHeader(AODVTYPE_RERR);
            Ptr<Packet> packet = Create<Packet>();
            SocketIpTtlTag tag;
            tag.SetTtl(1);
            packet->AddPacketTag(tag);
            packet->AddHeader(rerrHeader);
            packet->AddHeader(typeHeader);
            SendRerrMessage(packet, precursors);
            rerrHeader.Clear();
        }
        else
        {
            RoutingTableEntry toDst;
            m_routingTable.LookupRoute(i->first, toDst);
            toDst.GetPrecursors(precursors);
            ++i;
        }
    }
    if (rerrHeader.GetDestCount() != 0)
    {
        TypeHeader typeHeader(AODVTYPE_RERR);
        Ptr<Packet> packet = Create<Packet>();
        SocketIpTtlTag tag;
        tag.SetTtl(1);
        packet->AddPacketTag(tag);
        packet->AddHeader(rerrHeader);
        packet->AddHeader(typeHeader);
        SendRerrMessage(packet, precursors);
    }
    m_routingTable.InvalidateRoutesWithDst(unreachable);
}

void
RoutingProtocol::RouteRequestTimerExpire(Ipv4Address dst)
{
    NS_LOG_LOGIC(this);
    RoutingTableEntry toDst;
    if (m_routingTable.LookupValidRoute(dst, toDst))
    {
        SendPacketFromQueue(dst, toDst.GetRoute());
        NS_LOG_LOGIC("route to " << dst << " found");
        return;
    }
    /*
     *  If a route discovery has been attempted RreqRetries times at the maximum TTL without
     *  receiving any RREP, all data packets destined for the corresponding destination SHOULD be
     *  dropped from the buffer and a Destination Unreachable message SHOULD be delivered to the
     * application.
     */
    if (toDst.GetRreqCnt() == m_rreqRetries)
    {
        NS_LOG_LOGIC("route discovery to " << dst << " has been attempted RreqRetries ("
                                           << m_rreqRetries << ") times with ttl "
                                           << m_netDiameter);
        m_addressReqTimer.erase(dst);
        m_routingTable.DeleteRoute(dst);
        NS_LOG_DEBUG("Route not found. Drop all packets with dst " << dst);
        m_queue.DropPacketWithDst(dst);
        return;
    }

    if (toDst.GetFlag() == IN_SEARCH)
    {
        NS_LOG_LOGIC("Resend RREQ to " << dst << " previous ttl " << toDst.GetHop());
        SendRequest(dst);
    }
    else
    {
        NS_LOG_DEBUG("Route down. Stop search. Drop packet with destination " << dst);
        m_addressReqTimer.erase(dst);
        m_routingTable.DeleteRoute(dst);
        m_queue.DropPacketWithDst(dst);
    }
}

void
RoutingProtocol::HelloTimerExpire()
{
    NS_LOG_FUNCTION(this);
    Time offset;
    if (m_lastBcastTime.IsStrictlyPositive())
    {
        offset = Simulator::Now() - m_lastBcastTime;
        NS_LOG_DEBUG("Hello deferred due to last bcast at:" << m_lastBcastTime);
    }
    else
    {
        SendHello();
    }
    m_htimer.Cancel();
    Time diff = m_helloInterval - offset;
    m_htimer.Schedule(std::max(Seconds(0), diff));
    m_lastBcastTime = Seconds(0);
}

void
RoutingProtocol::RreqRateLimitTimerExpire()
{
    NS_LOG_FUNCTION(this);
    m_rreqCount = 0;
    m_rreqRateLimitTimer.Schedule(Seconds(1));
}

void
RoutingProtocol::RerrRateLimitTimerExpire()
{
    NS_LOG_FUNCTION(this);
    m_rerrCount = 0;
    m_rerrRateLimitTimer.Schedule(Seconds(1));
}

void
RoutingProtocol::AckTimerExpire(Ipv4Address neighbor, Time blacklistTimeout)
{
    NS_LOG_FUNCTION(this);
    m_routingTable.MarkLinkAsUnidirectional(neighbor, blacklistTimeout);
}

void
RoutingProtocol::SendHello()
{
    NS_LOG_FUNCTION(this);
    /* Broadcast a RREP with TTL = 1 with the RREP message fields set as follows:
     *   Destination IP Address         The node's IP address.
     *   Destination Sequence Number    The node's latest sequence number.
     *   Hop Count                      0
     *   Lifetime                       AllowedHelloLoss * HelloInterval
     */

    //隣接ノード数を取得
    uint32_t neigborCount = m_nb.GetNeighborCount();
    NS_LOG_DEBUG("IPアドレス：" << m_ipv4->GetAddress(1, 0).GetLocal() << " の隣接ノード数: " << neigborCount);
    
    
    //隣接ノード数の平均隣接ノード数と、自身の隣接ノードをリストアップ
    uint32_t totalNeighborCount = 0;  //全隣接ノードの隣接ノード数の合計
    std::vector<Ipv4Address> neighborList; //自身の隣接ノードリスト

    for (auto it = m_routingTable.m_ipv4AddressEntry.begin();
     it != m_routingTable.m_ipv4AddressEntry.end(); ++it)
    {
        const RoutingTableEntry& e = it->second;
        if (e.GetHop() == 1 && e.GetFlag() == VALID && e.GetNextHop() != Ipv4Address("127.0.0.1") && e.GetNextHop() != Ipv4Address("10.255.255.255"))
        {
            NS_LOG_UNCOND("隣接ノードのIPアドレス: " << e.GetDestination() 
                          << "隣接ノードの隣接ノード数：" << e.GetNeighborCount());
            totalNeighborCount += e.GetNeighborCount();
            neighborList.push_back(e.GetDestination());
        }
    }

    uint32_t avNeighborCount = 0;
    if(totalNeighborCount > 0)
    {
        avNeighborCount = static_cast<double>(totalNeighborCount) / neigborCount;
        NS_LOG_DEBUG("総隣接ノード数：" << totalNeighborCount);
    }else{
        NS_LOG_DEBUG("総隣接ノード数が0以下です。：" << totalNeighborCount);
    }

    float neighborRatio = 0;
    if(avNeighborCount > 0)
    {
        neighborRatio = static_cast<double>(neigborCount) / avNeighborCount;
        NS_LOG_DEBUG("隣接ノードの平均隣接ノード数：" << avNeighborCount);
    }else{
        NS_LOG_DEBUG("隣接ノードの平均隣接ノード数が0以下です。：" << avNeighborCount);
    }

    NS_LOG_DEBUG("隣接ノード比率: " << neighborRatio);
    

    for (auto j = m_socketAddresses.begin(); j != m_socketAddresses.end(); ++j)
    {
        Ptr<Socket> socket = j->first;
        Ipv4InterfaceAddress iface = j->second;
        RrepHeader helloHeader(/*prefixSize=*/0,
                               /*hopCount=*/0,
                               /*dst=*/iface.GetLocal(),
                               /*dstSeqNo=*/m_seqNo,
                               /*origin=*/iface.GetLocal(),
                               /*lifetime=*/Time(m_allowedHelloLoss * m_helloInterval),
                               /*whForwardFlag=*/0,//通常のHelloメッセージとして設定
                                /*neighborCount=*/neigborCount,
                                /*neighborRatio=*/neighborRatio);
            
        //helloメッセージに隣接ノードリストを記載
        helloHeader.SetNeighborList(neighborList); //隣接ノードリストを設定
        
        Ptr<Packet> packet = Create<Packet>();
        SocketIpTtlTag tag;
        tag.SetTtl(1);
        packet->AddPacketTag(tag);
        packet->AddHeader(helloHeader);
        TypeHeader tHeader(AODVTYPE_RREP);
        packet->AddHeader(tHeader);
        // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
        Ipv4Address destination;
        if (iface.GetMask() == Ipv4Mask::GetOnes())
        {
            destination = Ipv4Address("255.255.255.255");
        }
        else
        {
            destination = iface.GetBroadcast();
        }
        Time jitter = MilliSeconds(m_uniformRandomVariable->GetInteger(0, 10));
        Simulator::Schedule(jitter, &RoutingProtocol::SendTo, this, socket, packet, destination);
    }
}

void
RoutingProtocol::SendPacketFromQueue(Ipv4Address dst, Ptr<Ipv4Route> route)
{
    NS_LOG_FUNCTION(this);

    //ステップ3用の通信ブロック処理
    if (m_sendBlocked)
    {
        NS_LOG_DEBUG("SendPacketFromQueueがブロックされました　IPアドレス： " << m_ipv4->GetObject<Node>()->GetId());
        return;
    }

    QueueEntry queueEntry;
    while (m_queue.Dequeue(dst, queueEntry))
    {
        DeferredRouteOutputTag tag;
        Ptr<Packet> p = ConstCast<Packet>(queueEntry.GetPacket());
        if (p->RemovePacketTag(tag) && tag.GetInterface() != -1 &&
            tag.GetInterface() != m_ipv4->GetInterfaceForDevice(route->GetOutputDevice()))
        {
            NS_LOG_DEBUG("Output device doesn't match. Dropped.");
            return;
        }
        UnicastForwardCallback ucb = queueEntry.GetUnicastForwardCallback();
        Ipv4Header header = queueEntry.GetIpv4Header();
        header.SetSource(route->GetSource());
        header.SetTtl(header.GetTtl() +
                      1); // compensate extra TTL decrement by fake loopback routing
        ucb(route, p, header);
    }
}

void
RoutingProtocol::SendRerrWhenBreaksLinkToNextHop(Ipv4Address nextHop)
{
    NS_LOG_FUNCTION(this << nextHop);
    RerrHeader rerrHeader;
    std::vector<Ipv4Address> precursors;
    std::map<Ipv4Address, uint32_t> unreachable;

    RoutingTableEntry toNextHop;
    if (!m_routingTable.LookupRoute(nextHop, toNextHop))
    {
        return;
    }
    toNextHop.GetPrecursors(precursors);
    rerrHeader.AddUnDestination(nextHop, toNextHop.GetSeqNo());
    m_routingTable.GetListOfDestinationWithNextHop(nextHop, unreachable);
    for (auto i = unreachable.begin(); i != unreachable.end();)
    {
        if (!rerrHeader.AddUnDestination(i->first, i->second))
        {
            NS_LOG_LOGIC("Send RERR message with maximum size.");
            TypeHeader typeHeader(AODVTYPE_RERR);
            Ptr<Packet> packet = Create<Packet>();
            SocketIpTtlTag tag;
            tag.SetTtl(1);
            packet->AddPacketTag(tag);
            packet->AddHeader(rerrHeader);
            packet->AddHeader(typeHeader);
            SendRerrMessage(packet, precursors);
            rerrHeader.Clear();
        }
        else
        {
            RoutingTableEntry toDst;
            m_routingTable.LookupRoute(i->first, toDst);
            toDst.GetPrecursors(precursors);
            ++i;
        }
    }
    if (rerrHeader.GetDestCount() != 0)
    {
        TypeHeader typeHeader(AODVTYPE_RERR);
        Ptr<Packet> packet = Create<Packet>();
        SocketIpTtlTag tag;
        tag.SetTtl(1);
        packet->AddPacketTag(tag);
        packet->AddHeader(rerrHeader);
        packet->AddHeader(typeHeader);
        SendRerrMessage(packet, precursors);
    }
    unreachable.insert(std::make_pair(nextHop, toNextHop.GetSeqNo()));
    m_routingTable.InvalidateRoutesWithDst(unreachable);
}

void
RoutingProtocol::SendRerrWhenNoRouteToForward(Ipv4Address dst,
                                              uint32_t dstSeqNo,
                                              Ipv4Address origin)
{
    NS_LOG_FUNCTION(this);
    // A node SHOULD NOT originate more than RERR_RATELIMIT RERR messages per second.
    if (m_rerrCount == m_rerrRateLimit)
    {
        // Just make sure that the RerrRateLimit timer is running and will expire
        NS_ASSERT(m_rerrRateLimitTimer.IsRunning());
        // discard the packet and return
        NS_LOG_LOGIC("RerrRateLimit reached at "
                     << Simulator::Now().As(Time::S) << " with timer delay left "
                     << m_rerrRateLimitTimer.GetDelayLeft().As(Time::S) << "; suppressing RERR");
        return;
    }
    RerrHeader rerrHeader;
    rerrHeader.AddUnDestination(dst, dstSeqNo);
    RoutingTableEntry toOrigin;
    Ptr<Packet> packet = Create<Packet>();
    SocketIpTtlTag tag;
    tag.SetTtl(1);
    packet->AddPacketTag(tag);
    packet->AddHeader(rerrHeader);
    packet->AddHeader(TypeHeader(AODVTYPE_RERR));
    if (m_routingTable.LookupValidRoute(origin, toOrigin))
    {
        Ptr<Socket> socket = FindSocketWithInterfaceAddress(toOrigin.GetInterface());
        NS_ASSERT(socket);
        NS_LOG_LOGIC("Unicast RERR to the source of the data transmission");
        socket->SendTo(packet, 0, InetSocketAddress(toOrigin.GetNextHop(), AODV_PORT));
    }
    else
    {
        for (auto i = m_socketAddresses.begin(); i != m_socketAddresses.end(); ++i)
        {
            Ptr<Socket> socket = i->first;
            Ipv4InterfaceAddress iface = i->second;
            NS_ASSERT(socket);
            NS_LOG_LOGIC("Broadcast RERR message from interface " << iface.GetLocal());
            // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
            Ipv4Address destination;
            if (iface.GetMask() == Ipv4Mask::GetOnes())
            {
                destination = Ipv4Address("255.255.255.255");
            }
            else
            {
                destination = iface.GetBroadcast();
            }
            socket->SendTo(packet->Copy(), 0, InetSocketAddress(destination, AODV_PORT));
        }
    }
}

void
RoutingProtocol::SendRerrMessage(Ptr<Packet> packet, std::vector<Ipv4Address> precursors)
{
    NS_LOG_FUNCTION(this);

    if (precursors.empty())
    {
        NS_LOG_LOGIC("No precursors");
        return;
    }
    // A node SHOULD NOT originate more than RERR_RATELIMIT RERR messages per second.
    if (m_rerrCount == m_rerrRateLimit)
    {
        // Just make sure that the RerrRateLimit timer is running and will expire
        NS_ASSERT(m_rerrRateLimitTimer.IsRunning());
        // discard the packet and return
        NS_LOG_LOGIC("RerrRateLimit reached at "
                     << Simulator::Now().As(Time::S) << " with timer delay left "
                     << m_rerrRateLimitTimer.GetDelayLeft().As(Time::S) << "; suppressing RERR");
        return;
    }
    // If there is only one precursor, RERR SHOULD be unicast toward that precursor
    if (precursors.size() == 1)
    {
        RoutingTableEntry toPrecursor;
        if (m_routingTable.LookupValidRoute(precursors.front(), toPrecursor))
        {
            Ptr<Socket> socket = FindSocketWithInterfaceAddress(toPrecursor.GetInterface());
            NS_ASSERT(socket);
            NS_LOG_LOGIC("one precursor => unicast RERR to "
                         << toPrecursor.GetDestination() << " from "
                         << toPrecursor.GetInterface().GetLocal());
            Simulator::Schedule(MilliSeconds(m_uniformRandomVariable->GetInteger(0, 10)),
                                &RoutingProtocol::SendTo,
                                this,
                                socket,
                                packet,
                                precursors.front());
            m_rerrCount++;
        }
        return;
    }

    //  Should only transmit RERR on those interfaces which have precursor nodes for the broken
    //  route
    std::vector<Ipv4InterfaceAddress> ifaces;
    RoutingTableEntry toPrecursor;
    for (auto i = precursors.begin(); i != precursors.end(); ++i)
    {
        if (m_routingTable.LookupValidRoute(*i, toPrecursor) &&
            std::find(ifaces.begin(), ifaces.end(), toPrecursor.GetInterface()) == ifaces.end())
        {
            ifaces.push_back(toPrecursor.GetInterface());
        }
    }

    for (auto i = ifaces.begin(); i != ifaces.end(); ++i)
    {
        Ptr<Socket> socket = FindSocketWithInterfaceAddress(*i);
        NS_ASSERT(socket);
        NS_LOG_LOGIC("Broadcast RERR message from interface " << i->GetLocal());
        // std::cout << "Broadcast RERR message from interface " << i->GetLocal () << std::endl;
        // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
        Ptr<Packet> p = packet->Copy();
        Ipv4Address destination;
        if (i->GetMask() == Ipv4Mask::GetOnes())
        {
            destination = Ipv4Address("255.255.255.255");
        }
        else
        {
            destination = i->GetBroadcast();
        }
        Simulator::Schedule(MilliSeconds(m_uniformRandomVariable->GetInteger(0, 10)),
                            &RoutingProtocol::SendTo,
                            this,
                            socket,
                            p,
                            destination);
    }
}

Ptr<Socket>
RoutingProtocol::FindSocketWithInterfaceAddress(Ipv4InterfaceAddress addr) const
{
    NS_LOG_FUNCTION(this << addr);
    for (auto j = m_socketAddresses.begin(); j != m_socketAddresses.end(); ++j)
    {
        Ptr<Socket> socket = j->first;
        Ipv4InterfaceAddress iface = j->second;
        if (iface == addr)
        {
            return socket;
        }
    }
    Ptr<Socket> socket;
    return socket;
}

Ptr<Socket>
RoutingProtocol::FindSubnetBroadcastSocketWithInterfaceAddress(Ipv4InterfaceAddress addr) const
{
    NS_LOG_FUNCTION(this << addr);
    for (auto j = m_socketSubnetBroadcastAddresses.begin();
         j != m_socketSubnetBroadcastAddresses.end();
         ++j)
    {
        Ptr<Socket> socket = j->first;
        Ipv4InterfaceAddress iface = j->second;
        if (iface == addr)
        {
            return socket;
        }
    }
    Ptr<Socket> socket;
    return socket;
}

void
RoutingProtocol::DoInitialize()
{
    NS_LOG_FUNCTION(this);

    NS_ABORT_MSG_IF(m_ttlStart > m_netDiameter,
                    "AODV: configuration error, TtlStart ("
                        << m_ttlStart << ") must be less than or equal to NetDiameter ("
                        << m_netDiameter << ").");

    if (m_enableHello)
    {
        m_htimer.SetFunction(&RoutingProtocol::HelloTimerExpire, this);
        uint32_t startTime = m_uniformRandomVariable->GetInteger(0, 100);
        NS_LOG_DEBUG("Starting at time " << startTime << "ms");
        m_htimer.Schedule(MilliSeconds(startTime));
    }
    Ipv4RoutingProtocol::DoInitialize();
}

} // namespace aodv
} // namespace ns3
