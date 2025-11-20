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
#include "aodv-packet.h"

#include "ns3/address-utils.h"
#include "ns3/packet.h"

namespace ns3
{
namespace aodv
{

NS_OBJECT_ENSURE_REGISTERED(TypeHeader);

TypeHeader::TypeHeader(MessageType t)
    : m_type(t),
      m_valid(true)
{
}

TypeId
TypeHeader::GetTypeId()
{
    static TypeId tid = TypeId("ns3::aodv::TypeHeader")
                            .SetParent<Header>()
                            .SetGroupName("Aodv")
                            .AddConstructor<TypeHeader>();
    return tid;
}

TypeId
TypeHeader::GetInstanceTypeId() const
{
    return GetTypeId();
}

uint32_t
TypeHeader::GetSerializedSize() const
{
    return 1;
}

void
TypeHeader::Serialize(Buffer::Iterator i) const
{
    i.WriteU8((uint8_t)m_type);
}

uint32_t
TypeHeader::Deserialize(Buffer::Iterator start)
{
    Buffer::Iterator i = start;
    uint8_t type = i.ReadU8();
    m_valid = true;
    switch (type)
    {
    case AODVTYPE_RREQ:
    case AODVTYPE_RREP:
    case AODVTYPE_RERR:
    case AODVTYPE_RREP_ACK:
    case AODVTYPE_VSR: 
    case AODVTYPE_AUTH :{
        m_type = (MessageType)type;
        break;
    }
    default:
        m_valid = false;
    }
    uint32_t dist = i.GetDistanceFrom(start);
    NS_ASSERT(dist == GetSerializedSize());
    return dist;
}

void
TypeHeader::Print(std::ostream& os) const
{
    switch (m_type)
    {
    case AODVTYPE_RREQ: {
        os << "RREQ";
        break;
    }
    case AODVTYPE_RREP: {
        os << "RREP";
        break;
    }
    case AODVTYPE_RERR: {
        os << "RERR";
        break;
    }
    case AODVTYPE_RREP_ACK: {
        os << "RREP_ACK";
        break;
    }
    case AODVTYPE_VSR: {
        os << "共通隣接ノードに監視させるメッセージヘッダ";
    }
    case AODVTYPE_AUTH : {
        os << "認証メッセージヘッダ";
    }
    default:
        os << "UNKNOWN_TYPE";
    }
}

bool
TypeHeader::operator==(const TypeHeader& o) const
{
    return (m_type == o.m_type && m_valid == o.m_valid);
}

std::ostream&
operator<<(std::ostream& os, const TypeHeader& h)
{
    h.Print(os);
    return os;
}

//-----------------------------------------------------------------------------
// RREQ
//-----------------------------------------------------------------------------
RreqHeader::RreqHeader(uint8_t flags,
                       uint8_t reserved,
                       uint8_t hopCount,
                       uint32_t requestID,
                       Ipv4Address dst,
                       uint32_t dstSeqNo,
                       Ipv4Address origin,
                       uint32_t originSeqNo,
                       uint8_t WHForwardFlag
                       )
    : m_flags(flags),
      m_reserved(reserved),
      m_hopCount(hopCount),
      m_requestID(requestID),
      m_dst(dst),
      m_dstSeqNo(dstSeqNo),
      m_origin(origin),
      m_originSeqNo(originSeqNo),
      m_WHForwardFlag(WHForwardFlag)
{
}

NS_OBJECT_ENSURE_REGISTERED(RreqHeader);

TypeId
RreqHeader::GetTypeId()
{
    static TypeId tid = TypeId("ns3::aodv::RreqHeader")
                            .SetParent<Header>()
                            .SetGroupName("Aodv")
                            .AddConstructor<RreqHeader>();
    return tid;
}

TypeId
RreqHeader::GetInstanceTypeId() const
{
    return GetTypeId();
}

uint32_t
RreqHeader::GetSerializedSize() const
{
    return 23
            + 1; // +1 for WHForwardFlag
            //+ 1 //　別経路構築用のフラグ
            // + 4; // 別経路要求メッセージのID
}

void
RreqHeader::Serialize(Buffer::Iterator i) const
{
    i.WriteU8(m_flags);
    i.WriteU8(m_reserved);
    i.WriteU8(m_hopCount);
    i.WriteHtonU32(m_requestID);
    WriteTo(i, m_dst);
    i.WriteHtonU32(m_dstSeqNo);
    WriteTo(i, m_origin);
    i.WriteHtonU32(m_originSeqNo);

    i.WriteU8(m_WHForwardFlag); // WHForwardFlagを1バイトとしてシリアル化する
    //i.WriteU8(m_AnotherRouteCreateFlag); // 別経路作成用のフラグ
}

uint32_t
RreqHeader::Deserialize(Buffer::Iterator start)
{
    Buffer::Iterator i = start;
    m_flags = i.ReadU8();
    m_reserved = i.ReadU8();
    m_hopCount = i.ReadU8();
    m_requestID = i.ReadNtohU32();
    ReadFrom(i, m_dst);
    m_dstSeqNo = i.ReadNtohU32();
    ReadFrom(i, m_origin);
    m_originSeqNo = i.ReadNtohU32();

    m_WHForwardFlag = i.ReadU8(); // WHForwardFlagを1バイトとしてデシリアル化する
    //m_AnotherRouteCreateFlag = i.ReadU8();

    // m_ExcludedList.clear();
    // while (i.GetDistanceFrom(start) < GetSerializedSize())
    // {
    //     Ipv4Address addr;
    //     ReadFrom(i, addr);
    //     m_ExcludedList.push_back(addr);
    // }

    //m_DetectionReqID = i.ReadNtohU32();

    uint32_t dist = i.GetDistanceFrom(start);
    NS_ASSERT(dist == GetSerializedSize());
    return dist;
}

void
RreqHeader::Print(std::ostream& os) const
{
    os << "RREQ ID " << m_requestID;
    os << " destination: ipv4 " << m_dst << " sequence number " << m_dstSeqNo;
    os << " source: ipv4 " << m_origin << " sequence number " << m_originSeqNo;
    os << " flags: Gratuitous RREP " << (*this).GetGratuitousRrep() << " Destination only "
       << (*this).GetDestinationOnly() << " Unknown sequence number " << (*this).GetUnknownSeqno();
    os << " WHForwardFlag " << m_WHForwardFlag;
    //os << "別経路要求メッセージのID" << m_DetectionReqID;    
}

std::ostream&
operator<<(std::ostream& os, const RreqHeader& h)
{
    h.Print(os);
    return os;
}

void
RreqHeader::SetGratuitousRrep(bool f)
{
    if (f)
    {
        m_flags |= (1 << 5);
    }
    else
    {
        m_flags &= ~(1 << 5);
    }
}

bool
RreqHeader::GetGratuitousRrep() const
{
    return (m_flags & (1 << 5));
}

void
RreqHeader::SetDestinationOnly(bool f)
{
    if (f)
    {
        m_flags |= (1 << 4);
    }
    else
    {
        m_flags &= ~(1 << 4);
    }
}

bool
RreqHeader::GetDestinationOnly() const
{
    return (m_flags & (1 << 4));
}

void
RreqHeader::SetUnknownSeqno(bool f)
{
    if (f)
    {
        m_flags |= (1 << 3);
    }
    else
    {
        m_flags &= ~(1 << 3);
    }
}

bool
RreqHeader::GetUnknownSeqno() const
{
    return (m_flags & (1 << 3));
}

bool
RreqHeader::operator==(const RreqHeader& o) const
{
    return (m_flags == o.m_flags && m_reserved == o.m_reserved && m_hopCount == o.m_hopCount &&
            m_requestID == o.m_requestID && m_dst == o.m_dst && m_dstSeqNo == o.m_dstSeqNo &&
            m_origin == o.m_origin && m_originSeqNo == o.m_originSeqNo &&
            m_WHForwardFlag == o.m_WHForwardFlag);
}

//-----------------------------------------------------------------------------
// RREP
//-----------------------------------------------------------------------------

RrepHeader::RrepHeader(uint8_t prefixSize,
                       uint8_t hopCount,
                       Ipv4Address dst,
                       uint32_t dstSeqNo,
                       Ipv4Address origin,
                       Time lifeTime,
                       uint8_t WHForwardFlag,
                       uint32_t NeighborCount,
                       float NeighborRatio,
                       std::vector<Ipv4Address> neighborList)
    : m_flags(0),
      m_prefixSize(prefixSize),
      m_hopCount(hopCount),
      m_dst(dst),
      m_dstSeqNo(dstSeqNo),
      m_origin(origin),
      m_WHForwardFlag(WHForwardFlag),
      m_NeighborCount(NeighborCount),
      m_NeighborRatio(NeighborRatio),
      m_neighborList(neighborList)
{
    m_lifeTime = uint32_t(lifeTime.GetMilliSeconds());
}

NS_OBJECT_ENSURE_REGISTERED(RrepHeader);

TypeId
RrepHeader::GetTypeId()
{
    static TypeId tid = TypeId("ns3::aodv::RrepHeader")
                            .SetParent<Header>()
                            .SetGroupName("Aodv")
                            .AddConstructor<RrepHeader>();
    return tid;
}

TypeId
RrepHeader::GetInstanceTypeId() const
{
    return GetTypeId();
}

uint32_t
RrepHeader::GetSerializedSize() const
{
    uint32_t neighborListSize = m_neighborList.size() * 4; //隣接ノードリストのサイズ（IPv4アドレスは4バイト）



    return 19 
    + 1 /*WHForwardFlag*/ 
    + 4 /*NeighborCount*/
    // + 1 /*AnotherRouteCreateFlag*/
    + 4 /*NeighborRatio*/
    + neighborListSize; //隣接ノードリストのサイズを加
    // + 4 /*経路要求メッセージのID*/
    
}

void
RrepHeader::Serialize(Buffer::Iterator i) const
{
    i.WriteU8(m_flags);
    i.WriteU8(m_prefixSize);
    i.WriteU8(m_hopCount);
    WriteTo(i, m_dst);
    i.WriteHtonU32(m_dstSeqNo);
    WriteTo(i, m_origin);
    i.WriteHtonU32(m_lifeTime);
    i.WriteU8(m_WHForwardFlag); // WHForwardFlagを1バイトとしてシリアル化する
    i.WriteHtonU32(m_NeighborCount); // NeighborCountを4バイトとしてシリアル化する
    i.WriteHtonU32(static_cast<uint32_t>(m_NeighborRatio * 10000)); // NeighborRatioを4バイトとしてシリアル化する

    //隣接ノードリストのサイズ分書き込む
    for (auto addr : m_neighborList)
    {
        WriteTo(i, addr);
    }

    // i.WriteU8(m_AnotherRouteCreateFlag);//m_AnotherRouteCreateFlag
    // i.WriteHtonU32(m_DetectionReqID);
}

uint32_t
RrepHeader::Deserialize(Buffer::Iterator start)
{
    Buffer::Iterator i = start;

    m_flags = i.ReadU8();
    m_prefixSize = i.ReadU8();
    m_hopCount = i.ReadU8();
    ReadFrom(i, m_dst);
    m_dstSeqNo = i.ReadNtohU32();
    ReadFrom(i, m_origin);
    m_lifeTime = i.ReadNtohU32();
    m_WHForwardFlag = i.ReadU8(); // WHForwardFlagを1バイトとしてデシリアル化する
    m_NeighborCount = i.ReadNtohU32(); // NeighborCountを4バイトとしてデシリアル化する
    m_NeighborRatio = static_cast<float>(i.ReadNtohU32()) / 10000.0f; // NeighborRatioを4バイトとしてデシリアル化する

    //隣接ノード比率がしきい値以上の場合、隣接ノードリストを読み込む
    m_neighborList.clear();
    for (uint32_t idx = 0; idx < m_NeighborCount; ++idx)
    {
        Ipv4Address neighborAddr;
        ReadFrom(i, neighborAddr);
        m_neighborList.push_back(neighborAddr);
    }

    // m_AnotherRouteCreateFlag = i.ReadU8();
    // m_DetectionReqID = i.ReadNtohU32(); //別経路要求メッセージのID
    
    uint32_t dist = i.GetDistanceFrom(start);
    NS_ASSERT(dist == GetSerializedSize());
    return dist;
}

void
RrepHeader::Print(std::ostream& os) const
{
    os << "destination: ipv4 " << m_dst << " sequence number " << m_dstSeqNo;
    if (m_prefixSize != 0)
    {
        os << " prefix size " << m_prefixSize;
    }
    os << " source ipv4 " << m_origin << " lifetime " << m_lifeTime
       << " acknowledgment required flag " << (*this).GetAckRequired()
       << " WHForwardFlag " << m_WHForwardFlag
       << " NeighborCount " << m_NeighborCount;
    os << " NeighborRatio " << m_NeighborRatio;
}

void
RrepHeader::SetLifeTime(Time t)
{
    m_lifeTime = t.GetMilliSeconds();
}

Time
RrepHeader::GetLifeTime() const
{
    Time t(MilliSeconds(m_lifeTime));
    return t;
}

void
RrepHeader::SetAckRequired(bool f)
{
    if (f)
    {
        m_flags |= (1 << 6);
    }
    else
    {
        m_flags &= ~(1 << 6);
    }
}

bool
RrepHeader::GetAckRequired() const
{
    return (m_flags & (1 << 6));
}

void
RrepHeader::SetPrefixSize(uint8_t sz)
{
    m_prefixSize = sz;
}

uint8_t
RrepHeader::GetPrefixSize() const
{
    return m_prefixSize;
}

bool
RrepHeader::operator==(const RrepHeader& o) const
{
    return (m_flags == o.m_flags && m_prefixSize == o.m_prefixSize && m_hopCount == o.m_hopCount &&
            m_dst == o.m_dst && m_dstSeqNo == o.m_dstSeqNo && m_origin == o.m_origin &&
            m_lifeTime == o.m_lifeTime && m_WHForwardFlag == o.m_WHForwardFlag && m_NeighborCount == o.m_NeighborCount
            && m_NeighborRatio == o.m_NeighborRatio);
}

void
RrepHeader::SetHello(Ipv4Address origin, uint32_t srcSeqNo, Time lifetime)
{
    m_flags = 0;
    m_prefixSize = 0;
    m_hopCount = 0;
    m_dst = origin;
    m_dstSeqNo = srcSeqNo;
    m_origin = origin;
    m_lifeTime = lifetime.GetMilliSeconds();
    m_WHForwardFlag = 0;
    m_NeighborCount = 0;
    m_NeighborRatio = 0.0;
    // m_AnotherRouteCreateFlag = false;
    // m_DetectionReqID = 0;
}

std::ostream&
operator<<(std::ostream& os, const RrepHeader& h)
{
    h.Print(os);
    return os;
}

//-----------------------------------------------------------------------------
// RREP-ACK
//-----------------------------------------------------------------------------

RrepAckHeader::RrepAckHeader()
    : m_reserved(0)
{
}

NS_OBJECT_ENSURE_REGISTERED(RrepAckHeader);

TypeId
RrepAckHeader::GetTypeId()
{
    static TypeId tid = TypeId("ns3::aodv::RrepAckHeader")
                            .SetParent<Header>()
                            .SetGroupName("Aodv")
                            .AddConstructor<RrepAckHeader>();
    return tid;
}

TypeId
RrepAckHeader::GetInstanceTypeId() const
{
    return GetTypeId();
}

uint32_t
RrepAckHeader::GetSerializedSize() const
{
    return 1;
}

void
RrepAckHeader::Serialize(Buffer::Iterator i) const
{
    i.WriteU8(m_reserved);
}

uint32_t
RrepAckHeader::Deserialize(Buffer::Iterator start)
{
    Buffer::Iterator i = start;
    m_reserved = i.ReadU8();
    uint32_t dist = i.GetDistanceFrom(start);
    NS_ASSERT(dist == GetSerializedSize());
    return dist;
}

void
RrepAckHeader::Print(std::ostream& os) const
{
}

bool
RrepAckHeader::operator==(const RrepAckHeader& o) const
{
    return m_reserved == o.m_reserved;
}

std::ostream&
operator<<(std::ostream& os, const RrepAckHeader& h)
{
    h.Print(os);
    return os;
}

//-----------------------------------------------------------------------------
// RERR
//-----------------------------------------------------------------------------
RerrHeader::RerrHeader()
    : m_flag(0),
      m_reserved(0)
{
}

NS_OBJECT_ENSURE_REGISTERED(RerrHeader);

TypeId
RerrHeader::GetTypeId()
{
    static TypeId tid = TypeId("ns3::aodv::RerrHeader")
                            .SetParent<Header>()
                            .SetGroupName("Aodv")
                            .AddConstructor<RerrHeader>();
    return tid;
}

TypeId
RerrHeader::GetInstanceTypeId() const
{
    return GetTypeId();
}

uint32_t
RerrHeader::GetSerializedSize() const
{
    return (3 + 8 * GetDestCount());
}

void
RerrHeader::Serialize(Buffer::Iterator i) const
{
    i.WriteU8(m_flag);
    i.WriteU8(m_reserved);
    i.WriteU8(GetDestCount());
    for (auto j = m_unreachableDstSeqNo.begin(); j != m_unreachableDstSeqNo.end(); ++j)
    {
        WriteTo(i, (*j).first);
        i.WriteHtonU32((*j).second);
    }
}

uint32_t
RerrHeader::Deserialize(Buffer::Iterator start)
{
    Buffer::Iterator i = start;
    m_flag = i.ReadU8();
    m_reserved = i.ReadU8();
    uint8_t dest = i.ReadU8();
    m_unreachableDstSeqNo.clear();
    Ipv4Address address;
    uint32_t seqNo;
    for (uint8_t k = 0; k < dest; ++k)
    {
        ReadFrom(i, address);
        seqNo = i.ReadNtohU32();
        m_unreachableDstSeqNo.insert(std::make_pair(address, seqNo));
    }

    uint32_t dist = i.GetDistanceFrom(start);
    NS_ASSERT(dist == GetSerializedSize());
    return dist;
}

void
RerrHeader::Print(std::ostream& os) const
{
    os << "Unreachable destination (ipv4 address, seq. number):";
    for (auto j = m_unreachableDstSeqNo.begin(); j != m_unreachableDstSeqNo.end(); ++j)
    {
        os << (*j).first << ", " << (*j).second;
    }
    os << "No delete flag " << (*this).GetNoDelete();
}

void
RerrHeader::SetNoDelete(bool f)
{
    if (f)
    {
        m_flag |= (1 << 0);
    }
    else
    {
        m_flag &= ~(1 << 0);
    }
}

bool
RerrHeader::GetNoDelete() const
{
    return (m_flag & (1 << 0));
}

bool
RerrHeader::AddUnDestination(Ipv4Address dst, uint32_t seqNo)
{
    if (m_unreachableDstSeqNo.find(dst) != m_unreachableDstSeqNo.end())
    {
        return true;
    }

    NS_ASSERT(GetDestCount() < 255); // can't support more than 255 destinations in single RERR
    m_unreachableDstSeqNo.insert(std::make_pair(dst, seqNo));
    return true;
}

bool
RerrHeader::RemoveUnDestination(std::pair<Ipv4Address, uint32_t>& un)
{
    if (m_unreachableDstSeqNo.empty())
    {
        return false;
    }
    auto i = m_unreachableDstSeqNo.begin();
    un = *i;
    m_unreachableDstSeqNo.erase(i);
    return true;
}

void
RerrHeader::Clear()
{
    m_unreachableDstSeqNo.clear();
    m_flag = 0;
    m_reserved = 0;
}

bool
RerrHeader::operator==(const RerrHeader& o) const
{
    if (m_flag != o.m_flag || m_reserved != o.m_reserved || GetDestCount() != o.GetDestCount())
    {
        return false;
    }

    auto j = m_unreachableDstSeqNo.begin();
    auto k = o.m_unreachableDstSeqNo.begin();
    for (uint8_t i = 0; i < GetDestCount(); ++i)
    {
        if ((j->first != k->first) || (j->second != k->second))
        {
            return false;
        }

        j++;
        k++;
    }
    return true;
}

std::ostream&
operator<<(std::ostream& os, const RerrHeader& h)
{
    h.Print(os);
    return os;
}

//-----------------------------------------------------------------------------
// VerificationStartHeader
//-----------------------------------------------------------------------------

VerificationStartHeader::VerificationStartHeader(Ipv4Address origin,
                                                 Ipv4Address target,
                                                 Ipv4Address dst)
    : m_origin(origin),
      m_target(target),
      m_destination(dst)
{
}

NS_OBJECT_ENSURE_REGISTERED(VerificationStartHeader);

TypeId
VerificationStartHeader::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::aodv::VerificationStartHeader")
            .SetParent<Header>()
            .SetGroupName("Aodv")
            .AddConstructor<VerificationStartHeader>();
    return tid;
}

TypeId
VerificationStartHeader::GetInstanceTypeId() const
{
    return GetTypeId();
}

uint32_t
VerificationStartHeader::GetSerializedSize() const
{
    // IPv4Address は 4 byte × 2
    return 13;
}

void
VerificationStartHeader::Serialize(Buffer::Iterator i) const
{
    WriteTo(i, m_origin);
    WriteTo(i, m_target);
    WriteTo(i, m_destination);
    i.WriteU8(m_modeflag);

}

uint32_t
VerificationStartHeader::Deserialize(Buffer::Iterator start)
{
    Buffer::Iterator i = start;

    ReadFrom(i, m_origin);
    ReadFrom(i, m_target);
    ReadFrom(i,m_destination);
    m_modeflag = i.ReadU8();

    uint32_t dist = i.GetDistanceFrom(start);
    NS_ASSERT(dist == GetSerializedSize());
    return dist;
}

void
VerificationStartHeader::Print(std::ostream &os) const
{
    os << "VerificationStart: origin=" << m_origin
       << " target=" << m_target
       << "宛先ノード" << m_destination
       << "Mode Flag" << m_modeflag;
}

std::ostream &
operator<<(std::ostream &os, const VerificationStartHeader &h)
{
    h.Print(os);
    return os;
}

AuthPacketHeader::AuthPacketHeader(Ipv4Address origin,
                                   Ipv4Address target)
    : m_origin(origin),
      m_target(target)
{
}

TypeId
AuthPacketHeader::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::aodv::AuthPacketHeader")
            .SetParent<Header>()
            .SetGroupName("Aodv")
            .AddConstructor<AuthPacketHeader>();
    return tid;
}

TypeId
AuthPacketHeader::GetInstanceTypeId() const
{
    return GetTypeId();
}

uint32_t
AuthPacketHeader::GetSerializedSize() const
{
    return 8;
}

void
AuthPacketHeader::Serialize(Buffer::Iterator i) const
{
    WriteTo(i, m_origin);
    WriteTo(i, m_target);
}

uint32_t
AuthPacketHeader::Deserialize(Buffer::Iterator start)
{
    Buffer::Iterator i = start;

    ReadFrom(i, m_origin);
    ReadFrom(i, m_target);

    uint32_t dist = i.GetDistanceFrom(start);
    NS_ASSERT(dist == GetSerializedSize());
    return GetSerializedSize();
}

void
AuthPacketHeader::Print(std::ostream &os) const
{
    os << "AUTH origin=" << m_origin << " target=" << m_target;
}

std::ostream &
operator<<(std::ostream &os, const AuthPacketHeader &h)
{
    h.Print(os);
    return os;
}

} // namespace aodv
} // namespace ns3
