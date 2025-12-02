#include "out-band-WH.h"

#include "ns3/log.h"
#include "ns3/inet-socket-address.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/mac48-address.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("WormholeApp");

// ==============================
// WhTag 実装
// ==============================

NS_OBJECT_ENSURE_REGISTERED (WhTag);

TypeId
WhTag::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::WhTag")
    .SetParent<Tag> ()
    .SetGroupName ("Wormhole")
  ;
  return tid;
}

TypeId
WhTag::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

// ==============================
// WormholeApp 実装
// ==============================

NS_OBJECT_ENSURE_REGISTERED (WormholeApp);

TypeId
WormholeApp::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::WormholeApp")
    .SetParent<Application> ()
    .SetGroupName ("Wormhole")
    .AddConstructor<WormholeApp> ();
  return tid;
}

WormholeApp::WormholeApp ()
  : m_dev (0),
    m_socket (0),
    m_peer (),
    m_port (0)
{
}

WormholeApp::~WormholeApp ()
{
  m_dev = 0;
  m_socket = 0;
}

void
WormholeApp::Setup (Ptr<NetDevice> dev, Ipv4Address peer, uint16_t port)
{
  m_dev  = dev;
  m_peer = peer;
  m_port = port;
}

void
WormholeApp::StartApplication ()
{
  NS_LOG_FUNCTION (this);

  // UDP ソケット作成（WH トンネル）
  m_socket = Socket::CreateSocket (GetNode (), UdpSocketFactory::GetTypeId ());
  m_socket->Bind (InetSocketAddress (Ipv4Address::GetAny (), m_port));
  m_socket->SetRecvCallback (MakeCallback (&WormholeApp::TunnelRecv, this));

  // Promiscuous スニファ設定
  m_dev->SetPromiscReceiveCallback
    (MakeCallback (&WormholeApp::PromiscSniff, this));
}

void
WormholeApp::StopApplication ()
{
  NS_LOG_FUNCTION (this);

  if (m_socket)
    {
      m_socket->Close ();
      m_socket = 0;
    }
}

// --------------------------------------------------------
// PromiscSniff: 無線で受信したパケットをキャプチャしてトンネルへ
//   ただし「WH が再注入したパケット（WhTag 付き）」は無視する
// --------------------------------------------------------
bool
WormholeApp::PromiscSniff (Ptr<NetDevice> dev,
                           Ptr<const Packet> pkt,
                           uint16_t protocol,
                           const Address &src,
                           const Address &dst,
                           NetDevice::PacketType type)
{
  NS_LOG_FUNCTION (this << dev << pkt << protocol);

  // 1. すでに WhTag が付いているパケットは、
  //    自分 (WH) が再注入したものとみなして無視 → ループ防止
  WhTag tag;
  if (pkt->PeekPacketTag (tag))
    {
      NS_LOG_DEBUG ("[WH] PromiscSniff: skip packet with WhTag (loop prevention)");
      return true;
    }

  // 2. 通常の無線パケット → トンネルに送る
  Ptr<Packet> copy = pkt->Copy ();

  NS_LOG_DEBUG ("[WH] ENTRY: sniffed packet, size=" << pkt->GetSize ()
                << " -> send via tunnel to " << m_peer << ":" << m_port);

  if (m_socket)
    {
      m_socket->SendTo (copy, 0, InetSocketAddress (m_peer, m_port));
    }

  // true/false は上位の処理に特に影響を与えないが、true を返しておく
  return true;
}

// --------------------------------------------------------
// TunnelRecv: P2P (UDP) 経由で受け取ったパケットを無線に再注入
//   再注入前に WhTag を付けることで、逆側 WH の PromiscSniff でスキップできる
// --------------------------------------------------------
void
WormholeApp::TunnelRecv (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);

  Address from;
  Ptr<Packet> pkt = socket->RecvFrom (from);

  if (!pkt)
    {
      return;
    }

  NS_LOG_DEBUG ("[WH] EXIT: received tunneled packet, size=" << pkt->GetSize ()
                << " -> rebroadcast on wifi");

  // 1. 再注入するパケットに WhTag を追加
  WhTag tag;
  pkt->AddPacketTag (tag);

  // 2. 無線側にブロードキャスト送信
  //    EtherType=0x0800 (IPv4) として扱わせる
  m_dev->Send (pkt, Mac48Address::GetBroadcast (), 0x0800);
}

} // namespace ns3
