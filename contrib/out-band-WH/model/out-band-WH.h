#ifndef OUT_BAND_WH_H
#define OUT_BAND_WH_H

#include "ns3/application.h"
#include "ns3/net-device.h"
#include "ns3/ipv4-address.h"
#include "ns3/socket.h"
#include "ns3/tag.h"   // ★ WhTag 用

namespace ns3
{

// ==============================
// Wormhole 用のパケットタグ
// ==============================
class WhTag : public Tag
{
public:
  WhTag() {}

  static TypeId GetTypeId (void);
  virtual TypeId GetInstanceTypeId (void) const override;

  // 今回は中身を持たないので空でOK
  virtual uint32_t GetSerializedSize (void) const override
  {
    return 0;
  }

  virtual void Serialize (TagBuffer i) const override
  {
    // 何も書かない
  }

  virtual void Deserialize (TagBuffer i) override
  {
    // 何も読まない
  }

  virtual void Print (std::ostream &os) const override
  {
    os << "WhTag";
  }
};

// ==============================
// 外部 WH アプリケーション本体
// ==============================
class WormholeApp : public Application
{
public:
  static TypeId GetTypeId (void);

  WormholeApp ();
  virtual ~WormholeApp ();

  void Setup(Ptr<NetDevice> dev, Ipv4Address peer, uint16_t port);

private:
  virtual void StartApplication() override;
  virtual void StopApplication() override;

  // ★ 戻り値 bool （ループ防止のため WH パケットを判定してスキップ）
  bool PromiscSniff(Ptr<NetDevice> dev,
                    Ptr<const Packet> pkt,
                    uint16_t protocol,
                    const Address& src,
                    const Address& dst,
                    NetDevice::PacketType type);

  void TunnelRecv(Ptr<Socket> socket);

  Ptr<NetDevice> m_dev;   // sniff / 再送する無線デバイス
  Ptr<Socket>    m_socket; // WH トンネル用 UDP ソケット
  Ipv4Address    m_peer;   // 相方 WH ノードの P2P IP
  uint16_t       m_port;   // WH トンネル用 UDP ポート
};

} // namespace ns3

#endif // OUT_BAND_WH_H
