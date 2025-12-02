/*
 * 外部WH攻撃を組み込んだ AODV 例
 *
 * node0, node3: 通常の AODV ノード
 * node1, node2: 外部 WH ノード (WormholeApp)
 * node1 <-> node2 間は PointToPoint 有線リンク
 */

#include "ns3/aodv-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/ping-helper.h"
#include "ns3/point-to-point-module.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/point-to-point-module.h"
#include "ns3/animation-interface.h"

// 外部WHモジュール
#include "ns3/out-band-WH.h"

#include <cmath>
#include <iostream>

using namespace ns3;

/**
 * @ingroup aodv-examples
 * @brief 外部WH攻撃付きテスト
 */
class AodvExample
{
  public:
    AodvExample();
    bool Configure(int argc, char** argv);
    void Run();
    void Report(std::ostream& os);

  private:
    // parameters
    uint32_t size;      // ノード数 (ここでは 4 固定で使用)
    double step;        // ノード間距離
    double totalTime;   // シミュレーション時間
    bool pcap;          // PCAP 出力
    bool printRoutes;   // 経路出力

    // network
    NodeContainer nodes;

    // wifi (無線) デバイス (4 ノード分)
    NetDeviceContainer wifiDevices;

    // WH 用 P2P デバイス (node1 <-> node2 の 2 デバイス)
    NetDeviceContainer p2pDevices;

    // AODV 用のインタフェース（node0, node3 の wifi だけ）
    Ipv4InterfaceContainer wifiInterfaces;

    // WH 用 P2P インタフェース（node1, node2 の有線リンク用）
    Ipv4InterfaceContainer whP2pInterfaces;

  private:
    void CreateNodes();
    void CreateDevices();
    void InstallInternetStack();
    void InstallApplications();
};

int
main(int argc, char** argv)
{
    AodvExample test;
    if (!test.Configure(argc, argv))
    {
        NS_FATAL_ERROR("Configuration failed. Aborted.");
    }

    test.Run();
    test.Report(std::cout);
    return 0;
}

//-----------------------------------------------------------------------------
AodvExample::AodvExample()
    : size(4),          // ★ 4 ノード固定
      step(50),
      totalTime(10),
      pcap(true),
      printRoutes(true)
{
}

bool
AodvExample::Configure(int argc, char** argv)
{
    // LogComponentEnable("AodvRoutingProtocol", LOG_LEVEL_ALL);

    SeedManager::SetSeed(12345);
    CommandLine cmd(__FILE__);

    cmd.AddValue("pcap", "Write PCAP traces.", pcap);
    cmd.AddValue("printRoutes", "Print routing table dumps.", printRoutes);
    cmd.AddValue("time", "Simulation time, s.", totalTime);
    cmd.AddValue("step", "Grid step, m", step);

    // size は 4 固定にしたいので、コマンドラインからは変更させない
    cmd.Parse(argc, argv);

    size = 4; // 念のため強制
    return true;
}

void
AodvExample::Run()
{
    CreateNodes();
    CreateDevices();
    InstallInternetStack();
    InstallApplications();

    std::cout << "Starting simulation for " << totalTime << " s ...\n";

    Simulator::Stop(Seconds(totalTime));
    Simulator::Run();
    Simulator::Destroy();
}

void
AodvExample::Report(std::ostream&)
{
}

void
AodvExample::CreateNodes()
{
    std::cout << "Creating " << (unsigned)size << " nodes " << step << " m apart.\n";
    nodes.Create(size);
    // Name nodes
    for (uint32_t i = 0; i < size; ++i)
    {
        std::ostringstream os;
        os << "node-" << i;
        Names::Add(os.str(), nodes.Get(i));
    }
    // Create static grid
    MobilityHelper mobility;
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);

    AnimationInterface::SetConstantPosition (nodes.Get (0), 0, 0);
    AnimationInterface::SetConstantPosition (nodes.Get (1), 50, 0);  //WHノード
    AnimationInterface::SetConstantPosition (nodes.Get (2), 150, 0); //WHノード
    AnimationInterface::SetConstantPosition (nodes.Get (3), 200, 0);
}

void
AodvExample::CreateDevices()
{
    // ---- Wi-Fi (全ノードにインストール) ----
    WifiMacHelper wifiMac;
    wifiMac.SetType("ns3::AdhocWifiMac");
    YansWifiPhyHelper wifiPhy;
    YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default();
    wifiPhy.SetChannel(wifiChannel.Create());
    WifiHelper wifi;
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode",
                                 StringValue("OfdmRate6Mbps"),
                                 "RtsCtsThreshold",
                                 UintegerValue(0));
    wifiDevices = wifi.Install(wifiPhy, wifiMac, nodes);

    if (pcap)
    {
        wifiPhy.EnablePcapAll(std::string("aodv"));
    }

    // ---- WH 用 P2P (node1 <-> node2) ----
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("2ms"));

    // node1 と node2 の間だけ有線リンクを作る
    p2pDevices = p2p.Install(nodes.Get(1), nodes.Get(2));
}

void
AodvExample::InstallInternetStack()
{
    // ---- node0, node3：AODV を使う通常ノード ----
    AodvHelper aodv;
    InternetStackHelper stackAodv;
    stackAodv.SetRoutingHelper(aodv); // AODV をルーティングに使用
    NodeContainer normalNodes;
    normalNodes.Add(nodes.Get(0));
    normalNodes.Add(nodes.Get(3));
    stackAodv.Install(normalNodes);

    // ---- node1, node2：外部 WH ノード（AODV なし、基本的な IP/UDP だけ）----
    InternetStackHelper stackBasic; // RoutingHelper を設定しない → デフォルト(static)のみ
    NodeContainer whNodes;
    whNodes.Add(nodes.Get(1));
    whNodes.Add(nodes.Get(2));
    stackBasic.Install(whNodes);

    // ---- wifi 側 IP アドレス付与（node0, node3 だけ）----
    // wifiDevices: index 0 → node0, 1 → node1, 2 → node2, 3 → node3
    Ipv4AddressHelper wifiAddr;
    wifiAddr.SetBase("10.0.0.0", "255.255.255.0");

    NetDeviceContainer wifiDevicesNormal;
    wifiDevicesNormal.Add(wifiDevices.Get(0)); // node0 の wifi
    wifiDevicesNormal.Add(wifiDevices.Get(3)); // node3 の wifi

    wifiInterfaces = wifiAddr.Assign(wifiDevicesNormal);
    // wifiInterfaces[0] = node0, wifiInterfaces[1] = node3

    // ---- WH 用 P2P リンクに IP 付与（node1, node2）----
    Ipv4AddressHelper p2pAddr;
    p2pAddr.SetBase("10.1.1.0", "255.255.255.0");
    whP2pInterfaces = p2pAddr.Assign(p2pDevices);
    // whP2pInterfaces[0] = node1 の p2p
    // whP2pInterfaces[1] = node2 の p2p

    if (printRoutes)
    {
        Ptr<OutputStreamWrapper> routingStream =
            Create<OutputStreamWrapper>("aodv.routes", std::ios::out);
        // AODV を持っているのは node0, node3 だけだが、全ノード分を出力してもOK
        Ipv4RoutingHelper::PrintRoutingTableAllAt(Seconds(8), routingStream);
    }
}

void
AodvExample::InstallApplications()
{
    // ---- Ping (node0 → node3) ----
    // wifiInterfaces[0] = node0, wifiInterfaces[1] = node3
    Ipv4Address dst = wifiInterfaces.GetAddress(1); // node3 のアドレス

    PingHelper ping(dst);
    ping.SetAttribute("VerboseMode", EnumValue(Ping::VerboseMode::VERBOSE));

    ApplicationContainer p = ping.Install(nodes.Get(0));
    p.Start(Seconds(0.0));
    p.Stop(Seconds(totalTime) - Seconds(0.001));

    // ---- 外部 WH アプリケーションの設定 ----
    // node1: ENTRY 側（wifi をスニファして、node2 の p2p IP にトンネル送信）
    {
        Ptr<WormholeApp> whEntry = CreateObject<WormholeApp>();
        whEntry->Setup(
            wifiDevices.Get(1),                 // node1 の wifi デバイス
            whP2pInterfaces.GetAddress(1),      // 相方 (node2) の p2p IP
            50000                               // UDP ポート
        );
        nodes.Get(1)->AddApplication(whEntry);
        whEntry->SetStartTime(Seconds(0.0));
        whEntry->SetStopTime(Seconds(totalTime));
    }

    // node2: EXIT 側（wifi をスニファしつつ、p2p からのトンネルを受けて wifi に再注入）
    {
        Ptr<WormholeApp> whExit = CreateObject<WormholeApp>();
        whExit->Setup(
            wifiDevices.Get(2),                 // node2 の wifi デバイス
            whP2pInterfaces.GetAddress(0),      // 相方 (node1) の p2p IP
            50000
        );
        nodes.Get(2)->AddApplication(whExit);
        whExit->SetStartTime(Seconds(0.0));
        whExit->SetStopTime(Seconds(totalTime));
    }

    // 元の例にあった「真ん中ノードを遠くに飛ばす」処理は、
    // 今回は node1,2 が WH ノードなので消しておく。
    // （必要なら、WH ノードや通常ノードの位置を変える処理を追加してOK）
}
