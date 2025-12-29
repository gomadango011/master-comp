/*
 * Copyright (c) 2009 IITP RAS
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * This is an example script for AODV manet routing protocol.
 *
 * Authors: Pavel Boyko <boyko@iitp.ru>
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

#include <cmath>
#include <iostream>
#include <random>   // ★ これを追加

using namespace ns3;

/**
 * @defgroup aodv-examples AODV Examples
 * @ingroup aodv
 * @ingroup examples
 */

/**
 * @ingroup aodv-examples
 * @ingroup examples
 * @brief Test script.
 *
 * This script creates 1-dimensional grid topology and then ping last node from the first one:
 *
 * [10.0.0.1] <-- step --> [10.0.0.2] <-- step --> [10.0.0.3] <-- step --> [10.0.0.4]
 *
 * ping 10.0.0.4
 *
 * When 1/3 of simulation time has elapsed, one of the nodes is moved out of
 * range, thereby breaking the topology.  By default, this will result in
 * stopping ping replies reception after sequence number 33. If the step size is reduced
 * to cover the gap, then also the following pings can be received.
 */
class AodvExample
{
  public:
    AodvExample();
    /**
     * @brief Configure script parameters
     * @param argc is the command line argument count
     * @param argv is the command line arguments
     * @return true on successful configuration
     */
    bool Configure(int argc, char** argv);
    /// Run simulation
    void Run();
    /**
     * Report results
     * @param os the output stream
     */
    void Report(std::ostream& os);

  private:
    // parameters
    /// Number of nodes
    uint32_t size;
    /// Distance between nodes, meters
    double step;
    /// Simulation time, seconds
    double totalTime;
    /// Write per-device PCAP traces if true
    bool pcap;
    /// Print routes if true
    bool printRoutes;

    // network
    /// nodes used in the example
    NodeContainer nodes;
    ///攻撃者ノード
    NodeContainer malicious;

    /// devices used in the example
    NetDeviceContainer devices;

    //攻撃者のデバイス
    NetDeviceContainer mal_devices;

    /// interfaces used in the example
    Ipv4InterfaceContainer interfaces;

    //攻撃者のインターフェースコンテナ
    Ipv4InterfaceContainer mal_ifcont;

    //WHリンクの長さ
    int WH_size;

    //検知待機時間
    double wait_time;

    //エンド間の距離
    int end_distance;

    //シード値を決定するためのイテレーション
    int iteration;

  private:
    /// Create the nodes
    void CreateNodes();
    /// Create the devices
    void CreateDevices();
    /// Create the network
    void InstallInternetStack();
    /// Create the simulation applications
    void InstallApplications();
};

// 1ノード分のルーティングテーブルをファイルに書く
void PrintAllRoutingTables(Ptr<Node> node, Ptr<OutputStreamWrapper> stream)
{
    Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
    Ptr<Ipv4RoutingProtocol> rp = ipv4->GetRoutingProtocol();
    Ptr<aodv::RoutingProtocol> aodv = rp->GetObject<aodv::RoutingProtocol>();

    if (aodv)
    {
        aodv->PrintRoutingTable(stream);
    }
}

int
main(int argc, char** argv)
{
    AodvExample test;
    if (!test.Configure(argc, argv))
    {
        NS_FATAL_ERROR("Configuration failed. Aborted.");
    }

    test.Run();
    return 0;
}

//-----------------------------------------------------------------------------
AodvExample::AodvExample()
    : size(200),
      step(50),
      totalTime(10),
      pcap(true),
      printRoutes(true),
      WH_size(300),
      end_distance(600), //エンド間の距離
      iteration(1) //イテレーション
{
}

bool
AodvExample::Configure(int argc, char** argv)
{
    // Enable AODV logs by default. Comment this if too noisy
    // LogComponentEnable("AodvRoutingProtocol", LOG_LEVEL_ALL);

    std::random_device randomseed;
    // int rand = randomseed();

    SeedManager::SetSeed(1);

    CommandLine cmd(__FILE__);

    cmd.AddValue("pcap", "Write PCAP traces.", pcap);
    cmd.AddValue("printRoutes", "Print routing table dumps.", printRoutes);
    cmd.AddValue("size", "Number of nodes.", size);
    cmd.AddValue("time", "Simulation time, s.", totalTime);
    cmd.AddValue("step", "Grid step, m", step);
    cmd.AddValue("WH_size", "WH size", WH_size); //WHの長さ
    cmd.AddValue("end_distance", "end distance", end_distance); //エンド間の距離
    cmd.AddValue("iteration", "iteration", iteration); //イテレーション

    cmd.Parse(argc, argv);

    if(end_distance -WH_size - 110 < 30)
    {
        std::cerr << "エンド間の距離がWHリンクの長さよりも短いです。" << std::endl;
        return false;
    }

    return true;
}

void
AodvExample::Run()
{
    //  Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold", UintegerValue (1)); //
    //  enable rts cts all the time.
    CreateNodes();
    CreateDevices();
    InstallInternetStack();
    InstallApplications();

    std::cout << "Starting simulation for " << totalTime << " s ...\n";

    double dumpTime = 3.0;   // 出力タイミング（秒）

    Simulator::Schedule(Seconds(dumpTime), [this, dumpTime]() {

        Ptr<OutputStreamWrapper> stream =
            Create<OutputStreamWrapper>("aodv.routes", std::ios::out);

        for (uint32_t i = 0; i < nodes.GetN(); i++)
        {
            PrintAllRoutingTables(nodes.Get(i), stream);
        }

        std::cout << "*** AODV routing tables were written to aodv.routes at "
                  << dumpTime << " sec ***" << std::endl;
    });

    Simulator::Stop(Seconds(totalTime));
    Simulator::Run();
    Report(std::cout);
    Simulator::Destroy();
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
    //ノードをランダムに配置
    MobilityHelper mobility;
    mobility.SetPositionAllocator ("ns3::RandomRectanglePositionAllocator",
                                  "X", StringValue("ns3::UniformRandomVariable[Min=0|Max=800]"),
                                  "Y", StringValue("ns3::UniformRandomVariable[Min=0|Max=800]")
                                 );

    mobility.Install(nodes);

    AnimationInterface::SetConstantPosition (nodes.Get (0), 0, 400);
    AnimationInterface::SetConstantPosition (nodes.Get (1), 200, 400);  //WHノード
    AnimationInterface::SetConstantPosition (nodes.Get (2), 600, 400); //WHノード
    AnimationInterface::SetConstantPosition (nodes.Get (size - 1), 800, 400);
    // AnimationInterface::SetConstantPosition (nodes.Get (4), -20, 20);
    // AnimationInterface::SetConstantPosition (nodes.Get (5), -20, -20);
    // AnimationInterface::SetConstantPosition (nodes.Get (6), 220, 20);
    // AnimationInterface::SetConstantPosition (nodes.Get (7), 220, -20);
    
    //確認用
    // AnimationInterface::SetConstantPosition (nodes.Get (8), 50, 100);
    // AnimationInterface::SetConstantPosition (nodes.Get (9), 100, 100);
    // AnimationInterface::SetConstantPosition (nodes.Get (10), 30, 80);
    // AnimationInterface::SetConstantPosition (nodes.Get (11), 30, 120);
    // AnimationInterface::SetConstantPosition (nodes.Get (12), 120, 80);
    // AnimationInterface::SetConstantPosition (nodes.Get (13), 120, 120);

    //共通隣接ノード
    // AnimationInterface::SetConstantPosition (nodes.Get (14), 75, 120);

    // AnimationInterface::SetConstantPosition (nodes.Get (8), 250, 0);

    malicious.Add(nodes.Get(1)); //WH1
    malicious.Add(nodes.Get(2));//WH2
}

void
AodvExample::CreateDevices()
{
    WifiMacHelper wifiMac;
    wifiMac.SetType("ns3::AdhocWifiMac");
    
    Ptr<YansWifiChannel> wifiChannel = CreateObject<YansWifiChannel> ();

    Ptr<RangePropagationLossModel> rangeModel = CreateObject<RangePropagationLossModel> ();
    rangeModel->SetAttribute ("MaxRange", DoubleValue (100.0)); // 通信範囲を100mに設定

    wifiChannel->SetPropagationLossModel(rangeModel);
    wifiChannel->SetPropagationDelayModel(CreateObject<ConstantSpeedPropagationDelayModel>());

    YansWifiPhyHelper wifiPhy;
    //デフォルトの動作状態でチャネル ヘルパーを作成します。デフォルトでは、定数、光の速度に等しい伝播遅延、および基準距離 1m での基準損失 46.6777 dB の対数距離モデルに基づく伝播損失を持つチャネル モデルを作成します。
    wifiPhy.SetChannel(wifiChannel);

    //送信電力と受信電力を設定
    //送信電力と受信電力を設定
    // wifiPhy.Set("TxPowerStart", DoubleValue(24.7)); // 送信電力 20 dBm
    // wifiPhy.Set("TxPowerEnd", DoubleValue(24.7));

    WifiHelper wifi;
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode",
                                 StringValue("OfdmRate6Mbps"),
                                 "RtsCtsThreshold",
                                 UintegerValue(0));

    devices = wifi.Install(wifiPhy, wifiMac, nodes);

    PointToPointHelper pointToPoint;
    pointToPoint.SetDeviceAttribute ("DataRate", StringValue ("5Mbps"));
    pointToPoint.SetChannelAttribute ("Delay", StringValue ("2ms"));

    // NetDeviceContainer devices;
    mal_devices = pointToPoint.Install (malicious);

    if (pcap)
    {
        wifiPhy.EnablePcapAll(std::string("aodv"));
    }
}

void
AodvExample::InstallInternetStack()
{
    AodvHelper aodv;
    // you can configure AODV attributes here using aodv.Set(name, value)

    aodv.Set("WhMode", UintegerValue(2));  // 0 = 通常ノードのみ、1 = 提案手法のWH攻撃、2 = 既存手法のWH攻撃、3 = 外部WH攻撃
    InternetStackHelper stack;
    stack.SetRoutingHelper(aodv); // has effect on the next Install ()
    stack.Install(nodes);
    Ipv4AddressHelper address;
    address.SetBase("10.0.0.0", "255.0.0.0");
    interfaces = address.Assign(devices);

    address.SetBase("10.1.2.0", "255.255.255.0", "0.0.0.1");
    mal_ifcont = address.Assign (mal_devices);

    if (printRoutes)
    {
        Ptr<OutputStreamWrapper> routingStream =
            Create<OutputStreamWrapper>("aodv.routes", std::ios::out);
        Ipv4RoutingHelper::PrintRoutingTableAllAt(Seconds(8), routingStream);
    }

    // ---- 相手 WH ノードの P2P IP を設定 ----
    // mal_ifcont に割り当てた P2P のアドレス
    Ipv4Address wh1P2P = mal_ifcont.GetAddress(0); // 10.1.2.1
    Ipv4Address wh2P2P = mal_ifcont.GetAddress(1); // 10.1.2.2

    NS_LOG_UNCOND("WH node 1 IP=" << wh1P2P);
    NS_LOG_UNCOND("WH node 2 IP=" << wh2P2P);

    // ===============================
    // ① WH攻撃ノードの設定
    // ===============================
    // 攻撃者ノード
    Ptr<Node> wh1 = malicious.Get(0);
    Ptr<Node> wh2 = malicious.Get(1);

    // ---- WH1 の AODV を取得 ----
    Ptr<Ipv4> ipv4_1 = wh1->GetObject<Ipv4>();
    Ptr<Ipv4RoutingProtocol> rp1 = ipv4_1->GetRoutingProtocol();
    Ptr<aodv::RoutingProtocol> aodv1 = DynamicCast<aodv::RoutingProtocol>(rp1);

    // ---- WH2 の AODV を取得 ----
    Ptr<Ipv4> ipv4_2 = wh2->GetObject<Ipv4>();
    Ptr<Ipv4RoutingProtocol> rp2 = ipv4_2->GetRoutingProtocol();
    Ptr<aodv::RoutingProtocol> aodv2 = DynamicCast<aodv::RoutingProtocol>(rp2);

    // ---- 攻撃者フラグの設定 ----
    aodv1->SetIsWhNode(true);
    aodv2->SetIsWhNode(true);

    aodv1->SetWhPeer(wh2P2P); // WH1の相方は WH2
    aodv2->SetWhPeer(wh1P2P); // WH2の相方は WH1
}

void
AodvExample::InstallApplications()
{
    PingHelper ping(interfaces.GetAddress(size - 1));
    ping.SetAttribute("VerboseMode", EnumValue(Ping::VerboseMode::VERBOSE));

    ApplicationContainer p = ping.Install(nodes.Get(0));
    p.Start(Seconds(0));
    p.Stop(Seconds(totalTime) - Seconds(0.001));

    // move node away
    // Ptr<Node> node = nodes.Get(size / 2);
    // Ptr<MobilityModel> mob = node->GetObject<MobilityModel>();
    // Simulator::Schedule(Seconds(totalTime / 3),
    //                     &MobilityModel::SetPosition,
    //                     mob,
    //                     Vector(1e5, 1e5, 1e5));
}

void
AodvExample::Report(std::ostream& os)
{
    // ★ 出力ファイルを開く（追記 or 上書き）
    std::ofstream fout("aodv_result.log", std::ios::out);

    auto write = [&](auto const &msg) {
        os   << msg << std::endl;   // 標準出力
        fout << msg << std::endl;   // ファイル出力
    };

    write("==================== AODV PERFORMANCE REPORT ====================");

    uint32_t totalTP = 0, totalFN = 0, totalFP = 0, totalTN = 0, totalNA = 0;
    uint64_t totalBytes = 0;
    std::vector<double> latencies;

    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        Ptr<Ipv4> ipv4 = nodes.Get(i)->GetObject<Ipv4>();
        Ptr<Ipv4RoutingProtocol> rp = ipv4->GetRoutingProtocol();
        Ptr<aodv::RoutingProtocol> aodv = DynamicCast<aodv::RoutingProtocol>(rp);
        if (!aodv) continue;

        auto stats = aodv->Getevaluation();

        totalTP += stats.detectedWh;
        totalFN += stats.undetectedWh;
        totalFP += stats.falsePositive;
        totalTN += stats.truenegative;
        totalNA += stats.notApplicable;
        totalBytes += stats.totalAodvCtrlBytes;

        for (const auto &kv : stats.m_latencyTable)
        {
            const auto &entry = kv.second;
            if (entry.latency.GetSeconds() > 0)
                latencies.push_back(entry.latency.GetSeconds());
        }
    }

    double detectionRate = (totalTP + totalFN > 0)
                           ? (double)totalTP / (totalTP + totalFN)
                           : 0.0;

    double falsePositiveRate = (totalFP + totalTN > 0)
                               ? (double)totalFP / (totalFP + totalTN)
                               : 0.0;

    double avgLatency = 0.0;
    if (!latencies.empty()) {
        double sum = 0;
        for (double v : latencies) sum += v;
        avgLatency = sum / latencies.size();
    }

    write("WH Detection Rate        : " + std::to_string(detectionRate));
    write("False Positive Rate      : " + std::to_string(falsePositiveRate));
    write("Average Route Latency    : " + std::to_string(avgLatency) + " sec");
    write("");
    write("--- Detail Stats ---");
    write("TP  : " + std::to_string(totalTP));
    write("FN  : " + std::to_string(totalFN));
    write("FP  : " + std::to_string(totalFP));
    write("TN  : " + std::to_string(totalTN));
    write("NA  : " + std::to_string(totalNA));
    write("Detection Bytes : " + std::to_string(totalBytes) + " bytes");

    write("===============================================================");

    fout.close();
}



