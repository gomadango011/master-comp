/*
 * Copyright (c) 2009 IITP RAS
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
#include "ns3/animation-interface.h"
#include "ns3/netanim-module.h"
#include <ns3/aodv-helper.h>
#include <ns3/node-container.h>
#include "ns3/applications-module.h"

#include <cmath>
#include <iostream>
#include <random>
#include <fstream>
#include <filesystem>
#include <limits.h>
#include <stdio.h>

#include <algorithm>

namespace fs = std::filesystem;
using namespace ns3;

/**
 * \defgroup aodv-examples AODV Examples
 * \ingroup aodv
 * \ingroup examples
 */

/**
 * \ingroup aodv-examples
 * \ingroup examples
 * \brief Test script.
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

NodeContainer nodes;

//WHノード
NodeContainer malicious;
//固定ノード
NodeContainer fixedNodes;
//移動ノード
NodeContainer mobileNodes;

std::ofstream ofs;

//ファイルを更新または作成
void
OpenLogFileOverwrite(std::ofstream& ofs, const std::string& filepath)
{
    fs::path p(filepath);

    // 親ディレクトリが無ければ作成
    if (!p.parent_path().empty())
    {
        fs::create_directories(p.parent_path());
    }

    // 上書きモードで open（存在すれば中身は消える）
    ofs.open(filepath, std::ios::out | std::ios::app);

    if (!ofs.is_open())
    {
        NS_FATAL_ERROR("Cannot open result file: " << filepath);
    }
}

// AnimationInterface* anim = new AnimationInterface("anim.xml");

class AodvExample
{
  public:

    //保存用のファイルを返す関数
    std::string GetResultFile() const { return result_file; }

    //resulut_modeを返す関数
    int GetResultMode() const { return result_mode; }
    

    AodvExample();
    /**
     * \brief Configure script parameters
     * \param argc is the command line argument count
     * \param argv is the command line arguments
     * \return true on successful configuration
     */
    bool Configure(int argc, char** argv);
    /// Run simulation
    void Run();
    /**
     * Report results
     * \param os the output stream
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

    //RREPのログを取得
    int RREP_log;

    //結果を保存するファイル
    std::string result_file;

    //結果を保存するモード
    int result_mode;

    //WHリンクの長さ
    int WH_size;

    //エンド間の距離
    int end_distance;

    //シード値を決定するためのイテレーション
    int iteration;

    // network
    /// nodes used in the example
    // NodeContainer nodes;
    /// devices used in the example
    NetDeviceContainer devices, mal_devices;
    /// interfaces used in the example
    Ipv4InterfaceContainer interfaces;

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

std::string def = "p-log/packet-num.txt"; // コピー先ファイル
int counter = 1;
std::string newFilename;
std::string p_file;
std::string absPath;
// // AODVパケットを追跡するコールバック関数
// void AodvPacketTracer(Ptr<const Packet> packet, const Ipv4Header &header, uint32_t interface) {
//     totalAodvPacketSize += packet->GetSize();
//     aodvPacketCount++;
//     std::cout << "AODV Packet: " << packet->GetSize() << " bytes" << std::endl;
// }

// ファイルがすでに存在する場合に新しいファイル名を生成
std::string GenerateUniqueFilename(const std::string &filename) {
    if (!fs::exists(filename)) {
        return filename; // ファイルが存在しない場合はそのまま使用
    }

    std::string baseName = filename.substr(0, filename.find_last_of('.'));
    std::string extension = filename.substr(filename.find_last_of('.'));
    
    do {
        newFilename = baseName + "_" + std::to_string(counter) + extension;
        counter++;
    } while (fs::exists(newFilename)); // 新しい名前が存在しなくなるまで繰り返す

    

    //std::cout << node->Getfile() << std::endl;

    return newFilename;
}

std::string uniqueDestination;

// ファイルをコピー
// bool CopyFile(const std::string &source, const std::string &destination) {
//     // std::ifstream srcFile(source, std::ios::binary);
//     // if (!srcFile.is_open()) {
//     //     std::cerr << "ソースファイルを開けませんでした: " << source << std::endl;
//     //     return false;
//     // }

//     uniqueDestination = GenerateUniqueFilename(destination);

//     std::ofstream destFile(uniqueDestination, std::ios::binary);
//     if (!destFile.is_open()) {
//         std::cerr << "コピー先ファイルを開けませんでした: " << uniqueDestination << std::endl;
//         return false;
//     }

//     // destFile << srcFile.rdbuf(); // ファイル内容をコピー

//     destFile.close();

//     std::cout << "ファイルをコピーしました: " << source << " -> " << uniqueDestination << std::endl;
//     return true;
// }

int main(int argc, char** argv)
{
    AodvExample test;
    if (!test.Configure(argc, argv))
    {
        NS_FATAL_ERROR("Configuration failed. Aborted.");
    }

    test.Run();

    // AnimationInterface* anim = new AnimationInterface("anim.xml");

    return 0;
}

//-----------------------------------------------------------------------------
AodvExample::AodvExample()
    : size(400),
      step(),
      totalTime(10),
      //pcapファイルでログを取得したい場合はtrueにする
      pcap(false),
      printRoutes(false),
      RREP_log(1),  //RREPのログを取得(1:ログ取得、0:ログ取得しない)
      result_file("deff/p-log"), //結果を保存するファイル
      result_mode(2),
      WH_size(300),
      end_distance(1000), //エンド間の距離
      iteration(1) //イテレーション
{
}

bool
AodvExample::Configure(int argc, char** argv)
{
    // Enable AODV logs by default. Comment this if too noisy
    // LogComponentEnable("AodvRoutingProtocol", LOG_LEVEL_ALL);

    // std::random_device randomseed;
    // int rand = randomseed();

    CommandLine cmd(__FILE__);

    cmd.AddValue("pcap", "Write PCAP traces.", pcap);
    cmd.AddValue("printRoutes", "Print routing table dumps.", printRoutes);
    cmd.AddValue("size", "Number of nodes.", size);
    cmd.AddValue("time", "Simulation time, s.", totalTime);
    cmd.AddValue("step", "Grid step, m", step);
    cmd.AddValue("result_file", "result file", result_file);
    //cmd.AddValue("result_mode", "result mode", result_mode); //1=ご検知率と検知コスト　2=検知率　3=経路作成時間
    cmd.AddValue("WH_size", "WH size", WH_size); //WHの長さ
    cmd.AddValue("end_distance", "end distance", end_distance); //エンド間の距離
    cmd.AddValue("iteration", "iteration", iteration); //イテレーション

    cmd.Parse(argc, argv);

    SeedManager::SetSeed(iteration);

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
    CreateNodes();
    CreateDevices();
    InstallInternetStack();
    InstallApplications();

    std::cout << "Starting simulation for " << totalTime << " s ...\n";

    

    Simulator::Stop(Seconds(totalTime));
    Simulator::Run();
    Report(std::cout);
    Simulator::Destroy();

}

void
AodvExample::Report(std::ostream& os)
{
    // ★ 出力ファイルを開く（追記 or 上書き）
    OpenLogFileOverwrite(ofs, result_file);

    uint32_t totalTP = 0, totalFN = 0, totalFP = 0, totalTN = 0, totalNA = 0;
    uint64_t totalBytes = 0;
    std::vector<double> latencies;

    // ===== ヘッダはファイルが空のときだけ =====
    static bool headerWritten = false;
    if (!headerWritten)
    {
        ofs << "seed,nodes,wh_mode,end_distance,"
            << "tp,fn,fp,tn,"
            << "wh_detection_rate,false_positive_rate,"
            << "total_ctrl_bytes,avg_route_latency\n";
        headerWritten = true;
    }

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

     ofs << iteration << ","
        << size << ","
        << 2 << ","               // WhMode
        << end_distance << ","
        << totalTP << ","
        << totalFN << ","
        << totalFP << ","
        << totalTN << ","
        << detectionRate << ","
        << falsePositiveRate << ","
        << totalBytes << ","
        << avgLatency << "\n";

    ofs.close();
}

void
AodvExample::CreateNodes()
{
    //std::cout << "Creating " << (unsigned)size << " nodes " << step << " m apart.\n";
    nodes.Create(size);

    // Name nodes
    for (uint32_t i = 0; i < size; ++i)
    {
        std::ostringstream os;
        os << "node-" << i;
        Names::Add(os.str(), nodes.Get(i));
    }

    for (uint32_t i = 0; i < size; ++i) {
        if(i == 0 || i == size - 1 
            || i == 1 || i == 2 //WHノード
            || i == 3 || i == 4 //送受信ノード
            || i == 5 || i == 6 //送受信ノード
            ) {
           // 固定ノードとして追加
            fixedNodes.Add(nodes.Get(i));
        }
        else
        {
            // 移動ノードとして追加
            mobileNodes.Add(nodes.Get(i));
        }
    }

    uint32_t total = mobileNodes.GetN();
    uint32_t half  = total / 2;

    NodeContainer carNodes;
    NodeContainer pedestrianNodes;

    for (uint32_t i = 0; i < total; ++i)
    {
        if (i < half)
        {
            carNodes.Add(mobileNodes.Get(i));
        }
        else
        {
            pedestrianNodes.Add(mobileNodes.Get(i));
        }
    }
    
    // ===============================
    // 共通 PositionAllocator ノードをランダムに配置
    // ===============================
    Ptr<PositionAllocator> positionAlloc =
        CreateObject<RandomRectanglePositionAllocator>();
    positionAlloc->SetAttribute("X",
        StringValue("ns3::UniformRandomVariable[Min=0|Max=800]"));
    positionAlloc->SetAttribute("Y",
        StringValue("ns3::UniformRandomVariable[Min=0|Max=800]"));

    // ===============================
    // 自動車ノード（11–16 m/s）
    // ===============================
    MobilityHelper carMobility;
    carMobility.SetPositionAllocator(positionAlloc);
    carMobility.SetMobilityModel(
        "ns3::RandomWaypointMobilityModel",
        "Speed", StringValue("ns3::UniformRandomVariable[Min=11.0|Max=16.0]"),
        "Pause", StringValue("ns3::ConstantRandomVariable[Constant=0.0]"),
        "PositionAllocator", PointerValue(positionAlloc)
    );
    carMobility.Install(carNodes);

    // ===============================
    // 歩行者ノード（1–5 m/s）
    // ===============================
    MobilityHelper pedestrianMobility;
    pedestrianMobility.SetPositionAllocator(positionAlloc);
    pedestrianMobility.SetMobilityModel(
        "ns3::RandomWaypointMobilityModel",
        "Speed", StringValue("ns3::UniformRandomVariable[Min=1.0|Max=5.0]"),
        "Pause", StringValue("ns3::ConstantRandomVariable[Constant=0.0]"),
        "PositionAllocator", PointerValue(positionAlloc)
    );
    pedestrianMobility.Install(pedestrianNodes);

    //                              //ノードを移動させる
    // mobility.SetMobilityModel ("ns3::RandomWalk2dMobilityModel",
    //                             "Bounds", RectangleValue (Rectangle (0, 800, 0, 800)),
    //                            "Speed", StringValue("ns3::UniformRandomVariable[Min=3|Max=14]"),
    //                            "Distance", DoubleValue(50.0)
    //                         );
    // mobility.SetMobilityModel ("ns3::RandomWaypointMobilityModel",
    // "Speed", StringValue ("ns3::ConstantRandomVariable[Constant=5.0]"),
    // "Pause", StringValue ("ns3::ConstantRandomVariable[Constant=2.0]")
    // );

    // mobility.SetMobilityModel("ns3::RandomWalk2dMobilityModel",
    // "Bounds", RectangleValue(Rectangle(0, 800, 0, 800)),
    // "Speed", StringValue("ns3::UniformRandomVariable[Min=2|Max=5]")
    // "Time", TimeValue(Seconds(2))
    // );

    // mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");

    // mobility.Install (mobileNodes);

    MobilityHelper fixedMobility;

    // 固定ノードの位置を設定
    Ptr<ListPositionAllocator> fixedpositionAlloc = CreateObject<ListPositionAllocator>();
    fixedpositionAlloc->Add(Vector(0, 500, 0));  //送信者の位置情報　ID=0

    fixedpositionAlloc->Add(Vector(end_distance - WH_size - 150, 500, 0));  //WH1の位置情報　ID:1
    fixedpositionAlloc->Add(Vector(end_distance - 150, 500, 0));  //WH2の位置情報            ID:2

    fixedpositionAlloc->Add(Vector(0, 600, 0));  //送信ノード２            ID:3
    fixedpositionAlloc->Add(Vector(end_distance, 400, 0));  //受信ノード2         ID:4

    fixedpositionAlloc->Add(Vector(0, 400, 0));  //送信ノード３           ID:5
    fixedpositionAlloc->Add(Vector(end_distance, 600, 0));  //受信者ノード3  ID:6
    
    fixedpositionAlloc->Add(Vector(end_distance, 500, 0));  //受信者の位置情報  ID=size-1

    fixedMobility.SetPositionAllocator(fixedpositionAlloc);
    
    fixedMobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");

    fixedMobility.Install (fixedNodes);

    // WHノードをノードコンテナに追加
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
    rangeModel->SetAttribute ("MaxRange", DoubleValue (50.0)); // 通信範囲を100mに設定

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

    aodv.Set("DestinationOnly", BooleanValue(false));
    //エンド間の距離を設定
    aodv.Set("WhMode", UintegerValue(2));  // 0 = 通常ノードのみ、1 = 提案手法のWH攻撃、2 = 既存手法のWH攻撃、3 = 外部WH攻撃

    InternetStackHelper stack;
    stack.SetRoutingHelper(aodv); // has effect on the next Install ()
    stack.Install(nodes);
    Ipv4AddressHelper address;
    address.SetBase("10.0.0.0", "255.0.0.0");
    interfaces = address.Assign(devices);

    address.SetBase ("10.1.2.0", "255.255.255.0", "0.0.0.1");
    Ipv4InterfaceContainer mal_ifcont = address.Assign (mal_devices);

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
    // ================================
    // 1つ目の送信ノード（ID = 0 → 受信者 ID = size - 1）
    // ================================
    Ipv4Address dst1 = interfaces.GetAddress(size - 1); // 受信者
    PingHelper ping1(dst1);
    ping1.SetAttribute("VerboseMode", EnumValue(Ping::VerboseMode::VERBOSE));
    ApplicationContainer app1 = ping1.Install(nodes.Get(0));  // 送信者
    app1.Start(Seconds(3));
    app1.Stop(Seconds(totalTime) - Seconds(0.001));


    // ================================
    // 2つ目の送信ノード（ID = 3 → 受信者 ID = 4）
    // ================================
    Ipv4Address dst2 = interfaces.GetAddress(4);
    PingHelper ping2(dst2);
    ping2.SetAttribute("VerboseMode", EnumValue(Ping::VerboseMode::VERBOSE));
    ApplicationContainer app2 = ping2.Install(nodes.Get(3));  // 送信者
    app2.Start(Seconds(3));
    app2.Stop(Seconds(totalTime) - Seconds(0.001));


    // ================================
    // 3つ目の送信ノード（ID = 5 → 受信者 ID = 6）
    // ================================
    Ipv4Address dst3 = interfaces.GetAddress(6);
    PingHelper ping3(dst3);
    ping3.SetAttribute("VerboseMode", EnumValue(Ping::VerboseMode::VERBOSE));
    ApplicationContainer app3 = ping3.Install(nodes.Get(5));  // 送信者
    app3.Start(Seconds(3));
    app3.Stop(Seconds(totalTime) - Seconds(0.001));
}
