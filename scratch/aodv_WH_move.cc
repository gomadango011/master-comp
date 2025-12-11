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

    //検知待機時間
    double wait_time;

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

    AnimationInterface* anim = new AnimationInterface("anim.xml");

    Simulator::Run();

    Simulator::Destroy();

    // delete anim;
   
    test.Report(std::cout);

    return 0;
}

//-----------------------------------------------------------------------------
AodvExample::AodvExample()
    : size(400),
      step(),
      totalTime(20),
      //pcapファイルでログを取得したい場合はtrueにする
      pcap(false),
      printRoutes(false),
      RREP_log(1),  //RREPのログを取得(1:ログ取得、0:ログ取得しない)
      result_file("deff/p-log"), //結果を保存するファイル
      //result_mode(0)
      WH_size(350),
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
    int rand = randomseed();

    CommandLine cmd(__FILE__);

    cmd.AddValue("pcap", "Write PCAP traces.", pcap);
    cmd.AddValue("printRoutes", "Print routing table dumps.", printRoutes);
    cmd.AddValue("size", "Number of nodes.", size);
    cmd.AddValue("time", "Simulation time, s.", totalTime);
    cmd.AddValue("step", "Grid step, m", step);
    cmd.AddValue("result_file", "result file", result_file);
    //cmd.AddValue("result_mode", "result mode", result_mode); //1=ご検知率と検知コスト　2=検知率　3=経路作成時間
    cmd.AddValue("WH_size", "WH size", WH_size); //WHの長さ
    cmd.AddValue("wait_time", "Detection wait time", wait_time); //検知待機時間
    cmd.AddValue("end_distance", "end distance", end_distance); //エンド間の距離
    cmd.AddValue("iteration", "iteration", iteration); //イテレーション

    cmd.Parse(argc, argv);

    SeedManager::SetSeed(rand);

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
    //RREPのログを取得
    if(RREP_log == 1)
    {
        std::ofstream ofs3("p-log/RREP_log.txt", std::ios::trunc);  // truncで既存の内容を削除
    }

    CreateNodes();
    CreateDevices();
    InstallInternetStack();
    InstallApplications();

    std::cout << "Starting simulation for " << totalTime << " s ...\n";

    

    Simulator::Stop(Seconds(totalTime));

}

void
AodvExample::Report(std::ostream&)
{
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
        if(i == 0 || i == size - 1 || i == 1 || i == 2) {
           // 固定ノードとして追加
            fixedNodes.Add(nodes.Get(i));
        }
        else
        {
            // 移動ノードとして追加
            mobileNodes.Add(nodes.Get(i));
        }
    }


    
    //ノードをランダムに配置
    MobilityHelper mobility;
    mobility.SetPositionAllocator ("ns3::RandomRectanglePositionAllocator",
                                  "X", StringValue("ns3::UniformRandomVariable[Min=0|Max=800]"),
                                  "Y", StringValue("ns3::UniformRandomVariable[Min=0|Max=800]")
                                 ); 

                                 //ノードを移動させる
    mobility.SetMobilityModel ("ns3::RandomWalk2dMobilityModel",
                                "Bounds", RectangleValue (Rectangle (0, 800, 0, 800)),
                               "Speed", StringValue("ns3::UniformRandomVariable[Min=3|Max=14]"),
                               "Distance", DoubleValue(50.0)
                            );
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

    mobility.Install (mobileNodes);

    MobilityHelper fixedMobility;

    // 固定ノードの位置を設定
    Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator>();
    positionAlloc->Add(Vector(0, 400, 0));  //送信者の位置情報　ID=0
    positionAlloc->Add(Vector(end_distance - WH_size - 110, 400, 0));  //WH1の位置情報
    positionAlloc->Add(Vector(end_distance - 110, 400, 0));  //WH2の位置情報
    positionAlloc->Add(Vector(end_distance, 400, 0));  //受信者の位置情報  ID=size-1

    fixedMobility.SetPositionAllocator(positionAlloc);
    
    fixedMobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");

    fixedMobility.Install (fixedNodes);

    // for (uint32_t i = 0; i < nodes.GetN(); ++i)
    // {
    //     Ptr<Node> node = nodes.Get(i);
    //     Ptr<MobilityModel> mobility = node->GetObject<MobilityModel>();

    //     if (node && mobility)
    //     {
    //         Vector pos = mobility->GetPosition();
    //         anim.UpdatePosition(node, pos);  // ★これがないとクラッシュ
    //     }
    // }

    // Ptr<MobilityModel> sender = nodes.Get(0)->GetObject<MobilityModel>();
    // Ptr<MobilityModel> receiver = nodes.Get(size - 1)->GetObject<MobilityModel>();
    // Ptr<MobilityModel> WH1 = nodes.Get(1)->GetObject<MobilityModel>();
    // Ptr<MobilityModel> WH2 = nodes.Get(2)->GetObject<MobilityModel>();

    // sender->SetPosition(Vector(0, 400, 0)); //送信者の位置を設定
    // receiver->SetPosition(Vector(end_distance, 400, 0)); //受信者の位置を設定
    // WH1->SetPosition(Vector(end_distance - WH_size - 110, 400, 0)); //WH1の位置を設定
    // WH2->SetPosition(Vector(end_distance - 110, 400, 0)); //WH2の位置を設定

    //AnimationInterface anim ("wormhole.xml"); // Mandatory
    // AnimationInterface::SetConstantPosition (nodes.Get (0), 0, 400); //送信者
    // AnimationInterface::SetConstantPosition (nodes.Get (size - 1), end_distance, 400); //受信者

    // AnimationInterface::SetConstantPosition (nodes.Get (1), end_distance -WH_size - 110 , 400); //WH1
    // AnimationInterface::SetConstantPosition (nodes.Get (2), end_distance - 110, 400); //WH2

    // //2つ目の経路作成ノード
    // AnimationInterface::SetConstantPosition (nodes.Get (3), 0, 125); //送信者
    // AnimationInterface::SetConstantPosition (nodes.Get (size -2), 500, 375); //受信者

    // //3つ目の経路作成ノード
    // AnimationInterface::SetConstantPosition (nodes.Get (4), 0, 375); //送信者
    // AnimationInterface::SetConstantPosition (nodes.Get (size -3), 500, 125); //受信者

    // WHノードをノードコンテナに追加
    malicious.Add(nodes.Get(1)); //WH1
    malicious.Add(nodes.Get(2));//WH2

    //anim.EnablePacketMetadata(true);

    // mobility.Install(nodes);

    // mobility.SetMobilityModel ("ns3::RandomWalk2dMobilityModel",
    //                          "Bounds", RectangleValue (Rectangle (-50, 50, -50, 50)));
    // mobility.Install (nodes);

    // NetAnim ビジュアライザー設定
    // AnimationInterface anim("anim.xml");

    // // ビジュアライザーのスクリーンショット設定
    // Config::Set("/Visualizer/KeyPressEvent/Capture", BooleanValue(true));

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

    aodv.Set("DestinationOnly", BooleanValue(true));
    //WHリンクの長さを設定
    aodv.Set("WHLinkLength", UintegerValue(WH_size));
    //検知待機時間を設定
    aodv.Set("WaitTime", TimeValue(Seconds(wait_time)));
    //エンド間の距離を設定
    aodv.Set("EndDistance", UintegerValue(end_distance));

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

    //nodeにファイルの情報を追加
    for (NodeContainer::Iterator it = nodes.Begin(); it != nodes.End(); ++it)
    {
       Ptr<Node> node = *it;
       //ipv4 = node->GetObject<Ipv4>();
       node->Setfile(absPath);

       std::cout << node->Getfile() << std::endl;
    }
}

void
AodvExample::InstallApplications()
{
    //1つ目の送信元ノード
    PingHelper ping_250(interfaces.GetAddress(size - 1));
    ping_250.SetAttribute("VerboseMode", EnumValue(Ping::VerboseMode::VERBOSE));

    ApplicationContainer p = ping_250.Install(nodes.Get(0));

    // //2つ目の送信元ノード
    // PingHelper ping_125(interfaces.GetAddress(size - 2));
    // ping_125.SetAttribute("VerboseMode", EnumValue(Ping::VerboseMode::VERBOSE));

    // ApplicationContainer p2 = ping_125.Install(nodes.Get(3));

    // //3つ目の送信元ノード
    // PingHelper ping_375(interfaces.GetAddress(size - 3));
    // ping_375.SetAttribute("VerboseMode", EnumValue(Ping::VerboseMode::VERBOSE));

    // ApplicationContainer p3 = ping_375.Install(nodes.Get(4));
    

    //それぞれの送信元ノードがpingをスタート
    p.Start(Seconds(0));
    p.Stop(Seconds(totalTime) - Seconds(0.001));

    // p2.Start(Seconds(0));
    // p2.Stop(Seconds(totalTime) - Seconds(0.001));
    // p3.Start(Seconds(0));
    // p3.Stop(Seconds(totalTime) - Seconds(0.001));

    // move node away
    // Ptr<Node> node = nodes.Get(size / 2);
    // Ptr<MobilityModel> mob = node->GetObject<MobilityModel>();
    // Simulator::Schedule(Seconds(totalTime / 3),
    //                     &MobilityModel::SetPosition,
    //                     mob,
    //                     Vector(1e5, 1e5, 1e5));
}
