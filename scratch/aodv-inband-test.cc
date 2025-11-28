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
    : size(4),
      step(50),
      totalTime(100),
      pcap(true),
      printRoutes(true)
{
}

bool
AodvExample::Configure(int argc, char** argv)
{
    // Enable AODV logs by default. Comment this if too noisy
    // LogComponentEnable("AodvRoutingProtocol", LOG_LEVEL_ALL);

    SeedManager::SetSeed(12345);
    CommandLine cmd(__FILE__);

    cmd.AddValue("pcap", "Write PCAP traces.", pcap);
    cmd.AddValue("printRoutes", "Print routing table dumps.", printRoutes);
    cmd.AddValue("size", "Number of nodes.", size);
    cmd.AddValue("time", "Simulation time, s.", totalTime);
    cmd.AddValue("step", "Grid step, m", step);

    cmd.Parse(argc, argv);
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
    YansWifiPhyHelper wifiPhy;
    YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default();
    wifiPhy.SetChannel(wifiChannel.Create());
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

    // // IFUP コールバックの登録
    // ipv4_1->TraceConnectWithoutContext(
    //     "InterfaceUp",
    //     MakeCallback(&aodv::RoutingProtocol::InitializeWhSockets, aodv1)
    // );
    // ipv4_2->TraceConnectWithoutContext(
    //     "InterfaceUp",
    //     MakeCallback(&aodv::RoutingProtocol::InitializeWhSockets, aodv2)
    // );

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
