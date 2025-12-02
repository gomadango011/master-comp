#include "out-band-WH-helper.h"
#include "ns3/out-band-WH.h"

namespace ns3 {

WormholeHelper::WormholeHelper () {}

ApplicationContainer
WormholeHelper::InstallEntry (Ptr<Node> node, Ptr<NetDevice> dev,
                              Ipv4Address peer, uint16_t port)
{
  Ptr<WormholeApp> app = CreateObject<WormholeApp> ();
  app->Setup (dev, peer, port);
  node->AddApplication (app);
  return ApplicationContainer (app);
}

ApplicationContainer
WormholeHelper::InstallExit (Ptr<Node> node, Ptr<NetDevice> dev,
                             Ipv4Address peer, uint16_t port)
{
  Ptr<WormholeApp> app = CreateObject<WormholeApp> ();
  app->Setup (dev, peer, port);
  node->AddApplication (app);
  return ApplicationContainer (app);
}

} // namespace ns3
