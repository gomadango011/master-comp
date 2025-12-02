#ifndef WORMHOLE_HELPER_H
#define WORMHOLE_HELPER_H

#include "ns3/application-container.h"
#include "ns3/node-container.h"
#include "ns3/net-device.h"
#include "ns3/ipv4-address.h"

namespace ns3 {

class WormholeHelper
{
public:
  WormholeHelper ();

  ApplicationContainer InstallEntry (
      Ptr<Node> node,
      Ptr<NetDevice> dev,
      Ipv4Address peer,
      uint16_t port);

  ApplicationContainer InstallExit (
      Ptr<Node> node,
      Ptr<NetDevice> dev,
      Ipv4Address peer,
      uint16_t port);
};

} // namespace ns3

#endif
