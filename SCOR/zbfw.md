# Tips and Resources about Zone-based Firewalls

## Deployment and Configuration Guides
- [Security Configuration Guide: Zone-Based Policy Firewall](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_data_zbf/configuration/15-mt/sec-data-zbf-15-mt-book/sec-zone-pol-fw.html)
- [Zone-Based Policy Firewall Design and Application Guide](https://www.cisco.com/c/en/us/support/docs/security/ios-firewall/98628-zone-design-guide.html)
- [Configuring ZBFW from GeeksforGeeks](https://www.geeksforgeeks.org/zone-based-firewall/)

## Rules For Applying Zone-Based Policy Firewall
- Router network interfaces’ membership in zones is subject to several rules that govern interface behavior, as is the traffic moving between zone member interfaces:
- A zone must be configured before interfaces can be assigned to the zone.
- An interface can be assigned to only one security zone.
- All traffic to and from a given interface is implicitly blocked when the interface is assigned to a zone, except traffic to and from other interfaces in the same zone, and traffic to any interface on the router.
- Traffic is implicitly allowed to flow by default among interfaces that are members of the same zone.
- In order to permit traffic to and from a zone member interface, a policy allowing or inspecting traffic must be configured between that zone and any other zone.
- The self zone is the only exception to the default deny all policy. All traffic to any router interface is allowed until traffic is explicitly denied.
- Traffic cannot flow between a zone member interface and any interface that is not a zone member. Pass, inspect, and drop actions can only be applied between two zones.
- Interfaces that have not been assigned to a zone function as classical router ports and might still use classical stateful inspection/CBAC configuration.
- If it is required that an interface on the box not be part of the zoning/firewall policy. It might still be necessary to put that interface in a zone and configure a pass all policy (sort of a dummy policy) between that zone and any other zone to which traffic flow is desired.
- From the preceding it follows that, if traffic is to flow among all the interfaces in a router, all the interfaces must be part of the zoning model (each interface must be a member of one zone or another).
- The only exception to the preceding deny by default approach is the traffic to and from the router, which will be permitted by default. An explicit policy can be configured to restrict such traffic.
