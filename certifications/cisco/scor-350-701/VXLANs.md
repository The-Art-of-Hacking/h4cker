## VXLAN (Virtual Extensible LAN)

VXLAN is a network virtualization technology that addresses the scalability problems associated with large cloud computing deployments. It enables the creation of a logical network for virtual machines (VMs) across different networks.

Key aspects of VXLAN include:

- **MAC Address Space Extension**: VXLAN expands the Layer 2 network address space by using a 24-bit VXLAN Network Identifier (VNI), allowing for up to 16 million unique identifiers.
- **Overlay Networks**: It operates as an overlay network, encapsulating Ethernet frames in UDP packets for transport across the underlying IP network.
- **Tunneling**: VXLAN tunnels allow Layer 2 traffic to traverse Layer 3 networks, enabling the creation of distributed logical networks across geographically dispersed data centers.
- **Compatibility**: It works with existing virtualization technologies and doesn’t require any changes to the VMs or applications running on top of it.

Limitations of VXLAN include potential network complexity, increased overhead due to encapsulation, and the need for compatible network hardware and software that can handle VXLAN encapsulation and de-encapsulation.

### Network Overlays

Network overlays are a method of using software to virtually create layers of network abstraction that can be run over a physical network. This concept is integral to Software-Defined Networking (SDN).

Key aspects of network overlays include:

- **Abstraction**: Overlays abstract the underlying physical network, allowing for the creation of virtual networks that are decoupled from the physical topology.
- **Flexibility**: They provide flexibility in defining network topologies, policies, and services independent of the underlying hardware.
- **Agility**: Network overlays facilitate rapid provisioning and reconfiguration of network resources, aligning network capabilities with the dynamic nature of virtualized compute resources.
- **Efficiency**: They can optimize traffic flows and improve network utilization by bypassing traditional network hierarchies.

Limitations of network overlays include potential overhead due to encapsulation, challenges in visibility and troubleshooting across the overlay and underlay networks, and the need for coordination between overlay and underlay networks to ensure efficient operation.

