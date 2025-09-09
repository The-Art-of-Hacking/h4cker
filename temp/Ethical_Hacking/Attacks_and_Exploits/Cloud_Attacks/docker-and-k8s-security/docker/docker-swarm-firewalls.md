# Docker Swarm and Linux Firewall Implementations

By default, Docker Swarm uses an overlay network that encapsulates network traffic, making it difficult for firewall rules to filter or control the traffic. To handle this problem and enforce firewall rules effectively in a Docker Swarm environment, you can follow these steps:

1. **Disable Docker's built-in firewall management**: Docker includes its own firewall management, which can conflict with external firewalls like firewalld. Disable Docker's built-in firewall management by setting the `iptables` parameter in the Docker daemon configuration to "false". This ensures that Docker does not interfere with the external firewall rules.

2. **Configure firewall rules using firewalld**: Use firewalld or any other firewall management tool to define the desired rules for your Docker Swarm environment. Create appropriate rules to allow necessary ingress and egress traffic to and from the swarm nodes, including control plane and worker nodes.

3. **Configure the Docker daemon to use the external firewall**: Modify the Docker daemon configuration (`/etc/docker/daemon.json`) to use the external firewall rules. Add the `"iptables": false` option to the configuration file. This prevents Docker from altering the firewall rules, enabling the external firewall to control the network traffic.

4. **Restart the Docker daemon**: After making the changes, restart the Docker daemon to apply the updated configuration.

5. **Verify firewall rules and connectivity**: Ensure that the firewall rules are correctly applied and verify the connectivity to the Docker Swarm cluster. Test communication between nodes and services within the Swarm to ensure that the firewall rules are effectively enforced.

By disabling Docker's built-in firewall management and configuring the external firewall to handle the traffic, you can regain control over the network traffic and effectively secure your Docker Swarm installation while utilizing firewalld or any other firewall management tool of your choice.

**Note**: Docker Swarm relies on specific network ports for inter-node communication, so ensure that the necessary ports are appropriately configured in your firewall rules to allow communication within the Swarm cluster. Remember to consult the documentation and specific guides for your firewall management tool (e.g., firewalld, iptables, etc.) for detailed instructions on configuring rules and managing network traffic.

- **iptables**: iptables is a widely used and powerful firewall utility in Linux. It is a command-line tool for configuring the Linux kernel's netfilter firewall system. iptables provides extensive control over network traffic by allowing you to define rules based on IP addresses, ports, protocols, and more.

- **UFW (Uncomplicated Firewall):** UFW is a user-friendly frontend for iptables that simplifies the process of configuring a firewall. It provides an easy-to-use command-line interface and supports basic firewall operations such as allowing or blocking incoming and outgoing traffic based on port numbers or application profiles.

- **nftables:** nftables is the successor to iptables and provides a more modern and flexible framework for packet filtering and network address translation (NAT) in Linux. nftables allows you to define firewall rules using a more streamlined syntax and offers improved performance compared to iptables.

Here are the documentation links for iptables, UFW, and nftables:

1. **iptables**:
   - [iptables Tutorial](https://www.netfilter.org/documentation/index.html)
   - [iptables Man Page](https://man7.org/linux/man-pages/man8/iptables.8.html)

2. **UFW**:
   - [UFW Documentation](https://help.ubuntu.com/community/UFW)
   - [UFW Man Page](https://manpages.ubuntu.com/manpages/bionic/man8/ufw.8.html)

3. **nftables**:
   - [nftables wiki](https://wiki.nftables.org/)
   - [nftables in the Linux kernel documentation](https://www.kernel.org/doc/Documentation/networking/nftables.txt)

These resources provide comprehensive information, tutorials, and reference documentation to help you understand and effectively use iptables, UFW, and nftables for managing firewall rules on your Linux system.

| Feature           | iptables                                                     | UFW                                                               | nftables                                                         |
|-------------------|--------------------------------------------------------------|-------------------------------------------------------------------|------------------------------------------------------------------|
| Syntax            | Command-line tool with complex syntax                        | Command-line tool with simplified syntax                          | Command-line tool with a more streamlined and modern syntax      |
| Rule Management   | Allows fine-grained control over firewall rules               | Simplifies firewall configuration with easy-to-use syntax         | Provides a flexible and improved framework for packet filtering  |
| Firewall Backend  | Uses netfilter framework in the Linux kernel                  | Built on top of iptables or nftables                              | Built on top of nftables                                         |
| Ease of Use       | Can be complex for beginners due to the extensive options     | Provides an easy-to-use interface and simplified rule management | Offers a more user-friendly syntax compared to iptables          |
| User Interface    | Command-line interface                                        | Command-line interface                                           | Command-line interface                                           |
| Default on Distro | Default firewall management tool on many Linux distributions | Default firewall management tool on Ubuntu                       | May require installation on some distributions                   |
| Customizability   | Highly customizable with granular control over rule creation  | Allows customization through configuration files                 | Highly customizable with support for complex rule expressions    |
| Community Support | Well-established and widely used with extensive documentation | Strong community support and documentation                       | Growing community support with increasing adoption               |

Please note that the choice between these firewall management tools depends on your specific needs, familiarity with the tool, and the Linux distribution you are using. Consider evaluating each tool's features, syntax, and community support to determine the best fit for your requirements.


## Docker Swarm Common Ports
Docker Swarm relies on specific network ports for inter-node communication and coordination within the swarm cluster. Here are the ports commonly used by Docker Swarm:

1. TCP Port 2377: This port is used for the cluster management and communication between the Docker Swarm manager nodes. It is required to be open on all swarm manager nodes.

2. UDP Port 7946: This port is used for communication among swarm nodes for overlay network traffic, including container-to-container and service-to-service communication. It should be allowed on all swarm nodes, both managers and workers.

3. UDP Port 4789: This port is used for overlay network traffic using the VXLAN protocol. It allows swarm nodes to communicate with each other across different networks or hosts. UDP port 4789 should be open on all swarm nodes.

Additionally, if you are using Docker Swarm with a service that requires published ports, such as a web application, you need to consider the necessary ports for that particular service as well. These ports should be explicitly exposed and published when creating the service in the swarm.

It's important to note that the ports mentioned above are the default ports used by Docker Swarm. However, you can customize these ports during the swarm initialization process using the `--advertise-addr` and `--publish-addr` options.

When configuring your firewall rules, ensure that these ports are allowed for inbound and outbound traffic within the swarm cluster to enable proper communication between swarm nodes and services.

Always refer to the official Docker documentation and specific guides for Docker Swarm for the most up-to-date information regarding ports and network requirements.
