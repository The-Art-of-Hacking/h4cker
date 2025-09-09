# Example of a Network Policy in Kubernetes
In this example, we have created a network policy named `my-network-policy` that applies to pods with the label `app: my-app`.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: my-network-policy
spec:
  podSelector:
    matchLabels:
      app: my-app
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              role: backend
        - ipBlock:
            cidr: 10.0.0.0/24
    - ports:
        - protocol: TCP
          port: 80
  egress:
    - to:
        - podSelector:
            matchLabels:
              role: database
```


The policy has the following rules:

- `Ingress`: Incoming traffic rules
  - Allow traffic from pods with the label `role: backend`
  - Allow traffic from the IP block `10.0.0.0/24`
  - Allow incoming TCP traffic on port 80

- `Egress`: Outgoing traffic rules
  - Allow outgoing traffic to pods with the label `role: database`

This network policy restricts incoming and outgoing traffic for pods with the label `app: my-app`. It only allows incoming traffic from pods with the label `role: backend` and from the specified IP block. It also permits outgoing traffic to pods with the label `role: database`. All other incoming and outgoing traffic is denied by default.

To apply this network policy, you can save it in a YAML file (e.g., `network-policy.yaml`) and use the `kubectl apply` command:

```shell
kubectl apply -f network-policy.yaml
```

Once applied, the network policy takes effect, and the defined rules govern the traffic flow to and from pods based on the specified selectors and policies.

It's important to note that for network policies to take effect, the Kubernetes cluster must have a network plugin that supports network policy enforcement, such as Calico or Cilium. Additionally, make sure to evaluate and test your network policies thoroughly to ensure they align with your desired network segmentation and security requirements.

## Comparing Calico and Cilium

Calico and Cilium are both popular network plugins for Kubernetes that offer advanced networking and security capabilities. Calico utilizes a pure Layer 3 approach with BGP routing, providing robust network policy support, distributed firewalling, and scalability for large-scale deployments. It integrates seamlessly with Kubernetes, making it an excellent choice for managing network policies and enforcing security controls. On the other hand, Cilium combines Layer 3 and Layer 4/Layer 7 proxy-based networking and policy enforcement. It offers advanced features such as deep packet inspection, identity-based access controls, and application-layer security. Cilium also provides built-in service mesh functionality, including support for Envoy and Istio. With high scalability, performance, and observability features, Calico and Cilium offer reliable solutions for managing network connectivity, security, and observability within Kubernetes clusters.

1. Calico Documentation: [https://docs.projectcalico.org](https://docs.projectcalico.org)

The Calico documentation provides comprehensive information on getting started, installation, configuration, network policies, troubleshooting, and advanced features of Calico for Kubernetes and other platforms.

2. Cilium Documentation: [https://docs.cilium.io](https://docs.cilium.io)

The Cilium documentation covers various aspects of Cilium, including installation, networking, security, observability, service mesh integration, and API reference. It provides in-depth guidance on using Cilium in Kubernetes and other environments.


```
+-----------------+-----------------------------------------+----------------------------------+
|    Feature      |                 Calico                    |              Cilium              |
+-----------------+-----------------------------------------+----------------------------------+
| Architecture    | Uses a pure Layer 3 approach with BGP     | Utilizes a combination of Layer 3 |
|                 | routing for networking and policy        | and Layer 4/Layer 7 proxy-based  |
|                 | enforcement.                            | networking and policy.           |
+-----------------+-----------------------------------------+----------------------------------+
| Network Policy  | Provides robust network policy support   | Offers advanced network policy   |
| Management      | and integration with Kubernetes.         | capabilities, including         |
|                 |                                         | HTTP/HTTPS and gRPC-layer        |
|                 |                                         | filtering and policy enforcement.|
+-----------------+-----------------------------------------+----------------------------------+
| Security        | Implements a distributed firewall model  | Offers deep packet inspection,   |
|                 | with ingress and egress filtering.       | identity-based access controls,  |
|                 |                                         | and application-layer security.  |
+-----------------+-----------------------------------------+----------------------------------+
| Scalability     | Designed to scale to thousands of        | Provides high scalability and    |
|                 | nodes and handle large-scale deployments.| performance for large Kubernetes |
|                 |                                         | clusters and high-throughput      |
|                 |                                         | workloads.                       |
+-----------------+-----------------------------------------+----------------------------------+
| Service Mesh    | Can be used as a foundation for           | Provides built-in service mesh   |
| Integration     | integrating with service mesh solutions  | functionality, including support |
|                 | like Istio.                              | for Envoy and Istio.             |
+-----------------+-----------------------------------------+----------------------------------+
| Performance     | Offers high-performance networking and   | Provides efficient packet        |
|                 | forwarding with low latency.             | processing and low latency       |
|                 |                                         | communication between containers.|
+-----------------+-----------------------------------------+----------------------------------+
| Observability   | Provides network flow logs, network      | Offers advanced observability    |
|                 | policy auditing, and visibility into     | features, including detailed     |
|                 | network traffic and policies.            | network flow logs, service mesh  |
|                 |                                         | observability, and tracing.      |
+-----------------+-----------------------------------------+----------------------------------+
| Community       | Has a large and active community,        | Has a growing community and      |
|                 | backed by Project Calico and Tigera.     | strong industry support.         |
+-----------------+-----------------------------------------+----------------------------------+
```

Please note that the table provides a high-level comparison and may not include all features or specific details of each product. It's important to consult the official documentation and conduct a thorough evaluation to determine the best fit for your specific networking and security requirements in Kubernetes.
