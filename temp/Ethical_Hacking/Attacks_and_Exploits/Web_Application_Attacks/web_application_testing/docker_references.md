# Docker References

## The most amazing (#awesome) list of Docker-related resources!!

* https://awesome-docker.netlify.com/

## Container Networking

- [Calico-Docker](https://www.projectcalico.org/getting-started/docker/) - Calico is a pure layer 3 virtual network that allows containers over multiple docker-hosts to talk to each other.
- [Flannel](https://github.com/coreos/flannel/) - Flannel is a virtual network that gives a subnet to each host for use with container runtimes. By [@coreos][coreos]
- [netshoot](https://github.com/nicolaka/netshoot) - The netshoot container has a powerful set of networking tools to help troubleshoot Docker networking issues by [@nicolaka](https://github.com/nicolaka)
- [Weave][weave] (The Docker network) - Weave creates a virtual network that connects Docker containers deployed across multiple hosts.

## Container Orchestration

- [athena](https://github.com/athena-oss/athena) - An automation platform with a plugin architecture that allows you to easily create and share services.
- [CloudSlang](https://github.com/CloudSlang/cloud-slang) - CloudSlang is a workflow engine to create Docker process automation
- [clusterdock](https://github.com/clusterdock/clusterdock) - Docker container orchestration to enable the testing of long-running cluster deployments
- [ContainerShip](https://github.com/containership/containership) A simple container management platform
- [Crane](https://github.com/Dataman-Cloud/crane) - Control plane based on docker built-in swarm [@Dataman-Cloud](https://github.com/Dataman-Cloud)
- [Docker Flow Swarm Listener](https://github.com/vfarcic/docker-flow-swarm-listener) - Docker Flow Swarm Listener project is to listen to Docker Swarm events and send requests when a change occurs. By [@vfarcic][vfarcic]
- [Haven](https://github.com/codeabovelab/haven-platform) - Haven is a simplified container management platform that integrates container, application, cluster, image, and registry managements. By [@codeabovelab](https://github.com/codeabovelab)
- [Helios](https://github.com/spotify/helios) - A simple platform for deploying and managing containers across an entire fleet of servers by [@spotify](spotify)
- [Kontena](https://github.com/kontena/kontena) - Application Containers for Masses [website](https://www.kontena.io/)
- [Kubernetes](https://github.com/kubernetes/kubernetes) - Open source orchestration system for Docker containers by Google
- [ManageIQ](https://github.com/ManageIQ/manageiq) - Discover, optimize and control your hybrid IT. By [ManageIQ](https://github.com/ManageIQ)
- [Mantl](https://github.com/mantl/mantl) - Mantl is a modern platform for rapidly deploying globally distributed services
- [Marathon](https://mesosphere.github.io/marathon/docs/) - Marathon is a private PaaS built on Mesos. It automatically handles hardware or software failures and ensures that an app is "always on"
- [Mesos](https://mesos.apache.org/documentation/latest/docker-containerizer/) - Resource/Job scheduler for containers, VM's and physical hosts [@apache](https://mesos.apache.org/)
- [Mesosphere DC/OS](https://mesosphere.com/product/) - Integrated platform for data and containers built on Apache Mesos by [@mesosphere](https://mesosphere.com)
- [Nebula](https://github.com/nebula-orchestrator) - A Docker orchestration tool designed to manage massive scale distributed clusters.
- [Nomad](https://github.com/hashicorp/nomad) - Easily deploy applications at any scale. A Distributed, Highly Available, Datacenter-Aware Scheduler by [@hashicorp][hashicorp]
- [Rancher](https://github.com/rancher/rancher) - An open source project that provides a complete platform for operating Docker in production by [@rancher][rancher].
- [Swarmpit](https://github.com/swarmpit/swarmpit) - Lightweight Docker Swarm orchestration. Swarmpit provides clean way to manage your Docker Swarm cluster with various handful features such Service management, smart search, shared access and private registries.


## Container Reverse Proxy

- [docker-flow-proxy](https://github.com/vfarcic/docker-flow-proxy) - Reconfigures proxy every time a new service is deployed, or when a service is scaled. By [@vfarcic][vfarcic]
- [fabio](https://github.com/fabiolb/fabio) - A fast, modern, zero-conf load balancing HTTP(S) router for deploying microservices managed by consul. By [@magiconair](https://github.com/magiconair) (Frank Schroeder)
- [Let's Encrypt Nginx-proxy Companion](https://github.com/JrCs/docker-letsencrypt-nginx-proxy-companion) - A lightweight companion container for the nginx-proxy. It allow the creation/renewal of Let's Encrypt certificates automatically. By [@JrCs](https://github.com/JrCs)
- [muguet](https://github.com/mattallty/muguet) - DNS Server & Reverse proxy for Docker environments. By [@mattallty](https://github.com/mattallty)
- [nginx-proxy][nginxproxy] - Automated nginx proxy for Docker containers using docker-gen by [@jwilder][jwilder]
- [Swarm Ingress Router](https://github.com/tpbowden/swarm-ingress-router) - Route DNS names to Swarm services based on labels. By [@tpbowden](https://github.com/tpbowden/)
- [Swarm Router](https://github.com/flavioaiello/swarm-router) - A «zero config» service name based router for docker swarm mode with a fresh and more secure approach. By [@flavioaiello](https://twitter.com/flavioaiello)
- [Træfɪk](https://github.com/containous/traefik) - Automated reverse proxy and load-balancer for Docker, Mesos, Consul, Etcd... By [@EmileVauge](https://github.com/emilevauge)

## Container Security

- [Anchor Cloud](https://anchore.com/cloud/)- Hosted version of Anchor Engine by [@Anchor][anchore]
- [Anchor Engine](https://github.com/anchore/anchore) - Analyze images for CVE vulnerabilities and against custom security policies by [@Anchor][anchore]
- [Aqua Security](https://www.aquasec.com)- Securing container-based applications from Dev to Production on any platform
- [bane](https://github.com/genuinetools/bane) - AppArmor profile generator for Docker containers by [@genuinetools][genuinetools]
- [CIS Docker Benchmark](https://github.com/dev-sec/cis-docker-benchmark) - This [InSpec][inspec] compliance profile implement the CIS Docker 1.12.0 Benchmark in an automated way to provide security best-practice tests around Docker daemon and containers in a production environment. By [@dev-sec](https://github.com/dev-sec)
- [Clair](https://github.com/coreos/clair) - Clair is an open source project for the static analysis of vulnerabilities in appc and docker containers. By [@coreos][CoreOS]
- [Dagda](https://github.com/eliasgranderubio/dagda) - Dagda is a tool to perform static analysis of known vulnerabilities, trojans, viruses, malware & other malicious threats in docker images/containers and to monitor the docker daemon and running docker containers for detecting anomalous activities. By [@eliasgranderubio](https://github.com/eliasgranderubio)
- [docker-bench-security](https://github.com/docker/docker-bench-security) - script that checks for dozens of common best-practices around deploying Docker containers in production. By [@docker][docker]
- [notary](https://github.com/theupdateframework/notary) - a server and a client for running and interacting with trusted collections. By [@TUF](https://github.com/theupdateframework)
- [oscap-docker](https://github.com/OpenSCAP/openscap) - OpenSCAP provides oscap-docker tool which is used to scan Docker containers and images. By RedHat
- [Sysdig Falco](https://github.com/draios/falco) - Sysdig Falco is an open source container security monitor. It can monitor application, container, host, and network activity and alert on unauthorized activity.
- [Sysdig Secure](https://sysdig.com/product/secure/) - Sysdig Secure addresses run-time security through behavioral monitoring and defense, and provides deep forensics based on open source Sysdig for incident response.
- [Twistlock](https://www.twistlock.com/) - Twistlock Security Suite detects vulnerabilities, hardens container images, and enforces security policies across the lifecycle of applications.
