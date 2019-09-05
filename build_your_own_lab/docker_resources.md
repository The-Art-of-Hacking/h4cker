# Docker Resources

## Where to start

- [Basics – Docker, Containers, Hypervisors, CoreOS](http://etherealmind.com/basics-docker-containers-hypervisors-coreos/)
- [Dive Into Docker: From "What is Docker?" to "Hello World"](https://www.youtube.com/watch?v=XeSD17YRijk&list=PL-v3vdeWVEsXT-u0JDQZnM90feU3NE3v8) (60:25) by [@nickjanetakis][nickjanetakis]
- [Docker Curriculum](https://docker-curriculum.com): A comprehensive tutorial for getting started with Docker. Teaches how to use Docker and deploy dockerized apps on AWS with Elastic Beanstalk and Elastic Container Service.
- [Docker Documentation](https://docs.docker.com/)
- [Docker for all - Developers, Testers, DevOps, Product Owners + Videos](https://github.com/machzqcq/docker-for-all) Docker Training Videos for all
- [Docker Jumpstart](https://github.com/odewahn/docker-jumpstart/): a quick introduction
- [Docker Training](https://training.docker.com/) - Includes a free self-paced hands-on tutorial (free registration required or sign-in with DockerHub ID)
- [Katacoda](https://www.katacoda.com/): Learn Docker using Interactive Browser-Based Labs
- [Learn Docker](https://github.com/dwyl/learn-docker) Full environment set up, screenshots, step-by-step tutorial and more resources (video, articles, cheat sheets) by [@dwyl](https://github.com/dwyl)
- [Play With Docker](https://training.play-with-docker.com/) - PWD is a great way to get started with Docker from beginner to advanced users. Docker runs directly in your browser.
- [Play With Moby](http://play-with-moby.com/) - PWM is a web based Moby playground which allows you to try different components of the platform in seconds. It gives you the experience of having a free Alpine Linux Virtual Machine in the cloud where you can build and run Moby projects and even create clusters to experiment.
- [Practical Introduction to Container Terminology](https://developers.redhat.com/blog/2018/02/22/container-terminology-practical-introduction/) The landscape for container technologies is larger than just docker. Without a good handle on the terminology, It can be difficult to grasp the key differences between docker and (pick your favorites, CRI-O, rkt, lxc/lxd) or understand what the Open Container Initiative is doing to standardize container technology.

**Cheatsheets** by

- [@eon01](https://github.com/eon01/DockerCheatSheet)
- [@dimonomid][docker-quick-ref] (PDF)
- [@JensPiegsa](http://docker.jens-piegsa.com)
- [@wsargent][docker-cheat-sheet]

## Container Composition

- [bocker](https://github.com/icy/bocker) (2) - Write Dockerfile completely in Bash. Extensible and simple. --> Reusable by [@icy](https://github.com/icy)
- [box](https://github.com/box-builder/box) - Build Dockerfile images with a mruby DSL, includes flattening and layer manipulation
- [Capitan](https://github.com/byrnedo/capitan) - Composable docker orchestration with added scripting support by [@byrnedo](https://github.com/byrnedo).
- [compose_plantuml](hhttps://github.com/funkwerk/compose_plantuml) -  Generate Plantuml graphs from docker-compose files by [@funkwerk](https://github.com/funkwerk)
- [Composerize](https://github.com/magicmark/composerize) - Convert docker run commands into docker-compose files
- [crowdr](https://github.com/polonskiy/crowdr) - Tool for managing multiple Docker containers (`docker-compose` alternative) by [@polonskiy](https://github.com/polonskiy/)
- [docker-compose-graphviz](https://github.com/abesto/docker-compose-graphviz) - Turn a docker-compose.yml files into Graphviz .dot files by [@abesto](https://github.com/abesto)
- [draw-compose](https://github.com/Alexis-benoist/draw-compose) - Utility to draw a schema of a docker compose by [@Alexis-benoist](https://github.com/Alexis-benoist)
- [elsy](https://github.com/cisco/elsy) - An opinionated, multi-language, build tool based on Docker and Docker Compose
- [habitus](https://github.com/cloud66/habitus) - A Build Flow Tool for Docker by [@cloud66](https://github.com/cloud66)
- [plash](https://github.com/ihucos/plash) - A container run and build engine - runs inside docker.
- [rocker-compose](https://github.com/grammarly/rocker-compose) - Docker composition tool with idempotency features for deploying apps composed of multiple containers. By [@grammarly](grammarly)
- [rocker](https://github.com/grammarly/rocker) - Extended Dockerfile builder. Supports multiple FROMs, MOUNTS, templates, etc. by [grammarly](grammarly).
- [Stacker](https://github.com/stacker/stacker-cli) - Docker Compose Templates. Stacker provides an abstraction layer over Docker Compose and a better DX (developer experience)

## Deployment and Infrastructure

- [blackfish](https://gitlab.com/blackfish/blackfish) - a CoreOS VM to build swarm clusters for Dev & Production by [@DataMC](http://datamc.io/)
- [Centurion](https://github.com/newrelic/centurion) - Centurion is a mass deployment tool for Docker fleets. It takes containers from a Docker registry and runs them on a fleet of hosts with the correct environment variables, host volume mappings, and port mappings. By [@newrelic](https://github.com/newrelic)
- [Clocker](https://github.com/brooklyncentral/clocker) - Clocker creates and manages a Docker cloud infrastructure. Clocker supports single-click deployments and runtime management of multi-node applications that run as containers distributed across multiple hosts, on both Docker and Marathon. It leverages [Calico][calico] and [Weave][weave] for networking and [Brooklyn][brooklyn] for application blueprints. By [@brooklyncentral](https://github.com/brooklyncentral)
- [Conduit](https://github.com/ehazlett/conduit) - Experimental deployment system for Docker by [@ehazlett](https://github.com/ehazlett)
- [depcon](https://github.com/gondor/depcon) - Depcon is written in Go and allows you to easily deploy Docker containers to Apache Mesos/Marathon, Amazon ECS and Kubernetes.  By [@gonodr][gondor]
- [Grafeas](https://github.com/Grafeas/Grafeas) - A common API for metadata about containers, from image and build details to security vulnerabilities. By [Grafeas](https://github.com/Grafeas)

## Monitoring

- [Axibase Collector](https://github.com/axibase/atsd-use-cases/tree/master/Solutions/docker) - Axibase Collector streams performance counters, configuration changes and lifecycle events from the Docker engine(s) into Axibase Time Series Database for roll-up dashboards and integration with upstream monitoring systems.
- [cAdvisor](https://github.com/google/cadvisor) - Analyzes resource usage and performance characteristics of running containers. Created by [@Google](https://github.com/google)
- [Docker-Alertd](https://github.com/deltaskelta/docker-alertd) - Monitor and send alerts based on docker container resource usage/statistics
- [Docker-Flow-Monitor](https://github.com/vfarcic/docker-flow-monitor) - Reconfigures Prometheus when a new service is updated or deployed automatically by [@vfarcic][vfarcic]
- [Docker-Fluentd][fluentd] - Docker container to Log Other Containers' Logs. One can aggregate the logs of Docker containers running on the same host using Fluentd by [@kiyoto][kiyoto]
- [Glances](https://github.com/nicolargo/glances) - A cross-platform curses-based system monitoring tool written in Python by [@nicolargo](https://github.com/nicolargo)
- [Grafana Docker Dashboard Template](https://grafana.com/dashboards/179) - A template for your Docker, Grafana and Prometheus stack [@vegasbrianc][vegasbrianc]
- [InfluxDB, cAdvisor, Grafana](https://github.com/vegasbrianc/docker-monitoring) - InfluxDB Time series DB in combination with Grafana and cAdvisor by [@vegasbrianc][vegasbrianc]
- [LogJam](https://github.com/gocardless/logjam) - Logjam is a log forwarder designed to listen on a local port, receive log entries over UDP, and forward these messages on to a log collection server (such as logstash) by [@gocardless](https://github.com/gocardless)
- [Logsene for Docker][spm] Monitoring of Metrics, Events and Logs implemented in Node.js. Integrated [logagent-js](https://github.com/sematext/logagent-js) to detect and parse various log formats. [@sematext][sematext]
- [Logspout](https://github.com/gliderlabs/logspout) - Log routing for Docker container logs by [@gliderlabs][gliderlabs]
- [Out-of-the-box Host/Container Monitoring/Logging/Alerting Stack](https://github.com/uschtwill/docker_monitoring_logging_alerting) - Docker host and container monitoring, logging and alerting out of the box using cAdvisor, Prometheus, Grafana for monitoring, Elasticsearch, Kibana and Logstash for logging and elastalert and Alertmanager for alerting. Set up in 5 Minutes. Secure mode for production use with built-in [Automated Nginx Reverse Proxy (jwilder's)][nginxproxy].
- [Zabbix Docker module](https://github.com/monitoringartist/Zabbix-Docker-Monitoring) - Zabbix module that provides discovery of running containers, CPU/memory/blk IO/net container metrics. Systemd Docker and LXC execution driver is also supported. It's a dynamically linked shared object library, so its performance is (~10x) better, than any script solution.
- [Zabbix Docker](https://github.com/gomex/docker-zabbix) - Monitor containers automatically using zabbix LLD feature.

## Networking

- [Calico-Docker][calico] - Calico is a pure layer 3 virtual network that allows containers over multiple docker-hosts to talk to each other.
- [Flannel](https://github.com/coreos/flannel/) - Flannel is a virtual network that gives a subnet to each host for use with container runtimes. By [@coreos][coreos]
- [netshoot](https://github.com/nicolaka/netshoot) - The netshoot container has a powerful set of networking tools to help troubleshoot Docker networking issues by [@nicolaka](https://github.com/nicolaka)
- [Weave][weave] (The Docker network) - Weave creates a virtual network that connects Docker containers deployed across multiple hosts.

## Orchestration

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
- [Marathon](https://github.com/mesosphere/marathon) - Marathon is a private PaaS built on Mesos. It automatically handles hardware or software failures and ensures that an app is "always on"
- [Mesos](https://github.com/apache/mesos) - Resource/Job scheduler for containers, VM's and physical hosts [@apache](https://mesos.apache.org/)
- [Nebula](https://github.com/nebula-orchestrator) - A Docker orchestration tool designed to manage massive scale distributed clusters.
- [Nomad](https://github.com/hashicorp/nomad) - Easily deploy applications at any scale. A Distributed, Highly Available, Datacenter-Aware Scheduler by [@hashicorp][hashicorp]
- [Rancher](https://github.com/rancher/rancher) - An open source project that provides a complete platform for operating Docker in production by [@rancher][rancher].
- [Swarmpit](https://github.com/swarmpit/swarmpit) - Lightweight Docker Swarm orchestration. Swarmpit provides clean way to manage your Docker Swarm cluster with various handful features such Service management, smart search, shared access and private registries.

## PaaS

- [CaptainDuckDuck](https://github.com/githubsaturn/captainduckduck) - Open source Heroku-like platform with a one-liner installer and a GUI for managing apps - with serveral one-click databases and apps.
- [Convox Rack](https://github.com/convox/rack) - Convox Rack is open source PaaS built on top of expert infrastructure automation and devops best practices.
- [Dcw](https://github.com/pbertera/dcw) - Docker-compose SSH wrapper: a very poor man PaaS, exposing the docker-compose and custom-container commands defined in container labels.
- [Dokku][dokku] - Docker powered mini-Heroku that helps you build and manage the lifecycle of applications (originally by [@progrium][progrium])
- [Empire](https://github.com/remind101/empire) - A PaaS built on top of Amazon EC2 Container Service (ECS)
- [Flynn](https://github.com/flynn/flynn) - A next generation open source platform as a service
- [OpenShift][openshift] - An open source PaaS built on [Kubernetes][kubernetes] and optimized for Dockerized app development and deployment by [Red Hat](https://www.redhat.com/)
- [Tsuru](https://github.com/tsuru/tsuru) - Tsuru is an extensible and open source Platform as a Service software
- [Workflow](https://github.com/deis/workflow) - The open source PaaS for Kubernetes by [Deis](https://github.com/deis). Formerly Deis v1.
- [ZEIT Now](https://github.com/zeit/now-cli) - A universal serverless single-command deploy for Node.js applications or any application with a Dockerfile.

### Reverse Proxy

- [docker-flow-proxy](https://github.com/vfarcic/docker-flow-proxy) - Reconfigures proxy every time a new service is deployed, or when a service is scaled. By [@vfarcic][vfarcic]
- [fabio](https://github.com/fabiolb/fabio) - A fast, modern, zero-conf load balancing HTTP(S) router for deploying microservices managed by consul. By [@magiconair](https://github.com/magiconair) (Frank Schroeder)
- [Let's Encrypt Nginx-proxy Companion](https://github.com/JrCs/docker-letsencrypt-nginx-proxy-companion) - A lightweight companion container for the nginx-proxy. It allow the creation/renewal of Let's Encrypt certificates automatically. By [@JrCs](https://github.com/JrCs)
- [muguet](https://github.com/mattallty/muguet) - DNS Server & Reverse proxy for Docker environments. By [@mattallty](https://github.com/mattallty)
- [nginx-proxy][nginxproxy] - Automated nginx proxy for Docker containers using docker-gen by [@jwilder][jwilder]
- [Swarm Ingress Router](https://github.com/tpbowden/swarm-ingress-router) - Route DNS names to Swarm services based on labels. By [@tpbowden](https://github.com/tpbowden/)
- [Swarm Router](https://github.com/flavioaiello/swarm-router) - A «zero config» service name based router for docker swarm mode with a fresh and more secure approach. By [@flavioaiello](https://twitter.com/flavioaiello)
- [Træfɪk](https://github.com/containous/traefik) - Automated reverse proxy and load-balancer for Docker, Mesos, Consul, Etcd... By [@EmileVauge](https://github.com/emilevauge)

## Security

- [Anchor Engine](https://github.com/anchore/anchore) - Analyze images for CVE vulnerabilities and against custom security policies by [@Anchor][anchore]
- [bane](https://github.com/genuinetools/bane) - AppArmor profile generator for Docker containers by [@genuinetools][genuinetools]
- [CIS Docker Benchmark](https://github.com/dev-sec/cis-docker-benchmark) - This [InSpec][inspec] compliance profile implement the CIS Docker 1.12.0 Benchmark in an automated way to provide security best-practice tests around Docker daemon and containers in a production environment. By [@dev-sec](https://github.com/dev-sec)
- [Clair](https://github.com/coreos/clair) - Clair is an open source project for the static analysis of vulnerabilities in appc and docker containers. By [@coreos][CoreOS]
- [Dagda](https://github.com/eliasgranderubio/dagda) - Dagda is a tool to perform static analysis of known vulnerabilities, trojans, viruses, malware & other malicious threats in docker images/containers and to monitor the docker daemon and running docker containers for detecting anomalous activities. By [@eliasgranderubio](https://github.com/eliasgranderubio)
- [docker-bench-security](https://github.com/docker/docker-bench-security) - script that checks for dozens of common best-practices around deploying Docker containers in production. By [@docker][docker]
- [notary](https://github.com/theupdateframework/notary) - a server and a client for running and interacting with trusted collections. By [@TUF](https://github.com/theupdateframework)
- [oscap-docker](https://github.com/OpenSCAP/openscap) - OpenSCAP provides oscap-docker tool which is used to scan Docker containers and images. By RedHat
- [Sysdig Falco](https://github.com/draios/falco) - Sysdig Falco is an open source container security monitor. It can monitor application, container, host, and network activity and alert on unauthorized activity.

## Service Discovery

- [docker-consul](https://github.com/gliderlabs/docker-consul) by [@progrium][progrium]
- [etcd](https://github.com/coreos/etcd) - A highly-available key value store for shared configuration and service discovery by [@coreOS][coreos]
- [istio](https://github.com/istio/istio) - An open platform to connect, manage, and secure microservices by [@IstioMesh](istio)
- [registrator](https://github.com/gliderlabs/registrator) - Service registry bridge for Docker by [@gliderlabs][gliderlabs] and [@progrium][progrium]

## Volume Management / Data

- [Blockbridge](https://github.com/blockbridge/blockbridge-docker-volume) - The Blockbridge plugin is a volume plugin that provides access to an extensible set of container-based persistent storage options. It supports single and multi-host Docker environments with features that include tenant isolation, automated provisioning, encryption, secure deletion, snapshots and QoS. By [@blockbridge][blockbridge]
- [Convoy](https://github.com/rancher/convoy) - an open-source Docker volume driver that can snapshot, backup and restore Docker volumes anywhere. By [@rancher][rancher]
- [Docker Machine NFS](https://github.com/adlogix/docker-machine-nfs) Activates NFS for an existing boot2docker box created through Docker Machine on OS X.
- [Docker Unison](https://github.com/leighmcculloch/docker-unison) A docker volume container using Unison for fast two-way folder sync. Created as an alternative to slow boot2docker volumes on OS X. By [@leighmcculloch](https://github.com/leighmcculloch)
- [Local Persist](https://github.com/CWSpear/local-persist) Specify a mountpoint for your local volumes (created via `docker volume create`) so that files will always persist and so you can mount to different directories in different containers.
- [Minio](https://github.com/jelastic-jps/minio) - S3 compatible object storage server in Docker containers
- [Netshare](https://github.com/ContainX/docker-volume-netshare) Docker NFS, AWS EFS, Ceph & Samba/CIFS Volume Plugin. By [@ContainX](https://github.com/ContainX)
- [REX-Ray](https://github.com/rexray/rexray) provides a vendor agnostic storage orchestration engine. The primary design goal is to provide persistent storage for Docker, Kubernetes, and Mesos. By[@thecodeteam](https://github.com/thecodeteam) (DELL Technologies)

## Awesome Lists

- [Awesome CI/CD](https://github.com/ciandcd/awesome-ciandcd) - Not specific to docker but relevant.
- [Awesome Kubernetes](https://github.com/ramitsurana/awesome-kubernetes) by [@ramitsurana][ramitsurana]
- [Awesome Linux Container](https://github.com/Friz-zy/awesome-linux-containers) more general about container than this repo, by [@Friz-zy](https://github.com/Friz-zy).
- [Awesome Selfhosted](https://github.com/Kickball/awesome-selfhosted) list of Free Software network services and web applications which can be hosted locally by running in a classical way (setup local web server and run applications from there) or in a Docker container. By [@Kickball](https://github.com/Kickball)
- [Awesome Sysadmin](https://github.com/n1trux/awesome-sysadmin) by [@n1trux](https://github.com/n1trux)
- [ToolsOfTheTrade](https://github.com/cjbarber/ToolsOfTheTrade) a list of SaaS and On premise applications by [@cjbarber](https://github.com/cjbarber)

## Videos

- [Contributing to Docker by Andrew "Tianon" Page (InfoSiftr)](https://www.youtube.com/watch?v=1jwo8-1HYYg) (34:31)
- [Deploying and scaling applications with Docker, Swarm, and a tiny bit of Python magic](https://www.youtube.com/watch?v=GpHMTR7P2Ms) (3:11:06) by [@jpetazzo][jpetazzo]
- [Docker and SELinux by Daniel Walsh from Red Hat](https://www.youtube.com/watch?v=zWGFqMuEHdw) (40:23)
- [Docker for Developers][docker4dev] (54:26) by [@jpetazzo][jpetazzo]  <== Good introduction, context, demo
- [Docker in Production](https://www.youtube.com/watch?v=Glk5d5WP6MI) by [@jpetazzo][jpetazzo] (36:05)
- [Docker: How to Use Your Own Private Registry](https://www.youtube.com/watch?v=CAewZCBT4PI) (15:01)
- [Extending Docker with Plugins](https://vimeo.com/110835013) (15:21)
- [From Local Docker Development to Production Deployments](https://www.youtube.com/watch?v=7CZFpHUPqXw) by [@jpetazzo][jpetazzo] @ AWS re:Invent 2015
- [Immutable Infrastructure with Docker and EC2 by Michael Bryzek (Gilt)](https://www.youtube.com/watch?v=GaHzdqFithc) (42:04)
- [Introduction to Docker and containers](https://www.youtube.com/watch?v=ZVaRK10HBjo) (3:09:00) by [@jpetazzo][jpetazzo]
- [Logging on Docker: What You Need to Know][loggingDocker] (51:27)
- [Performance Analysis of Docker - Jeremy Eder](https://www.youtube.com/watch?v=6f2E6PKYb0w) (1:36:58)
- [Scalable Microservices with Kubernetes](https://www.udacity.com/course/scalable-microservices-with-kubernetes--ud615) Free Udacity course
- [State of containers: a debate with CoreOS, VMware and Google](https://www.youtube.com/watch?v=IiITP3yIRd8) (27:38)
- [SysAdminCasts: Introduction to Docker](https://sysadmincasts.com/episodes/31-introduction-to-docker) (15:49)
