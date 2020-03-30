# Security Onion, RedHunt OS, Proxmox, and Open vSwitch
If you have attended some of my classes and read some of my books, you know that I really like [Proxmox](https://www.proxmox.com/en/). I have several Proxmox clusters that I use for my training courses and to develop labs to learn new cybersecurity skills (offensive and defensive techniques). 

You can instantiate Linux systems such as [Kali Linux](https://www.kali.org/), [WebSploit](https://websploit.org), [Parrot](https://parrotlinux.org/), [BlackArch](https://blackarch.org/), [Security Onion](https://securityonion.net), [RedHuntOS](https://github.com/redhuntlabs/RedHunt-OS), and others in different VMs to practice and learn new skills in a safe environment. 

Systems like [Security Onion](https://securityonion.net) and [RedHuntOS](https://github.com/redhuntlabs/RedHunt-OS) come with with [Snort](https://www.snort.org/), [Suricata](https://suricata-ids.org/), [ELK](https://www.elastic.co/what-is/elk-stack), and many other security tools that allow you to monitor your network.

You have to setup [port mirroring](https://en.wikipedia.org/wiki/Port_mirroring) for IDS/IPS systems like Snort to be able to monitor traffic. In Proxmox, you can setup [Linux bridges](https://pve.proxmox.com/wiki/Network_Configuration) and [Open vSwitch (OVS) bridges](https://pve.proxmox.com/wiki/Open_vSwitch). 

## OVS Setup
I strongly recommend to use OVS bridges to send traffic to your Security Onion VM (or whatever other VM you would like to capture packets or monitor for IDS/IPS functions. 

- **Note:** A bridge is another term for a Switch. It directs traffic to the appropriate interface based on mac address. Open vSwitch bridges should contain raw ethernet devices, along with virtual interfaces such as OVSBonds or OVSIntPorts. These bridges can carry multiple vlans, and be broken out into 'internal ports' to be used as vlan interfaces on the host.

1. First, you need to update the package index and then install the Open vSwitch packages by executing:

```
 apt update
 apt install openvswitch-switch
```

2. Then you can create an OVS bridge and assign the interfaces of each VM that you want to capture packets to that OVS bridge.

3. You then configure the `tap` interfaces. These are only visible in the system shell (not in the Proxmox GUI) and are added automatically for VMs attached to an OVS-bridge interface. The naming convention of the tap interfaces is based on the ID of the VM they are assigned to, with the name `tap[VM-ID]i[interface#]`.

For example, these are some of the interfaces in one of the Proxmox nodes/servers in one of my clusters:

```
┌─[root@hermes]─[~]
└──╼ #ip -brie a
lo               UNKNOWN        127.0.0.1/8 ::1/128 
enp0s31f6        DOWN           
enp1s0f0         UP             
enp1s0f1         DOWN           
enp3s0f0         UP             
enp3s0f1         DOWN           
vmbr0            UP             192.168.78.10/24 fe80::92e2:baff:fe84:dbd0/64 
vmbr1            UP             10.1.1.10/24 fe80::a236:9fff:fe1c:2430/64 
vmbr2            UNKNOWN        fe80::f84b:12ff:fe3c:6e61/64 
ovs-system       DOWN           
vmbr3            UNKNOWN        fe80::208a:52ff:fe6d:504f/64 
tap109i0         UNKNOWN        
fwbr109i0        UP             
fwpr109p0@fwln109i0 UP             
fwln109i0@fwpr109p0 UP             
tap109i1         UNKNOWN        
tap109i2         UNKNOWN        
fwbr109i2        UP             
fwpr109p2@fwln109i2 UP             
fwln109i2@fwpr109p2 UP             
tap112i0         UNKNOWN        
fwbr112i0        UP             
fwpr112p0@fwln112i0 UP             
fwln112i0@fwpr112p0 UP             
tap112i1         UNKNOWN        
fwbr112i1        UP             
fwpr112p1@fwln112i1 UP             
fwln112i1@fwpr112p1 UP             
tap114i0         UNKNOWN        
tap119i0         UNKNOWN        
fwbr119i0        UP             
fwpr119p0@fwln119i0 UP             
fwln119i0@fwpr119p0 UP             
tap119i1         UNKNOWN        
fwbr119i1        UP             
fwpr119p1@fwln119i1 UP             
fwln119i1@fwpr119p1 UP             
tap121i0         UNKNOWN        
veth122i0@if59   UP             
fwbr122i0        UP             
fwpr122p0@fwln122i0 UP             
fwln122i0@fwpr122p0 UP             
veth122i1@if64   UP             
fwbr122i1        UP             
fwpr122p1@fwln122i1 UP             
fwln122i1@fwpr122p1 UP             
tap126i0         UNKNOWN        
fwbr126i0        UP             
fwpr126p0@fwln126i0 UP             
fwln126i0@fwpr126p0 UP             
veth130i0@if73   UP             
fwbr130i0        UP             
fwpr130p0@fwln130i0 UP             
fwln130i0@fwpr130p0 UP             
veth136i0@if78   UP             
fwbr136i0        UP             
fwpr136p0@fwln136i0 UP             
fwln136i0@fwpr136p0 UP             
fwbr109i1        UP             
fwln109o1        UNKNOWN        
veth115i0@if89   UP             
fwbr115i0        UP             
fwln115o0        UNKNOWN        
tap106i0         UNKNOWN        
fwbr106i0        UP             
fwpr106p0@fwln106i0 UP             
fwln106i0@fwpr106p0 UP             
tap106i1         UNKNOWN        
```

`tap106i0` is the first (0) virtual interface created for VM with ID 106, and `tap106i1` is the second such interface. 

In order to send all traffic on the OVS bridge to the Security Onion VM (VM 106). I use the following command in the Proxmox node:

```
ovs-vsctl -- --id=@p get port tap106i1 \
    -- --id=@m create mirror name=span1 select-all=true output-port=@p \
    -- set bridge vmbr3 mirrors=@m
```

`vmbr3` is the OVS bridge for that internal network. This creates a new “mirror” object named “span1”. Span1 will send any IP traffic on the `vmbr3` OVS bridge to the second virtual interface on VM 106 (tap106i1).







