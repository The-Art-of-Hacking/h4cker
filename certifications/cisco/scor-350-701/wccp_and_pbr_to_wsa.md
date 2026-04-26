# Configuring WCCP or Policy-Based Routing to Send Traffic to WSA

## Configuring WCCP on a Cisco Switch
Let’s take a look on how to configure WCCP on a Cisco switch to redirect traffic to the Cisco Secure Web Appliance. 

1. Configure an access control list (ACL) to match the web traffic.

```
ip access-list extended WEB-TRAFFIC
 permit tcp 10.1.1.0 0.0.0.255 any eq www
 permit tcp 10.1.2.0 0.0.0.255 any eq www
 permit tcp 10.1.1.0 0.0.0.255 any eq 443
 permit tcp 10.1.2.0 0.0.0.255 any eq 443
```
   
2. Configure another ACL to define where to send the traffic (that is, the Cisco Secure Web Appliance’s IP address).

```
ip access-list standard WSA
 permit 10.1.3.3
```

3. Create the WCCP lists.
```
ip wccp web-cache redirect-list HTTP-TRAFFIC group-list WSA
ip wccp 10 redirect-list FTP-TRAFFIC group-list WSA
ip wccp 20 redirect-list HTTPS-TRAFFIC group-list WSA
```

4. Configure the WCCP redirection of traffic on the source interface.
```
interface vlan88
 ip wccp web-cache redirect in
 ip wccp 10 redirect in
 ip wccp 20 redirect in
```



## Traffic Redirection with Policy-Based Routing
You can also configure PBR on a Cisco router to redirect web traffic to the Cisco Secure Web Appliance.

Configuring PBR can affect the router’s performance if enabled in software (without hardware acceleration). You should review the respective router documentation to determine any impact.

- First, a PBR policy is configured in a Cisco router that matches traffic from two source subnets (10.1.1.0/24 and 10.1.1.2.0/24). 
- The web traffic is received on interface VLAN 88.
- The traffic is sent to the Cisco Secure Web Appliance configured with IP address 10.1.2.3.

```
access-list 101 permit tcp 10.1.1.0 0.0.0.255 any eq 80
access-list 101 permit tcp 10.1.2.0 0.0.0.255 any eq 80
access-list 101 permit tcp 10.1.1.0 0.0.0.255 any eq 443
access-list 101 permit tcp 10.1.2.0 0.0.0.255 any eq 443
!
route-map WebRedirect permit 10
 match ip address 101
 set ip next-hop 10.1.3.3
interface vlan88
 ip policy route-map WebRedirect
```
