# Using Scapy to Scan a System

The following is an example of a Python script that uses Scapy to perform a basic TCP port scan:

```python
from scapy.all import *
import sys

def tcp_port_scan(target, ports):
    for port in ports:
        tcp_packet = IP(dst=target) / TCP(dport=port, flags="S")
        response = sr1(tcp_packet, timeout=2, verbose=0)

        if response is not None and response[TCP].flags == 18:
            print(f"Port {port} is open on {target}")
        else:
            print(f"Port {port} is closed on {target}")

if __name__ == "__main__":
    target = sys.argv[1]
    ports = range(1, 1024)

    tcp_port_scan(target, ports)
```

Here's how to use the script:
1. Save the script in a file named `port_scan.py`.
2. Run the script by using the following command in the terminal:
   
```
python port_scan.py <target_ip>
```
Remember to replace `<target_ip>` with the IP address of the target machine.

## Detailed Explanation

- The script begins by importing necessary modules:
  - `from scapy.all import *` imports all necessary components from the Scapy library, a powerful interactive packet manipulation tool.
  - `import sys` imports the system-specific parameters and functions module.

- The `tcp_port_scan(target, ports)` function is defined to perform the TCP port scan:
  - For each port in the provided ports, it creates a TCP packet with the `S` (SYN) flag set using `IP(dst=target) / TCP(dport=port, flags="S")`.
  - The script then sends the packet to the target machine using the `sr1()` function, which sends the packet and returns the first response received. 
  - If a response is received (`response is not None`) and the TCP flags of the response are equal to 18 (`response[TCP].flags == 18`), the script prints that the port is open. TCP flag 18 represents `SYN/ACK` packet which is usually the response to our SYN packet when a port is open. If there is no response or the response is not `SYN/ACK`, the script prints that the port is closed.

- In the `__main__` part of the script:
  - `target` is set to the first argument given in the command line (`sys.argv[1]`), which is the IP address of the target machine.
  - `ports` is set to the range of 1-1023, which are the well-known port numbers. 
  - The `tcp_port_scan()` function is then called with the `target` and `ports` as parameters.

This is a simple script and does not handle many edge cases. In a real-world situation, additional code would be required to handle potential exceptions, timeouts, and other situations. 
