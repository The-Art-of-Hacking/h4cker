# Useful SNMP Commands

# Search for Windows installed software
`smpwalk !grep hrSWinstalledName`

## Search for Windows users
`snmpwalk ip 1.3 lgrep --.1.2.25 -f4`

## Search for Windows running services
`snrnpwalk -c public -v1 ip 1 lgrep hrSWRJnName !cut -d" " -f4`

## Search for Windows open TCP ports
`smpwalk lgrep tcpConnState !cut -d" " -f6 !sort -u`
