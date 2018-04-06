#!/bin/bash
# quick script to test exfil ports
# using mubix letmeoutofyour.net website
# omar santos @santosomar


for i in $(eval echo {$1..$2})
do
    echo "Is port $i open for potential exfil?"
    curl http://letmeoutofyour.net:$i

done
