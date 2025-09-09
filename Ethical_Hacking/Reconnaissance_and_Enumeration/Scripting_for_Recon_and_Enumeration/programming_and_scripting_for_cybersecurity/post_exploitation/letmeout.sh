#!/bin/bash
# A quick script to test exfil ports.
# Using @mubix letmeoutofyour.net site (https://gitlab.com/mubix/letmeoutofyour.net)
# Author: Omar Santos @santosomar


for i in $(eval echo {$1..$2})
do
    echo "Is port $i open for potential exfil?"
    curl http://letmeoutofyour.net:$i

done
