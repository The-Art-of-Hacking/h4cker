import os
import sys
from optparse import OptionParser

import ParseLogs


#
# Logalyzer.  Original: https://github.com/hatRiot/logalyzer
# Converted to python3.6 by @programmerchad
#

# callback for the user flag
def user_call(option, opt_str, value, parser):
    if len(parser.rargs) != 0:
        value = parser.rargs[0]
    else:
        value = None
    setattr(parser.values, option.dest, value)


if __name__ == "__main__":

    # default location
    log = '/var/log/auth.log'

    # parsing options
    parser = OptionParser(epilog=
                          "Combine flags to view user-specific information.  \'-u test -i\' lists IP addresses "
                          "associated with user test")
    parser.add_option("-u", help="Specify user.  Blank lists all users.", action="callback",
                      callback=user_call, default=None, dest="user")
    parser.add_option("--full", help="Full log dump for specified user", action="store_true",
                      default=False, dest="fullu")
    parser.add_option("-l", help="Specify log file.  Default is auth.log", default=None, dest="log")
    parser.add_option("-f", help="List failures", action="store_true", default=False, dest="fail")
    parser.add_option("-s", help="List success logs", action="store_true", default=False, dest="success")
    parser.add_option("-c", help="List commands by user", action="store_true", default=False, dest="commands")
    parser.add_option("-i", help="List IP Addresses", action="store_true", default=False, dest="ip")

    # get arguments
    (options, args) = parser.parse_args()

    # if they're trying to access /var/log/auth.log without proper privs, bail
    if not os.getuid() == 0 and options.log is None:
        print("[-] Please run with SUDO")
        sys.exit(1)

    # check if they specified another file
    if options.log is not None:
        log = options.log

    # parse logs
    LOGS = ParseLogs.ParseLogs(log)
    if LOGS is None: sys.exit(1)

    # validate the user
    if options.user:
        if not options.user in LOGS:
            print(f"[-] User \'{options.user}\' is not present in the logs.")
            sys.exit(1)

    # tag log location first
    print('[!] Log file: ', log)

    # output all commands
    if options.commands and not options.user:
        for i in LOGS:
            for comms in LOGS[i].commands:
                print(f"{i}:\t{comms}")
        sys.exit(1)

    # output all failures
    elif options.fail and not options.user:
        for i in LOGS:
            for fail in LOGS[i].fail_logs:
                print(f"{i}:\t{fail}")
        sys.exit(1)

    # output all logged IP addresses
    elif options.ip and not options.user:
        for i in LOGS:
            for ip in LOGS[i].ips:
                print(f"{i}:\t{ip}")
        sys.exit(1)

    # output user-specific commands
    if options.commands and options.user:
        print(f"[+] Commands for user \'{options.user}\'")
        for com in LOGS[options.user].commands:
            print("\t", com)

    # output user-specific success logs
    elif options.success and options.user:
        print(f"[+] Successes logs for user \'{options.user}\'")
        for log in LOGS[options.user].succ_logs:
            print("\t", log)

    # output user-specific failures
    elif options.fail and options.user:
        print(f"[+] Failures for user \'{options.user}\'")
        for fail in LOGS[options.user].fail_logs:
            print("\t", fail)

    # output user-specific ip addresses
    elif options.ip and options.user:
        print(f"[+] Logged IPs for user \'{options.user}\'")
        for i in LOGS[options.user].ips:
            print("\t", i)

    # print out all information regarding specified user
    elif options.user is not None:
        print(f"[!] Logs associated with user \'{options.user}\'")
        print('[+] First log: ', LOGS[options.user].first_date())
        print('[+] Last log: ', LOGS[options.user].last_date())
        print("[!] Failure Logs")
        for fail in LOGS[options.user].fail_logs:
            print("\t", fail)
        print("[!] Success Logs")
        for succ in LOGS[options.user].succ_logs:
            print("\t", succ)
        print("[!] Associated IPs")
        for ip in LOGS[options.user].ips:
            print("\t", ip)
        print("[!] Commands")
        for comm in LOGS[options.user].commands:
            print("\t", comm)

    # dump the full log for the user if specified
    if options.fullu and options.user:
        print("[!] Full Log")
        for log in LOGS[options.user].logs:
            print(log)

    # if they supplied us with an empty user, dump all of the logged users
    elif options.user is None:
        if len(LOGS) > 0:
            for i in LOGS:
                print(i)
