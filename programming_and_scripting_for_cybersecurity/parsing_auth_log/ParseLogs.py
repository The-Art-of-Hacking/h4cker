import gzip
import re

#
# ParseLogs.py
# Parsing component of Logalyzer.  Original: https://github.com/hatRiot/logalyzer
# Converted to python3.6 by @programmerchad
#

# log object
# Stuck into a dictionary by user:Log, where log houses
# logs, fails, successes, logged IPs, and commands used
class Log:
    # dump date of first log
    def first_date(self):
        if len(self.logs) > 0:
            date = None
            i = 0
            # sometimes the first few aren't right, so look
            # until we find one
            while i < len(self.logs) and date is None:
                date = ParseDate(self.logs[i])
                i += 1
            return date

    # dump date of last log
    def last_date(self):
        if len(self.logs) > 0:
            return ParseDate(self.logs[len(self.logs) - 1])

    def __init__(self, usr):
        self.usr = usr
        self.logs = []
        self.fail_logs = []
        self.succ_logs = []
        self.ips = []
        self.commands = []


# parse user from various lines
def ParseUsr(line):
    usr = None
    if "Accepted password" in line:
        usr = re.search(r'(\bfor\s)(\w+)', line)
    elif "sudo:" in line:
        usr = re.search(r'(sudo:\s+)(\w+)', line)
    elif "authentication failure" in line:
        usr = re.search(r'USER=\w+', line)
    elif "for invalid user" in line:
        usr = re.search(r'(\buser\s)(\w+)', line)
    if usr is not None:
        return usr.group(2)


# parse an IP from a line
def ParseIP(line):
    ip = re.search(r'(\bfrom\s)(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)', line)
    if ip is not None:
        return ip.group(2)


# parse a date from the line
def ParseDate(line):
    date = re.search(r'^[A-Za-z]{3}\s*[0-9]{1,2}\s[0-9]{1,2}:[0-9]{2}:[0-9]{2}', line)
    if date is not None:
        return date.group(0)


# parse a command from a line
def ParseCmd(line):
    # parse command to end of line
    cmd = re.search(r'(\bCOMMAND=)(.+?$)', line)
    if cmd is not None:
        return cmd.group(2)


# begin parsing the passed LOG
def ParseLogs(log):
    # initialize the dictionary
    logs = {}

    # parse the log
    f = None
    try:
        f = gzip.open(log, 'r') if '.gz' in log else open(log, 'r')
        log = f.read()
    except Exception as e:
        print('[-] Error opening \'%s\': %s' % (log, e))
        return None
    finally:
        if f is not None:
            f.close()

    for line in log.split('\n'):
        # match a login
        if "Accepted password for" in line:
            usr = ParseUsr(line)

            # add 'em if they don't exist
            if usr not in logs:
                logs[usr] = Log(usr)

            ip = ParseIP(line)
            # set info
            if ip not in logs[usr].ips:
                logs[usr].ips.append(ip)
            logs[usr].succ_logs.append(line.rstrip('\n'))
            logs[usr].logs.append(line.rstrip('\n'))

        # match a failed login
        elif "Failed password for" in line:
            # parse user
            usr = ParseUsr(line)

            if usr not in logs:
                logs[usr] = Log(usr)

            ip = ParseIP(line)

            if ip not in logs[usr].ips:
                logs[usr].ips.append(ip)
            logs[usr].fail_logs.append(line.rstrip('\n'))
            logs[usr].logs.append(line.rstrip('\n'))

        # match failed auth
        elif ":auth): authentication failure;" in line:
            # so there are three flavors of authfail we care about;
            # su, sudo, and ssh.  Lets parse each.
            usr = re.search(r'(\blogname=)(\w+)', line)
            if usr is not None:
                usr = usr.group(2)
            # parse a fail log to ssh
            if "(sshd:auth)" in line:
                # ssh doesn't have a logname hurr
                usr = ParseUsr(line)
                if usr not in logs:
                    logs[usr] = Log(usr)
                logs[usr].ips.append(ParseIP(line))
            # parse sudo/su fails
            else:
                if usr not in logs:
                    logs[usr] = Log(usr)
            logs[usr].fail_logs.append(line.rstrip('\n'))
            logs[usr].logs.append(line.rstrip('\n'))
        # match commands
        elif "sudo:" in line:
            # parse user
            usr = ParseUsr(line)
            if usr not in logs:
                logs[usr] = Log(usr)

            cmd = ParseCmd(line)
            # append the command if it isn't there already
            if cmd is not None:
                if cmd not in logs[usr].commands:
                    logs[usr].commands.append(cmd)
            logs[usr].logs.append(line.rstrip('\n'))
    return logs
