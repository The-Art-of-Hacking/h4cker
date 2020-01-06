| PowerShell Command  | Description                                                                |
|----------------------------------------------|------------------------------------|
| `Get-ChildItem` | Lists directories |
| `Copy-Item sourceFile.doc destinationFile.doc` | Copies a file (cp, copy, cpi) |
| `Move-Item sourceFile.doc destinationFile.doc` | Moves a file (mv, move, mi) |
| `Select-String –path c:\users\*.txt –pattern password` | Finds text within a file |
| `Get-Content omar_s_passwords.txt`    | Prints the contents of a file     |
| `Get-Location`   | Gets the present directory   |
| `Get-Process`  | Gets a process listing |
| `Get-Service` | Gets a service listing |
| `Get-Process \| Export-Csvprocs.csv`  | Exports output to a comma-separated values (CSV) file |
| `1..255 \| % {echo "10.1.2.$_"; ping -n 1 -w 100 10.1.2.$_ \| SelectString ttl}`  | Launches a ping sweep to the 10.1.2.0/24 network |
| `1..1024 \| % {echo ((new-object Net.Sockets.TcpClient).Connect("10.1.2.3",$_))"Port $_ is open!"} 2>$null` | Launches a port scan to the 10.1.2.3 host (scans for ports 1 through 1024) |
| `Get-HotFix`    | Obtains a list of all installed hotfixes |
| `cd HKLM:` and then `ls` | Navigates the Windows registry |
| `Get-NetFirewallRule –all` or `New-NetFirewallRule -Action Allow -DisplayName LetMeIn-RemoteAddress 10.6.6.6`   | Lists and modifies the Windows firewall rules |
| `Get-Command` | Gets a list of all available commands |
