# SELinux in Ubuntu Lab

The following can be completed with Ubuntu 22.x or later.

## Installing and Enabling SELinux
The first step is to install SELinux. Start by opening a command line terminal and installing the necessary packages with the apt commands below.
```
$sudo apt update
$ sudo apt install policycoreutils selinux-utils selinux-basics
```
### Activate SELinux
Execute the following command with root permissions to enable SELinux on the system.
```
$ sudo selinux-activate
```

## Enforcing Mode
Set SELinux to enforcing mode:
```
$ sudo selinux-config-enforcing
```

Reboot your system. The relabelling will be triggered after you reboot your system. When finished the system will reboot one more time automatically.
```
$ reboot

```
Check SELinux status with the following command to ensure that it is in enforcing mode.
$ sestatus


## Disabling SELinux
To disable SELinux open up the `/etc/selinux/config` configuration file and change the following line:

FROM:
```
SELINUX=enforcing
```
TO:
```
SELINUX=disabled
```
Reboot your system for the changes to take effect.

Alternatively you can temporarily put SELinux into permissive mode with the following command.
```
$ sudo setenforce 0
```
Note this change will not be persistent (i.e., survive a reboot). It will go back to enforcing later. To enable SELinux again just execute:
```
$ sudo setenforce 1
```
