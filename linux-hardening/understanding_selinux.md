# Understanding and Using SELinux

SELinux, or Security-Enhanced Linux, is an advanced access control mechanism integrated into the Linux kernel. Initially developed by the National Security Agency (NSA), it provides Mandatory Access Control (MAC) unlike traditional Unix/Linux access control which provides Discretionary Access Control (DAC). In this article, we will explore the basics of SELinux and how to use it effectively.

**NOTE:** Check the out the two labs I have here: [CENTOS LAB](https://github.com/The-Art-of-Hacking/h4cker/blob/master/linux-hardening/selinux_CENTOS_lab.md) and [UBUNTU SELINUX LAB](https://github.com/The-Art-of-Hacking/h4cker/blob/master/linux-hardening/selinux_UBUNTU_lab.md).

## Introduction to SELinux

SELinux adds another layer of access control, defining how/what a user process can access. It makes use of policies to enforce the rules that govern these permissions. It's designed to protect the integrity of the system, even when a process is compromised, by limiting potential damage.

SELinux has three modes of operation:

1. **Enforcing:** SELinux policy is enforced. SELinux denies access based on SELinux policy rules.
2. **Permissive:** SELinux policy is not enforced. SELinux does not deny access, but denials are logged for actions that would have been denied if running in enforcing mode.
3. **Disabled:** SELinux is fully disabled.

You can check the current status of SELinux by using the command: `sestatus`

## Working with SELinux

To get started with SELinux, you need to understand its concepts of 'Types' and 'Contexts':

- **Type Enforcement:** The primary mechanism of access control used in SELinux is Type Enforcement. Everything that acts upon or is acted upon in a system is assigned a type: files, directories, ports, and even processes have types.
  
- **Security Contexts:** SELinux attaches a security context to every system object. This context includes information like SELinux user, role, type, and, optionally, security level. You can view the security context of a file or process using `-Z` option with `ls` or `ps` command respectively.

For example, to view the context of files in a directory:

```bash
ls -Z /var/www/html
```

To view the context of running processes:

```bash
ps -efZ
```

## Managing SELinux Policies

The true power of SELinux comes from its fine-grained control over system objects, achieved through SELinux policies. These policies are the rules that the SELinux system uses to allow or disallow actions.

For example, if you have an application that requires access to a non-standard port, you can create or modify a SELinux policy to allow this access. The `semanage` command is a powerful tool for this:

```bash
semanage port -a -t http_port_t -p tcp 8080
```

In the above command, `-a` is to add a port, `-t` is to define the type, `-p` to define the protocol, and `8080` is the port number.

## Managing SELinux Modes

As mentioned earlier, SELinux has three modes of operation. To switch between these modes, you use the `setenforce` command:

```bash
setenforce 0   # Sets SELinux to Permissive mode
setenforce 1   # Sets SELinux to Enforcing mode
```

To make these changes persistent across reboots, modify the `SELINUX=` line in the `/etc/selinux/config` file.

## Handling SELinux Denials

When SELinux blocks an action, it generates a denial message that is logged to the `/var/log/audit/audit.log` file. The `audit2why` utility can help you understand why the action was denied:

```bash
audit2why -al
```

If a particular denial isn't in line with your system needs, you can create a custom SELinux policy module to allow the previously denied action using the `audit2allow` utility.

Again, check the out the two labs I have here: [CENTOS LAB](https://github.com/The-Art-of-Hacking/h4cker/blob/master/linux-hardening/selinux_CENTOS_lab.md) and [UBUNTU SELINUX LAB](https://github.com/The-Art-of-Hacking/h4cker/blob/master/linux-hardening/selinux_UBUNTU_lab.md).
