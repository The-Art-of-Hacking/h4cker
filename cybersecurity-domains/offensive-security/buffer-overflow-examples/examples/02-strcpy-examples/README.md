# Buffer Overflow with strcpy() Examples

## Overview

The `strcpy()` function is one of the most notorious sources of buffer overflow vulnerabilities in C programs. This directory contains multiple examples demonstrating how unsafe string copying leads to memory corruption and how to exploit or prevent it.

## Why is strcpy() Dangerous?

### The Problem

```c
char buffer[12];
strcpy(buffer, user_input);  // NO BOUNDS CHECKING!
```

**Critical Issues:**
1. **No size checking** - `strcpy()` copies until it finds `'\0'`
2. **Assumes destination is large enough** - No validation
3. **Can't limit copy size** - No way to specify maximum bytes
4. **Silent memory corruption** - Overwrites adjacent memory without warning

### What strcpy() Does

```c
// Simplified implementation
char* strcpy(char* dest, const char* src) {
    char* original = dest;
    while (*src != '\0') {  // Copy until null terminator
        *dest++ = *src++;   // Keep copying regardless of dest size!
    }
    *dest = '\0';           // Add null terminator
    return original;
}
```

**The danger**: The `while` loop never checks if `dest` has enough space!

## Example 1: Understanding Null Terminators

### Code: strcpy_example.c

```c
#include <string.h>
void omarsucks(char *str)
{
	char buffer[12];
	/* The following strcpy will result in buffer overflow */
	strcpy(buffer, str);
}
int main()
{
	char *str = "This text is indeed a lot bigger or longer than 12";
	omarsucks(str);
	return 1;
}
```

### What Happens?

**Input String**: `"This text is indeed a lot bigger or longer than 12"` (52 bytes + null)

**Buffer Size**: 12 bytes

**Overflow**: 41 bytes overflow into adjacent stack memory!

### Compilation & Testing

```bash
# Compile without protections
gcc strcpy_example.c -o strcpy1 -fno-stack-protector -z execstack -m32

# Run normally - it will crash
./strcpy1

# Examine in GDB
gdb ./strcpy1
(gdb) run
(gdb) info registers
(gdb) x/40wx $esp  # Examine stack memory
```

### Stack Layout Before Overflow

```
High Memory
┌─────────────────────┐
│  Return Address     │ ← 0x08048123 (back to main)
├─────────────────────┤
│  Saved EBP          │ ← 0xbffff678
├─────────────────────┤
│  buffer[8-11]       │ ← Empty
├─────────────────────┤
│  buffer[4-7]        │ ← Empty
├─────────────────────┤
│  buffer[0-3]        │ ← Empty
└─────────────────────┘
Low Memory
```

### Stack Layout After Overflow

```
High Memory
┌─────────────────────┐
│  Return Address     │ ← OVERWRITTEN: "gger" (0x67676572)
├─────────────────────┤
│  Saved EBP          │ ← OVERWRITTEN: "big " (0x62696720)
├─────────────────────┤
│  buffer[8-11]       │ ← " lot" (overflowed)
├─────────────────────┤
│  buffer[4-7]        │ ← "d a " (overflowed)
├─────────────────────┤
│  buffer[0-3]        │ ← "This" (within bounds)
└─────────────────────┘
Low Memory
```

**Result**: When `omarsucks()` tries to return, it attempts to jump to address `0x67676572`, which is invalid → **Segmentation Fault**

### Visual Diagram

![Buffer Overflow Stack Layout](../../BufferOverFlow.png)

The image shows how the buffer overflow overwrites the saved frame pointer and return address on the stack.

![Stack After Buffer Overflow](../../stack_after_buffer_overflow.png)

## Example 2: Command Line Argument Overflow

### Code: strcpy_example2.c

```c
#include <stdio.h> 
#include <string.h> 
#include <stdlib.h> 
  
int main(int argc, char *argv[]) 
{ 
       // Reserve 5 byte of buffer plus the terminating NULL. 
       // should allocate 8 bytes = 2 double words, 
       // To overflow, need more than 8 bytes... 
       char buffer[5];  // If more than 8 characters input 
                        // by user, there will be access  
                        // violation, segmentation fault 
  
       // a prompt how to execute the program... 
       if (argc < 2) 
       { 
              printf("strcpy() NOT executed....\n"); 
              printf("Syntax: %s <characters>\n", argv[0]); 
              exit(0); 
       } 
  
       // copy the user input to mybuffer, without any 
       // bound checking a secure version is strncpy() or strcpy_s() 
       strcpy(buffer, argv[1]); 
       printf("buffer content= %s\n", buffer); 
  
       printf("strcpy() executed...\n"); 
  
       return 0; 
}
```

### What's Different?

This example takes input from command-line arguments instead of hardcoded strings, making it more realistic and exploitable.

**Key Points:**
- Buffer is only 5 bytes
- Input comes from `argv[1]` (user-controlled)
- No validation of input length
- Perfect for hands-on exploitation practice

### Compilation & Testing

```bash
# Compile
gcc strcpy_example2.c -o strcpy2 -fno-stack-protector -z execstack -m32

# Normal usage (safe)
./strcpy2 "Hi"
# Output: buffer content= Hi

# Trigger overflow
./strcpy2 "ThisIsWayTooLong"
# Output: buffer content= ThisIsWayTooLong
#         Segmentation fault (core dumped)

# Controlled overflow for exploitation
./strcpy2 "AAAABBBBCCCCDDDD\x9d\x84\x04\x08"
```

### Testing Different Input Sizes

```bash
# Safe (within buffer)
./strcpy2 "AAAA"                    # 4 bytes - OK
./strcpy2 "AAAAA"                   # 5 bytes - fills buffer exactly (including null)

# Dangerous (overflow)
./strcpy2 "AAAAAA"                  # 6 bytes - overflows by 1
./strcpy2 "AAAAAAAA"                # 8 bytes - overflows by 3
./strcpy2 "$(python -c 'print "A"*20')"  # 20 bytes - significant overflow
```

## Exploitation Challenges

### Challenge 1: Crash the Program (Easy)

**Goal**: Make the program crash with a segmentation fault

**Hint**: Input more than 8 bytes

```bash
./strcpy2 "AAAAAAAAAAAA"
```

### Challenge 2: Control EIP (Medium)

**Goal**: Make the program crash with a specific value in EIP/RIP

**Steps**:
1. Find the offset to the return address
2. Craft payload with specific value

```bash
# Example: Try to set EIP to 0x42424242 ('BBBB')
./strcpy2 "$(python -c 'print("A"*12 + "BBBB")')"

# Check crash in GDB
gdb ./strcpy2
(gdb) run "$(python -c 'print("A"*12 + "BBBB")')"
(gdb) info registers eip
# Should show eip = 0x42424242
```

### Challenge 3: Execute Arbitrary Code (Advanced)

**Goal**: Redirect execution to shellcode or existing function

**Requirements**:
- Know the address of your target (function or shellcode)
- Calculate exact offset to return address
- Account for little-endian byte order

See the [Exploitation Techniques](../../exploitation/) directory for detailed guidance.

## Safe Alternatives to strcpy()

### Option 1: strncpy()

```c
char buffer[12];
strncpy(buffer, user_input, sizeof(buffer) - 1);
buffer[sizeof(buffer) - 1] = '\0';  // Ensure null termination
```

**Pros**: Size-limited copying  
**Cons**: Doesn't always null-terminate; less efficient

### Option 2: strlcpy() (BSD, not standard C)

```c
char buffer[12];
strlcpy(buffer, user_input, sizeof(buffer));
```

**Pros**: Always null-terminates; returns string length  
**Cons**: Not available on all systems

### Option 3: strcpy_s() (C11 Annex K)

```c
char buffer[12];
errno_t result = strcpy_s(buffer, sizeof(buffer), user_input);
if (result != 0) {
    fprintf(stderr, "String copy failed!\n");
}
```

**Pros**: Built-in error checking; standard in C11  
**Cons**: Not widely supported yet

### Option 4: Manual Validation (Recommended)

```c
char buffer[12];
size_t input_len = strlen(user_input);

if (input_len >= sizeof(buffer)) {
    fprintf(stderr, "Error: Input too long (max %zu bytes)\n", 
            sizeof(buffer) - 1);
    return 1;
}

strcpy(buffer, user_input);  // Now safe
```

**Pros**: Explicit, clear intent; works everywhere  
**Cons**: More verbose

### Option 5: Use Modern Languages

```rust
// Rust prevents buffer overflows at compile time
let mut buffer = String::with_capacity(12);
buffer.push_str(user_input);  // Automatically resizes if needed
```

## Detailed Analysis: How strcpy() Fails

### The Vulnerable Pattern

```c
void process_username(char *input) {
    char username[32];
    strcpy(username, input);  // VULNERABLE!
    printf("Welcome, %s!\n", username);
}
```

### What an Attacker Sees

**Normal Input**: `"Alice"` → Works fine

**Malicious Input**: 
```
[32 bytes of padding][4 bytes: address of shellcode][shellcode bytes]
```

### Attack Sequence

1. **Overflow the buffer** with padding (32 bytes)
2. **Overwrite return address** with shellcode location (4 bytes)
3. **Add shellcode** after return address
4. **Function returns** → jumps to shellcode → **compromise!**

## Comparison: Safe vs Unsafe String Functions

| Unsafe | Safe Alternative | Why Unsafe? | Fix |
|--------|------------------|-------------|-----|
| `strcpy(dst, src)` | `strncpy(dst, src, n)` | No size limit | Specify max bytes |
| `strcat(dst, src)` | `strncat(dst, src, n)` | No size limit | Specify max bytes |
| `sprintf(buf, fmt, ...)` | `snprintf(buf, n, fmt, ...)` | No size limit | Specify buffer size |
| `gets(buf)` | `fgets(buf, n, stdin)` | No size limit | NEVER use gets()! |
| `scanf("%s", buf)` | `scanf("%31s", buf)` | No size limit | Specify width limit |

## Real-World Impact

### Famous strcpy() Vulnerabilities

**Morris Worm (1988)**
- Exploited `strcpy()` in `fingerd`
- First major internet worm
- Infected ~10% of internet

**Code Red (2001)**
- Buffer overflow in IIS via `strcpy()`-like operation
- Infected 359,000 servers
- $2.6 billion in damages

**Heartbleed (2014)**
- Not strcpy(), but similar memory overflow
- OpenSSL vulnerability
- Affected 17% of secure web servers

## Debugging with GDB

### Finding the Overflow Point

```bash
gdb ./strcpy2

# Set breakpoint before strcpy
(gdb) break strcpy
(gdb) run "AAAAAAAAAAAAAAAA"

# Step through and watch memory
(gdb) next
(gdb) x/20wx $esp  # Examine stack

# Check registers after crash
(gdb) continue
(gdb) info registers
```

### Analyzing the Crash

```bash
# Look at where it tried to jump
(gdb) info registers eip
eip            0x41414141

# This means return address was overwritten with 'AAAA'
```

## Learning Exercises

### Exercise 1: Buffer Boundary Testing
Test both programs with increasing input sizes. Record at what size they crash.

### Exercise 2: Offset Calculation
For `strcpy_example2.c`, determine the exact offset to the return address.

### Exercise 3: Pattern Matching
Use unique patterns (e.g., "AAAABBBBCCCCDDDD") to identify which bytes overwrite the return address.

### Exercise 4: Address Discovery
Use GDB or `objdump` to find addresses of functions, then redirect execution to them.

### Exercise 5: Exploitation
Write a complete exploit that spawns a shell or calls a specific function.

## Key Takeaways

1. **strcpy() is inherently unsafe** - It cannot prevent buffer overflows
2. **Stack corruption is predictable** - Understanding layout enables exploitation
3. **User input is dangerous** - Always validate and limit input size
4. **Modern alternatives exist** - Use `strncpy()`, `strlcpy()`, or safer languages
5. **Defense in depth** - Combine safe coding, compiler protections, and OS mitigations

## Next Steps

- Practice [Calculating Offsets](../../exploitation/calculating-offsets.md)
- Learn about [Writing Exploits](../../exploitation/writing-exploits.md)
- Study [Shellcode Basics](../../exploitation/shellcode-basics.md)
- Explore [Modern Mitigations](../../defenses/mitigations.md)
- Try the [Advanced Stack Overflow](../04-advanced-stack/) challenge

## References

- [CWE-120: Buffer Copy without Checking Size of Input](https://cwe.mitre.org/data/definitions/120.html)
- [strcpy() Man Page](https://man7.org/linux/man-pages/man3/strcpy.3.html)
- [CERT C Secure Coding: STR31-C](https://wiki.sei.cmu.edu/confluence/display/c/STR31-C.+Guarantee+that+storage+for+strings+has+sufficient+space+for+character+data+and+the+null+terminator)
- [Smashing the Stack for Fun and Profit](http://phrack.org/issues/49/14.html)

---

**⚠️ Warning**: These examples intentionally demonstrate vulnerable code. Never use `strcpy()` in production without proper input validation. Always prefer safer alternatives like `strncpy()`, `strlcpy()`, or bounds-checked functions.
