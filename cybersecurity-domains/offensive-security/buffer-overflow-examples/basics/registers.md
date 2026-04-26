# CPU Registers Explained

## Introduction

Registers are small, extremely fast storage locations built directly into the CPU. Understanding registers is essential for:
- Reading and writing assembly code
- Understanding buffer overflow exploitation
- Debugging programs at the instruction level
- Reverse engineering binaries

## What are Registers?

**Registers** are the CPU's working memory - tiny storage spaces that can hold data being actively processed. They are:
- **Fastest memory** available (faster than cache, RAM, or disk)
- **Limited in number** (typically 8-16 general-purpose registers)
- **Architecture-specific** (different CPUs have different registers)
- **Directly accessible** by assembly instructions

### Why Registers Matter for Exploitation

In buffer overflow attacks:
- **EIP/RIP** - The instruction pointer we want to control
- **ESP/RSP** - Points to our overflow data on the stack
- **EBP/RBP** - Helps us locate return addresses
- **EAX/RAX** - Often holds return values we might want to control

## 32-bit Registers (x86)

In 32-bit x86 architecture, registers can hold 32-bit (4-byte) values. These registers are used to temporarily store data that is being operated on by the CPU. The most common use of 32-bit registers is to hold memory addresses, but they can also be used to hold data that is being operated on by the CPU.

### General-Purpose Registers (x86 32-bit)

| Register | Full Name | Primary Purpose | Common Use in Exploitation |
|----------|-----------|-----------------|---------------------------|
| **EAX** | Accumulator | Arithmetic operations, return values | Return value storage, syscall number |
| **EBX** | Base | Memory addressing | Base address for memory operations |
| **ECX** | Counter | Loop counter | Loop iterations, string operations |
| **EDX** | Data | I/O operations, arithmetic | Extended arithmetic, syscall parameters |
| **ESI** | Source Index | String/array source pointer | Memory copy source |
| **EDI** | Destination Index | String/array destination pointer | Memory copy destination |
| **EBP** | Base Pointer | Stack frame base pointer | **Critical: Saved frame pointer** |
| **ESP** | Stack Pointer | Current stack position | **Critical: Current stack top** |

### Special-Purpose Registers (x86 32-bit)

| Register | Purpose | Exploitation Relevance |
|----------|---------|------------------------|
| **EIP** | Instruction Pointer | **MOST CRITICAL: Controls execution flow** |
| **EFLAGS** | Processor flags | Conditional jumps, status flags |

### Why Each Register Matters

**EAX (Accumulator)**
- Holds function return values
- Used for syscall numbers in Linux (`int 0x80`)
- First register to check when analyzing function results

**EBX (Base)**
- Often holds memory base addresses
- First syscall argument in Linux
- Can hold pointers to important data

**ECX (Counter)**
- Loop counter in `loop` instruction
- Used in `rep` string operations
- Second syscall argument

**EDX (Data)**
- Third syscall argument
- High-order bits in multiplication/division
- I/O port operations

**EBP (Base Pointer)** ⭐
- Points to the base of current stack frame
- **Saved on stack during function calls**
- Overwriting saved EBP affects stack walking
- Used to access local variables and parameters

**ESP (Stack Pointer)** ⭐⭐
- **Points to top of stack**
- Modified by `push`/`pop` instructions
- Critical for understanding buffer location
- Buffer overflows fill from ESP upward

**EIP (Instruction Pointer)** ⭐⭐⭐
- **THE TARGET of buffer overflow attacks**
- Contains address of next instruction to execute
- **Overwriting EIP = Code execution control**
- Cannot be directly modified (only via jumps/returns)

### Register Relationships in Stack Frames

```
High Memory
┌─────────────────────────┐
│  Previous Frame         │
├─────────────────────────┤
│  Return Address (EIP)   │ ← What we want to overwrite!
├─────────────────────────┤
│  Saved EBP              │ ← Previous EBP value
├─────────────────────────┤ ← EBP points here (current frame base)
│  Local Variable 1       │
├─────────────────────────┤
│  Local Variable 2       │
├─────────────────────────┤
│  Buffer[N]              │
└─────────────────────────┘ ← ESP points here (current stack top)
Low Memory
```

**Official Documentation:**
- Intel Software Developer Manual: https://software.intel.com/en-us/articles/intel-sdm

## 64-bit Registers (x86-64 / x64 / AMD64)

In 64-bit x86-64 architecture, registers can hold 64-bit (8-byte) values. This is the dominant architecture in modern desktops, servers, and many laptops.

### General-Purpose Registers (x86-64)

| 64-bit | 32-bit | 16-bit | 8-bit | Purpose | Notes |
|--------|--------|--------|-------|---------|-------|
| **RAX** | EAX | AX | AL | Accumulator | Return values, syscall numbers |
| **RBX** | EBX | BX | BL | Base | General purpose |
| **RCX** | ECX | CX | CL | Counter | 4th function argument |
| **RDX** | EDX | DX | DL | Data | 3rd function argument |
| **RSI** | ESI | SI | SIL | Source Index | 2nd function argument |
| **RDI** | EDI | DI | DIL | Destination Index | 1st function argument |
| **RBP** | EBP | BP | BPL | Base Pointer | Stack frame base |
| **RSP** | ESP | SP | SPL | Stack Pointer | Stack top |
| **R8** | R8D | R8W | R8B | Extended | 5th function argument |
| **R9** | R9D | R9W | R9B | Extended | 6th function argument |
| **R10** | R10D | R10W | R10B | Extended | Temporary |
| **R11** | R11D | R11W | R11B | Extended | Temporary |
| **R12** | R12D | R12W | R12B | Extended | General purpose |
| **R13** | R13D | R13W | R13B | Extended | General purpose |
| **R14** | R14D | R14W | R14B | Extended | General purpose |
| **R15** | R15D | R15W | R15B | Extended | General purpose |

### Special-Purpose Registers (x86-64)

| Register | Purpose | Exploitation Relevance |
|----------|---------|------------------------|
| **RIP** | Instruction Pointer | **MOST CRITICAL: 64-bit execution control** |
| **RFLAGS** | Processor flags | Status and control flags |

### Key Differences from 32-bit

1. **More Registers**: x64 adds R8-R15 (8 additional registers)
2. **Larger Addresses**: Can address much more memory (theoretically 2^64 bytes)
3. **Different Calling Convention**: Function arguments passed in registers, not stack
4. **Syscall Instruction**: Uses `syscall` instead of `int 0x80`
5. **RIP-Relative Addressing**: Code can be position-independent more easily

### x64 Function Calling Convention (System V AMD64 ABI - Linux/Unix)

**Function Arguments (in order):**
1. **RDI** - 1st argument
2. **RSI** - 2nd argument
3. **RDX** - 3rd argument
4. **RCX** - 4th argument
5. **R8** - 5th argument
6. **R9** - 6th argument
7. Stack - 7th+ arguments

**Return Value:** **RAX**

**Example:**
```c
int func(int a, int b, int c, int d, int e, int f);
// a in RDI, b in RSI, c in RDX, d in RCX, e in R8, f in R9
```

### Exploitation Differences in 64-bit

**Challenges:**
- **Larger addresses** - Harder to fit in exploits
- **No NULL bytes in middle** - Addresses like `0x00007fffffffe000` contain NULLs
- **Calling convention** - Must control registers, not just stack
- **ASLR more effective** - Larger address space

**Advantages:**
- **More registers** - More ROP gadgets available
- **Cleaner architecture** - More orthogonal instruction set

### Practical Impact for Buffer Overflows

**32-bit Exploit:**
```python
# Easy: just overflow to return address
payload = b"A" * 76 + p32(0x08048456)
```

**64-bit Exploit:**
```python
# Harder: must setup registers for function calls
payload = b"A" * 72
payload += p64(pop_rdi_gadget)    # Set up RDI
payload += p64(binsh_address)     # RDI = "/bin/sh"
payload += p64(system_address)    # Call system()
```

**Important Notes:**
- 64-bit architecture is standard in modern systems
- Exploitation is more complex but still very possible
- Understanding both 32-bit and 64-bit is essential
- The principles remain the same, techniques differ

### Additional Notes: 
The x64 architecture extends x86's 8 general-purpose registers to be 64-bit, and adds 8 new 64-bit registers.  The 64-bit registers have names beginning with "r", so for example the 64-bit extension of **eax** is called **rax**.  The lower 32 bits, 16 bits, and 8 bits of each register are directly addressable in operands.  This includes registers, like **esi**, whose lower 8 bits were not previously addressable.  The following table specifies the assembly-language names for the lower portions of 64-bit registers.

<table><colgroup><col width="25%"> <col width="25%"> <col width="25%"> <col width="25%"></colgroup>

<thead>

<tr class="header">

<th align="left">64-bit register</th>

<th align="left">Lower 32 bits</th>

<th align="left">Lower 16 bits</th>

<th align="left">Lower 8 bits</th>

</tr>

</thead>

<tbody>

<tr class="odd">

<td align="left">**rax**</td>

<td align="left">**eax**</td>

<td align="left">**ax**</td>

<td align="left">**al**</td>

</tr>

<tr class="even">

<td align="left">**rbx**</td>

<td align="left">**ebx**</td>

<td align="left">**bx**</td>

<td align="left">**bl**</td>

</tr>

<tr class="odd">

<td align="left">**rcx**</td>

<td align="left">**ecx**</td>

<td align="left">**cx**</td>

<td align="left">**cl**</td>

</tr>

<tr class="even">

<td align="left">**rdx**</td>

<td align="left">**edx**</td>

<td align="left">**dx**</td>

<td align="left">**dl**</td>

</tr>

<tr class="odd">

<td align="left">**rsi**</td>

<td align="left">**esi**</td>

<td align="left">**si**</td>

<td align="left">**sil**</td>

</tr>

<tr class="even">

<td align="left">**rdi**</td>

<td align="left">**edi**</td>

<td align="left">**di**</td>

<td align="left">**dil**</td>

</tr>

<tr class="odd">

<td align="left">**rbp**</td>

<td align="left">**ebp**</td>

<td align="left">**bp**</td>

<td align="left">**bpl**</td>

</tr>

<tr class="even">

<td align="left">**rsp**</td>

<td align="left">**esp**</td>

<td align="left">**sp**</td>

<td align="left">**spl**</td>

</tr>

<tr class="odd">

<td align="left">**r8**</td>

<td align="left">**r8d**</td>

<td align="left">**r8w**</td>

<td align="left">**r8b**</td>

</tr>

<tr class="even">

<td align="left">**r9**</td>

<td align="left">**r9d**</td>

<td align="left">**r9w**</td>

<td align="left">**r9b**</td>

</tr>

<tr class="odd">

<td align="left">**r10**</td>

<td align="left">**r10d**</td>

<td align="left">**r10w**</td>

<td align="left">**r10b**</td>

</tr>

<tr class="even">

<td align="left">**r11**</td>

<td align="left">**r11d**</td>

<td align="left">**r11w**</td>

<td align="left">**r11b**</td>

</tr>

<tr class="odd">

<td align="left">**r12**</td>

<td align="left">**r12d**</td>

<td align="left">**r12w**</td>

<td align="left">**r12b**</td>

</tr>

<tr class="even">

<td align="left">**r13**</td>

<td align="left">**r13d**</td>

<td align="left">**r13w**</td>

<td align="left">**r13b**</td>

</tr>

<tr class="odd">

<td align="left">**r14**</td>

<td align="left">**r14d**</td>

<td align="left">**r14w**</td>

<td align="left">**r14b**</td>

</tr>

<tr class="even">

<td align="left">**r15**</td>

<td align="left">**r15d**</td>

<td align="left">**r15w**</td>

<td align="left">**r15b**</td>

</tr>

</tbody>

</table>

 

* Operations that output to a 32-bit subregister are automatically zero-extended to the entire 64-bit register. 
* Operations that output to 8-bit or 16-bit subregisters are *not* zero-extended (this is compatible x86 behavior).
* The high 8 bits of **ax**, **bx**, **cx**, and **dx** are still addressable as **ah**, **bh**, **ch**, **dh**, but cannot be used with all types of operands.
* The instruction pointer, **eip**, and **flags** register have been extended to 64 bits (**rip** and **rflags**, respectively) as well.

The x64 processor also provides several sets of floating-point registers:

* Eight 80-bit x87 registers.
*  Eight 64-bit MMX registers. (These overlap with the x87 registers.)
*  The original set of eight 128-bit SSE registers is increased to sixteen.

The addressing modes in 64-bit mode are similar to, but not identical to, x86.

* Instructions that refer to 64-bit registers are automatically performed with 64-bit precision. (For example **mov rax, \[rbx\]** moves 8 bytes beginning at **rbx** into **rax**.)
* A special form of the **mov** instruction has been added for 64-bit immediate constants or constant addresses. For all other instructions, immediate constants or constant addresses are still 32 bits.
* x64 provides a new **rip**-relative addressing mode. Instructions that refer to a single constant address are encoded as offsets from **rip**. For example, the **mov rax, \[***addr***\]** instruction moves 8 bytes beginning at *addr* + **rip** to **rax**.

Note: Instructions, like **jmp**, **call**, **push**, and **pop**, that implicitly refer to the instruction pointer and the stack pointer treat them as 64 bits registers on x64.


## ARM-based Registers

In the ARM architecture, there are several different types of registers. These include:

### ARM General-Purpose Registers

| Register | Alternative Name | Purpose |
|----------|------------------|---------|
| **R0-R12** | - | General purpose data manipulation |
| **R13** | SP (Stack Pointer) | Points to top of stack |
| **R14** | LR (Link Register) | Return address for function calls |
| **R15** | PC (Program Counter) | Next instruction address |

**Key Points:**
- **R0-R3**: Function arguments and return values
- **R4-R11**: General purpose, callee-saved
- **R13 (SP)**: Similar to ESP/RSP in x86
- **R14 (LR)**: Stores return address (unlike x86 which uses stack)
- **R15 (PC)**: Execution control (like EIP/RIP)

**Special Registers:**
- **CPSR** (Current Program Status Register) - Like EFLAGS
- **32 NEON/VFP registers** - For floating-point and SIMD
- **16 double-precision FP registers**

**For more ARM-specific information, see:** [ARM Resources](../resources/arm-resources.md)

## Practical Examples: Viewing Registers in GDB

### Examining Registers During Exploitation

```bash
# Start GDB
gdb ./vulnerable_program

# Run with input
(gdb) run < input.txt

# When it crashes, check registers
(gdb) info registers

# Common output (32-bit):
eax            0x0      0
ebx            0xb7fce000       -1208229888
ecx            0x41414141       1094795585
edx            0x41414141       1094795585
esi            0x0      0
edi            0x0      0
ebp            0x41414141       0x41414141
esp            0xbffff600       0xbffff600
eip            0x41414141       0x41414141  ← CONTROLLED!

# Check specific register
(gdb) print $eip
$1 = (void (*)()) 0x41414141

# Check what's at ESP
(gdb) x/20wx $esp

# Check what's at EBP
(gdb) x/wx $ebp
```

### Finding the Buffer in Registers

```bash
(gdb) break vulnerable_function
(gdb) run

# Check where buffer is
(gdb) print &buffer
$1 = (char (*)[100]) 0xbffff650

# Check ESP and EBP
(gdb) print $esp
$2 = (void *) 0xbffff600

(gdb) print $ebp
$3 = (void *) 0xbffff6f0

# Calculate offset: 0xbffff6f0 - 0xbffff650 = 0xa0 (160 bytes)
```

### Tracing Register Changes

```bash
(gdb) break main
(gdb) run

# Watch register
(gdb) display/x $eip
(gdb) display/x $esp
(gdb) display/x $ebp

# Step through instructions
(gdb) stepi
(gdb) stepi
# Registers displayed after each step
```

## Register Usage in Common Instructions

### Stack Operations

```assembly
push eax        ; ESP -= 4, [ESP] = EAX
pop eax         ; EAX = [ESP], ESP += 4

push rbx        ; RSP -= 8, [RSP] = RBX (64-bit)
pop rbx         ; RBX = [RSP], RSP += 8
```

### Function Calls (32-bit)

```assembly
call func       ; push EIP, EIP = func
ret             ; pop EIP (return to caller)

; Function prologue
push ebp        ; Save old base pointer
mov ebp, esp    ; Set new base pointer

; Function epilogue
mov esp, ebp    ; Restore stack pointer
pop ebp         ; Restore base pointer
ret             ; Return
```

### Function Calls (64-bit)

```assembly
; Before call, set up arguments
mov rdi, arg1   ; 1st argument
mov rsi, arg2   ; 2nd argument
mov rdx, arg3   ; 3rd argument
call func

; After return, result is in RAX
mov result, rax
```

## Quick Reference Card

### 32-bit Exploitation Cheat Sheet

| Register | What to Look For | What It Means |
|----------|------------------|---------------|
| **EIP = 0x41414141** | You control execution! | Successful overflow |
| **ESP = 0xbffff600** | Stack location | Buffer/shellcode might be here |
| **EBP = 0x41414141** | Saved frame pointer overwritten | Close to return address |
| **EAX = 0xffffffff** | -1 return value | Function failed |
| **EAX = 0x0** | 0 return value | Function succeeded |

### 64-bit Exploitation Cheat Sheet

| Register | What to Look For | What It Means |
|----------|------------------|---------------|
| **RIP = 0x4141414141414141** | You control execution! | Successful overflow |
| **RSP = 0x7fffffffe000** | Stack location | Higher addresses than 32-bit |
| **RDI** | 1st function argument | Check for controlled value |
| **RAX = 0x3b** | Syscall 59 (execve) | Possible shellcode execution |

### GDB Commands for Registers

```bash
info registers          # Show all registers
info registers eax ebx  # Show specific registers
print $eip              # Print EIP
print/x $esp            # Print ESP in hex
set $eax = 0x41414141   # Modify register
x/wx $esp               # Examine memory at ESP
```

## Common Exploitation Patterns

### Pattern 1: Finding Offset to EIP

1. Generate pattern and send to program
2. Check EIP value after crash
3. Find that value in pattern
4. Offset = position in pattern

### Pattern 2: Checking if Shellcode Executed

```bash
(gdb) info registers eax

# If EAX = 0x0b (11), might be execve syscall
# If you see registers set up like:
# EBX = address of "/bin/sh"
# ECX = address of argv
# EDX = 0
# Then shellcode likely executing
```

### Pattern 3: Debugging ROP Chains

```bash
# After setting ROP payload, watch stack
(gdb) x/20gx $rsp  # 64-bit (g = 8 bytes)
(gdb) x/20wx $esp  # 32-bit (w = 4 bytes)

# Step through each RET
(gdb) break *0x... # Break at each gadget
(gdb) stepi        # Step through gadget instructions
```

## Summary

### Key Takeaways

1. **Registers are the CPU's working memory** - Fast, limited, and architecture-specific
2. **EIP/RIP is the primary target** in buffer overflow attacks
3. **ESP/RSP shows stack location** - Where our overflow data lives
4. **EBP/RBP helps locate return addresses** - Understanding stack frames
5. **Different architectures have different registers** - x86, x64, ARM all differ
6. **64-bit exploitation is more complex** - More registers, different calling conventions
7. **Understanding registers is essential** - For exploitation and reverse engineering

### Next Steps

- Practice examining registers in GDB with [Simple Buffer Overflow](../examples/01-simple-overflow/)
- Learn [Assembly Basics](assembly-basics.md) to see registers in action
- Understand [Memory and the Stack](memory-and-stack.md) for stack frame details
- Try calculating offsets with register analysis

## Further Reading

- [Intel Software Developer Manual](https://software.intel.com/en-us/articles/intel-sdm) - Comprehensive x86/x64 documentation
- [AMD64 ABI Reference](https://refspecs.linuxfoundation.org/elf/x86_64-abi-0.99.pdf) - 64-bit calling conventions
- [ARM Architecture Reference Manual](https://developer.arm.com/documentation/)
- [GDB Tutorial](https://darkdust.net/files/GDB%20Cheat%20Sheet.pdf) - Register examination in GDB

---

**Remember**: Understanding registers deeply is fundamental to both offensive and defensive security. Master these concepts through hands-on practice with debuggers and exploitation challenges.
