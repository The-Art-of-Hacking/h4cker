# Memory and the Stack

## Understanding Computer Memory

To understand buffer overflows, you need to understand how programs use memory. When a program runs, the operating system allocates memory to it, which is divided into several regions.

## Memory Layout of a Process

A typical process memory layout (from low to high addresses):

```
High Memory Address
┌─────────────────┐
│  Kernel Space   │ ← Operating system memory (off-limits)
├─────────────────┤
│  Stack          │ ← Local variables, function calls (grows downward ⬇)
│       ⬇         │
│                 │
│   [free space]  │
│                 │
│       ⬆         │
│  Heap           │ ← Dynamic memory allocation (grows upward ⬆)
├─────────────────┤
│  BSS Segment    │ ← Uninitialized global/static variables
├─────────────────┤
│  Data Segment   │ ← Initialized global/static variables
├─────────────────┤
│  Text Segment   │ ← Program code (instructions)
└─────────────────┘
Low Memory Address
```

### Memory Segments Explained

| Segment | Purpose | Characteristics |
|---------|---------|-----------------|
| **Text** | Program code (machine instructions) | Read-only, executable, shared |
| **Data** | Initialized global/static variables | Read-write, fixed size |
| **BSS** | Uninitialized global/static variables | Read-write, zeroed at start |
| **Heap** | Dynamic memory (`malloc`, `new`) | Grows upward, managed manually |
| **Stack** | Local variables, function calls | Grows downward, automatic management |

## The Stack: Where Buffer Overflows Usually Happen

The **stack** is a Last-In-First-Out (LIFO) data structure used for:
- Storing local variables
- Managing function calls and returns
- Passing function arguments
- Saving CPU register states

### Stack Growth Direction

**Important:** The stack grows from high memory addresses to low memory addresses (downward), but buffers within the stack grow from low to high addresses (upward).

```
High Address
┌──────────────┐
│   Old Data   │  ⬅ Stack starts here
├──────────────┤
│  Function 1  │
├──────────────┤
│  Function 2  │  ⬅ Stack grows down
├──────────────┤
│  Function 3  │  ⬅ Most recent function
└──────────────┘
Low Address
```

## Stack Frame Anatomy

Each function call creates a **stack frame** (also called activation record):

```
High Memory
┌─────────────────────┐
│  Function Arguments │ ⬅ Pushed by caller
├─────────────────────┤
│  Return Address     │ ⬅ Where to jump back after function completes
├─────────────────────┤
│  Saved Frame Ptr    │ ⬅ Previous function's base pointer (EBP/RBP)
├─────────────────────┤
│  Local Variable 1   │
├─────────────────────┤
│  Local Variable 2   │
├─────────────────────┤
│  Buffer[0..N]       │ ⬅ Local arrays/buffers
├─────────────────────┤
│  ...more locals...  │
└─────────────────────┘
Low Memory
```

### Key Stack Pointers

Two CPU registers track the stack:

**ESP/RSP (Stack Pointer)**
- Points to the current top of the stack
- Moves as data is pushed/popped
- Changes frequently during execution

**EBP/RBP (Base/Frame Pointer)**
- Points to the base of the current stack frame
- Used as a reference point for accessing local variables and parameters
- Remains stable during function execution

## How Function Calls Work

Let's trace what happens when `main()` calls `vulnerable()`:

### Before the Call (in main)

```
Stack:
┌─────────────────┐
│   main's vars   │ ⬅ EBP, ESP here
└─────────────────┘
```

### Step 1: Push Arguments (if any)

```c
vulnerable("Hello");  // Push "Hello" pointer
```

```
Stack:
┌─────────────────┐
│   main's vars   │
├─────────────────┤
│   argument      │ ⬅ "Hello" pointer
└─────────────────┘
```

### Step 2: Execute CALL Instruction

The `call` instruction:
1. Pushes the **return address** (next instruction in `main`)
2. Jumps to `vulnerable()` function

```
Stack:
┌─────────────────┐
│   main's vars   │
├─────────────────┤
│   argument      │
├─────────────────┤
│ Return Address  │ ⬅ Where to return after vulnerable()
└─────────────────┘
```

### Step 3: Function Prologue

At the start of `vulnerable()`:

```assembly
push ebp          ; Save old base pointer
mov ebp, esp      ; Set new base pointer
sub esp, N        ; Allocate space for local variables
```

```
Stack:
┌─────────────────┐
│   main's vars   │
├─────────────────┤
│   argument      │
├─────────────────┤
│ Return Address  │ ⬅ CRITICAL: Controls where program returns
├─────────────────┤
│ Saved EBP       │ ⬅ Previous frame pointer
├─────────────────┤
│ Local Var 1     │
├─────────────────┤
│ buffer[20]      │ ⬅ ESP, EBP now point here
└─────────────────┘
```

### Step 4: Function Epilogue (Normal Return)

At the end of `vulnerable()`:

```assembly
mov esp, ebp      ; Restore stack pointer
pop ebp           ; Restore base pointer
ret               ; Pop return address and jump to it
```

The program returns to `main()` and continues normally.

## Buffer Overflow Visualization

Now let's see what happens with a buffer overflow:

### Normal Case

```c
void vulnerable() {
    char buffer[8];
    strcpy(buffer, "Hello");  // 5 bytes + null terminator = 6 bytes (OK)
}
```

```
Stack:
┌──────────────────┐
│ Return Address   │ ⬅ 0x08048123 (unchanged)
├──────────────────┤
│ Saved EBP        │ ⬅ 0xbffff678 (unchanged)
├──────────────────┤
│ buffer[4-7]      │ ⬅ "\0\0\0\0"
├──────────────────┤
│ buffer[0-3]      │ ⬅ "Hell"
└──────────────────┘
    ⬆ ESP
```

### Overflow Case

```c
void vulnerable() {
    char buffer[8];
    strcpy(buffer, "ThisStringIsMuchLongerThan8Bytes");  // OVERFLOW!
}
```

```
Stack Before:
┌──────────────────┐
│ Return Address   │ ⬅ 0x08048123
├──────────────────┤
│ Saved EBP        │ ⬅ 0xbffff678
├──────────────────┤
│ buffer[8]        │
└──────────────────┘

Stack After Overflow:
┌──────────────────┐
│ Return Address   │ ⬅ 0x73736572 (OVERWRITTEN! Actually "ress" from string)
├──────────────────┤
│ Saved EBP        │ ⬅ 0x676e6f4c (OVERWRITTEN! Actually "Long" from string)
├──────────────────┤
│ buffer[8-11]     │ ⬅ "Much"
├──────────────────┤
│ buffer[4-7]      │ ⬅ "ngIs"
├──────────────────┤
│ buffer[0-3]      │ ⬅ "This"
└──────────────────┘
    ⬆ ESP
```

**What happens next:**
1. Function tries to return
2. Pops corrupted return address (0x73736572)
3. Tries to jump to that address
4. **CRASH!** - Segmentation fault (invalid memory access)

## Exploiting Buffer Overflows

An attacker can carefully craft input to:

### 1. Control the Return Address

```
Stack Layout:
┌──────────────────┐
│ Return Address   │ ⬅ Overwrite with 0xbffff7d0 (address of shellcode)
├──────────────────┤
│ Saved EBP        │ ⬅ Can be junk (not critical)
├──────────────────┤
│ buffer + padding │ ⬅ Fill with NOPs + shellcode
└──────────────────┘
```

### 2. Inject Malicious Code

```
Payload Structure:
[  NOP Sled  ][  Shellcode  ][  Junk  ][  Return Address  ]
  (safety)      (exploit)     (fill)     (points to NOPs)
```

### 3. Redirect Execution

When the function returns:
1. Pops attacker-controlled return address
2. Jumps to NOP sled
3. Slides down to shellcode
4. Executes arbitrary code!

## Little Endian vs Big Endian

When overwriting addresses, byte order matters:

**Little Endian** (x86, x64):
- Least significant byte first
- Address 0x12345678 stored as: `\x78\x56\x34\x12`

**Big Endian** (some ARM, network protocols):
- Most significant byte first
- Address 0x12345678 stored as: `\x12\x34\x56\x78`

Example:
```python
# To overwrite return address with 0xdeadbeef on x86:
payload = b"A" * 32 + b"\xef\xbe\xad\xde"
```

## Stack vs Heap Overflows

### Stack Overflow Characteristics
- **Target**: Local variables, return addresses
- **Easier to exploit**: Predictable structure
- **Impact**: Code execution via return address overwrite

### Heap Overflow Characteristics
- **Target**: Dynamically allocated memory
- **Harder to exploit**: Less predictable layout
- **Impact**: Data corruption, function pointer overwrite, metadata manipulation

## Key Takeaways

1. **The stack grows downward** (high to low addresses), but **buffers grow upward** (low to high)
2. **Return addresses are stored on the stack** and can be overwritten
3. **Buffer overflow happens** when data exceeds buffer boundaries
4. **Careful memory layout understanding** is critical for both exploitation and defense
5. **Stack frames contain critical control data** that attackers want to modify

## Practical Implications

### For Attackers (Ethical Hackers)
- Need to calculate exact offset to return address
- Must understand stack layout of target function
- Payload must account for stack alignment and protections

### For Defenders (Developers)
- Use stack canaries to detect corruption
- Enable DEP/NX to prevent code execution on stack
- Use ASLR to randomize stack addresses
- Validate all input sizes
- Use safe string functions

## Next Steps

1. Learn about [CPU Registers](registers.md) used in stack operations
2. Study [Assembly Basics](assembly-basics.md) to understand low-level stack manipulation
3. Practice with [Simple Buffer Overflow Example](../examples/01-simple-overflow/)
4. Read about [Modern Mitigations](../defenses/mitigations.md)

## Further Reading

- [Smashing the Stack for Fun and Profit](http://phrack.org/issues/49/14.html) - The classic paper
- [Intel Software Developer Manual](https://software.intel.com/en-us/articles/intel-sdm) - Architecture details
- [Stack Frame Layout](https://eli.thegreenplace.net/2011/09/06/stack-frame-layout-on-x86-64/)
- [ASLR Explained](https://en.wikipedia.org/wiki/Address_space_layout_randomization)

---

**Remember:** Understanding the stack is fundamental to both exploiting and defending against buffer overflows. Master these concepts before moving to exploitation techniques.

