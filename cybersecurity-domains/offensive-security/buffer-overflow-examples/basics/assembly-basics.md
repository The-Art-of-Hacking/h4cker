# Learning Assembly for the Purpose of Principles of Reverse Engineering

Learning assembly language, whether it's for x86 or ARM architectures, can be a complex task as it involves understanding the computer at a more fundamental level compared to high-level languages. Here are some important concepts and topics you should understand when learning assembly language:

1. **Basic Computer Architecture**: Before starting with assembly, it's important to understand how computers work at a fundamental level. This includes concepts like memory management, CPU architecture, registers, and instruction cycle.

2. **Data Representation**: You should understand how data is represented in a computer system, including binary, hexadecimal, and two's complement for negative numbers. Knowing how data is represented will help you understand how different instructions manipulate this data.

3. **Instruction Set Architecture (ISA)**: Every architecture (like x86 and ARM) has its own ISA, which is a set of instructions that the CPU can execute. These include instructions for moving data, arithmetic operations, logical operations, control flow, and more.

4. **Registers**: Registers are small storage locations in the CPU that store data. Understanding the role of each register and how to use them is fundamental to assembly programming.

5. **Addressing Modes**: These are the methods used to access data in memory. Some common addressing modes include direct, indirect, register, immediate, and indexed addressing.

6. **Control Flow**: This includes concepts like loops, conditional branching (if-else statements), and function calls. Assembly has instructions for each of these, but they are often more complex to implement than in high-level languages.

7. **Stack**: The stack is a region of memory used for temporary storage of data. It's especially important for function calls and for saving the state of the program.

8. **Debugging and Tools**: Knowledge of tools for writing, assembling, linking, and debugging assembly programs is vital. This includes assemblers (like NASM for x86 and AS for ARM), linkers (like LD), and debuggers (like GDB).

For both x86 and ARM:

- **x86 Assembly**: x86 assembly can be written in either AT&T syntax or Intel syntax, which have some differences. x86 has a lot of legacy, which means there are many instructions, some of which do similar things. x86 architecture also includes different modes of operation, such as real mode, protected mode, and long mode (64-bit), each of which changes how the CPU interprets instructions.

- **ARM Assembly**: ARM uses a load-store architecture, which means that only specific instructions (load and store) can access memory. Most other instructions operate on registers. ARM also has a simpler, more orthogonal instruction set than x86. ARM processors also often include a Thumb instruction set, which uses 16-bit instructions instead of the standard 32-bit, for more compact code.

9. **Interrupts and Exception Handling**: Understanding how interrupts work, and how to handle exceptions at a low level, is a significant part of assembly programming.

10. **System Calls**: System calls are how a program interacts with the operating system. They can do things like read from a file, write to the console, allocate memory, and more. The specifics of how system calls are made are different on each operating system.

11. **Inline Assembly**: In many cases, you might use assembly language within a high-level language program to optimize a specific part of the code. Understanding how to write and use inline assembly could be very helpful.

Assembly language is low-level, so it requires a good understanding of the underlying hardware. But it also gives you a lot of power and flexibility, since you're working directly with the CPU and memory. Be patient with yourself as you learn, and practice regularly to reinforce your understanding.

## Examples

Different assemblers might require slightly different syntax, and details like system calls can vary between different operating systems.

**x86 Assembly**

This is a simple "Hello, World!" program in x86 assembly using the NASM assembler:

```assembly
section .data
    hello db 'Hello, World!',0   ; null-terminated string to be printed

section .text
    global _start

_start:
    ; syscall to write
    mov eax, 4  ; syscall number (sys_write)
    mov ebx, 1  ; file descriptor (stdout)
    mov ecx, hello  ; pointer to message to write
    mov edx, 13  ; message length
    int 0x80  ; call kernel

    ; syscall to exit
    mov eax, 1  ; syscall number (sys_exit)
    xor ebx, ebx  ; exit code
    int 0x80  ; call kernel
```

In this program, we're using the `int 0x80` instruction to make system calls. The specific system call and its arguments are determined by the values we put in the `eax`, `ebx`, `ecx`, and `edx` registers.

**ARM Assembly**

This is the same "Hello, World!" program in ARM assembly. This example uses the GNU assembler and is for Linux:

```assembly
.section .data
hello: .asciz "Hello, World!"

.text
.global _start
_start:
    mov r0, 1  ; file descriptor (stdout)
    ldr r1, =hello  ; pointer to message to write
    mov r2, 13  ; message length
    mov r7, 4  ; syscall number (sys_write)
    swi 0  ; call kernel

    mov r0, 0  ; exit code
    mov r7, 1  ; syscall number (sys_exit)
    swi 0  ; call kernel
```

The ARM version is similar to the x86 version. We're using the `swi 0` instruction to make system calls, and the `mov` and `ldr` instructions to put values into registers.

## Reversing a Simple C Program

Let's start with a simple C program:

```c
#include <stdio.h>

int main() {
    int a = 5;
    int b = 7;
    int sum = a + b;
    printf("The sum is: %d\n", sum);
    return 0;
}
```

First, you'll want to compile this program. We'll use GCC, a common C compiler. Use the `-g` flag to include debugging symbols, which will make the disassembled output easier to understand:

```
gcc -g -o sum sum.c
```

This compiles the program into an executable file named `sum`.

Now, you can disassemble the program using a tool like `objdump`:

```
objdump -d sum
```

This will output the assembly code of the program. The `-d` flag tells `objdump` to disassemble the executable sections of the file.

The output can be quite long and complex, especially for larger programs, but here's an annotated version of what the `main` function might look like in assembly:

```assembly
0000000000001139 <main>:
    1139:	55                   	push   rbp
    113a:	48 89 e5             	mov    rbp,rsp
    113d:	48 83 ec 10          	sub    rsp,0x10
    1141:	c7 45 fc 05 00 00 00 	mov    DWORD PTR [rbp-0x4],0x5
    1148:	c7 45 f8 07 00 00 00 	mov    DWORD PTR [rbp-0x8],0x7
    114f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
    1152:	03 45 f8             	add    eax,DWORD PTR [rbp-0x8]
    1155:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
    1158:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
    115b:	89 c6                	mov    esi,eax
    115d:	48 8d 3d a4 0e 00 00 	lea    rdi,[rip+0xea4]        # 2008 <_IO_stdin_used+0x8>
    1164:	b0 00                	mov    al,0x0
    1166:	e8 c5 fe ff ff       	call   1030 <printf@plt>
    116b:	b8 00 00 00 00       	mov    eax,0x0
    1170:	c9                   	leave  
    1171:	c3                   	ret    
```

Here's what's happening in this function, line by line:

- The function starts by setting up the stack frame: it pushes the old base pointer (`rbp`) onto the stack, then moves the stack pointer (`rsp`) to the new base pointer. This creates a new stack frame for the `main` function.

- The `sub rsp,0x10` instruction reserves space on the stack for local variables.

- The `mov` instructions store the values of `a` and `b` on the stack. The `[rbp-0x4]` and `[rbp-0x8]` are offsets from the base pointer, used to identify the locations of these local variables.

- The `add` instruction adds `a` and `b` together, and the result is stored on the stack as `sum`.

- The `lea` instruction loads the address of the format string for `printf` into `rdi`, and the `mov` and `call` instructions call `printf` to print the sum. The `printf` function is called with the string "The sum is: %d\n" and the sum as its arguments.

- The `mov eax,0x0` instruction sets the return value of the function to 0.

- The `leave` and `ret` instructions clean up the stack frame and return from the function.

Please note that exact assembly might differ based on the compiler, version, and optimization settings used. The interpretation of assembly code requires understanding of both the instruction set architecture (in this case, x86-64) and the calling convention used by the system (in this case, the System V AMD64 ABI, which is common on Unix-like systems, including Linux).

For more advanced reverse engineering, you might use a tool like Ghidra or IDA Pro, which provide more sophisticated analysis and decompilation capabilities. However, they require more knowledge to use effectively. 
