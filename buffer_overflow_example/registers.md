# Good Information about Registers

- Refer to Intel's Architecture Documentation for latest information: https://software.intel.com/en-us/articles/intel-sdm

Additional Notes: The x64 architecture extends x86's 8 general-purpose registers to be 64-bit, and adds 8 new 64-bit registers.  The 64-bit registers have names beginning with "r", so for example the 64-bit extension of **eax** is called **rax**.  The lower 32 bits, 16 bits, and 8 bits of each register are directly addressable in operands.  This includes registers, like **esi**, whose lower 8 bits were not previously addressable.  The following table specifies the assembly-language names for the lower portions of 64-bit registers.

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

