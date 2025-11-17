# Buffer Overflow Examples and Learning Guide

A comprehensive collection of buffer overflow examples, exploitation techniques, and defensive mechanisms. This repository is part of Omar's Ethical Hacking training videos and books.

## 🎯 Learning Objectives

After working through these examples, you will understand:
- How buffer overflows occur at a fundamental level
- How memory is organized on the stack
- How to identify vulnerable code patterns
- Common exploitation techniques
- Modern defense mechanisms and mitigations
- How to write secure code that prevents buffer overflows

## 📚 Table of Contents

### 1. Fundamentals
- **[What is a Buffer Overflow?](basics/what-is-buffer-overflow.md)** - Core concepts and terminology
- **[Memory and the Stack](basics/memory-and-stack.md)** - Understanding memory layout
- **[CPU Registers Explained](basics/registers.md)** - x86, x64, and ARM registers
- **[Introduction to Assembly](basics/assembly-basics.md)** - Essential assembly language concepts

### 2. Vulnerable Code Examples
- **[Simple Buffer Overflow](examples/01-simple-overflow/)** - Basic vulnerable program
- **[strcpy() Vulnerabilities](examples/02-strcpy-examples/)** - Common dangerous functions
- **[Command Line Argument Overflow](examples/03-cli-overflow/)** - Exploiting argv inputs
- **[Advanced Stack Overflow](examples/04-advanced-stack/)** - The Demeter challenge

### 3. Exploitation Techniques
- **[Finding Offsets](exploitation/calculating-offsets.md)** - Determining buffer boundaries
- **[Writing Exploits](exploitation/writing-exploits.md)** - Crafting malicious payloads
- **[Shellcode Basics](exploitation/shellcode-basics.md)** - Understanding shellcode
- **[One-Liner Exploits](exploitation/one-liner-exploit.sh)** - Quick exploitation scripts

### 4. Defense Mechanisms
- **[Modern Mitigations](defenses/mitigations.md)** - ASLR, DEP, Stack Canaries
- **[Secure Coding Practices](defenses/secure-coding.md)** - How to prevent buffer overflows
- **[Memory-Safe Languages](defenses/memory-safe-languages.md)** - Moving beyond C/C++

### 5. Architecture-Specific Resources
- **[ARM Exploitation](resources/arm-resources.md)** - ARM-specific techniques and references
- **[x86/x64 Differences](basics/registers.md#x86-vs-x64)** - Understanding architecture variations

### 6. Additional Resources
- **[External Learning Platforms](resources/external-platforms.md)** - CTFs and practice environments
- **[Recommended Tools](resources/tools.md)** - Debuggers, disassemblers, and utilities

## 🚀 Quick Start

### Prerequisites
```bash
# For 32-bit compilation on 64-bit systems
sudo apt-get install gcc-multilib g++-multilib

# For debugging
sudo apt-get install gdb

# Optional: Enhanced GDB
pip install pwntools
```

### Running Your First Example

1. Navigate to the simple example:
```bash
cd examples/01-simple-overflow/
```

2. Compile the vulnerable program:
```bash
gcc vuln.c -o vuln -fno-stack-protector -z execstack -m32
```

3. Run it normally:
```bash
echo "Alice" | ./vuln
```

4. Trigger the overflow:
```bash
python -c "print('A' * 100)" | ./vuln
```

## ⚠️ Important Security Disclaimer

**These examples demonstrate dangerous programming practices for educational purposes only.**

- Never use these techniques on systems you don't own or have explicit permission to test
- These examples disable security features (`-fno-stack-protector`, `-z execstack`) that should be enabled in production
- Real-world exploitation is more complex due to modern security mitigations
- Always follow responsible disclosure practices

## 🛠️ Compilation Flags Explained

| Flag | Purpose |
|------|---------|
| `-fno-stack-protector` | Disables stack canaries (stack smashing protection) |
| `-z execstack` | Makes the stack executable (allows shellcode execution) |
| `-m32` | Compiles as 32-bit binary on 64-bit systems |
| `-g` | Includes debugging symbols |
| `-o` | Specifies output file name |

## 📖 Learning Path

### Beginner Track
1. Start with [What is a Buffer Overflow?](basics/what-is-buffer-overflow.md)
2. Learn about [Memory and the Stack](basics/memory-and-stack.md)
3. Study the [Simple Buffer Overflow](examples/01-simple-overflow/) example
4. Read about [Modern Mitigations](defenses/mitigations.md)

### Intermediate Track
1. Understand [CPU Registers](basics/registers.md)
2. Learn [Assembly Basics](basics/assembly-basics.md)
3. Practice with [strcpy() Examples](examples/02-strcpy-examples/)
4. Learn about [Finding Offsets](exploitation/calculating-offsets.md)

### Advanced Track
1. Deep dive into [Writing Exploits](exploitation/writing-exploits.md)
2. Study [Shellcode Basics](exploitation/shellcode-basics.md)
3. Complete the [Advanced Stack Overflow](examples/04-advanced-stack/) challenge
4. Explore [ARM Exploitation](resources/arm-resources.md)

## 🎓 Related Training

This repository supports:
- [The Art of Hacking Series](https://www.safaribooksonline.com/search/?query=Omar%20Santos%20hacking) by Omar Santos
- Live security training and workshops
- Cybersecurity certification preparation

## 🤝 Contributing

Found an error or want to add an example? Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with a clear description

## 📜 License

This content is provided for educational purposes. See the main repository for license information.

## 🔗 Additional Resources

- [Exploit Education](https://exploit.education) - Practice platforms with VMs
- [Azeria Labs](https://azeria-labs.com/) - ARM exploitation tutorials
- [LiveOverflow](https://www.youtube.com/c/LiveOverflow) - Binary exploitation videos
- [OWASP](https://owasp.org/) - Application security resources

---

**Last Updated**: November 2025  
**Maintained by**: Omar Santos (@santosomar)
