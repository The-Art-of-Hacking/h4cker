# Firmware Reverse Engineering Demos

[This repository](https://github.com/emproof-com/workshop_firmware_reverse_engineering) contains [slides](slides.pdf) and hands-on materials for [Emproof's](https://emproof.com) workshop on firmware reverse engineering, presented at [ScapyCon Automotive 2025](https://dissec.to/scapycon-automotive-2025/). The workshop targets a technical audience with minimal security experience and teaches the fundamentals through practical, self-contained tasks. Topics include

* basic file/ELF analysis;
* software cracking and keygenning;
* string decryption & malware triage;
* embedded-Linux firmware unpacking;
* bare-metal analysis;
* crypto detection;
* obfuscation/anti-analysis techniques and how to bypass them;

Also check out the [Emproof technical webinar series](https://github.com/emproof-com/webinars) with additional exercises and recorded sessions.

Workshop content was designed and organized by [Tim Blazytko](https://github.com/mrphrazer/), with support from Simran Kathpalia.


## Setup

To set up the environment, clone the repository:

```bash
git clone https://github.com/emproof-com/workshop_firmware_reverse_engineering
cd workshop_firmware_reverse_engineering
```

For several tasks we require an AArch64 Linux execution environment. We provide a [Docker container](Dockerfile) based on [Kali Linux](https://www.kali.org) with common tools (e.g., [GNU Binutils](https://www.gnu.org/software/binutils/), [Binwalk](https://github.com/ReFirmLabs/binwalk)) preinstalled. This streamlines the environment across Linux, Windows, and macOS—regardless of the host CPU architecture. To start the container and enter the shell, execute:

```bash
./docker_run.sh
```

> **Note:** The first run may take a while to build the image.
 
> **Note (architecture):** The Docker Compose service sets `platform: "linux/arm64"`.  
> On x86_64 hosts (Intel macOS/Windows/Linux) Docker Desktop will run the image under emulation, so the first build and startup can be slower — that’s expected. On native ARM64 hosts (Apple Silicon, ARM servers) it runs natively and is faster.

> **Note:** The Docker container can also run ARMv7 (armhf) binaries. We install the armhf runtime (dynamic loader + libs) in the image and register binfmt handlers for both `aarch64` and `arm` via the startup script.

In addition, install the following graphical tools on your host for interactive reverse engineering tasks (these are not included in the container):

* [Ghidra](https://ghidra-sre.org)
* [Binary Ninja Free](https://binary.ninja/free/)

Both tools are available for Windows, Linux, and macOS.

> **Note:** Binary Ninja Free does **not** support AArch64. For AArch64 analysis use Ghidra (or a licensed Binary Ninja build). Therefore, several labs ship an **ARMv7 companion** binary (`*.armv7`) specifically for Binary Ninja Free; these can also be run in the same container.


## Tasks Order

Each task is self-contained in `tasks/<name>/` and includes:

* `samples/` — binaries (and sometimes source) used in the exercise  
* `task.md` — the assignment with step-by-step instructions and hints

Tasks can be attempted independently, but we provide a **recommended order** (listed below) that ramps up difficulty and gradually introduces new techniques. Most samples target **ARMv7 (Thumb/ARM32)** or **AArch64**; where relevant, the task notes call out architecture, required tools, and any special runtime needs.

* [tasks/hello_world](tasks/hello_world): basics of ELF files and metadata analysis; first steps in Ghidra / Binary Ninja.

* [tasks/license_check](tasks/license_check): extract hardcoded secrets / unlock features; basic patching to bypass validations (cracking).

* [tasks/game](tasks/game): simple number-guessing game; understand the logic and crack trial vs. full mode.

* [tasks/keygenning_1](tasks/keygenning_1): reverse a license validation and write a minimal keygen to generate valid serials.

* [tasks/keygenning_2](tasks/keygenning_2): a slightly more sophisticated keygenning task (salts/keys, hex encoding).

* [tasks/string_encryption](tasks/string_encryption): binary with encrypted strings (common in malware); identify the decryptor and recover strings statically.

* [tasks/mirai](tasks/mirai): embedded malware using a string-decryption routine; navigate a larger codebase, identify interesting constructs, and deal with obfuscated strings.

* [tasks/embedded_linux_1](tasks/embedded_linux_1): embedded-Linux firmware with filesystem; unpack, explore, and crack Linux login information (CTF-style).

* [tasks/embedded_linux_2](tasks/embedded_linux_2): similar, but find and analyze a hidden binary that shouldn’t be there.

* [tasks/car_demo](tasks/car_demo): bare-metal firmware analysis: identify architecture, board, memory map, toolchain artifacts; extract Wi-Fi credentials and protocol endpoints.

* [tasks/iot_diag](tasks/iot_diag): bare-metal firmware dump of a diagnostics tool; recreate memory layouts from the datasheet, then find the password to unlock diagnostics mode.

* [tasks/crypto_detection](tasks/crypto_detection): AArch64 binary performing cryptographic operations with a hardcoded AES key; locate the EVP call and backtrack key/IV to decrypt without the program.

* [tasks/license_check_anti_patching](tasks/license_check_anti_patching): anti-patching via code checksumming; understand the CRC guard and learn ways to bypass it.

* [tasks/fibonacci_obfuscation](tasks/fibonacci_obfuscation): clean vs. obfuscated Fibonacci implementations (switch flattening, computed goto, opaque predicates, arithmetic obfuscation, small VM); understand techniques and normalize them.
