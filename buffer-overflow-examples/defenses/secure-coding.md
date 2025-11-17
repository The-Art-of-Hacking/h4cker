# Secure Coding Practices to Prevent Buffer Overflows

## Introduction

Buffer overflows are preventable! While modern systems have multiple layers of defense, the most effective protection is writing secure code from the start. This guide provides practical, actionable techniques for preventing buffer overflows in C and C++ programs.

## The Security-First Mindset

### Core Principles

1. **Never trust input** - All input is potentially malicious
2. **Validate everything** - Check sizes, ranges, and formats
3. **Fail safely** - Handle errors explicitly
4. **Defense in depth** - Use multiple layers of protection
5. **Least privilege** - Run with minimum necessary permissions

### The Security Triangle

```
    Security
    /     \
   /       \
Usability - Performance
```

Balance these three factors, but prioritize security when in doubt.

## Safe String Handling

### Rule 1: Avoid Dangerous Functions

**Never use these functions** (they have no bounds checking):

```c
// BANNED FUNCTIONS - DO NOT USE!
gets()        // No way to limit input size
strcpy()      // No bounds checking
strcat()      // No bounds checking
sprintf()     // No bounds checking
scanf("%s")   // No bounds checking (without width)
```

### Rule 2: Use Safe Alternatives

#### Option 1: strncpy() / strncat()

```c
// GOOD: Using strncpy
char dest[20];
strncpy(dest, source, sizeof(dest) - 1);
dest[sizeof(dest) - 1] = '\0';  // Always null-terminate!

// GOOD: Using strncat
char dest[50] = "Hello ";
strncat(dest, name, sizeof(dest) - strlen(dest) - 1);
```

**⚠️ Warning**: `strncpy()` doesn't always null-terminate! Always add `'\0'` manually.

#### Option 2: snprintf()

```c
// GOOD: Using snprintf (preferred)
char buffer[100];
int result = snprintf(buffer, sizeof(buffer), "User: %s, ID: %d", name, id);

if (result >= sizeof(buffer)) {
    // Output was truncated
    fprintf(stderr, "Warning: Output truncated\n");
}
```

**Why snprintf() is better:**
- Always null-terminates
- Returns size needed (not just what fit)
- Works with format strings

#### Option 3: strlcpy() / strlcat() (BSD)

```c
// GOOD: Using strlcpy (if available)
char dest[20];
size_t result = strlcpy(dest, source, sizeof(dest));

if (result >= sizeof(dest)) {
    fprintf(stderr, "Error: String truncated\n");
    return -1;
}
```

**Benefits:**
- Always null-terminates
- Returns source length (for truncation detection)
- More intuitive than strncpy()

**Drawback:** Not standard C, only available on BSD and some other systems

### Rule 3: Validate Before Copying

```c
// BEST PRACTICE: Validate then copy
int safe_copy(char *dest, size_t dest_size, const char *src) {
    // Check parameters
    if (!dest || !src || dest_size == 0) {
        return -1;
    }
    
    // Check source length
    size_t src_len = strlen(src);
    if (src_len >= dest_size) {
        fprintf(stderr, "Error: Source too long (%zu bytes, max %zu)\n", 
                src_len, dest_size - 1);
        return -1;
    }
    
    // Safe to copy
    strcpy(dest, src);  // Now safe because we validated
    return 0;
}
```

## Safe Memory Management

### Rule 4: Always Check Sizes

```c
// BAD: No size checking
void process_data(char *buffer, const char *input) {
    strcpy(buffer, input);  // DANGEROUS!
}

// GOOD: Size checking
void process_data(char *buffer, size_t buffer_size, const char *input) {
    size_t input_len = strlen(input);
    
    if (input_len >= buffer_size) {
        fprintf(stderr, "Error: Input too large\n");
        return;
    }
    
    memcpy(buffer, input, input_len + 1);  // +1 for null terminator
}
```

### Rule 5: Use sizeof() Correctly

```c
// GOOD: Using sizeof with arrays
void func1() {
    char buffer[100];
    snprintf(buffer, sizeof(buffer), "Format: %s", input);  // ✅ Correct
}

// BAD: Using sizeof with pointers
void func2(char *buffer) {
    snprintf(buffer, sizeof(buffer), "Format: %s", input);  // ❌ Wrong!
    // sizeof(buffer) returns size of pointer (4 or 8), not buffer size!
}

// GOOD: Pass size explicitly
void func2(char *buffer, size_t buffer_size) {
    snprintf(buffer, buffer_size, "Format: %s", input);  // ✅ Correct
}
```

### Rule 6: Check Dynamic Allocations

```c
// GOOD: Always check malloc/calloc results
char *buffer = malloc(size);
if (!buffer) {
    fprintf(stderr, "Error: Memory allocation failed\n");
    return -1;
}

// Use the buffer...

// Always free when done
free(buffer);
buffer = NULL;  // Prevent use-after-free
```

## Input Validation

### Rule 7: Validate All Input Sources

```c
// Validate command-line arguments
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    // Validate length
    size_t len = strlen(argv[1]);
    if (len > MAX_INPUT_SIZE) {
        fprintf(stderr, "Error: Input too long (max %d)\n", MAX_INPUT_SIZE);
        return 1;
    }
    
    // Validate content (example: alphanumeric only)
    for (size_t i = 0; i < len; i++) {
        if (!isalnum(argv[1][i]) && argv[1][i] != '_') {
            fprintf(stderr, "Error: Invalid character at position %zu\n", i);
            return 1;
        }
    }
    
    // Now safe to process
    process_input(argv[1]);
    return 0;
}
```

### Rule 8: Whitelist, Don't Blacklist

```c
// BAD: Blacklist approach (easy to bypass)
int is_safe_char(char c) {
    if (c == ';' || c == '|' || c == '&' || c == '\n') {
        return 0;  // Dangerous character
    }
    return 1;  // Assume safe
}

// GOOD: Whitelist approach (much safer)
int is_safe_char(char c) {
    if (isalnum(c) || c == '_' || c == '-' || c == '.') {
        return 1;  // Explicitly allowed
    }
    return 0;  // Everything else rejected
}
```

### Rule 9: Sanitize and Escape

```c
// GOOD: Escape special characters
void escape_string(char *dest, size_t dest_size, const char *src) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j < dest_size - 2; i++) {
        if (src[i] == '"' || src[i] == '\'' || src[i] == '\\') {
            if (j < dest_size - 2) {
                dest[j++] = '\\';  // Add escape character
            }
        }
        dest[j++] = src[i];
    }
    dest[j] = '\0';
}
```

## Array Access Safety

### Rule 10: Always Bounds Check Array Access

```c
// BAD: No bounds checking
char buffer[100];
int index = user_input;
buffer[index] = 'A';  // DANGEROUS! index could be negative or > 99

// GOOD: Bounds checking
char buffer[100];
int index = user_input;

if (index < 0 || index >= sizeof(buffer)) {
    fprintf(stderr, "Error: Index out of bounds\n");
    return -1;
}

buffer[index] = 'A';  // Now safe
```

### Rule 11: Use Safe Loop Constructs

```c
// BAD: Easy to make off-by-one errors
for (int i = 0; i <= sizeof(buffer); i++) {  // ❌ Should be <, not <=
    buffer[i] = 0;
}

// GOOD: Clear bounds
for (size_t i = 0; i < sizeof(buffer); i++) {  // ✅ Correct
    buffer[i] = 0;
}

// BETTER: Use memset
memset(buffer, 0, sizeof(buffer));
```

## Integer Overflow Prevention

### Rule 12: Check Integer Operations

```c
// BAD: Integer overflow can lead to buffer overflow
size_t size = user_count * sizeof(item_t);
char *buffer = malloc(size);  // DANGEROUS! What if multiplication overflows?

// GOOD: Check for overflow
#include <stdint.h>
#include <limits.h>

size_t size;
if (user_count > SIZE_MAX / sizeof(item_t)) {
    fprintf(stderr, "Error: Size overflow\n");
    return -1;
}
size = user_count * sizeof(item_t);
char *buffer = malloc(size);  // Now safe
```

### Rule 13: Use Safe Integer Functions

```c
// GOOD: Using safe_add (example implementation)
bool safe_add(size_t a, size_t b, size_t *result) {
    if (a > SIZE_MAX - b) {
        return false;  // Overflow would occur
    }
    *result = a + b;
    return true;
}

// Usage
size_t total;
if (!safe_add(count, offset, &total)) {
    fprintf(stderr, "Error: Addition overflow\n");
    return -1;
}
```

## Function Design

### Rule 14: Use Safe Function Signatures

```c
// BAD: No size information
void process(char *buffer, const char *input);

// GOOD: Include buffer size
void process(char *buffer, size_t buffer_size, const char *input);

// BETTER: Return error codes
int process(char *buffer, size_t buffer_size, const char *input);

// BEST: Complete error handling
typedef enum {
    PROC_SUCCESS = 0,
    PROC_ERROR_NULL_PTR = -1,
    PROC_ERROR_BUFFER_TOO_SMALL = -2,
    PROC_ERROR_INVALID_INPUT = -3
} ProcessResult;

ProcessResult process(char *buffer, size_t buffer_size, const char *input);
```

### Rule 15: Validate Function Parameters

```c
// GOOD: Defensive parameter checking
int copy_string(char *dest, size_t dest_size, const char *src) {
    // Check for NULL pointers
    if (!dest || !src) {
        return -1;
    }
    
    // Check for zero size
    if (dest_size == 0) {
        return -1;
    }
    
    // Check for sufficient space
    size_t src_len = strlen(src);
    if (src_len >= dest_size) {
        return -1;
    }
    
    // Safe to proceed
    memcpy(dest, src, src_len + 1);
    return 0;
}
```

## Compiler and Build Settings

### Rule 16: Enable Security Features

```bash
# GOOD: Compile with all security features
gcc program.c -o program \
    -Wall -Wextra -Werror \           # Enable all warnings, treat as errors
    -D_FORTIFY_SOURCE=2 \              # Add runtime buffer overflow checks
    -fstack-protector-strong \         # Enable stack canaries
    -fPIE -pie \                       # Position Independent Executable
    -Wl,-z,relro,-z,now \              # Read-only relocations, immediate binding
    -O2                                # Enable optimizations (helps FORTIFY_SOURCE)
```

### Rule 17: Use Static Analysis Tools

```bash
# Scan code with static analyzers
cppcheck --enable=all program.c
scan-build gcc program.c -o program

# Use linters
splint program.c
flawfinder program.c
```

## Testing and Verification

### Rule 18: Test with Oversized Inputs

```c
// Create test cases for boundary conditions
void test_buffer_handling() {
    char buffer[10];
    
    // Test cases
    assert(copy_safe(buffer, sizeof(buffer), "") == 0);          // Empty
    assert(copy_safe(buffer, sizeof(buffer), "123456789") == 0); // Max-1
    assert(copy_safe(buffer, sizeof(buffer), "1234567890") < 0); // Too large
    assert(copy_safe(buffer, sizeof(buffer), "12345678901") < 0);// Much too large
}
```

### Rule 19: Use Fuzz Testing

```bash
# Use AFL for fuzzing
afl-gcc program.c -o program
afl-fuzz -i input_dir -o output_dir ./program @@

# Or use libFuzzer
clang -fsanitize=fuzzer,address program.c -o program_fuzzer
./program_fuzzer
```

## Code Review Checklist

When reviewing code for buffer overflows, check:

- [ ] Are dangerous functions (gets, strcpy, etc.) used?
- [ ] Is all input validated before use?
- [ ] Are buffer sizes checked before copying?
- [ ] Is sizeof() used correctly (arrays vs pointers)?
- [ ] Are array indices bounds-checked?
- [ ] Are integer overflows possible in size calculations?
- [ ] Are all malloc() results checked?
- [ ] Do loops have correct termination conditions?
- [ ] Are function parameters validated?
- [ ] Is error handling comprehensive?

## Real-World Example: Secure File Reader

```c
#define MAX_LINE_SIZE 4096

// SECURE: Complete implementation with all safety checks
int read_config_file(const char *filename, char **output) {
    // Validate parameters
    if (!filename || !output) {
        return -1;
    }
    
    // Open file safely
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen");
        return -1;
    }
    
    // Allocate buffer with size limit
    char *buffer = malloc(MAX_LINE_SIZE);
    if (!buffer) {
        fclose(fp);
        return -1;
    }
    
    // Read line with size limit
    if (fgets(buffer, MAX_LINE_SIZE, fp) == NULL) {
        free(buffer);
        fclose(fp);
        return -1;
    }
    
    // Remove newline safely
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len-1] == '\n') {
        buffer[len-1] = '\0';
    }
    
    // Validate content (example: max length)
    if (len > 1000) {
        fprintf(stderr, "Error: Line too long\n");
        free(buffer);
        fclose(fp);
        return -1;
    }
    
    *output = buffer;
    fclose(fp);
    return 0;
}
```

## Moving Beyond C/C++

### Consider Memory-Safe Languages

For new projects, strongly consider:

- **Rust** - Memory safety without garbage collection
- **Go** - Simple, safe, with garbage collection
- **Java/C#** - Established, safe, garbage collected
- **Python** - Very safe, but slower

See [Memory-Safe Languages](memory-safe-languages.md) for more details.

## Summary: The 19 Rules of Safe C Programming

1. ✅ Avoid dangerous functions (gets, strcpy, etc.)
2. ✅ Use safe alternatives (strncpy, snprintf, strlcpy)
3. ✅ Validate before copying
4. ✅ Always check sizes
5. ✅ Use sizeof() correctly
6. ✅ Check dynamic allocations
7. ✅ Validate all input sources
8. ✅ Whitelist, don't blacklist
9. ✅ Sanitize and escape
10. ✅ Bounds check array access
11. ✅ Use safe loop constructs
12. ✅ Check integer operations
13. ✅ Use safe integer functions
14. ✅ Use safe function signatures
15. ✅ Validate function parameters
16. ✅ Enable security features
17. ✅ Use static analysis tools
18. ✅ Test with oversized inputs
19. ✅ Use fuzz testing

## Quick Reference Card

```c
// ❌ NEVER USE
gets()
strcpy(dest, src)
strcat(dest, src)
sprintf(buf, fmt, ...)
scanf("%s", buf)

// ✅ USE INSTEAD
fgets(buf, size, stdin)
strncpy(dest, src, size-1); dest[size-1]='\0'
strncat(dest, src, size-strlen(dest)-1)
snprintf(buf, size, fmt, ...)
scanf("%Ns", buf)  // Where N = size-1

// ✅ ALWAYS DO
- Validate input length
- Check buffer sizes
- Null-terminate strings
- Check malloc() results
- Bounds check array access
- Enable compiler protections
```

## Further Reading

- [CERT C Coding Standard](https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard)
- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [NASA C Coding Standards](https://ntrs.nasa.gov/api/citations/20080039927/downloads/20080039927.pdf)
- [Linux Kernel Coding Style](https://www.kernel.org/doc/html/latest/process/coding-style.html)

---

**Remember**: Secure coding is not optional—it's a professional responsibility. Every buffer overflow vulnerability is preventable with proper coding practices. Write code that you'd be proud to have audited publicly.

