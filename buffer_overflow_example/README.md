# Buffer Overflow Example

***This is an example of a very bad coding practices*** that introduces a buffer overflow. The purpose of this code is to serve as a demonstration and exercise for [The Art of Hacking Series and live training](https://www.safaribooksonline.com/search/?query=Omar%20Santos%20hacking&extended_publisher_data=true&highlight=true&is_academic_institution_account=false&source=user&include_assessments=false&include_case_studies=true&include_courses=true&include_orioles=true&include_playlists=true&sort=relevance)

```
#include <stdio.h>

void secretFunction()
{
    printf("Omar's Crappy Function\n");
    printf("This is a super secret function!\n");
}

void echo()
{
    char buffer[20];

    printf("Please enter your name:\n");
    scanf("%s", buffer);
    printf("You entered: %s\n", buffer);    
}

int main()
{
    echo();

    return 0;
}
```

The `char buffer[20];` is a really bad idea. The rest will be demonstrated in the course.

You can compile this code or use the already-compiled binary [here](https://github.com/The-Art-of-Hacking/h4cker/raw/master/buffer_overflow_example/vuln_program).

For 32 bit systems you can use [gcc](https://www.gnu.org/software/gcc/) as shown below:
```
gcc vuln.c -o vuln -fno-stack-protector
```
For 64 bit systems

```
gcc vuln.c -o vuln -fno-stack-protector -m32
```
`-fno-stack-protector` disabled the stack protection. Smashing the stack is now allowed. `-m32` made sure that the compiled binary is 32 bit. You may need to install some additional libraries to compile 32 bit binaries on 64 bit machines.

## Additional Examples and References

A buffer overflow is a type of software vulnerability that occurs when a program attempts to store more data in a buffer (a temporary storage area) than it can hold. This can cause the extra data to overflow into adjacent memory locations, potentially overwriting important data or instructions.

Here is another example of a buffer overflow in C:

```
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[]) {
    char buffer[5]; // Declare a buffer with a size of 5 bytes
    strcpy(buffer, argv[1]); // Copy the first command line argument into the buffer
    printf("%s\n", buffer); // Print the contents of the buffer
    return 0;
}
```
In this example, the program declares a `buffer` of size 5 bytes and uses the `strcpy` function to copy the first command line argument into the buffer. However, if the command line argument is longer than 5 bytes, the `strcpy` function will copy all the characters of the argument into the buffer, causing the extra characters to overflow into adjacent memory locations.

A malicious attacker could exploit this vulnerability by providing a long string as an argument to the program, which can cause the program to crash or execute arbitrary code.

Another example:

```
#include <stdio.h>

void vulnerable_function(char* user_input) {
    char buffer[10];
    strcpy(buffer, user_input); // copy user input into the buffer
    printf("Input: %s\n", buffer);
}

int main(int argc, char* argv[]) {
    vulnerable_function(argv[1]);
    return 0;
}
```
In this example, the program has a function called `vulnerable_function` which takes a single argument, a string of user input. The function then declares a buffer of size 10 bytes and uses the `strcpy` function to copy the user input into the buffer.

However, if the user input is longer than 10 bytes, the `strcpy` function will copy all the characters of the input into the buffer, causing the extra characters to overflow into adjacent memory locations.

A malicious attacker could exploit this vulnerability by providing a long string as an argument to the program when it is executed, which can cause the program to crash or execute arbitrary code.

There are several ways to fix a buffer overflow vulnerability. Here are a few examples:

- Using a different function: Instead of using the `strcpy` function, which does not check for buffer overflow, you can use a function like `strncpy` which takes an additional argument specifying the maximum number of bytes to be copied. This can prevent overflowing the buffer.

```
strncpy(buffer, user_input, sizeof(buffer) - 1);
buffer[sizeof(buffer) - 1] = '\0';
```

- Using a library function: You can use a library function like `snprintf` which can be used to write a limited number of characters to a buffer, making sure that the buffer is not overflown.

```
snprintf(buffer, sizeof(buffer), "%s", user_input);
```

- Input validation: You can validate the user input before it is copied into the buffer, checking if the length of the input is less than the size of the buffer.

```
if (strlen(user_input) < sizeof(buffer)) {
    strcpy(buffer, user_input);
} else {
    printf("Error: input too long\n");
    exit(1);
}
```

- Using a safer data type: You can use a safer data type like std::string in C++, which automatically handles buffer overflow and other security issues.

```
std::string buffer;
buffer = user_input;
```

It is important to remember that buffer overflow vulnerabilities can have serious security implications, so it is essential to ensure that your code is free of such vulnerabilities.
