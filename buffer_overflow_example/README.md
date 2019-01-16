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
