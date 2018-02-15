# Buffer Overflow Example
***DO NOT USE THIS CODE METHODOLOGY***
This is an example of a very bad coding practice that introduces a buffer overflow.

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
