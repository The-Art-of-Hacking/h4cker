# Buffer Overflow Example When Copying Data to a Buffer

There are many functions in C that can be used to copy data, including `strcpy()`, `strcat()`, `memcpy()`, etc. In the following example `strcpy()`is used to copy strings. An example is shown in the code below. The function `strcpy()` stops copying only
when it encounters the terminating character `'\0'`.

```
#include <string.h>
#include <stdio.h>
void main ()
{
    char src[40]="Hello world \0 Extra string";
    char dest[40];
    // copy to dest (destination) from src (source)
    strcpy (dest, src);
}
```

When you run the code above, you will notice that `strcpy()` only copies the string "Hello world" to the buffer dest, even though the entire string contains more than that. This is because when making the copy, `strcpy()` stops when it sees number zero, which is represented by `'\0'` in the code. It should be noted that this is not the same as character '0', which is represented as `0x30` in computers, not zero. Without the zero in the middle of the string, the string copy will end when it reaches the end of the string, which is marked by a zero (the zero is not shown in the code, but compilers will automatically add a zero to the end of a string).

When we copy a string to a target buffer, what will happen if the string is longer than the size of the buffer? Let's see:

```
#include <string.h>
void omarsucks(char *str)
{
	char buffer[12];
	/* The following strcpy will result in buffer overflow */
	strcpy(buffer, str);
}
int main()
{
	char *str = "This text is indeed a lot bigger or longer than 12";
	omarsucks(str);
	return 1;
}
```

The following is the stack layout for the code above:

<img src="https://github.com/The-Art-of-Hacking/h4cker/blob/master/buffer_overflow_example/BufferOverFlow.png" width="50%" height="50%">

The local array `buffer[]` in `omarsucks()` has 12 bytes of memory. The `omarsucks()` function uses `strcpy()` to copy the string from `str` to `buffer[]`. The `strcpy()` function does not stop until it sees a zero (a number zero, `'\0'`) in the source string. Since the source string is longer than 12 bytes, `strcpy()` will overwrite some portion of the stack above the buffer. This is called buffer overflow.

It should be noted that stacks grow from high address to low address, but buffers still grow in the normal direction (i.e., from low to high). Therefore, when we copy data to `buffer[]`, we start from `buffer[0]`, and eventually to `buffer[11]`. If there are still more data to be copied, `strcpy()` will continue copying the data to the region above the buffer, treating the memory beyond the buffer as `buffer[12]`, `buffer[13]`, and so on.

The following is the stack after exploitation:

<img src="https://github.com/The-Art-of-Hacking/h4cker/blob/master/buffer_overflow_example/stack_after_buffer_overflow.png">


