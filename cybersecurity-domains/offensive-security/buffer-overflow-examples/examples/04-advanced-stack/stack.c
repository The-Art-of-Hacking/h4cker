/* stack.c */

/* This is the program that introduces the buffer overflow vulnerability. */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int bof(char *str)
{
    char buffer[12];

    /* Can you spot the buffer overflow here? ;-) */ 
    strcpy(buffer, str);

    return 1;
}

int main(int argc, char **argv)
{
    /* This tries to handle 517 bytes and the strcpy is trying to copy that to buffer which only has 12 bytes */ 
    char str[517];
    FILE *badfile;

    badfile = fopen("badfile", "r");
    fread(str, sizeof(char), 517, badfile);
    bof(str);

    printf("Returned Properly\n");
    return 1;
}