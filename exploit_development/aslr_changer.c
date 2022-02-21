#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    FILE *fp;
    char buff[100];
    
    if(seteuid(0) == -1) {
        fprintf(stderr, "Failed to set UID to root - is this binary setuid root?\n");
        return -1;
    }
    
    if(argc != 2 || (strcmp(argv[1], "0") != 0 && strcmp(argv[1], "2") != 0)) {
        fprintf(stderr, "Usage: %s [0 or 2]\nSets randomize_va_space to 0 (ASLR off) or 2 (ASLR on)\n", argv[0]);
        return -1;
    }
    
    fp = fopen("/proc/sys/kernel/randomize_va_space", "w");
    fprintf(fp, "%s\n", argv[1]);
    fclose(fp);
    
    fp = fopen("/proc/sys/kernel/randomize_va_space", "r");
    fgets(buff, 99, fp);
    fclose(fp);
    
    printf("randomize_va_space is now %s", buff);
    return 0;
}
