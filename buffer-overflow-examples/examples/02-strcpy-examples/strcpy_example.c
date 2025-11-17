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
