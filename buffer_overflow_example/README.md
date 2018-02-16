# Buffer Overflow Example

*** This is an example of a very bad coding practices*** that introduces a buffer overflow. The purpose of this code is to serve as a demonstration and exercise for [The Art of Hacking Series and live training](https://www.safaribooksonline.com/search/?query=Omar%20Santos%20hacking&extended_publisher_data=true&highlight=true&is_academic_institution_account=false&source=user&include_assessments=false&include_case_studies=true&include_courses=true&include_orioles=true&include_playlists=true&sort=relevance)

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
