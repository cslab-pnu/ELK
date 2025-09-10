#include <stdio.h>

int main() {
    char *ptr = (char*)malloc(32);

    printf("obj allocated at: %p\n", ptr);

    free(ptr);
    printf("obj %p has been deallocated\n", ptr);

    printf("use after free...\n");
    printf("%x\n", ptr[0]);

    return 0;
}