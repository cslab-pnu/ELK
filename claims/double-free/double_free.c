#include <stdio.h>

int main(void) {
    char *p = malloc(16);
    
    printf("allocated: %p\n", (void*)p);
    free(p);
    printf("freed once: %p\n", (void*)p);

    free(p);

    return 0;
}
