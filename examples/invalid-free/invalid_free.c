#include <stdio.h>

int main(void) {
    char *p = malloc(16);

    char *q = p + 8;
    printf("base: %p, interior: %p\n", (void*)p, (void*)q);

    free(q);
    
    return 0;
}
