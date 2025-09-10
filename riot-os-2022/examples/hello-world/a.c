#include <stdio.h>
#include <stdlib.h>

char *aa;

void foo(char * a) {
    *a = '1';
    *(a + 1) = '2';
    printf("%s\n", a);
    //printf("%s\n", a);
    //free(a);
}

void boo(char *a) {
    for (int i = 0; i < 100; i++) {
        *(a + i) = i;
    }
    aa = malloc(5);
    free(a);
}