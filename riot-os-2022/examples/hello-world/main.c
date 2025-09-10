#include <stdio.h>

void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);
    printf("%s", buffer);
}


__attribute__((__noinline__)) void foo2(char * a) {
    *a = '1';
    *(a + 1) = '2';
    for (int i = 0; i < 11; i++) *(a + i) = i;
    //printf("%s\n", a);
    //printf("%s\n", a);
    //free(a);
}

// __attribute__((noinline)) int foo(int a, char* ss) {
//     char buffer[100];
//     buffer[0] = 'a';
//     for (int i = 0; i < 100; i++) buffer[i] = i;
//     printf("%s\n", buffer);
//     printf("ss address: %p\n", ss);
//     return a;
// }

int main(void) {
    char small_buffer[4] = "This";
    char *long_string = "This string is definitely longer than 64 characters and will overflow the buffer.";
    small_buffer[4] = 'X'; 
    small_buffer[5] = 'Y';
    char *ss = malloc(5);
    *(ss + 1) = 'a';
    printf("%s\n", ss);

    printf("small_buffer: %s\n", small_buffer);
    //vulnerable_function(long_string);

    foo2(ss);
    printf("%d\n", ss);
    //printf("Escaping: arr[0] = %d\n", arr[0]);
    
    return 0;
}
