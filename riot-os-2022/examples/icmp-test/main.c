#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xtimer.h"
//#include "malloc_thread_safe.h"


typedef uint8_t uint8;
typedef int8_t int8;
typedef uint16_t uint16;
typedef int16_t int16;
typedef uint32_t uint32;
typedef int32_t int32;
typedef float float32;
typedef double float64;
typedef uint64_t uint64;
typedef int64_t int64;

#define DWT_CYCCNT (*(uint32_t *) 0xE0001004)


int main(void) {
  puts("\nHello malloc!\n");

  // printf("You are running RIOT on a(n) %s board.\n", RIOT_BOARD);
  // printf("This board features a(n) %s MCU.\n\n", RIOT_MCU);

  char *p1 = malloc(1);
  *p1 = 'a';
  printf("%c\n", *p1);
  printf("%p\n", p1);
  free(p1);
  char *p2 = malloc(1);
  printf("%p\n", p2);
  *p2 = 'b';
  printf("%d\n", p1 == p2);
  
  printf("DONE!!\n");
  return 0;
}
