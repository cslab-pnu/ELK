#include <stdio.h>
#include <stdlib.h>
#include "xtimer.h"
#include "malloc_thread_safe.h"


#define DWT_CYCCNT (*(uint32_t *) 0xE0001004)

uint32_t SIZE_MAP2[4] = { 0x4000, 0x100, 0x40, 0x10 };
uint8_t SHIFT_MAP2[4] = { 14, 8, 6, 4 };

void *check_and_translation_micro(const void *t_ptr) {
//   //recoverAddress_cnt++;
  enable_dwt();
  // if (!(0xC0040000 <= (uintptr_t) t_ptr && (uintptr_t) t_ptr <= 0xD0000000)) {
  //   uint32_t clock = DWT_CYCCNT;
  //   printf("check_and_translation clock (not heap): %u\n", clock);
  //   return t_ptr;
  // }
  void * return_ptr;
  //uint8_t tt_valid = __builtin_arm_cmse_TT(t_ptr) & 0x000000FF;
  uint8_t tt_valid = (uintptr_t) t_ptr >> 28;
  if (!!(tt_valid ^ 0xC)) {
    uint32_t clock = DWT_CYCCNT;
    printf("check_and_translation clock (not heap): %u\n", clock);
    //return t_ptr;
    return_ptr = t_ptr;
  }
  uintptr_t r_ptr = (((uintptr_t) t_ptr & 0x000FFFFF) | 0x20000000);

  unsigned tt_val = __builtin_arm_cmse_TT((void *) r_ptr) & 0x000000FF;

  uint8_t *block_metadata = (uint8_t *) ((uintptr_t)(((uintptr_t)r_ptr >> SHIFT_MAP2[tt_val]) << SHIFT_MAP2[tt_val]) + (uintptr_t)((1 << SHIFT_MAP2[tt_val]) - 1));

  uint8_t pointer_round = (uint8_t) (((uint32_t) t_ptr & 0x0FF00000) >> 20);
  /* for Juliet */
  // if (*block_metadata != pointer_round) {
  //   CWE416++;
  //   printf("UAF Detected (check_and_translation). CWE-416 Count: %d\n", CWE416);
  //   return (void *) r_ptr;
  // }
  /* for Juliet */
  //void * reptr = !(*block_metadata ^ pointer_round) ? (void *) r_ptr : t_ptr;
  //void * ssptr = (void *) (r_ptr | (((pointer_round ^ *block_metadata) << 20) & 0x0FF00000));
  void * ssptr = !(*block_metadata ^ pointer_round) ? (void *) r_ptr : t_ptr;
  uint32_t clock = DWT_CYCCNT;
  printf("check_and_translation clock: %u\n", clock);
  //printf("ptr: %p\n", ssptr);
  //return !(*block_metadata ^ pointer_round) ? (void *) r_ptr : t_ptr;
  //return ssptr;
  return ssptr;
//   // uintptr_t r_ptr = (((uintptr_t) t_ptr & 0x000FFFFF) | 0x20000000);

//   // unsigned tt_val = __builtin_arm_cmse_TT((void *) r_ptr) & 0x000000FF;
  
//   // // unsigned SHIFT_VALUE = 0;
//   // // if (tt_val == 0x0) SHIFT_VALUE = 4;
//   // // else if (tt_val == 0x1) SHIFT_VALUE = 6;
//   // // else if (tt_val == 0x2) SHIFT_VALUE = 8;
//   // // else if (tt_val == 0x3) SHIFT_VALUE = 14;
  
//   // uint8_t *block_metadata = (uint8_t *) ((uintptr_t)(((uintptr_t)r_ptr >> SHIFT_MAP2[tt_val]) << SHIFT_MAP2[tt_val]) + (uintptr_t)((1 << SHIFT_MAP2[tt_val]) - 1));
//   // //uint8_t *block_metadata = (uint8_t *) ((uintptr_t)(((uintptr_t)r_ptr >> SHIFT_VALUE) << SHIFT_VALUE) + (uintptr_t)((1 << SHIFT_VALUE) - 1));
  
//   // uint8_t pointer_round = (uint8_t) (((uint32_t) t_ptr & 0x0FF00000) >> 20);
//   // /* for Juliet */
//   // // if (*block_metadata != pointer_round) {
//   // //   CWE416++;
//   // //   printf("UAF Detected (check_and_translation). CWE-416 Count: %d\n", CWE416);
//   // //   return (void *) r_ptr;
//   // // }
//   // /* for Juliet */
//   // //void * reptr = !(*block_metadata ^ pointer_round) ? (void *) r_ptr : t_ptr;
//   // void * ssptr = (void *) (r_ptr | (((pointer_round ^ *block_metadata) << 20) & 0x0FF00000));
//   // uint32_t clock = DWT_CYCCNT;
//   // printf("check_and_translation clock: %u\n", clock);
//   // //printf("ptr: %p\n", ssptr);
//   // //return !(*block_metadata ^ pointer_round) ? (void *) r_ptr : t_ptr;
//   // return ssptr;
}


// void __attribute__((noinline)) *check_and_translation_micro(const void *t_ptr) {
//   uint8_t tt_valid = __builtin_arm_cmse_TT(t_ptr) & 0x000000FF;
//   enable_dwt();
//   if (!!(tt_valid ^ 0x07)) {
//     uint32_t clock = DWT_CYCCNT;
//     printf("translation (not heap) clock: %u\n", clock);
//     return t_ptr;
//   } 
//   uintptr_t r_ptr = (((uintptr_t) t_ptr & 0x000FFFFF) | 0x20000000);
//   uint32_t clock = DWT_CYCCNT;
//   printf("translation clock: %u\n", clock);
//   return (void *) r_ptr;
// }

int main(void) {
  puts("\nHello malloc!\n");

  printf("You are running RIOT on a(n) %s board.\n", RIOT_BOARD);
  printf("This board features a(n) %s MCU.\n\n", RIOT_MCU);

  printf("tt test\n");
  int tt = __builtin_arm_cmse_TT(&SIZE_MAP2);
  printf("%d\n", tt);

  char *data111 = (char *) malloc(11);
  *data111 = 'a';
  uint32_t start = xtimer_now_usec();
  enable_dwt();
  char* pa1 = (char *) check_and_translation_micro((void *) data111);
  uint32_t clock = DWT_CYCCNT;
  uint32_t end = xtimer_now_usec();
  printf("recoverAddress clock: %u\n", clock);
  printf("recoverAddress time: %d ms\n", end - start);
  printf("p: %p\n", data111);

  char carr1[1] = { 'a' };
  start = xtimer_now_usec();
  enable_dwt();
  char* pa2 = (char *) check_and_translation_micro((void *) carr1);
  clock = DWT_CYCCNT;
  end = xtimer_now_usec();
  printf("recoverAddress clock: %u\n", clock);
  printf("recoverAddress time: %d ms\n", end - start);
  printf("p: %p\n", pa2);

  // start = xtimer_now_usec();
  // enable_dwt();
  // char* pa3 = (char *) recoverAddress_Condition((void *) data111);
  // clock = DWT_CYCCNT;
  // end = xtimer_now_usec();
  // printf("recoverAddress_Condition clock: %u\n", clock);
  // printf("recoverAddress_Condition time: %d ms\n", end - start);
  // printf("p: %p\n", pa3);

  // char carr2[1] = { 'a' };
  // start = xtimer_now_usec();
  // enable_dwt();
  // char* pa4 = (char *) recoverAddress_Condition((void *) carr2);
  // clock = DWT_CYCCNT;
  // end = xtimer_now_usec();
  // printf("recoverAddress_Condition clock: %u\n", clock);
  // printf("recoverAddress_Condition time: %d ms\n", end - start);
  // printf("p: %p\n", pa4);

  printf("DONE!!\n");
  return 0;
}
