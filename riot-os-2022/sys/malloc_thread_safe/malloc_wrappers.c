/*
 * Copyright (C) 2019 Gunar Schorcht
 *               2022 Otto-von-Guericke-Universität Magdeburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 *
 * @file
 * @brief   Implements various POSIX syscalls
 * @author  Gunar Schorcht <gunar@schorcht.net>
 * @author  Marian Buschsieweke <marian.buschsieweke@ovgu.de>
 */

#include <stdarg.h>
#include <stdint.h>  // uint32_t, uintptr_t
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "architecture.h"
#include "assert.h"
#include "cpu.h"
#include "irq.h"
#include "kernel_defines.h"
#include "log.h"
#include "mutex.h"
#include "panic.h"
#include "periph/hwrng.h"

/*
 * mpu set header file
 */
#include "mpu_defs.h"
#include "mpu_prog.h"

/* micro evaluation */
#include "xtimer.h"

#define DWT_CYCCNT (*(uint32_t *)0xE0001004)

extern void *__wrap_malloc(size_t size);
extern void __wrap_free(void *ptr);
extern void *__wrap_realloc(void *ptr, size_t size);

extern void *check_and_translation(const void *t_ptr);
extern void *translation_only(const void *t_ptr);
extern void *restore_only(const void *t_ptr);

/* for wasm */
// uint32_t SIZE_MAP[4] = { 0x4000, 0x200, 0x40, 0x10 };
// uint8_t SHIFT_MAP[4] = { 14, 9, 6, 4 };
// uint32_t SIZE_MAP[7] __attribute__((section(".data"))) = { 0x4000, 0x200, 0x100, 0x80, 0x40, 0x20, 0x10 };
// uint8_t SHIFT_MAP[7] __attribute__((section(".data"))) = { 14, 9, 8, 7, 6, 5, 4 };
// uint32_t SIZE_MAP[8] __attribute__((section(".data"))) = { 0x10, 0x3800, 0x3000, 0x1C0, 0x100, 0x80, 0x40, 0x18 };
// uint32_t SIZE_MAP[8] __attribute__((section(".data"))) = { 0x10, 0x34BC, 0x2710, 0x1C0, 0x100, 0x80, 0x40, 0x18 };
// uint32_t SIZE_MAP[8] __attribute__((section(".data"))) = { 0x18, 0x3448, 0x2640, 0x1a8, 0x108, 0xc8, 0x68, 0x38 };
// uint8_t SHIFT_MAP[8] __attribute__((section(".data"))) = { 4, 15, 12, 6, 8, 7, 6, 3 };

// static uint16_t SIZE_MAP[8] __attribute__((section(".data"))) = { 0x18, 0x38, 0x68, 0xc8, 0x108, 0x1a8, 0x2640, 0x3448 };
// static uint16_t SIZE_MAP[8] __attribute__((section(".data"))) = { 0, 0, 0, 0, 0, 0x18, 0x208, 0x408};
static uint16_t SIZE_MAP[8] __attribute__((section(".data"))) = {0x18, 0x38, 0x68, 0xc8, 0x108, 0x1a8, 0x8000, 0x8000};
// optimized
static uintptr_t BASE_ADDR[8] __attribute__((section(".data"))) = {0x20004000, 0x20006000, 0x20007000, 0x20008000, 0x2000A000, 0x2000C000, 0x2000E000, 0x2002E000};
static uintptr_t REGION_PEAK_ADDRESS[8] __attribute__((section(".data"))) = {0x20004000, 0x20006000, 0x20007000, 0x20008000, 0x2000A000, 0x2000C000, 0x2000E000, 0x2002E000};
static uintptr_t REGION_SIZES[8] __attribute__((section(".data"))) = {
    0x2000,
    0x1000,
    0x1000,
    0x2000,
    0x2000,
    0x2000,
    0x20000,
    0x12000,
};

// no optimized
//   uintptr_t BASE_ADDR[8] = { 0x20004000, 0x2000B800, 0x20013000, 0x2001A800, 0x20022000, 0x20029800, 0x20031000, 0x20038800 };
//   uintptr_t REGION_PEAK_ADDRESS[8] = { 0x20004000, 0x2000B800, 0x20013000, 0x2001A800, 0x20022000, 0x20029800, 0x20031000, 0x20038800 };
//   uintptr_t REGION_SIZES[8] = { 0x7800, 0x7800, 0x7800, 0x7800, 0x7800, 0x7800, 0x7800, 0x7800 };

// uintptr_t REGION_PEAK_ADDRESS[8] = { 0x20004000, 0x20010000, 0x20020000, 0x20030000, 0x20034000, 0x20038000, 0x2003A000, 0x2003E000 };

// uintptr_t BASE_ADDR[8] __attribute__((section(".data"))) = { 0x20004000, 0x20010000, 0x20020000, 0x20030000, 0x20034000, 0x20038000, 0x2003A000, 0x2003E000 };

/* for wasm */
/* for beebs */
// uint32_t SIZE_MAP[4] = { 0x1000, 0x100, 0x40, 0x10 };
// uint8_t SHIFT_MAP[4] = { 12, 8, 6, 4 };
/* for beebs */
/* for mibench2 (susan) */
// uint32_t SIZE_MAP[4] = { 0x8000, 0x4000, 0x100, 0x40 };
// uint8_t SHIFT_MAP[4] = { 15, 14, 8, 6 };
// uint32_t SIZE_MAP[4] = { 0x4000, 0x8000, 0x100, 0x40 };
// uint8_t SHIFT_MAP[4] = { 14, 15, 8, 6 };
//   uint32_t SIZE_MAP[1] = { 0x8000 };
//   uint8_t SHIFT_MAP[1] = { 15 };

/* for mibench2 (susan) */

unsigned int HEAPSIZE = 0x3C000;  // region size. 0xF000 * 4 = 0x3C000.
// uint32_t REGION_SIZE = 0xF000;

static mutex_t _lock;
bool elk_malloc_inited = false;  // checking allocator is initiated.

/*
 * elk data structure
 */
struct elk_freelist_s {
    uintptr_t _reserved;
    struct elk_freelist_s *next;
};
typedef struct elk_freelist_s *elk_freelist_t;

struct elk_regioninfo_s {
    elk_freelist_t freelist;
    void *freeptr;
    void *baseptr;
    void *endptr;
};
typedef struct elk_regioninfo_s *elk_regioninfo_t;

struct elk_regioninfo_s elk_REGION_INFO[8];

#ifdef ELK_PEAK_MEMORY_USAGE
/* for Memory Peak Usage Evaluation */
// uintptr_t REGION_PEAK_ADDRESS[4] = { 0x20004000, 0x20013000, 0x20022000, 0x20031000 };
// uintptr_t REGION_PEAK_ADDRESS[4] = { 0x20010000, 0x20020000, 0x20030000, 0x20034000 };

// uintptr_t REGION_PEAK_ADDRESS[8] = { 0x20004000, 0x20010000, 0x20020000, 0x20030000, 0x20034000, 0x20038000, 0x2003A000, 0x2003E000 };
uint32_t validation_cnt = 0;
uint32_t translation_cnt = 0;

// inspection mode
//  void inspection() {

//  }

void print_memory_peak() {
    printf("validation Call Count: %u\n", validation_cnt);
    printf("translation Call Count: %u\n", translation_cnt);
    if (!elk_malloc_inited) return;
    printf("Memory Peak Usage: \n");
    uint32_t usage = 0;
    uint32_t use_block = 0;
    for (int i = 0; i < 8; i++) {
        printf("Region %d - %p\n", (i + 1), REGION_PEAK_ADDRESS[i]);
        usage += REGION_PEAK_ADDRESS[i] - (uintptr_t)(elk_REGION_INFO + i)->baseptr;
        use_block += (REGION_PEAK_ADDRESS[i] - (uintptr_t)(elk_REGION_INFO + i)->baseptr) / SIZE_MAP[i];
    }
    printf("Use 0x%x Bytes. (Total: 0x3C000)\n", usage);
    printf("Use %d Objects.\n", use_block);
    printf("Total Memory Overhead: %d%%\n", ((usage * 100) / (uint32_t)0x6382));
    printf("Region Usage:\n");
    for (int i = 0; i < 8; i++) {
        uint32_t total = (elk_REGION_INFO + i)->endptr - (elk_REGION_INFO + i)->baseptr;
        uint32_t r_usage = REGION_PEAK_ADDRESS[i] - (uintptr_t)(elk_REGION_INFO + i)->baseptr;
        printf("Region %d - total %p, used %p (%d%%)\n", (i + 1), total + 1, r_usage, ((r_usage * 100) / (total + 1)));
    }
    printf("\n");
}
#endif

/*
 * elk initialize mpu region, data structure
 */
bool elk_init(void) {
    elk_regioninfo_t info1 = elk_REGION_INFO;
    elk_regioninfo_t info2 = elk_REGION_INFO + 1;
    elk_regioninfo_t info3 = elk_REGION_INFO + 2;
    elk_regioninfo_t info4 = elk_REGION_INFO + 3;
    elk_regioninfo_t info5 = elk_REGION_INFO + 4;
    elk_regioninfo_t info6 = elk_REGION_INFO + 5;
    elk_regioninfo_t info7 = elk_REGION_INFO + 6;
    elk_regioninfo_t info8 = elk_REGION_INFO + 7;

    info1->freelist = NULL;
    info2->freelist = NULL;
    info3->freelist = NULL;
    info4->freelist = NULL;
    info5->freelist = NULL;
    info6->freelist = NULL;
    info7->freelist = NULL;
    info8->freelist = NULL;

    // 20004000 ~ 20040000
    //  void* region1 = (void *)0x20004000; // 0xC000
    //  void* region2 = (void *)0x20010000; // 0x10000
    //  void* region3 = (void *)0x20020000; // 0x10000
    //  void* region4 = (void *)0x20030000; // 0x4000
    //  void* region5 = (void *)0x20034000; // 0x4000
    //  void* region6 = (void *)0x20038000; // 0x4000
    //  void* region7 = (void *)0x2003A000; // 0x2000
    //  void* region8 = (void *)0x2003E000; // 0x2000

    void *region1 = (void *)BASE_ADDR[0];  // 0xC000
    void *region2 = (void *)BASE_ADDR[1];  // 0x10000
    void *region3 = (void *)BASE_ADDR[2];  // 0x10000
    void *region4 = (void *)BASE_ADDR[3];  // 0x4000
    void *region5 = (void *)BASE_ADDR[4];  // 0x4000
    void *region6 = (void *)BASE_ADDR[5];  // 0x4000
    void *region7 = (void *)BASE_ADDR[6];  // 0x2000
    void *region8 = (void *)BASE_ADDR[7];  // 0x2000

    info1->freeptr = region1;
    info1->baseptr = region1;
    // info1->endptr = region1 + 0xC000 - 1;
    info1->endptr = (void *)((uintptr_t)region1 + REGION_SIZES[0] - 1);
    // printf("%p\n", info1->endptr);

    info2->freeptr = region2;
    info2->baseptr = region2;
    // info2->endptr = region2 + 0x10000 - 1;
    info2->endptr = (void *)((uintptr_t)region2 + REGION_SIZES[1] - 1);

    info3->freeptr = region3;
    info3->baseptr = region3;
    // info3->endptr = region3 + 0x10000 - 1;
    info3->endptr = (void *)((uintptr_t)region3 + REGION_SIZES[2] - 1);

    info4->freeptr = region4;
    info4->baseptr = region4;
    // info4->endptr = region4 + 0x4000 - 1;
    info4->endptr = (void *)((uintptr_t)region4 + REGION_SIZES[3] - 1);

    info5->freeptr = region5;
    info5->baseptr = region5;
    // info5->endptr = region5 + 0x4000 - 1;
    info5->endptr = (void *)((uintptr_t)region5 + REGION_SIZES[4] - 1);

    info6->freeptr = region6;
    info6->baseptr = region6;
    // info6->endptr = region6 + 0x4000 - 1;
    info6->endptr = (void *)((uintptr_t)region6 + REGION_SIZES[5] - 1);

    info7->freeptr = region7;
    info7->baseptr = region7;
    // info7->endptr = region7 + 0x2000 - 1;
    info7->endptr = (void *)((uintptr_t)region7 + REGION_SIZES[6] - 1);

    info8->freeptr = region8;
    info8->baseptr = region8;
    // info8->endptr = region8 + 0x2000 - 1;
    info8->endptr = (void *)((uintptr_t)region8 + REGION_SIZES[7] - 1);

    //  setMPU(0UL, (void *)0x20004000, (void *)0x2000FFFF, ARM_MPU_RW, 0UL, ARM_MPU_XN);
    //  setMPU(1UL, (void *)0x20010000, (void *)0x2001FFFF, ARM_MPU_RW, 0UL, ARM_MPU_XN);
    //  setMPU(2UL, (void *)0x20020000, (void *)0x2002FFFF, ARM_MPU_RW, 0UL, ARM_MPU_XN);
    //  setMPU(3UL, (void *)0x20030000, (void *)0x20033FFF, ARM_MPU_RW, 0UL, ARM_MPU_XN);
    //  setMPU(4UL, (void *)0x20034000, (void *)0x20037FFF, ARM_MPU_RW, 0UL, ARM_MPU_XN);
    //  setMPU(5UL, (void *)0x20038000, (void *)0x20039FFF, ARM_MPU_RW, 0UL, ARM_MPU_XN);
    //  setMPU(6UL, (void *)0x2003A000, (void *)0x2003DFFF, ARM_MPU_RW, 0UL, ARM_MPU_XN);
    //  setMPU(7UL, (void *)0x2003E000, (void *)0x2FFFFFFF, ARM_MPU_RW, 0UL, ARM_MPU_XN);
    setMPU(0UL, (void *)info1->baseptr, (void *)info1->endptr, ARM_MPU_RW, 0UL, ARM_MPU_XN);
    setMPU(1UL, (void *)info2->baseptr, (void *)info2->endptr, ARM_MPU_RW, 0UL, ARM_MPU_XN);
    setMPU(2UL, (void *)info3->baseptr, (void *)info3->endptr, ARM_MPU_RW, 0UL, ARM_MPU_XN);
    setMPU(3UL, (void *)info4->baseptr, (void *)info4->endptr, ARM_MPU_RW, 0UL, ARM_MPU_XN);
    setMPU(4UL, (void *)info5->baseptr, (void *)info5->endptr, ARM_MPU_RW, 0UL, ARM_MPU_XN);
    setMPU(5UL, (void *)info6->baseptr, (void *)info6->endptr, ARM_MPU_RW, 0UL, ARM_MPU_XN);
    setMPU(6UL, (void *)info7->baseptr, (void *)info7->endptr, ARM_MPU_RW, 0UL, ARM_MPU_XN);
    setMPU(7UL, (void *)info8->baseptr, (void *)0x3FFFFFFF, ARM_MPU_RW, 0UL, ARM_MPU_XN);

    //  void* region1 = (void *)0x20010000; // 0x10000

    //  info1->freeptr = region1;
    //  info1->baseptr = region1;
    //  info1->endptr = region1 + 0x30000 - 1;

    //  setMPU(0UL, (void *)0x20004000, (void *)0x2FFFFFFF, ARM_MPU_RW, 0UL, ARM_MPU_XN);

    //  setMPU(0UL, (void *)0x20010000, (void *)0x2001FFFF, ARM_MPU_RW, 0UL, ARM_MPU_XN);
    //  setMPU(1UL, (void *)0x20020000, (void *)0x2002FFFF, ARM_MPU_RW, 0UL, ARM_MPU_XN);
    //  setMPU(2UL, (void *)0x20030000, (void *)0x20033FFF, ARM_MPU_RW, 0UL, ARM_MPU_XN);
    //  setMPU(3UL, (void *)0x20034000, (void *)0x20035FFF, ARM_MPU_RW, 0UL, ARM_MPU_XN);
    //  setMPU(4UL, (void *)0x20036000, (void *)0x20037FFF, ARM_MPU_RW, 0UL, ARM_MPU_XN);
    //  setMPU(5UL, (void *)0x20038000, (void *)0x20039FFF, ARM_MPU_RW, 0UL, ARM_MPU_XN);
    //  //setMPU(6UL, (void *)0x2003A000, (void *)0x2003BFFF, ARM_MPU_RW, 0UL, ARM_MPU_XN);
    //  setMPU(6UL, (void *)0x2003A000, (void *)0x2FFFFFFF, ARM_MPU_RW, 0UL, ARM_MPU_XN);
    // setMPU(7UL, (void *)0xC0000000, (void *)0xCFFFFFFF, ARM_MPU_RW, 0UL, ARM_MPU_XN);

    // Initialize HW Random Number Generator
    hwrng_init();

    elk_malloc_inited = true;
    // printf("HEAP INIT\n");
    return true;
}

#ifdef ELK_SECURITY
/* for Juliet */
uint32_t CWE415 = 0;
uint32_t CWE416 = 0;
uint32_t CWE590 = 0;
uint32_t CWE761 = 0;
/* for Juliet */
#endif

static inline bool is_heap(uintptr_t ptr) {
    return (0x20040000 <= ptr && ptr <= 0x3FFFFFFF);
}

static inline uint8_t get_tt(uintptr_t ptr) {
    for (int i = 0; i < 8; i++) {
        if (BASE_ADDR[i] <= ptr && ptr < (BASE_ADDR[i] + REGION_SIZES[i])) return i;
    }
    return 8;
}

// uintptr_t BIN_SIZE = 0x7800;
// uintptr_t HEAP_START = 0x20004000;

extern void *check_and_translation(const void *t_ptr) {
    // for ARMv8-M
    // enable_dwt();
    if (!(__builtin_arm_cmse_TT(t_ptr) >> 16 & 1)) return t_ptr;
    uintptr_t r = (uintptr_t)t_ptr & 0x2003FFFFU;
    uint8_t tt_val = (uint8_t)__builtin_arm_cmse_TT((void *)r);
    // for ARMv8-M

    // for Cortex-M
    // if (!is_heap((uintptr_t) t_ptr)) return t_ptr;
    // uintptr_t r = (uintptr_t)t_ptr & 0x2003FFFF;
    // uint8_t tt_val = get_tt(r);
    // for Cortex-M

    // for RTT
    // if (!is_heap((uintptr_t) t_ptr)) return t_ptr;
    // uintptr_t r = (uintptr_t)t_ptr & 0x2003FFFFU;
    // uintptr_t BASE_ADDRESS = r - HEAP_START;
    // uintptr_t BIN_ID = BASE_ADDRESS / BIN_SIZE;
    // uintptr_t BUFFER_SIZE = SIZE_MAP[BIN_ID];
    // uintptr_t BUFFER_ID = (r / BUFFER_SIZE) * BUFFER_SIZE + HEAP_START;
    // uintptr_t BASE = BUFFER_ID = BUFFER_ID + BUFFER_SIZE - 1;
    // for RTT

    uintptr_t BASE_ADDRESS = (uintptr_t)BASE_ADDR[tt_val];
    uint16_t sz = SIZE_MAP[tt_val];
    uintptr_t offset = ((uintptr_t)r - BASE_ADDRESS);
    uintptr_t block_base = (offset / sz) * sz;
    uintptr_t block_metadata_addr = BASE_ADDRESS + (block_base + sz - 1);

    // uint32_t clock = DWT_CYCCNT;
    // printf("ELK_H translation clock: %u\n", clock);

    uint8_t *block_metadata = (uint8_t *)block_metadata_addr;
    uint8_t pointer_round = (uint8_t)(((uint32_t)t_ptr & 0x0FF00000) >> 20);
// if (*block_metadata != pointer_round) {
//    CWE416++;
//    printf("Use After Free! CWE-416 Count: %d\n", CWE416);
//    return (void*) r;
// }
#ifdef ELK_SECURITY
    if (*block_metadata != pointer_round) {
        printf("[ELK] Use After Free Detected!\n");
        hard_fault_default();
        return (void *)r;
    }
#endif
    return (void *)(*block_metadata == pointer_round ? r : t_ptr);
    // return (void*) BASE;
}

extern void *translation_only(const void *t_ptr) {
#ifdef ELK_PEAK_MEMORY_USAGE
    translation_cnt++;
#endif

#ifdef ELK_ASM
    __asm__ __volatile__(
        "tt    r1, r0                 \n\t"
        //"tst   r1, #0x00010000      \n\t"
        "lsls    r1, r1, #15          \n\t"
        "it      eq                   \n\t"
        "bxeq    lr                   \n\t"
        //"beq   1f                   \n\t"

        "ldr    r2, =0x2003FFFF       \n\t"
        "and   r0, r0, r2             \n\t"

        "bx     lr                  "
        :
        :
        : "r1", "r2", "cc", "memory");
#endif

// for wasm
#ifndef ELK_ASM
    if (!(__builtin_arm_cmse_TT(t_ptr) >> 16 & 1)) return t_ptr;
    return (void *)((uintptr_t)t_ptr & 0x2003FFFF);
#endif
    // for wasm

    // for Cortex-m
    // if (!is_heap((uintptr_t)t_ptr)) return t_ptr;
    // return (void *) ((uintptr_t) t_ptr & 0x2003FFFF);
    // for Cortex-m
}

static inline uint8_t get_alloc_idx(size_t size) {
    if (SIZE_MAP[0] > size)
        return 0;
    else if (SIZE_MAP[1] > size)
        return 1;
    else if (SIZE_MAP[2] > size)
        return 2;
    else if (SIZE_MAP[3] > size)
        return 3;
    else if (SIZE_MAP[4] > size)
        return 4;
    else if (SIZE_MAP[5] > size)
        return 5;
    else if (SIZE_MAP[6] > size)
        return 6;
    else if (SIZE_MAP[7] > size)
        return 7;
    return 8;
    //  else {
    //   //  LOG_ERROR("Too big size to allocate");
    //   //  hard_fault_default();
    //    return 8;
    //  }
}

/*
 * elk allocator malloc
 */
// malloc()
extern void __attribute__((used)) * __wrap_malloc(size_t size) {
    assert(!irq_is_in());
    mutex_lock(&_lock);

    if (!elk_malloc_inited) elk_init();
    uint8_t idx = get_alloc_idx(size);
    size_t alloc_size = SIZE_MAP[idx];
    elk_regioninfo_t info = elk_REGION_INFO + idx;

    // Generate Random Number
    uint8_t random_value;
    hwrng_read(&random_value, sizeof(random_value));
    random_value |= 0x01;  // non-zero

    void *ptr;
    elk_freelist_t freelist = info->freelist;
    if (freelist != NULL) {
        info->freelist = freelist->next;
        ptr = (void *)freelist;
        uint8_t *block_metadata = (uint8_t *)(ptr + alloc_size - 1);
        *block_metadata = random_value;
        ptr = (void *)((uintptr_t)ptr | (uintptr_t)(0x00100000 * random_value));
#ifdef ELK_PEAK_MEMORY_USAGE
        /* for Memory Peak Usage Evaluation */
        REGION_PEAK_ADDRESS[idx] = (uintptr_t)block_metadata + 1 > REGION_PEAK_ADDRESS[idx] ? (uintptr_t)block_metadata + 1 : REGION_PEAK_ADDRESS[idx];
/* for Memory Peak Usage Evaluation */
#endif
        mutex_unlock(&_lock);
        return (void *)ptr;
    }

    ptr = info->freeptr;
    void *freeptr;
    freeptr = (void *)ptr + alloc_size;
    if (freeptr > info->endptr) {
        mutex_unlock(&_lock);
        LOG_ERROR("Region is full, can't alloc more");
        hard_fault_default();
    }
    uint8_t *block_metadata = (uint8_t *)(ptr + alloc_size - 1);
    *block_metadata = random_value;
    info->freeptr = freeptr;
    ptr = (void *)((uintptr_t)ptr | (uintptr_t)(0x00100000 * random_value));
#ifdef ELK_PEAK_MEMORY_USAGE
    /* for Memory Peak Usage Evaluation */
    REGION_PEAK_ADDRESS[idx] = (uintptr_t)block_metadata + 1 > REGION_PEAK_ADDRESS[idx] ? (uintptr_t)block_metadata + 1 : REGION_PEAK_ADDRESS[idx];
/* for Memory Peak Usage Evaluation */
#endif
    mutex_unlock(&_lock);
    return (void *)ptr;
}

// free()
extern void __attribute__((used)) __wrap_free(void *ptr) {
    assert(!irq_is_in());
    mutex_lock(&_lock);
    if (ptr == NULL) return;
    unsigned tt = __builtin_arm_cmse_TT(ptr);
    /* for Juliet */
    if (!((tt >> 16) & 0x01)) {
#ifdef ELK_SECURITY
        CWE590++;
        printf("[ELK] Invalid Free Detected! (Free of Memory not on the Heap) CWE-590 Count: %d\n", CWE590);
        mutex_unlock(&_lock);
#else
        mutex_unlock(&_lock);
        LOG_ERROR("[ELK] Invalid Free Detected! (Free of Memory not on the Heap)");
        hard_fault_default();
#endif
        return;
    }
    /* for Juliet */
    uintptr_t r_ptr = (uintptr_t)ptr & 0x2003FFFF;
    uint8_t idx = __builtin_arm_cmse_TT((void *)r_ptr) & 0x000000FF;
    elk_regioninfo_t info = &elk_REGION_INFO[idx];
    uintptr_t base = (uintptr_t)info->baseptr + (((uintptr_t)(r_ptr - (uintptr_t)info->baseptr) / SIZE_MAP[idx]) * SIZE_MAP[idx]);
    /* for Juliet */
    if (r_ptr != base) {
#ifdef ELK_SECURITY
        CWE761++;
        printf("[ELK] Invalid Free Detected! (Free of Pointer not at Start of Buffer) CWE-761 Count: %d\n", CWE761);
        mutex_unlock(&_lock);
#else
        mutex_unlock(&_lock);
        LOG_ERROR("[ELK] Invalid Free Detected! (Free of Pointer not at Start of Buffer)");
        hard_fault_default();
#endif
        return;
    }
    /* for Juliet */
    uintptr_t metadata_address = (base + (SIZE_MAP[idx]) - 1);
    uint8_t b_metadata = (uint8_t)*((uint8_t *)metadata_address);
    uint8_t pointer_round = (uint8_t)(((uint32_t)ptr & 0x0FF00000) >> 20);
    uint8_t *block_metadata = (uint8_t *)metadata_address;
    /* for Juliet */
    if (b_metadata == 0) {
#ifdef ELK_SECURITY
        CWE415++;
        printf("[ELK] Double Free Detected! CWE-415 Count: %d\n", CWE415);
        mutex_unlock(&_lock);
#else
        mutex_unlock(&_lock);
        LOG_ERROR("[ELK] Double Free Detected!");
        hard_fault_default();
#endif
        return;
    }
    /* for Juliet */
    *block_metadata = 0x00;
    elk_freelist_t newfreelist = (elk_freelist_t)base;
    elk_freelist_t oldfreelist = info->freelist;
    newfreelist->next = oldfreelist;
    info->freelist = newfreelist;
    mutex_unlock(&_lock);
    return;
}

void *__attribute__((used)) __wrap_calloc(size_t nmemb, size_t size) {
    /* some c libs don't perform proper overflow check (e.g. newlib < 4.0.0). Hence, we
     * just implement calloc on top of malloc ourselves. In addition to ensuring proper
     * overflow checks, this likely saves a bit of ROM */
    size_t total_size;
    if (__builtin_mul_overflow(nmemb, size, &total_size)) {
        return NULL;
    }
    void *res = __wrap_malloc(total_size);
    if (res) {
        memset(translation_only(res), 0, total_size);
    }
    return res;
}

extern void *__attribute__((used)) __wrap_realloc(void *ptr, size_t size) {
    assert(!irq_is_in());
    if (ptr == NULL || size == 0) return malloc(size);
    void *newptr = __wrap_malloc(size);
    if (newptr == NULL) return NULL;
    memcpy(translation_only(newptr), translation_only(ptr), size);
    __wrap_free(ptr);
    return newptr;
}