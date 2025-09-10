/*
 * Copyright (C) 2019 Kaleb J. Himes, Daniele Lacamera
 *
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       wolfSSL cryptographic library test
 *
 * @author      Kaleb J. Himes <kaleb@wolfssl.com>
 *              Daniele Lacamera <daniele@wolfssl.com>
 *
 * @}
 */

#include <stdio.h>
#include "xtimer.h"
#include "log.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfcrypt/test/test.h>
#ifdef MODULE_WOLFCRYPT_BENCHMARK
#include <wolfcrypt/benchmark/benchmark.h>
#endif

#define DWT_CYCCNT (*(uint32_t *) 0xE0001004)

int main(void)
{
    enable_dwt();
    LOG_INFO("wolfSSL Crypto Test!\n");
    /* Wait to work around a failing tests
     * on platforms that don't have RTC synchronized
     */
    xtimer_sleep(1);
    int ret = 0;
    // if ( (ret = chacha_test()) != 0)
    //     printf("asn      test failed!\n", ret);
    // else
    //     printf("asn      test passed!\n");

        
    // if ( (ret = curve25519_test()) != 0)
    //     printf("asn      test failed!\n", ret);
    // else
    //     printf("asn      test passed!\n");

        
    // if ( (ret = sha256_test()) != 0)
    //     printf("asn      test failed!\n", ret);
    // else
    //     printf("asn      test passed!\n");
        
    // if ( (ret = sha384_test()) != 0)
    //     printf("asn      test failed!\n", ret);
    // else
    //     printf("asn      test passed!\n");
        
    // if ( (ret = sha512_test()) != 0)
    //     printf("asn      test failed!\n", ret);
    // else
    //     printf("asn      test passed!\n");

    // if ( (ret = ed25519_test()) != 0)
    //     printf("asn      test failed!\n", ret);
    // else
    //     printf("asn      test passed!\n");
    
    if ( (ret = aes_test()) != 0)
        printf("asn      test failed!\n", ret);
    else
        printf("asn      test passed!\n");


    uint32_t clock = DWT_CYCCNT;
    printf("wolfssl clock cycle : %u\n", clock);
    //wolfcrypt_test(NULL);
#ifdef MODULE_WOLFCRYPT_BENCHMARK
    //LOG_INFO("wolfSSL Benchmark!\n");
    //benchmark_test(NULL);
#else
    LOG_INFO("wolfSSL Benchmark disabled\n");
#endif
    //print_memory_peak();
    return 0;
}
