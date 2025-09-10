/*
 * Copyright (C) 2022 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @brief       Example application for PSA Crypto
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#include <stdio.h>
#include "psa/crypto.h"
#include "ztimer.h"

extern psa_status_t example_cipher_aes_128(void);
extern psa_status_t example_hmac_sha256(void);

#ifdef MULTIPLE_SE
extern psa_status_t example_cipher_aes_128_sec_se(void);
extern psa_status_t example_hmac_sha256_sec_se(void);
#endif

#define DWT_CYCCNT (*(uint32_t *) 0xE0001004)

int main(void)
{
    psa_status_t status;

    psa_crypto_init();

    ztimer_acquire(ZTIMER_USEC);
    ztimer_now_t start = ztimer_now(ZTIMER_USEC);

    status = example_hmac_sha256();
    printf("HMAC SHA256 took %d us\n", (int)(ztimer_now(ZTIMER_USEC) - start));
    if (status != PSA_SUCCESS) {
        printf("HMAC SHA256 failed: %s\n", psa_status_to_humanly_readable(status));
    }

    start = ztimer_now(ZTIMER_USEC);
    status = example_cipher_aes_128();
    printf("Cipher AES 128 took %d us\n", (int)(ztimer_now(ZTIMER_USEC) - start));
    if (status != PSA_SUCCESS) {
        printf("Cipher AES 128 failed: %s\n", psa_status_to_humanly_readable(status));
    }


#ifdef MULTIPLE_SE
    puts("Running Examples with secondary SE:");
    status = example_hmac_sha256_sec_se();
    printf("HMAC SHA256 took %d us\n", (int)(ztimer_now(ZTIMER_USEC) - start));
    if (status != PSA_SUCCESS) {
        printf("HMAC SHA256 failed: %s\n", psa_status_to_humanly_readable(status));
    }

    start = ztimer_now(ZTIMER_USEC);
    status = example_cipher_aes_128_sec_se();
    printf("Cipher AES 128 took %d us\n", (int)(ztimer_now(ZTIMER_USEC) - start));
    if (status != PSA_SUCCESS) {
        printf("Cipher AES 128 failed: %s\n", psa_status_to_humanly_readable(status));
    }

#endif

    ztimer_release(ZTIMER_USEC);

    uint32_t cycle = DWT_CYCCNT;
    printf("cycle : %u\n", cycle);

    puts("All Done");
    return 0;
}
