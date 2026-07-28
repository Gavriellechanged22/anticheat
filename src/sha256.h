#ifndef AC_SHA256_H
#define AC_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define AC_SHA256_DIGEST_SIZE 32u
#define AC_SHA256_BLOCK_SIZE 64u
#define AC_SHA256_HEX_SIZE 65u

typedef struct AcSha256 {
    uint32_t state[8];
    uint64_t bit_length;
    uint8_t buffer[AC_SHA256_BLOCK_SIZE];
    size_t buffer_length;
} AcSha256;

void ac_sha256_init(AcSha256 *context);
void ac_sha256_update(AcSha256 *context, const void *data, size_t length);
void ac_sha256_final(AcSha256 *context, uint8_t digest[AC_SHA256_DIGEST_SIZE]);
void ac_sha256(const void *data, size_t length, uint8_t digest[AC_SHA256_DIGEST_SIZE]);
void ac_sha256_to_hex(const uint8_t digest[AC_SHA256_DIGEST_SIZE], char hex[AC_SHA256_HEX_SIZE]);

#endif
