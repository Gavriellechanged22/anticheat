#include "sha256.h"

#include <string.h>

static const uint32_t AC_SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static uint32_t ac_rotr32(uint32_t value, unsigned int bits)
{
    return (value >> bits) | (value << (32u - bits));
}

static void ac_sha256_compress(uint32_t state[8], const uint8_t block[AC_SHA256_BLOCK_SIZE])
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    unsigned int index;

    for (index = 0; index < 16u; ++index) {
        w[index] = ((uint32_t)block[index * 4u] << 24) |
                   ((uint32_t)block[index * 4u + 1u] << 16) |
                   ((uint32_t)block[index * 4u + 2u] << 8) |
                   (uint32_t)block[index * 4u + 3u];
    }

    for (index = 16u; index < 64u; ++index) {
        const uint32_t s0 = ac_rotr32(w[index - 15u], 7u) ^
                            ac_rotr32(w[index - 15u], 18u) ^
                            (w[index - 15u] >> 3);
        const uint32_t s1 = ac_rotr32(w[index - 2u], 17u) ^
                            ac_rotr32(w[index - 2u], 19u) ^
                            (w[index - 2u] >> 10);
        w[index] = w[index - 16u] + s0 + w[index - 7u] + s1;
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    for (index = 0; index < 64u; ++index) {
        const uint32_t s1 = ac_rotr32(e, 6u) ^ ac_rotr32(e, 11u) ^ ac_rotr32(e, 25u);
        const uint32_t choose = (e & f) ^ ((~e) & g);
        const uint32_t temp1 = h + s1 + choose + AC_SHA256_K[index] + w[index];
        const uint32_t s0 = ac_rotr32(a, 2u) ^ ac_rotr32(a, 13u) ^ ac_rotr32(a, 22u);
        const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t temp2 = s0 + majority;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void ac_sha256_init(AcSha256 *context)
{
    if (context == NULL) {
        return;
    }

    context->state[0] = 0x6a09e667u;
    context->state[1] = 0xbb67ae85u;
    context->state[2] = 0x3c6ef372u;
    context->state[3] = 0xa54ff53au;
    context->state[4] = 0x510e527fu;
    context->state[5] = 0x9b05688cu;
    context->state[6] = 0x1f83d9abu;
    context->state[7] = 0x5be0cd19u;
    context->bit_length = 0;
    context->buffer_length = 0;
    memset(context->buffer, 0, sizeof(context->buffer));
}

void ac_sha256_update(AcSha256 *context, const void *data, size_t length)
{
    const uint8_t *bytes = (const uint8_t *)data;
    size_t offset = 0;

    if (context == NULL || (data == NULL && length != 0)) {
        return;
    }

    context->bit_length += (uint64_t)length * 8u;

    if (context->buffer_length != 0) {
        const size_t missing = AC_SHA256_BLOCK_SIZE - context->buffer_length;
        const size_t take = length < missing ? length : missing;

        memcpy(context->buffer + context->buffer_length, bytes, take);
        context->buffer_length += take;
        offset += take;

        if (context->buffer_length < AC_SHA256_BLOCK_SIZE) {
            return;
        }

        ac_sha256_compress(context->state, context->buffer);
        context->buffer_length = 0;
    }

    while (length - offset >= AC_SHA256_BLOCK_SIZE) {
        ac_sha256_compress(context->state, bytes + offset);
        offset += AC_SHA256_BLOCK_SIZE;
    }

    if (offset < length) {
        context->buffer_length = length - offset;
        memcpy(context->buffer, bytes + offset, context->buffer_length);
    }
}

void ac_sha256_final(AcSha256 *context, uint8_t digest[AC_SHA256_DIGEST_SIZE])
{
    uint8_t padding[AC_SHA256_BLOCK_SIZE * 2];
    size_t padding_length;
    uint64_t bit_length;
    unsigned int index;

    if (context == NULL || digest == NULL) {
        return;
    }

    bit_length = context->bit_length;
    memset(padding, 0, sizeof(padding));
    padding[0] = 0x80u;

    padding_length = (context->buffer_length < 56u)
        ? (56u - context->buffer_length)
        : (120u - context->buffer_length);

    for (index = 0; index < 8u; ++index) {
        padding[padding_length + index] =
            (uint8_t)((bit_length >> (56u - 8u * index)) & 0xffu);
    }

    context->bit_length = bit_length;
    ac_sha256_update(context, padding, padding_length + 8u);
    context->bit_length = bit_length;

    for (index = 0; index < 8u; ++index) {
        digest[index * 4u] = (uint8_t)(context->state[index] >> 24);
        digest[index * 4u + 1u] = (uint8_t)(context->state[index] >> 16);
        digest[index * 4u + 2u] = (uint8_t)(context->state[index] >> 8);
        digest[index * 4u + 3u] = (uint8_t)context->state[index];
    }
}

void ac_sha256(const void *data, size_t length, uint8_t digest[AC_SHA256_DIGEST_SIZE])
{
    AcSha256 context;

    ac_sha256_init(&context);
    ac_sha256_update(&context, data, length);
    ac_sha256_final(&context, digest);
}

void ac_sha256_to_hex(const uint8_t digest[AC_SHA256_DIGEST_SIZE], char hex[AC_SHA256_HEX_SIZE])
{
    static const char alphabet[] = "0123456789abcdef";
    unsigned int index;

    if (digest == NULL || hex == NULL) {
        return;
    }

    for (index = 0; index < AC_SHA256_DIGEST_SIZE; ++index) {
        hex[index * 2u] = alphabet[(digest[index] >> 4) & 0x0fu];
        hex[index * 2u + 1u] = alphabet[digest[index] & 0x0fu];
    }
    hex[AC_SHA256_DIGEST_SIZE * 2u] = '\0';
}
