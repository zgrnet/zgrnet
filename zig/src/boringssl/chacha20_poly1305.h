#ifndef CHACHA20_POLY1305_H
#define CHACHA20_POLY1305_H

#include <stdint.h>
#include <stddef.h>

// Input structure for seal (encrypt)
// Must match ring's seal_data_in exactly
struct seal_data_in {
    uint32_t key[8];              // 32 bytes
    uint32_t counter;             // 4 bytes
    uint8_t nonce[12];            // 12 bytes
    const uint8_t *extra_ciphertext;  // 8 bytes
    size_t extra_ciphertext_len;      // 8 bytes
} __attribute__((aligned(16)));       // Total: 64 bytes

// Input structure for open (decrypt)
struct open_data_in {
    uint32_t key[8];              // 32 bytes
    uint32_t counter;             // 4 bytes
    uint8_t nonce[12];            // 12 bytes
} __attribute__((aligned(16)));       // Total: 48 bytes

// Output structure - just the tag
struct data_out {
    uint8_t tag[16];
} __attribute__((aligned(16)));

// Union that shares memory between input and output
// BoringSSL writes tag to the beginning of this structure
union seal_data {
    struct seal_data_in input;
    struct data_out out;
} __attribute__((aligned(16)));

union open_data {
    struct open_data_in input;
    struct data_out out;
} __attribute__((aligned(16)));

// Assembly functions from BoringSSL
void chacha20_poly1305_seal(
    uint8_t *out_ciphertext,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *ad,
    size_t ad_len,
    union seal_data *data
);

void chacha20_poly1305_open(
    uint8_t *out_plaintext,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *ad,
    size_t ad_len,
    union open_data *data
);

#endif
