#include "chacha20_poly1305.h"
#include <string.h>

void aead_seal_with_ad(
    uint8_t *out,
    const uint8_t *key,
    uint64_t nonce,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *ad,
    size_t ad_len
) {
    union seal_data data __attribute__((aligned(16)));
    memset(&data, 0, sizeof(data));
    
    for (int i = 0; i < 8; i++) {
        data.input.key[i] = ((uint32_t)key[i*4]) |
                           ((uint32_t)key[i*4+1] << 8) |
                           ((uint32_t)key[i*4+2] << 16) |
                           ((uint32_t)key[i*4+3] << 24);
    }
    data.input.counter = 0;
    memcpy(data.input.nonce, &nonce, 8);
    data.input.extra_ciphertext = NULL;
    data.input.extra_ciphertext_len = 0;
    
    chacha20_poly1305_seal(out, plaintext, plaintext_len, ad, ad_len, &data);
    memcpy(out + plaintext_len, data.out.tag, 16);
}

// Legacy function for backward compatibility (no AD)
void aead_seal(
    uint8_t *out,
    const uint8_t *key,
    uint64_t nonce,
    const uint8_t *plaintext,
    size_t plaintext_len
) {
    aead_seal_with_ad(out, key, nonce, plaintext, plaintext_len, NULL, 0);
}

int aead_open_with_ad(
    uint8_t *out,
    const uint8_t *key,
    uint64_t nonce,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *ad,
    size_t ad_len
) {
    if (ciphertext_len < 16) return -1;
    size_t plaintext_len = ciphertext_len - 16;
    
    union open_data data __attribute__((aligned(16)));
    memset(&data, 0, sizeof(data));
    
    for (int i = 0; i < 8; i++) {
        data.input.key[i] = ((uint32_t)key[i*4]) |
                           ((uint32_t)key[i*4+1] << 8) |
                           ((uint32_t)key[i*4+2] << 16) |
                           ((uint32_t)key[i*4+3] << 24);
    }
    data.input.counter = 0;
    memcpy(data.input.nonce, &nonce, 8);
    
    chacha20_poly1305_open(out, ciphertext, plaintext_len, ad, ad_len, &data);
    
    // Constant-time tag comparison
    const uint8_t *expected_tag = ciphertext + plaintext_len;
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= data.out.tag[i] ^ expected_tag[i];
    }
    
    return (diff == 0) ? 0 : -1;
}

// Legacy function for backward compatibility (no AD)
int aead_open(
    uint8_t *out,
    const uint8_t *key,
    uint64_t nonce,
    const uint8_t *ciphertext,
    size_t ciphertext_len
) {
    return aead_open_with_ad(out, key, nonce, ciphertext, ciphertext_len, NULL, 0);
}
