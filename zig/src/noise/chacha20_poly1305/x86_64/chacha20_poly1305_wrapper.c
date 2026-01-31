// x86_64 ChaCha20-Poly1305 wrapper
// Provides simple aead_seal/aead_open interface for Zig

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <cpuid.h>

// Input structure for seal (must match ring's layout exactly)
struct seal_data_in {
    uint32_t key[8];              // 32 bytes
    uint32_t counter;             // 4 bytes  
    uint8_t nonce[12];            // 12 bytes
    const uint8_t *extra_ciphertext;
    size_t extra_ciphertext_len;
} __attribute__((aligned(16)));

// Input structure for open
struct open_data_in {
    uint32_t key[8];
    uint32_t counter;
    uint8_t nonce[12];
} __attribute__((aligned(16)));

// Output structure
struct data_out {
    uint8_t tag[16];
} __attribute__((aligned(16)));

// Union for seal
union seal_data {
    struct seal_data_in input;
    struct data_out out;
} __attribute__((aligned(16)));

// Union for open
union open_data {
    struct open_data_in input;
    struct data_out out;
} __attribute__((aligned(16)));

// ASM functions from chacha20_poly1305_x86_64.S
extern void chacha20_poly1305_seal_avx2(
    uint8_t *out, const uint8_t *in, size_t len,
    const uint8_t *ad, size_t ad_len, union seal_data *data);
extern void chacha20_poly1305_open_avx2(
    uint8_t *out, const uint8_t *in, size_t len,
    const uint8_t *ad, size_t ad_len, union open_data *data);
extern void chacha20_poly1305_seal_sse41(
    uint8_t *out, const uint8_t *in, size_t len,
    const uint8_t *ad, size_t ad_len, union seal_data *data);
extern void chacha20_poly1305_open_sse41(
    uint8_t *out, const uint8_t *in, size_t len,
    const uint8_t *ad, size_t ad_len, union open_data *data);

// Check CPU features
static int has_avx2_bmi2(void) {
    unsigned int eax, ebx, ecx, edx;
    // Check for AVX2 and BMI2
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        int avx2 = (ebx >> 5) & 1;   // AVX2
        int bmi2 = (ebx >> 8) & 1;   // BMI2
        return avx2 && bmi2;
    }
    return 0;
}

// Cached CPU feature detection
static int cpu_has_avx2 = -1;

static inline int use_avx2(void) {
    if (cpu_has_avx2 < 0) {
        cpu_has_avx2 = has_avx2_bmi2();
    }
    return cpu_has_avx2;
}

// AEAD seal with AD (encrypt)
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
    
    // Copy key as little-endian u32 words
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
    
    if (use_avx2()) {
        chacha20_poly1305_seal_avx2(out, plaintext, plaintext_len, ad, ad_len, &data);
    } else {
        chacha20_poly1305_seal_sse41(out, plaintext, plaintext_len, ad, ad_len, &data);
    }
    
    // Append tag
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

// AEAD open with AD (decrypt)
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
    
    if (use_avx2()) {
        chacha20_poly1305_open_avx2(out, ciphertext, plaintext_len, ad, ad_len, &data);
    } else {
        chacha20_poly1305_open_sse41(out, ciphertext, plaintext_len, ad, ad_len, &data);
    }
    
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
