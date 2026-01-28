#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>

int main() {
    unsigned char key[32] = {0};
    unsigned char nonce[12] = {0};
    unsigned char plaintext[1024] = {0};
    unsigned char ciphertext[1024 + 16];
    size_t clen;

    EVP_AEAD_CTX *ctx = EVP_AEAD_CTX_new(EVP_aead_chacha20_poly1305(), key, 32, 16);
    if (!ctx) {
        printf("Failed to create AEAD context\n");
        return 1;
    }

    // Warmup
    for (int i = 0; i < 100000; i++) {
        nonce[0] = i & 0xff;
        nonce[1] = (i >> 8) & 0xff;
        EVP_AEAD_CTX_seal(ctx, ciphertext, &clen, sizeof(ciphertext),
                          nonce, 12, plaintext, 1024, NULL, 0);
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int iterations = 1000000;
    for (int i = 0; i < iterations; i++) {
        nonce[0] = i & 0xff;
        nonce[1] = (i >> 8) & 0xff;
        EVP_AEAD_CTX_seal(ctx, ciphertext, &clen, sizeof(ciphertext),
                          nonce, 12, plaintext, 1024, NULL, 0);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    EVP_AEAD_CTX_free(ctx);

    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double per_op_ns = elapsed * 1e9 / iterations;
    double throughput_gbps = (1024.0 * 8.0 * iterations) / elapsed / 1e9;

    printf("boringssl encrypt_1kb: %.0f ns/op (%.2f Gbps)\n", per_op_ns, throughput_gbps);
    return 0;
}
