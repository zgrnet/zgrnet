// OpenSSL ChaCha20-Poly1305 wrapper for Zig
// This provides the same aead_seal/aead_open interface using OpenSSL EVP API

#include <openssl/evp.h>
#include <string.h>
#include <stdint.h>

// AEAD seal (encrypt) using OpenSSL EVP
void aead_seal(
    uint8_t *out,           // output: ciphertext + tag (plaintext_len + 16 bytes)
    const uint8_t *key,     // 32-byte key
    uint64_t nonce,         // 64-bit nonce (will be zero-padded to 96 bits)
    const uint8_t *plaintext,
    size_t plaintext_len
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    
    // Build 96-bit nonce: 32-bit zero + 64-bit nonce (little-endian)
    uint8_t nonce_bytes[12] = {0};
    memcpy(nonce_bytes, &nonce, 8);  // little-endian
    
    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce_bytes);
    
    int outlen;
    EVP_EncryptUpdate(ctx, out, &outlen, plaintext, (int)plaintext_len);
    EVP_EncryptFinal_ex(ctx, out + outlen, &outlen);
    
    // Get tag and append to output
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, out + plaintext_len);
    
    EVP_CIPHER_CTX_free(ctx);
}

// AEAD open (decrypt) using OpenSSL EVP
// Returns 0 on success, -1 on failure (tag mismatch)
int aead_open(
    uint8_t *out,           // output: plaintext
    const uint8_t *key,     // 32-byte key  
    uint64_t nonce,         // 64-bit nonce
    const uint8_t *ciphertext,  // ciphertext + tag
    size_t ciphertext_len       // includes 16-byte tag
) {
    if (ciphertext_len < 16) return -1;
    size_t plaintext_len = ciphertext_len - 16;
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    
    // Build 96-bit nonce
    uint8_t nonce_bytes[12] = {0};
    memcpy(nonce_bytes, &nonce, 8);
    
    EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce_bytes);
    
    int outlen;
    EVP_DecryptUpdate(ctx, out, &outlen, ciphertext, (int)plaintext_len);
    
    // Set expected tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)(ciphertext + plaintext_len));
    
    // Verify tag
    int ret = EVP_DecryptFinal_ex(ctx, out + outlen, &outlen);
    
    EVP_CIPHER_CTX_free(ctx);
    
    return (ret > 0) ? 0 : -1;
}
