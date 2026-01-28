//! Cryptographic primitives: BLAKE2s, HKDF, ChaCha20-Poly1305.

use blake2::{Blake2s256, Blake2sMac, Digest};
use blake2::digest::{Mac, KeyInit};
use ring::aead::{self, LessSafeKey, UnboundKey, Nonce, Aad, CHACHA20_POLY1305};
use crate::keypair::Key;

/// Hash output size (BLAKE2s-256).
pub const HASH_SIZE: usize = 32;

/// AEAD tag size (Poly1305).
pub const TAG_SIZE: usize = 16;

/// A 32-byte hash output.
pub type Hash = [u8; HASH_SIZE];

/// Computes BLAKE2s-256 hash.
pub fn hash(data: &[&[u8]]) -> Hash {
    let mut hasher = Blake2s256::new();
    for d in data {
        hasher.update(d);
    }
    hasher.finalize().into()
}

/// Computes BLAKE2s-128 MAC (for mac1/mac2).
pub fn mac(key: &[u8], data: &[&[u8]]) -> [u8; 16] {
    let mut m = <Blake2sMac::<blake2::digest::consts::U16> as KeyInit>::new_from_slice(key)
        .expect("valid key size");
    for d in data {
        Mac::update(&mut m, d);
    }
    m.finalize().into_bytes().into()
}

/// Computes HMAC-BLAKE2s-256.
pub fn hmac(key: &Hash, data: &[&[u8]]) -> Hash {
    // HMAC(K, m) = H((K ^ opad) || H((K ^ ipad) || m))
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    
    for i in 0..HASH_SIZE {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    
    // Inner hash
    let mut inner = Blake2s256::new();
    inner.update(&ipad);
    for d in data {
        inner.update(d);
    }
    let inner_result: Hash = inner.finalize().into();
    
    // Outer hash
    let mut outer = Blake2s256::new();
    outer.update(&opad);
    outer.update(&inner_result);
    outer.finalize().into()
}

/// HKDF with BLAKE2s.
/// Derives `num_outputs` keys (1-3) from chaining key and input.
pub fn hkdf(chaining_key: &Key, input: &[u8], num_outputs: usize) -> Vec<Key> {
    assert!(num_outputs >= 1 && num_outputs <= 3, "num_outputs must be 1-3");
    
    // Extract: secret = HMAC(ck, input)
    let secret = hmac(chaining_key.as_bytes(), &[input]);
    
    let mut outputs = Vec::with_capacity(num_outputs);
    
    // output1 = HMAC(secret, 0x01)
    let out1 = hmac(&secret, &[&[0x01]]);
    outputs.push(Key::new(out1));
    
    if num_outputs >= 2 {
        // output2 = HMAC(secret, output1 || 0x02)
        let out2 = hmac(&secret, &[&out1, &[0x02]]);
        outputs.push(Key::new(out2));
    }
    
    if num_outputs >= 3 {
        // output3 = HMAC(secret, output2 || 0x03)
        let out3 = hmac(&secret, &[outputs[1].as_bytes(), &[0x03]]);
        outputs.push(Key::new(out3));
    }
    
    outputs
}

/// Derives two keys from chaining key and input.
pub fn kdf2(chaining_key: &Key, input: &[u8]) -> (Key, Key) {
    let keys = hkdf(chaining_key, input, 2);
    (keys[0].clone(), keys[1].clone())
}

/// Derives three keys from chaining key and input.
pub fn kdf3(chaining_key: &Key, input: &[u8]) -> (Key, Key, Key) {
    let keys = hkdf(chaining_key, input, 3);
    (keys[0].clone(), keys[1].clone(), keys[2].clone())
}

/// Creates a nonce from u64 counter.
fn make_nonce(counter: u64) -> Nonce {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..8].copy_from_slice(&counter.to_le_bytes());
    Nonce::assume_unique_for_key(nonce_bytes)
}

/// Encrypts plaintext with ChaCha20-Poly1305.
pub fn encrypt(key: &[u8], nonce: u64, plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
    let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key).expect("valid key size");
    let sealing_key = LessSafeKey::new(unbound_key);
    
    let mut out = Vec::with_capacity(plaintext.len() + TAG_SIZE);
    out.extend_from_slice(plaintext);
    
    sealing_key.seal_in_place_append_tag(make_nonce(nonce), Aad::from(ad), &mut out)
        .expect("encryption failed");
    out
}

/// Encrypts plaintext in place, appending tag.
pub fn encrypt_in_place(key: &[u8], nonce: u64, buffer: &mut Vec<u8>, ad: &[u8]) {
    let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key).expect("valid key size");
    let sealing_key = LessSafeKey::new(unbound_key);
    
    sealing_key.seal_in_place_append_tag(make_nonce(nonce), Aad::from(ad), buffer)
        .expect("encryption failed");
}

/// Decrypts ciphertext with ChaCha20-Poly1305.
pub fn decrypt(key: &[u8], nonce: u64, ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>, DecryptError> {
    let mut buffer = ciphertext.to_vec();
    decrypt_in_place(key, nonce, &mut buffer, ad)?;
    Ok(buffer)
}

/// Decrypts ciphertext in place.
pub fn decrypt_in_place(key: &[u8], nonce: u64, buffer: &mut Vec<u8>, ad: &[u8]) -> Result<(), DecryptError> {
    let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| DecryptError)?;
    let opening_key = LessSafeKey::new(unbound_key);
    
    let plaintext = opening_key.open_in_place(make_nonce(nonce), Aad::from(ad), buffer)
        .map_err(|_| DecryptError)?;
    let len = plaintext.len();
    buffer.truncate(len);
    Ok(())
}

/// Encrypts with zero nonce (for handshake).
pub fn encrypt_with_ad(key: &Key, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    encrypt(key.as_bytes(), 0, plaintext, ad)
}

/// Decrypts with zero nonce (for handshake).
pub fn decrypt_with_ad(key: &Key, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, DecryptError> {
    decrypt(key.as_bytes(), 0, ciphertext, ad)
}

/// Decryption error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecryptError;

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "decryption failed")
    }
}

impl std::error::Error for DecryptError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::KEY_SIZE;

    #[test]
    fn test_hash() {
        let h1 = hash(&[b"hello"]);
        let h2 = hash(&[b"hello"]);
        assert_eq!(h1, h2);

        let h3 = hash(&[b"world"]);
        assert_ne!(h1, h3);

        // Concatenation
        let h4 = hash(&[b"hello", b"world"]);
        let h5 = hash(&[b"helloworld"]);
        assert_eq!(h4, h5);
    }

    #[test]
    fn test_mac() {
        let key = [0u8; 32];
        let m1 = mac(&key, &[b"message"]);
        let m2 = mac(&key, &[b"message"]);
        assert_eq!(m1, m2);

        let m3 = mac(&key, &[b"different"]);
        assert_ne!(m1, m3);
    }

    #[test]
    fn test_hmac() {
        let key = [0u8; HASH_SIZE];
        let h1 = hmac(&key, &[b"data"]);
        let h2 = hmac(&key, &[b"data"]);
        assert_eq!(h1, h2);

        let h3 = hmac(&key, &[b"different"]);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_hkdf() {
        let ck = Key::default();
        
        let keys1 = hkdf(&ck, b"input", 1);
        assert_eq!(keys1.len(), 1);
        assert!(!keys1[0].is_zero());

        let keys2 = hkdf(&ck, b"input", 2);
        assert_eq!(keys2.len(), 2);
        assert_eq!(keys2[0], keys1[0]);
        assert_ne!(keys2[0], keys2[1]);

        let keys3 = hkdf(&ck, b"input", 3);
        assert_eq!(keys3.len(), 3);
        assert_eq!(keys3[0], keys2[0]);
        assert_eq!(keys3[1], keys2[1]);
    }

    #[test]
    #[should_panic]
    fn test_hkdf_panic_zero() {
        let ck = Key::default();
        hkdf(&ck, b"input", 0);
    }

    #[test]
    #[should_panic]
    fn test_hkdf_panic_four() {
        let ck = Key::default();
        hkdf(&ck, b"input", 4);
    }

    #[test]
    fn test_kdf2() {
        let ck = Key::default();
        let (k1, k2) = kdf2(&ck, b"input");
        assert!(!k1.is_zero());
        assert!(!k2.is_zero());
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_kdf3() {
        let ck = Key::default();
        let (k1, k2, k3) = kdf3(&ck, b"input");
        assert_ne!(k1, k2);
        assert_ne!(k2, k3);
        assert_ne!(k1, k3);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 32];
        let plaintext = b"hello, world!";
        let ad = b"additional data";

        let ciphertext = encrypt(&key, 0, plaintext, ad);
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);

        let decrypted = decrypt(&key, 0, &ciphertext, ad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_different_nonces() {
        let key = [0u8; 32];
        let plaintext = b"hello";

        let ct1 = encrypt(&key, 0, plaintext, &[]);
        let ct2 = encrypt(&key, 1, plaintext, &[]);
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        key2[0] = 1;

        let ct = encrypt(&key1, 0, b"secret", &[]);
        assert!(decrypt(&key2, 0, &ct, &[]).is_err());
    }

    #[test]
    fn test_decrypt_wrong_ad() {
        let key = [0u8; 32];
        let ct = encrypt(&key, 0, b"secret", b"ad1");
        assert!(decrypt(&key, 0, &ct, b"ad2").is_err());
    }

    #[test]
    fn test_encrypt_decrypt_with_ad() {
        let key = Key::new([42u8; KEY_SIZE]);
        let plaintext = b"hello";
        let ad = b"ad";

        let ct = encrypt_with_ad(&key, ad, plaintext);
        let pt = decrypt_with_ad(&key, ad, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }
}
