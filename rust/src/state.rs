//! CipherState and SymmetricState for Noise Protocol.

use crate::cipher::{self, Hash, HASH_SIZE, TAG_SIZE};
use crate::keypair::{Key, KEY_SIZE};
use ring::aead::{self, LessSafeKey, UnboundKey, Nonce, Aad, CHACHA20_POLY1305};

/// Manages encryption for one direction of communication.
pub struct CipherState {
    key: Key,
    nonce: u64,
    cipher: LessSafeKey,
}

impl CipherState {
    /// Creates a new CipherState with the given key.
    pub fn new(key: Key) -> Self {
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key.as_bytes())
            .expect("valid key size");
        let cipher = LessSafeKey::new(unbound_key);
        Self {
            key,
            nonce: 0,
            cipher,
        }
    }

    /// Creates a nonce from current counter.
    fn make_nonce(&self) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&self.nonce.to_le_bytes());
        Nonce::assume_unique_for_key(nonce_bytes)
    }

    /// Encrypts plaintext and increments nonce.
    pub fn encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(plaintext.len() + TAG_SIZE);
        buffer.extend_from_slice(plaintext);
        self.encrypt_in_place(&mut buffer, ad);
        buffer
    }

    /// Encrypts plaintext in place (appends tag) and increments nonce.
    pub fn encrypt_in_place(&mut self, buffer: &mut Vec<u8>, ad: &[u8]) {
        let nonce = self.make_nonce();
        self.nonce += 1;
        
        self.cipher.seal_in_place_append_tag(nonce, Aad::from(ad), buffer)
            .expect("encryption failed");
    }

    /// Encrypts plaintext to output buffer (no allocation).
    /// Output buffer must be at least plaintext.len() + 16.
    pub fn encrypt_to(&mut self, plaintext: &[u8], ad: &[u8], out: &mut [u8]) {
        let pt_len = plaintext.len();
        out[..pt_len].copy_from_slice(plaintext);
        
        let nonce = self.make_nonce();
        self.nonce += 1;
        
        let tag = self.cipher.seal_in_place_separate_tag(nonce, Aad::from(ad), &mut out[..pt_len])
            .expect("encryption failed");
        out[pt_len..pt_len + TAG_SIZE].copy_from_slice(tag.as_ref());
    }

    /// Decrypts ciphertext and increments nonce.
    pub fn decrypt(&mut self, ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>, cipher::DecryptError> {
        let mut buffer = ciphertext.to_vec();
        self.decrypt_in_place(&mut buffer, ad)?;
        Ok(buffer)
    }

    /// Decrypts ciphertext in place and increments nonce.
    pub fn decrypt_in_place(&mut self, buffer: &mut Vec<u8>, ad: &[u8]) -> Result<(), cipher::DecryptError> {
        let nonce = self.make_nonce();
        self.nonce += 1;
        
        let plaintext = self.cipher.open_in_place(nonce, Aad::from(ad), buffer)
            .map_err(|_| cipher::DecryptError)?;
        let len = plaintext.len();
        buffer.truncate(len);
        Ok(())
    }

    /// Decrypts ciphertext to output buffer (no allocation).
    /// Output buffer must be at least ciphertext.len() - 16.
    pub fn decrypt_to(&mut self, ciphertext: &[u8], ad: &[u8], out: &mut [u8]) -> Result<usize, cipher::DecryptError> {
        let ct_len = ciphertext.len();
        if ct_len < TAG_SIZE {
            return Err(cipher::DecryptError);
        }
        
        out[..ct_len].copy_from_slice(ciphertext);
        
        let nonce = self.make_nonce();
        self.nonce += 1;
        
        let plaintext = self.cipher.open_in_place(nonce, Aad::from(ad), &mut out[..ct_len])
            .map_err(|_| cipher::DecryptError)?;
        Ok(plaintext.len())
    }

    /// Returns current nonce value.
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Sets nonce value (for testing).
    pub fn set_nonce(&mut self, n: u64) {
        self.nonce = n;
        // Need to recreate cipher with same key since ring doesn't allow nonce reuse
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, self.key.as_bytes())
            .expect("valid key size");
        self.cipher = LessSafeKey::new(unbound_key);
    }

    /// Returns the key.
    pub fn key(&self) -> &Key {
        &self.key
    }
}

/// Holds the evolving state during a Noise handshake.
pub struct SymmetricState {
    chaining_key: Key,
    hash: Hash,
}

impl SymmetricState {
    /// Creates a new SymmetricState with the protocol name.
    pub fn new(protocol_name: &str) -> Self {
        let mut chaining_key = [0u8; KEY_SIZE];
        
        if protocol_name.len() <= HASH_SIZE {
            chaining_key[..protocol_name.len()].copy_from_slice(protocol_name.as_bytes());
        } else {
            chaining_key = cipher::hash(&[protocol_name.as_bytes()]);
        }
        
        Self {
            chaining_key: Key::new(chaining_key),
            hash: chaining_key,
        }
    }

    /// Mixes input into the chaining key.
    /// Returns the derived key.
    pub fn mix_key(&mut self, input: &[u8]) -> Key {
        let (new_ck, k) = cipher::kdf2(&self.chaining_key, input);
        self.chaining_key = new_ck;
        k
    }

    /// Mixes data into the hash.
    pub fn mix_hash(&mut self, data: &[u8]) {
        self.hash = cipher::hash(&[&self.hash, data]);
    }

    /// Mixes input into both chaining key and hash (for PSK).
    pub fn mix_key_and_hash(&mut self, input: &[u8]) -> Key {
        let (ck, temp, k) = cipher::kdf3(&self.chaining_key, input);
        self.chaining_key = ck;
        self.mix_hash(temp.as_bytes());
        k
    }

    /// Encrypts plaintext and updates hash.
    pub fn encrypt_and_hash(&mut self, key: &Key, plaintext: &[u8]) -> Vec<u8> {
        let ciphertext = cipher::encrypt_with_ad(key, &self.hash, plaintext);
        self.mix_hash(&ciphertext);
        ciphertext
    }

    /// Decrypts ciphertext and updates hash.
    pub fn decrypt_and_hash(&mut self, key: &Key, ciphertext: &[u8]) -> Result<Vec<u8>, cipher::DecryptError> {
        let plaintext = cipher::decrypt_with_ad(key, &self.hash, ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    /// Splits into two CipherStates for transport.
    pub fn split(&self) -> (CipherState, CipherState) {
        let keys = cipher::hkdf(&self.chaining_key, &[], 2);
        (CipherState::new(keys[0].clone()), CipherState::new(keys[1].clone()))
    }

    /// Returns the current chaining key.
    pub fn chaining_key(&self) -> &Key {
        &self.chaining_key
    }

    /// Returns the current hash.
    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    /// Clones the state.
    pub fn clone(&self) -> Self {
        Self {
            chaining_key: self.chaining_key.clone(),
            hash: self.hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_state_new() {
        let key = Key::new([42u8; KEY_SIZE]);
        let cs = CipherState::new(key.clone());
        assert_eq!(cs.nonce(), 0);
        assert_eq!(cs.key(), &key);
    }

    #[test]
    fn test_cipher_state_encrypt_decrypt() {
        let key = Key::new([42u8; KEY_SIZE]);
        let mut cs1 = CipherState::new(key.clone());
        let mut cs2 = CipherState::new(key);

        let plaintext = b"hello, world!";
        let ct = cs1.encrypt(plaintext, &[]);
        assert_eq!(cs1.nonce(), 1);

        let pt = cs2.decrypt(&ct, &[]).unwrap();
        assert_eq!(cs2.nonce(), 1);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_cipher_state_nonce_increment() {
        let key = Key::new([0u8; KEY_SIZE]);
        let mut cs = CipherState::new(key);

        for i in 0..10 {
            assert_eq!(cs.nonce(), i);
            cs.encrypt(b"test", &[]);
        }
    }

    #[test]
    fn test_cipher_state_set_nonce() {
        let key = Key::new([0u8; KEY_SIZE]);
        let mut cs = CipherState::new(key);
        cs.set_nonce(100);
        assert_eq!(cs.nonce(), 100);
    }

    #[test]
    fn test_cipher_state_wrong_nonce() {
        let key = Key::new([0u8; KEY_SIZE]);
        let mut cs1 = CipherState::new(key.clone());
        let mut cs2 = CipherState::new(key);

        let ct = cs1.encrypt(b"test", &[]);
        cs2.set_nonce(5); // Wrong nonce
        assert!(cs2.decrypt(&ct, &[]).is_err());
    }

    #[test]
    fn test_symmetric_state_new() {
        // Short name
        let ss1 = SymmetricState::new("Noise_IK");
        assert!(!ss1.chaining_key().is_zero());

        // Long name
        let ss2 = SymmetricState::new("Noise_IK_25519_ChaChaPoly_BLAKE2s");
        assert!(!ss2.chaining_key().is_zero());
    }

    #[test]
    fn test_symmetric_state_mix_hash() {
        let mut ss = SymmetricState::new("Test");
        let initial = *ss.hash();
        ss.mix_hash(b"data");
        assert_ne!(*ss.hash(), initial);
    }

    #[test]
    fn test_symmetric_state_mix_key() {
        let mut ss = SymmetricState::new("Test");
        let initial = ss.chaining_key().clone();
        let k = ss.mix_key(b"input");
        assert_ne!(ss.chaining_key(), &initial);
        assert!(!k.is_zero());
    }

    #[test]
    fn test_symmetric_state_mix_key_and_hash() {
        let mut ss = SymmetricState::new("Test");
        let initial_ck = ss.chaining_key().clone();
        let initial_h = *ss.hash();
        
        let k = ss.mix_key_and_hash(b"input");
        
        assert_ne!(ss.chaining_key(), &initial_ck);
        assert_ne!(ss.hash(), &initial_h);
        assert!(!k.is_zero());
    }

    #[test]
    fn test_symmetric_state_encrypt_decrypt_and_hash() {
        let mut ss1 = SymmetricState::new("Test");
        let mut ss2 = SymmetricState::new("Test");

        let k1 = ss1.mix_key(b"key");
        let k2 = ss2.mix_key(b"key");
        assert_eq!(k1, k2);

        let plaintext = b"secret message";
        let ct = ss1.encrypt_and_hash(&k1, plaintext);
        let pt = ss2.decrypt_and_hash(&k2, &ct).unwrap();

        assert_eq!(pt, plaintext);
        assert_eq!(ss1.hash(), ss2.hash());
    }

    #[test]
    fn test_symmetric_state_split() {
        let mut ss = SymmetricState::new("Test");
        ss.mix_key(b"input");

        let (cs1, cs2) = ss.split();
        assert_ne!(cs1.key(), cs2.key());
    }

    #[test]
    fn test_symmetric_state_clone() {
        let mut ss = SymmetricState::new("Test");
        ss.mix_hash(b"data");
        
        let cloned = ss.clone();
        assert_eq!(ss.chaining_key(), cloned.chaining_key());
        assert_eq!(ss.hash(), cloned.hash());

        ss.mix_hash(b"more");
        assert_ne!(ss.hash(), cloned.hash());
    }

    #[test]
    fn test_encrypt_to_decrypt_to() {
        let key = Key::new([42u8; KEY_SIZE]);
        let mut cs1 = CipherState::new(key.clone());
        let mut cs2 = CipherState::new(key);

        let plaintext = b"hello, world!";
        let mut ct_buf = [0u8; 13 + 16];
        let mut pt_buf = [0u8; 13 + 16];

        cs1.encrypt_to(plaintext, &[], &mut ct_buf);
        let pt_len = cs2.decrypt_to(&ct_buf, &[], &mut pt_buf).unwrap();

        assert_eq!(&pt_buf[..pt_len], plaintext);
    }
}
