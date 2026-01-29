//! Noise handshake patterns (IK, XX, NN).

use crate::cipher::{HASH_SIZE, TAG_SIZE};
use crate::keypair::{Key, KeyPair, KEY_SIZE};
use crate::state::{CipherState, SymmetricState};
use thiserror::Error;

/// Handshake pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pattern {
    /// IK: Initiator knows responder's static key.
    /// <- s
    /// -> e, es, s, ss
    /// <- e, ee, se
    IK,
    /// XX: Mutual authentication, no prior knowledge.
    /// -> e
    /// <- e, ee, s, es
    /// -> s, se
    XX,
    /// NN: No authentication.
    /// -> e
    /// <- e, ee
    NN,
}

impl Pattern {
    fn responder_pre_message(&self) -> &'static [Token] {
        match self {
            Pattern::IK => &[Token::S],
            Pattern::XX | Pattern::NN => &[],
        }
    }

    fn message_patterns(&self) -> &'static [&'static [Token]] {
        match self {
            Pattern::IK => &[
                &[Token::E, Token::ES, Token::S, Token::SS],
                &[Token::E, Token::EE, Token::SE],
            ],
            Pattern::XX => &[
                &[Token::E],
                &[Token::E, Token::EE, Token::S, Token::ES],
                &[Token::S, Token::SE],
            ],
            Pattern::NN => &[
                &[Token::E],
                &[Token::E, Token::EE],
            ],
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Pattern::IK => "IK",
            Pattern::XX => "XX",
            Pattern::NN => "NN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token {
    E,  // ephemeral
    S,  // static
    EE, // DH(e, re)
    ES, // DH(e, rs) or DH(s, re)
    SE, // DH(s, re) or DH(e, rs)
    SS, // DH(s, rs)
}

/// Handshake configuration.
#[derive(Default)]
pub struct Config {
    /// Handshake pattern.
    pub pattern: Option<Pattern>,
    /// True if this side initiates.
    pub initiator: bool,
    /// Local static key pair.
    pub local_static: Option<KeyPair>,
    /// Remote static public key.
    pub remote_static: Option<Key>,
    /// Optional prologue.
    pub prologue: Vec<u8>,
    /// Optional preshared key.
    pub preshared_key: Option<Key>,
}

/// Handshake errors.
#[derive(Debug, Error)]
pub enum Error {
    #[error("handshake already finished")]
    Finished,
    #[error("handshake not ready to split")]
    NotReady,
    #[error("invalid handshake message")]
    InvalidMessage,
    #[error("missing local static key")]
    MissingLocalStatic,
    #[error("missing remote static key")]
    MissingRemoteStatic,
    #[error("missing pattern")]
    MissingPattern,
    #[error("not our turn to write")]
    NotOurTurn,
    #[error("decryption failed")]
    Decryption,
    #[error("DH failed")]
    DhFailed,
}

/// Manages the state of a Noise handshake.
pub struct HandshakeState {
    pattern: Pattern,
    initiator: bool,
    local_static: Option<KeyPair>,
    remote_static: Key,
    preshared_key: Option<Key>,
    ss: SymmetricState,
    local_ephemeral: Option<KeyPair>,
    remote_ephemeral: Key,
    msg_index: usize,
    finished: bool,
}

impl HandshakeState {
    /// Creates a new handshake state.
    pub fn new(config: Config) -> Result<Self, Error> {
        let pattern = config.pattern.ok_or(Error::MissingPattern)?;
        
        // Validate config
        Self::validate_config(&config, pattern)?;
        
        // Build protocol name
        let protocol_name = format!("Noise_{}_25519_ChaChaPoly_BLAKE2s", pattern.name());
        let mut ss = SymmetricState::new(&protocol_name);
        
        // Mix prologue
        ss.mix_hash(&config.prologue);
        
        let mut remote_static = Key::default();
        
        // Process pre-messages
        if config.initiator {
            // Initiator processes responder's pre-message
            for token in pattern.responder_pre_message() {
                if *token == Token::S {
                    let rs = config.remote_static.as_ref().ok_or(Error::MissingRemoteStatic)?;
                    ss.mix_hash(rs.as_bytes());
                    remote_static = *rs;
                }
            }
        } else {
            // Responder processes own pre-message
            for token in pattern.responder_pre_message() {
                if *token == Token::S {
                    let ls = config.local_static.as_ref().ok_or(Error::MissingLocalStatic)?;
                    ss.mix_hash(ls.public.as_bytes());
                }
            }
        }
        
        Ok(Self {
            pattern,
            initiator: config.initiator,
            local_static: config.local_static,
            remote_static,
            preshared_key: config.preshared_key,
            ss,
            local_ephemeral: None,
            remote_ephemeral: Key::default(),
            msg_index: 0,
            finished: false,
        })
    }

    fn validate_config(config: &Config, pattern: Pattern) -> Result<(), Error> {
        // Check if local static is needed
        let needs_local_static = matches!(pattern, Pattern::IK | Pattern::XX);
        if needs_local_static && config.local_static.is_none() {
            return Err(Error::MissingLocalStatic);
        }

        // IK initiator needs remote static
        if pattern == Pattern::IK && config.initiator && config.remote_static.is_none() {
            return Err(Error::MissingRemoteStatic);
        }

        Ok(())
    }

    /// Generates the next handshake message.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        if self.finished {
            return Err(Error::Finished);
        }

        #[allow(clippy::manual_is_multiple_of)]
        let my_turn = (self.initiator && self.msg_index % 2 == 0)
            || (!self.initiator && self.msg_index % 2 == 1);
        if !my_turn {
            return Err(Error::NotOurTurn);
        }

        let patterns = self.pattern.message_patterns();
        if self.msg_index >= patterns.len() {
            return Err(Error::Finished);
        }

        let tokens = patterns[self.msg_index];
        let mut msg = Vec::new();

        for token in tokens {
            match token {
                Token::E => {
                    let ephemeral = KeyPair::generate();
                    msg.extend_from_slice(ephemeral.public.as_bytes());
                    self.ss.mix_hash(ephemeral.public.as_bytes());
                    if self.preshared_key.is_some() {
                        self.ss.mix_key(ephemeral.public.as_bytes());
                    }
                    self.local_ephemeral = Some(ephemeral);
                }
                Token::S => {
                    let ls = self.local_static.as_ref().ok_or(Error::MissingLocalStatic)?;
                    let k = self.ss.mix_key(&[]);
                    let encrypted = self.ss.encrypt_and_hash(&k, ls.public.as_bytes());
                    msg.extend_from_slice(&encrypted);
                }
                Token::EE => {
                    let le = self.local_ephemeral.as_ref().ok_or(Error::InvalidMessage)?;
                    let shared = le.dh(&self.remote_ephemeral).map_err(|_| Error::DhFailed)?;
                    self.ss.mix_key(shared.as_bytes());
                }
                Token::ES => {
                    let shared = if self.initiator {
                        let le = self.local_ephemeral.as_ref().ok_or(Error::InvalidMessage)?;
                        le.dh(&self.remote_static).map_err(|_| Error::DhFailed)?
                    } else {
                        let ls = self.local_static.as_ref().ok_or(Error::MissingLocalStatic)?;
                        ls.dh(&self.remote_ephemeral).map_err(|_| Error::DhFailed)?
                    };
                    self.ss.mix_key(shared.as_bytes());
                }
                Token::SE => {
                    let shared = if self.initiator {
                        let ls = self.local_static.as_ref().ok_or(Error::MissingLocalStatic)?;
                        ls.dh(&self.remote_ephemeral).map_err(|_| Error::DhFailed)?
                    } else {
                        let le = self.local_ephemeral.as_ref().ok_or(Error::InvalidMessage)?;
                        le.dh(&self.remote_static).map_err(|_| Error::DhFailed)?
                    };
                    self.ss.mix_key(shared.as_bytes());
                }
                Token::SS => {
                    let ls = self.local_static.as_ref().ok_or(Error::MissingLocalStatic)?;
                    let shared = ls.dh(&self.remote_static).map_err(|_| Error::DhFailed)?;
                    self.ss.mix_key(shared.as_bytes());
                }
            }
        }

        // Encrypt payload
        if !payload.is_empty() || self.msg_index == patterns.len() - 1 {
            let k = self.ss.mix_key(&[]);
            let encrypted = self.ss.encrypt_and_hash(&k, payload);
            msg.extend_from_slice(&encrypted);
        }

        self.msg_index += 1;
        if self.msg_index >= patterns.len() {
            self.finished = true;
        }

        Ok(msg)
    }

    /// Processes a received handshake message.
    pub fn read_message(&mut self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        if self.finished {
            return Err(Error::Finished);
        }

        #[allow(clippy::manual_is_multiple_of)]
        let my_turn = (self.initiator && self.msg_index % 2 == 0)
            || (!self.initiator && self.msg_index % 2 == 1);
        if my_turn {
            return Err(Error::NotOurTurn);
        }

        let patterns = self.pattern.message_patterns();
        if self.msg_index >= patterns.len() {
            return Err(Error::Finished);
        }

        let tokens = patterns[self.msg_index];
        let mut offset = 0;

        for token in tokens {
            match token {
                Token::E => {
                    if offset + KEY_SIZE > msg.len() {
                        return Err(Error::InvalidMessage);
                    }
                    let mut re = [0u8; KEY_SIZE];
                    re.copy_from_slice(&msg[offset..offset + KEY_SIZE]);
                    self.remote_ephemeral = Key::new(re);
                    offset += KEY_SIZE;
                    self.ss.mix_hash(self.remote_ephemeral.as_bytes());
                    if self.preshared_key.is_some() {
                        self.ss.mix_key(self.remote_ephemeral.as_bytes());
                    }
                }
                Token::S => {
                    let encrypted_len = KEY_SIZE + TAG_SIZE;
                    if offset + encrypted_len > msg.len() {
                        return Err(Error::InvalidMessage);
                    }
                    let k = self.ss.mix_key(&[]);
                    let decrypted = self.ss.decrypt_and_hash(&k, &msg[offset..offset + encrypted_len])
                        .map_err(|_| Error::Decryption)?;
                    let mut rs = [0u8; KEY_SIZE];
                    rs.copy_from_slice(&decrypted);
                    self.remote_static = Key::new(rs);
                    offset += encrypted_len;
                }
                Token::EE => {
                    let le = self.local_ephemeral.as_ref().ok_or(Error::InvalidMessage)?;
                    let shared = le.dh(&self.remote_ephemeral).map_err(|_| Error::DhFailed)?;
                    self.ss.mix_key(shared.as_bytes());
                }
                Token::ES => {
                    let shared = if self.initiator {
                        let le = self.local_ephemeral.as_ref().ok_or(Error::InvalidMessage)?;
                        le.dh(&self.remote_static).map_err(|_| Error::DhFailed)?
                    } else {
                        let ls = self.local_static.as_ref().ok_or(Error::MissingLocalStatic)?;
                        ls.dh(&self.remote_ephemeral).map_err(|_| Error::DhFailed)?
                    };
                    self.ss.mix_key(shared.as_bytes());
                }
                Token::SE => {
                    let shared = if self.initiator {
                        let ls = self.local_static.as_ref().ok_or(Error::MissingLocalStatic)?;
                        ls.dh(&self.remote_ephemeral).map_err(|_| Error::DhFailed)?
                    } else {
                        let le = self.local_ephemeral.as_ref().ok_or(Error::InvalidMessage)?;
                        le.dh(&self.remote_static).map_err(|_| Error::DhFailed)?
                    };
                    self.ss.mix_key(shared.as_bytes());
                }
                Token::SS => {
                    let ls = self.local_static.as_ref().ok_or(Error::MissingLocalStatic)?;
                    let shared = ls.dh(&self.remote_static).map_err(|_| Error::DhFailed)?;
                    self.ss.mix_key(shared.as_bytes());
                }
            }
        }

        // Decrypt payload
        let payload = if offset < msg.len() {
            let k = self.ss.mix_key(&[]);
            self.ss.decrypt_and_hash(&k, &msg[offset..])
                .map_err(|_| Error::Decryption)?
        } else {
            Vec::new()
        };

        self.msg_index += 1;
        if self.msg_index >= patterns.len() {
            self.finished = true;
        }

        Ok(payload)
    }

    /// Returns true if handshake is complete.
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Splits into transport CipherStates.
    pub fn split(&self) -> Result<(CipherState, CipherState), Error> {
        if !self.finished {
            return Err(Error::NotReady);
        }

        let (cs1, cs2) = self.ss.split();
        if self.initiator {
            Ok((cs1, cs2))
        } else {
            Ok((cs2, cs1))
        }
    }

    /// Returns the remote static public key.
    pub fn remote_static(&self) -> &Key {
        &self.remote_static
    }

    /// Returns the local ephemeral public key.
    /// Only valid after write_message has been called with 'e' token.
    pub fn local_ephemeral(&self) -> Option<Key> {
        self.local_ephemeral.as_ref().map(|kp| kp.public)
    }

    /// Returns the handshake hash.
    pub fn hash(&self) -> &[u8; HASH_SIZE] {
        self.ss.hash()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_ik() {
        let initiator_static = KeyPair::generate();
        let responder_static = KeyPair::generate();

        let mut initiator = HandshakeState::new(Config {
            pattern: Some(Pattern::IK),
            initiator: true,
            local_static: Some(initiator_static.clone()),
            remote_static: Some(responder_static.public.clone()),
            ..Default::default()
        }).unwrap();

        let mut responder = HandshakeState::new(Config {
            pattern: Some(Pattern::IK),
            initiator: false,
            local_static: Some(responder_static),
            ..Default::default()
        }).unwrap();

        // Message 1
        let msg1 = initiator.write_message(&[]).unwrap();
        responder.read_message(&msg1).unwrap();
        assert_eq!(responder.remote_static(), &initiator_static.public);

        // Message 2
        let msg2 = responder.write_message(&[]).unwrap();
        initiator.read_message(&msg2).unwrap();

        assert!(initiator.is_finished());
        assert!(responder.is_finished());

        // Test transport
        let (mut send_i, mut recv_i) = initiator.split().unwrap();
        let (mut send_r, mut recv_r) = responder.split().unwrap();

        let ct = send_i.encrypt(b"hello from initiator", &[]);
        let pt = recv_r.decrypt(&ct, &[]).unwrap();
        assert_eq!(pt, b"hello from initiator");

        let ct2 = send_r.encrypt(b"hello from responder", &[]);
        let pt2 = recv_i.decrypt(&ct2, &[]).unwrap();
        assert_eq!(pt2, b"hello from responder");
    }

    #[test]
    fn test_handshake_xx() {
        let initiator_static = KeyPair::generate();
        let responder_static = KeyPair::generate();

        let mut initiator = HandshakeState::new(Config {
            pattern: Some(Pattern::XX),
            initiator: true,
            local_static: Some(initiator_static.clone()),
            ..Default::default()
        }).unwrap();

        let mut responder = HandshakeState::new(Config {
            pattern: Some(Pattern::XX),
            initiator: false,
            local_static: Some(responder_static.clone()),
            ..Default::default()
        }).unwrap();

        // Message 1: -> e
        let msg1 = initiator.write_message(&[]).unwrap();
        responder.read_message(&msg1).unwrap();

        // Message 2: <- e, ee, s, es
        let msg2 = responder.write_message(&[]).unwrap();
        initiator.read_message(&msg2).unwrap();
        assert_eq!(initiator.remote_static(), &responder_static.public);

        // Message 3: -> s, se
        let msg3 = initiator.write_message(&[]).unwrap();
        responder.read_message(&msg3).unwrap();
        assert_eq!(responder.remote_static(), &initiator_static.public);

        assert!(initiator.is_finished());
        assert!(responder.is_finished());

        // Test transport
        let (mut send_i, mut recv_i) = initiator.split().unwrap();
        let (mut send_r, mut recv_r) = responder.split().unwrap();

        let ct = send_i.encrypt(b"XX test", &[]);
        let pt = recv_r.decrypt(&ct, &[]).unwrap();
        assert_eq!(pt, b"XX test");

        let ct2 = send_r.encrypt(b"XX reply", &[]);
        let pt2 = recv_i.decrypt(&ct2, &[]).unwrap();
        assert_eq!(pt2, b"XX reply");
    }

    #[test]
    fn test_handshake_nn() {
        let mut initiator = HandshakeState::new(Config {
            pattern: Some(Pattern::NN),
            initiator: true,
            ..Default::default()
        }).unwrap();

        let mut responder = HandshakeState::new(Config {
            pattern: Some(Pattern::NN),
            initiator: false,
            ..Default::default()
        }).unwrap();

        // Message 1: -> e
        let msg1 = initiator.write_message(&[]).unwrap();
        responder.read_message(&msg1).unwrap();

        // Message 2: <- e, ee
        let msg2 = responder.write_message(&[]).unwrap();
        initiator.read_message(&msg2).unwrap();

        assert!(initiator.is_finished());
        assert!(responder.is_finished());

        let (mut send_i, mut recv_i) = initiator.split().unwrap();
        let (mut send_r, mut recv_r) = responder.split().unwrap();

        let ct = send_i.encrypt(b"NN test", &[]);
        let pt = recv_r.decrypt(&ct, &[]).unwrap();
        assert_eq!(pt, b"NN test");

        let ct2 = send_r.encrypt(b"NN reply", &[]);
        let pt2 = recv_i.decrypt(&ct2, &[]).unwrap();
        assert_eq!(pt2, b"NN reply");
    }

    #[test]
    fn test_handshake_with_payload() {
        let initiator_static = KeyPair::generate();
        let responder_static = KeyPair::generate();

        let mut initiator = HandshakeState::new(Config {
            pattern: Some(Pattern::IK),
            initiator: true,
            local_static: Some(initiator_static),
            remote_static: Some(responder_static.public.clone()),
            ..Default::default()
        }).unwrap();

        let mut responder = HandshakeState::new(Config {
            pattern: Some(Pattern::IK),
            initiator: false,
            local_static: Some(responder_static),
            ..Default::default()
        }).unwrap();

        let msg1 = initiator.write_message(b"payload1").unwrap();
        let recv1 = responder.read_message(&msg1).unwrap();
        assert_eq!(recv1, b"payload1");

        let msg2 = responder.write_message(b"payload2").unwrap();
        let recv2 = initiator.read_message(&msg2).unwrap();
        assert_eq!(recv2, b"payload2");
    }

    #[test]
    fn test_handshake_hash() {
        let initiator_static = KeyPair::generate();
        let responder_static = KeyPair::generate();

        let mut initiator = HandshakeState::new(Config {
            pattern: Some(Pattern::IK),
            initiator: true,
            local_static: Some(initiator_static),
            remote_static: Some(responder_static.public.clone()),
            ..Default::default()
        }).unwrap();

        let mut responder = HandshakeState::new(Config {
            pattern: Some(Pattern::IK),
            initiator: false,
            local_static: Some(responder_static),
            ..Default::default()
        }).unwrap();

        let msg1 = initiator.write_message(&[]).unwrap();
        responder.read_message(&msg1).unwrap();
        let msg2 = responder.write_message(&[]).unwrap();
        initiator.read_message(&msg2).unwrap();

        assert_eq!(initiator.hash(), responder.hash());
    }

    #[test]
    fn test_handshake_errors() {
        // Missing pattern
        assert!(HandshakeState::new(Config::default()).is_err());

        // Missing local static for IK
        let rs = KeyPair::generate();
        assert!(HandshakeState::new(Config {
            pattern: Some(Pattern::IK),
            initiator: true,
            remote_static: Some(rs.public),
            ..Default::default()
        }).is_err());

        // Missing remote static for IK initiator
        let ls = KeyPair::generate();
        assert!(HandshakeState::new(Config {
            pattern: Some(Pattern::IK),
            initiator: true,
            local_static: Some(ls),
            ..Default::default()
        }).is_err());
    }

    #[test]
    fn test_handshake_wrong_turn() {
        let mut initiator = HandshakeState::new(Config {
            pattern: Some(Pattern::NN),
            initiator: true,
            ..Default::default()
        }).unwrap();

        let mut responder = HandshakeState::new(Config {
            pattern: Some(Pattern::NN),
            initiator: false,
            ..Default::default()
        }).unwrap();

        // Responder tries to write first
        assert!(responder.write_message(&[]).is_err());

        // Initiator tries to read first
        assert!(initiator.read_message(&[]).is_err());
    }

    #[test]
    fn test_split_before_finish() {
        let initiator = HandshakeState::new(Config {
            pattern: Some(Pattern::NN),
            initiator: true,
            ..Default::default()
        }).unwrap();

        assert!(initiator.split().is_err());
    }
}
