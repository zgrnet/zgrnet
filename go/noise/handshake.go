package noise

import (
	"errors"
	"fmt"
)

// Handshake pattern tokens
const (
	tokenE  = "e"  // ephemeral key
	tokenS  = "s"  // static key
	tokenEE = "ee" // DH(e, re)
	tokenES = "es" // DH(e, rs) or DH(s, re)
	tokenSE = "se" // DH(s, re) or DH(e, rs)
	tokenSS = "ss" // DH(s, rs)
)

// Pattern defines a Noise handshake pattern.
type Pattern struct {
	Name            string     // e.g., "IK"
	InitiatorPreMsg []string   // pre-message tokens for initiator (e.g., ["s"] for IK)
	ResponderPreMsg []string   // pre-message tokens for responder
	MessagePatterns [][]string // message patterns
}

// Predefined patterns
var (
	// PatternIK: Initiator knows responder's static key
	// <- s
	// ...
	// -> e, es, s, ss
	// <- e, ee, se
	PatternIK = Pattern{
		Name:            "IK",
		ResponderPreMsg: []string{tokenS},
		MessagePatterns: [][]string{
			{tokenE, tokenES, tokenS, tokenSS},
			{tokenE, tokenEE, tokenSE},
		},
	}

	// PatternXX: Mutual authentication, no prior knowledge
	// -> e
	// <- e, ee, s, es
	// -> s, se
	PatternXX = Pattern{
		Name: "XX",
		MessagePatterns: [][]string{
			{tokenE},
			{tokenE, tokenEE, tokenS, tokenES},
			{tokenS, tokenSE},
		},
	}

	// PatternNN: No authentication
	// -> e
	// <- e, ee
	PatternNN = Pattern{
		Name: "NN",
		MessagePatterns: [][]string{
			{tokenE},
			{tokenE, tokenEE},
		},
	}
)

// Config holds the configuration for a handshake.
type Config struct {
	Pattern      Pattern  // Handshake pattern
	Initiator    bool     // true if this side initiates
	LocalStatic  *KeyPair // Local static key pair (required for patterns with 's')
	RemoteStatic *Key     // Remote static public key (required for IK initiator)
	Prologue     []byte   // Optional prologue data
	PresharedKey *Key     // Optional PSK (for psk patterns)
}

// HandshakeState manages the state of a Noise handshake.
type HandshakeState struct {
	config Config
	ss     *SymmetricState

	localEphemeral  *KeyPair // Generated during handshake
	remoteEphemeral Key      // Received from peer
	remoteStatic    Key      // Received from peer (for XX pattern)

	msgIndex int  // Current message index
	finished bool // Handshake complete
}

// Errors
var (
	ErrHandshakeFinished   = errors.New("noise: handshake already finished")
	ErrHandshakeNotReady   = errors.New("noise: handshake not ready to split")
	ErrInvalidMessage      = errors.New("noise: invalid handshake message")
	ErrMissingLocalStatic  = errors.New("noise: missing local static key")
	ErrMissingRemoteStatic = errors.New("noise: missing remote static key")
)

// NewHandshakeState creates a new handshake state.
func NewHandshakeState(config Config) (*HandshakeState, error) {
	// Validate config
	if err := validateConfig(&config); err != nil {
		return nil, err
	}

	// Build protocol name
	protocolName := fmt.Sprintf("Noise_%s_25519_ChaChaPoly_BLAKE2s", config.Pattern.Name)

	hs := &HandshakeState{
		config: config,
		ss:     NewSymmetricState(protocolName),
	}

	// Mix in prologue
	hs.ss.MixHash(config.Prologue)

	// Process pre-messages
	if config.Initiator {
		// Initiator processes responder's pre-message (remote static)
		for _, token := range config.Pattern.ResponderPreMsg {
			if token == tokenS {
				if config.RemoteStatic == nil {
					return nil, ErrMissingRemoteStatic
				}
				hs.ss.MixHash(config.RemoteStatic[:])
				hs.remoteStatic = *config.RemoteStatic
			}
		}
		// Then initiator's pre-message
		for _, token := range config.Pattern.InitiatorPreMsg {
			if token == tokenS {
				hs.ss.MixHash(config.LocalStatic.Public[:])
			}
		}
	} else {
		// Responder processes initiator's pre-message (their static)
		for _, token := range config.Pattern.InitiatorPreMsg {
			if token == tokenS {
				if config.RemoteStatic == nil {
					return nil, ErrMissingRemoteStatic
				}
				hs.ss.MixHash(config.RemoteStatic[:])
				hs.remoteStatic = *config.RemoteStatic
			}
		}
		// Then responder's pre-message (our static)
		for _, token := range config.Pattern.ResponderPreMsg {
			if token == tokenS {
				hs.ss.MixHash(config.LocalStatic.Public[:])
			}
		}
	}

	return hs, nil
}

func validateConfig(config *Config) error {
	pattern := config.Pattern

	// Check if local static is needed
	needsLocalStatic := false
	for _, msg := range pattern.MessagePatterns {
		for _, token := range msg {
			if token == tokenS || token == tokenSS || token == tokenSE || token == tokenES {
				needsLocalStatic = true
				break
			}
		}
	}
	if needsLocalStatic && config.LocalStatic == nil {
		return ErrMissingLocalStatic
	}

	// For IK pattern, initiator needs remote static
	if pattern.Name == "IK" && config.Initiator && config.RemoteStatic == nil {
		return ErrMissingRemoteStatic
	}

	return nil
}

// WriteMessage generates the next handshake message.
// Returns the message to send to the peer.
func (hs *HandshakeState) WriteMessage(payload []byte) ([]byte, error) {
	if hs.finished {
		return nil, ErrHandshakeFinished
	}

	// Check if it's our turn
	myTurn := (hs.config.Initiator && hs.msgIndex%2 == 0) ||
		(!hs.config.Initiator && hs.msgIndex%2 == 1)
	if !myTurn {
		return nil, fmt.Errorf("noise: not our turn to write (msg %d)", hs.msgIndex)
	}

	if hs.msgIndex >= len(hs.config.Pattern.MessagePatterns) {
		return nil, ErrHandshakeFinished
	}

	tokens := hs.config.Pattern.MessagePatterns[hs.msgIndex]
	var msg []byte

	for _, token := range tokens {
		switch token {
		case tokenE:
			// Generate ephemeral key pair
			var err error
			hs.localEphemeral, err = GenerateKeyPair()
			if err != nil {
				return nil, fmt.Errorf("noise: failed to generate ephemeral key: %w", err)
			}
			msg = append(msg, hs.localEphemeral.Public[:]...)
			hs.ss.MixHash(hs.localEphemeral.Public[:])
			// If PSK mode, also mix key
			if hs.config.PresharedKey != nil {
				hs.ss.MixKey(hs.localEphemeral.Public[:])
			}

		case tokenS:
			// Encrypt and send static public key
			k := hs.ss.MixKey(nil) // Get encryption key
			encrypted := hs.ss.EncryptAndHash(&k, hs.config.LocalStatic.Public[:])
			msg = append(msg, encrypted...)

		case tokenEE:
			shared, err := hs.localEphemeral.DH(hs.remoteEphemeral)
			if err != nil {
				return nil, fmt.Errorf("noise: DH(e, re) failed: %w", err)
			}
			hs.ss.MixKey(shared[:])

		case tokenES:
			var shared Key
			var err error
			if hs.config.Initiator {
				// Initiator: DH(e, rs)
				shared, err = hs.localEphemeral.DH(hs.remoteStatic)
			} else {
				// Responder: DH(s, re)
				shared, err = hs.config.LocalStatic.DH(hs.remoteEphemeral)
			}
			if err != nil {
				return nil, fmt.Errorf("noise: DH(es) failed: %w", err)
			}
			hs.ss.MixKey(shared[:])

		case tokenSE:
			var shared Key
			var err error
			if hs.config.Initiator {
				// Initiator: DH(s, re)
				shared, err = hs.config.LocalStatic.DH(hs.remoteEphemeral)
			} else {
				// Responder: DH(e, rs)
				shared, err = hs.localEphemeral.DH(hs.remoteStatic)
			}
			if err != nil {
				return nil, fmt.Errorf("noise: DH(se) failed: %w", err)
			}
			hs.ss.MixKey(shared[:])

		case tokenSS:
			shared, err := hs.config.LocalStatic.DH(hs.remoteStatic)
			if err != nil {
				return nil, fmt.Errorf("noise: DH(s, rs) failed: %w", err)
			}
			hs.ss.MixKey(shared[:])
		}
	}

	// Encrypt payload if any
	if len(payload) > 0 || hs.msgIndex == len(hs.config.Pattern.MessagePatterns)-1 {
		// Get key for payload encryption
		k := hs.ss.MixKey(nil)
		encrypted := hs.ss.EncryptAndHash(&k, payload)
		msg = append(msg, encrypted...)
	}

	hs.msgIndex++
	if hs.msgIndex >= len(hs.config.Pattern.MessagePatterns) {
		hs.finished = true
	}

	return msg, nil
}

// ReadMessage processes a received handshake message.
// Returns the decrypted payload (if any).
func (hs *HandshakeState) ReadMessage(msg []byte) ([]byte, error) {
	if hs.finished {
		return nil, ErrHandshakeFinished
	}

	// Check if it's peer's turn
	myTurn := (hs.config.Initiator && hs.msgIndex%2 == 0) ||
		(!hs.config.Initiator && hs.msgIndex%2 == 1)
	if myTurn {
		return nil, fmt.Errorf("noise: not peer's turn to write (msg %d)", hs.msgIndex)
	}

	if hs.msgIndex >= len(hs.config.Pattern.MessagePatterns) {
		return nil, ErrHandshakeFinished
	}

	tokens := hs.config.Pattern.MessagePatterns[hs.msgIndex]
	offset := 0

	for _, token := range tokens {
		switch token {
		case tokenE:
			// Read remote ephemeral
			if offset+KeySize > len(msg) {
				return nil, ErrInvalidMessage
			}
			copy(hs.remoteEphemeral[:], msg[offset:offset+KeySize])
			offset += KeySize
			hs.ss.MixHash(hs.remoteEphemeral[:])
			if hs.config.PresharedKey != nil {
				hs.ss.MixKey(hs.remoteEphemeral[:])
			}

		case tokenS:
			// Decrypt remote static
			k := hs.ss.MixKey(nil)
			encryptedLen := KeySize + TagSize
			if offset+encryptedLen > len(msg) {
				return nil, ErrInvalidMessage
			}
			decrypted, err := hs.ss.DecryptAndHash(&k, msg[offset:offset+encryptedLen])
			if err != nil {
				return nil, fmt.Errorf("noise: failed to decrypt static key: %w", err)
			}
			copy(hs.remoteStatic[:], decrypted)
			offset += encryptedLen

		case tokenEE:
			shared, err := hs.localEphemeral.DH(hs.remoteEphemeral)
			if err != nil {
				return nil, fmt.Errorf("noise: DH(e, re) failed: %w", err)
			}
			hs.ss.MixKey(shared[:])

		case tokenES:
			var shared Key
			var err error
			if hs.config.Initiator {
				shared, err = hs.localEphemeral.DH(hs.remoteStatic)
			} else {
				shared, err = hs.config.LocalStatic.DH(hs.remoteEphemeral)
			}
			if err != nil {
				return nil, fmt.Errorf("noise: DH(es) failed: %w", err)
			}
			hs.ss.MixKey(shared[:])

		case tokenSE:
			var shared Key
			var err error
			if hs.config.Initiator {
				shared, err = hs.config.LocalStatic.DH(hs.remoteEphemeral)
			} else {
				shared, err = hs.localEphemeral.DH(hs.remoteStatic)
			}
			if err != nil {
				return nil, fmt.Errorf("noise: DH(se) failed: %w", err)
			}
			hs.ss.MixKey(shared[:])

		case tokenSS:
			shared, err := hs.config.LocalStatic.DH(hs.remoteStatic)
			if err != nil {
				return nil, fmt.Errorf("noise: DH(s, rs) failed: %w", err)
			}
			hs.ss.MixKey(shared[:])
		}
	}

	// Decrypt payload
	var payload []byte
	if offset < len(msg) {
		k := hs.ss.MixKey(nil)
		var err error
		payload, err = hs.ss.DecryptAndHash(&k, msg[offset:])
		if err != nil {
			return nil, fmt.Errorf("noise: failed to decrypt payload: %w", err)
		}
	}

	hs.msgIndex++
	if hs.msgIndex >= len(hs.config.Pattern.MessagePatterns) {
		hs.finished = true
	}

	return payload, nil
}

// IsFinished returns true if the handshake is complete.
func (hs *HandshakeState) IsFinished() bool {
	return hs.finished
}

// Split returns the transport CipherStates after handshake completion.
// Returns (send, recv) cipher states.
func (hs *HandshakeState) Split() (*CipherState, *CipherState, error) {
	if !hs.finished {
		return nil, nil, ErrHandshakeNotReady
	}

	cs1, cs2, err := hs.ss.Split()
	if err != nil {
		return nil, nil, err
	}

	if hs.config.Initiator {
		return cs1, cs2, nil
	}
	return cs2, cs1, nil
}

// RemoteStatic returns the remote peer's static public key.
// Only valid after the handshake message containing 's' has been processed.
func (hs *HandshakeState) RemoteStatic() Key {
	return hs.remoteStatic
}

// LocalEphemeral returns the local ephemeral public key.
// Only valid after WriteMessage has been called with 'e' token.
func (hs *HandshakeState) LocalEphemeral() Key {
	if hs.localEphemeral == nil {
		return Key{}
	}
	return hs.localEphemeral.Public
}

// Hash returns the current handshake hash.
// Can be used for channel binding after handshake.
func (hs *HandshakeState) Hash() [HashSize]byte {
	return hs.ss.Hash()
}
