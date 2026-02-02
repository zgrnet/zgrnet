package net

import (
	"context"
	"testing"

	"github.com/vibing/zgrnet/pkg/noise"
)

func TestDialMissingLocalKey(t *testing.T) {
	transport := NewMockTransport("test")
	defer transport.Close()

	remotePK := noise.PublicKey{}
	copy(remotePK[:], []byte("12345678901234567890123456789012"))

	ctx := context.Background()
	_, err := Dial(ctx, transport, transport.LocalAddr(), remotePK, nil)
	if err != ErrMissingLocalKey {
		t.Errorf("Dial() error = %v, want ErrMissingLocalKey", err)
	}
}

func TestDialMissingTransport(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	remotePK := noise.PublicKey{}
	copy(remotePK[:], []byte("12345678901234567890123456789012"))

	ctx := context.Background()
	_, err := Dial(ctx, nil, NewMockAddr("test"), remotePK, key)
	if err != ErrMissingTransport {
		t.Errorf("Dial() error = %v, want ErrMissingTransport", err)
	}
}

func TestDialMissingRemotePK(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := NewMockTransport("test")
	defer transport.Close()

	ctx := context.Background()
	_, err := Dial(ctx, transport, transport.LocalAddr(), noise.PublicKey{}, key)
	if err != ErrMissingRemotePK {
		t.Errorf("Dial() error = %v, want ErrMissingRemotePK", err)
	}
}

func TestDialMissingRemoteAddr(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := NewMockTransport("test")
	defer transport.Close()

	remotePK := noise.PublicKey{}
	copy(remotePK[:], []byte("12345678901234567890123456789012"))

	ctx := context.Background()
	_, err := Dial(ctx, transport, nil, remotePK, key)
	if err != ErrMissingRemoteAddr {
		t.Errorf("Dial() error = %v, want ErrMissingRemoteAddr", err)
	}
}
