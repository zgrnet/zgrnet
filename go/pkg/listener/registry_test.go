package listener

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestRegistryRegisterAndLookup(t *testing.T) {
	r := NewRegistry("/tmp/test-handlers")

	h, err := r.Register(69, "proxy", ModeStream, "")
	if err != nil {
		t.Fatal(err)
	}
	if h.Proto != 69 {
		t.Errorf("proto = %d, want 69", h.Proto)
	}
	if h.Name != "proxy" {
		t.Errorf("name = %q, want %q", h.Name, "proxy")
	}
	if h.Sock != "/tmp/test-handlers/proxy.sock" {
		t.Errorf("sock = %q, want %q", h.Sock, "/tmp/test-handlers/proxy.sock")
	}

	got := r.Lookup(69)
	if got != h {
		t.Error("Lookup(69) returned different handler")
	}
	if r.Lookup(70) != nil {
		t.Error("Lookup(70) should be nil")
	}

	gotByName := r.LookupByName("proxy")
	if gotByName != h {
		t.Error("LookupByName returned different handler")
	}
}

func TestRegistryDuplicateProto(t *testing.T) {
	r := NewRegistry("/tmp")

	if _, err := r.Register(69, "proxy", ModeStream, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(69, "proxy2", ModeStream, ""); err == nil {
		t.Fatal("expected error for duplicate proto")
	}
}

func TestRegistryDuplicateName(t *testing.T) {
	r := NewRegistry("/tmp")

	if _, err := r.Register(69, "proxy", ModeStream, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(70, "proxy", ModeStream, ""); err == nil {
		t.Fatal("expected error for duplicate name")
	}
}

func TestRegistryUnregister(t *testing.T) {
	r := NewRegistry("/tmp")

	r.Register(69, "proxy", ModeStream, "")
	if err := r.Unregister("proxy"); err != nil {
		t.Fatal(err)
	}
	if r.Lookup(69) != nil {
		t.Error("Lookup should be nil after unregister")
	}
	if r.LookupByName("proxy") != nil {
		t.Error("LookupByName should be nil after unregister")
	}

	if err := r.Unregister("proxy"); err == nil {
		t.Error("expected error for double unregister")
	}
}

func TestRegistryList(t *testing.T) {
	r := NewRegistry("/tmp")

	r.Register(69, "tcp-proxy", ModeStream, "")
	r.Register(65, "udp-proxy", ModeDgram, "")

	list := r.List()
	if len(list) != 2 {
		t.Fatalf("List() returned %d items, want 2", len(list))
	}

	found := make(map[string]bool)
	for _, info := range list {
		found[info.Name] = true
	}
	if !found["tcp-proxy"] || !found["udp-proxy"] {
		t.Errorf("List missing expected handlers: %v", list)
	}
}

func TestRegistryModeBTarget(t *testing.T) {
	r := NewRegistry("/tmp")

	h, err := r.Register(128, "chat", ModeStream, "unix:///tmp/chat.sock")
	if err != nil {
		t.Fatal(err)
	}
	if h.Target != "unix:///tmp/chat.sock" {
		t.Errorf("target = %q", h.Target)
	}
	if h.Sock != "" {
		t.Errorf("sock should be empty for mode B, got %q", h.Sock)
	}
}

func TestStreamHeaderRoundTrip(t *testing.T) {
	var pubkey [32]byte
	rand.Read(pubkey[:])
	proto := byte(69)
	metadata := []byte("hello world metadata")

	var buf bytes.Buffer
	if err := WriteStreamHeader(&buf, pubkey, proto, metadata); err != nil {
		t.Fatal(err)
	}

	meta, err := ReadStreamHeader(&buf)
	if err != nil {
		t.Fatal(err)
	}

	if meta.RemotePubkey != pubkey {
		t.Error("pubkey mismatch")
	}
	if meta.Proto != proto {
		t.Errorf("proto = %d, want %d", meta.Proto, proto)
	}
	if !bytes.Equal(meta.Metadata, metadata) {
		t.Errorf("metadata = %q, want %q", meta.Metadata, metadata)
	}
}

func TestStreamHeaderEmptyMetadata(t *testing.T) {
	var pubkey [32]byte
	pubkey[0] = 0x42

	var buf bytes.Buffer
	if err := WriteStreamHeader(&buf, pubkey, 128, nil); err != nil {
		t.Fatal(err)
	}

	if buf.Len() != StreamHeaderSize {
		t.Errorf("header size = %d, want %d", buf.Len(), StreamHeaderSize)
	}

	meta, err := ReadStreamHeader(&buf)
	if err != nil {
		t.Fatal(err)
	}

	if meta.Proto != 128 {
		t.Errorf("proto = %d, want 128", meta.Proto)
	}
	if len(meta.Metadata) != 0 {
		t.Errorf("metadata should be empty, got %d bytes", len(meta.Metadata))
	}
}

func TestRegistryOnChange(t *testing.T) {
	r := NewRegistry("/tmp")

	var called int
	r.SetOnChange(func() { called++ })

	r.Register(1, "a", ModeStream, "")
	r.Register(2, "b", ModeStream, "")
	r.Unregister("a")

	if called != 3 {
		t.Errorf("onChange called %d times, want 3", called)
	}
}

func TestHandlerActive(t *testing.T) {
	r := NewRegistry("/tmp")
	h, _ := r.Register(69, "proxy", ModeStream, "")

	if h.Active() != 0 {
		t.Errorf("initial active = %d, want 0", h.Active())
	}

	h.active.Add(1)
	h.active.Add(1)
	if h.Active() != 2 {
		t.Errorf("active = %d, want 2", h.Active())
	}

	h.active.Add(-1)
	if h.Active() != 1 {
		t.Errorf("active = %d, want 1", h.Active())
	}
}
