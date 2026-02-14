package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCreateAndListContexts(t *testing.T) {
	dir := t.TempDir()

	// Initially empty
	names, err := ListContexts(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 0 {
		t.Fatalf("expected 0 contexts, got %d", len(names))
	}

	// Create context
	if err := CreateContext(dir, "work"); err != nil {
		t.Fatal(err)
	}

	// Verify files
	if _, err := os.Stat(filepath.Join(dir, "work", "config.yaml")); err != nil {
		t.Fatal("config.yaml not created")
	}
	if _, err := os.Stat(filepath.Join(dir, "work", "private.key")); err != nil {
		t.Fatal("private.key not created")
	}
	if _, err := os.Stat(filepath.Join(dir, "work", "data")); err != nil {
		t.Fatal("data dir not created")
	}

	// List should show 1
	names, err = ListContexts(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "work" {
		t.Fatalf("expected [work], got %v", names)
	}
}

func TestCreateDuplicateContext(t *testing.T) {
	dir := t.TempDir()

	if err := CreateContext(dir, "test"); err != nil {
		t.Fatal(err)
	}
	if err := CreateContext(dir, "test"); err == nil {
		t.Fatal("expected error for duplicate context")
	}
}

func TestCurrentContext(t *testing.T) {
	dir := t.TempDir()

	// No current set
	_, err := CurrentContextName(dir)
	if err == nil {
		t.Fatal("expected error when no current set")
	}

	// Create and set
	if err := CreateContext(dir, "default"); err != nil {
		t.Fatal(err)
	}
	if err := SetCurrentContext(dir, "default"); err != nil {
		t.Fatal(err)
	}

	name, err := CurrentContextName(dir)
	if err != nil {
		t.Fatal(err)
	}
	if name != "default" {
		t.Fatalf("expected 'default', got %q", name)
	}
}

func TestSetCurrentContextNotExist(t *testing.T) {
	dir := t.TempDir()
	if err := SetCurrentContext(dir, "nope"); err == nil {
		t.Fatal("expected error for nonexistent context")
	}
}

func TestDeleteContext(t *testing.T) {
	dir := t.TempDir()

	if err := CreateContext(dir, "temp"); err != nil {
		t.Fatal(err)
	}

	if err := DeleteContext(dir, "temp"); err != nil {
		t.Fatal(err)
	}

	// Should be gone
	if _, err := os.Stat(filepath.Join(dir, "temp")); !os.IsNotExist(err) {
		t.Fatal("context dir should be deleted")
	}
}

func TestDeleteCurrentContextBlocked(t *testing.T) {
	dir := t.TempDir()

	if err := CreateContext(dir, "active"); err != nil {
		t.Fatal(err)
	}
	if err := SetCurrentContext(dir, "active"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteContext(dir, "active"); err == nil {
		t.Fatal("expected error deleting current context")
	}
}

func TestDeleteNonexistentContext(t *testing.T) {
	dir := t.TempDir()
	if err := DeleteContext(dir, "ghost"); err == nil {
		t.Fatal("expected error for nonexistent context")
	}
}

func TestShowPublicKey(t *testing.T) {
	dir := t.TempDir()

	if err := CreateContext(dir, "keytest"); err != nil {
		t.Fatal(err)
	}
	if err := SetCurrentContext(dir, "keytest"); err != nil {
		t.Fatal(err)
	}

	pubkey, err := ShowPublicKey(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(pubkey) != 64 {
		t.Fatalf("expected 64-char hex pubkey, got len=%d: %q", len(pubkey), pubkey)
	}
}

func TestGenerateKey(t *testing.T) {
	dir := t.TempDir()

	if err := CreateContext(dir, "regen"); err != nil {
		t.Fatal(err)
	}
	if err := SetCurrentContext(dir, "regen"); err != nil {
		t.Fatal(err)
	}

	pk1, err := ShowPublicKey(dir, "")
	if err != nil {
		t.Fatal(err)
	}

	pk2, err := GenerateKey(dir, "")
	if err != nil {
		t.Fatal(err)
	}

	if pk1 == pk2 {
		t.Fatal("generated key should be different from original")
	}
	if len(pk2) != 64 {
		t.Fatalf("expected 64-char hex pubkey, got len=%d", len(pk2))
	}
}

func TestContextConfigPath(t *testing.T) {
	dir := t.TempDir()

	if err := CreateContext(dir, "pathtest"); err != nil {
		t.Fatal(err)
	}
	if err := SetCurrentContext(dir, "pathtest"); err != nil {
		t.Fatal(err)
	}

	path, err := ContextConfigPath(dir, "")
	if err != nil {
		t.Fatal(err)
	}

	expected := filepath.Join(dir, "pathtest", "config.yaml")
	if path != expected {
		t.Fatalf("expected %q, got %q", expected, path)
	}
}

func TestShowConfig(t *testing.T) {
	dir := t.TempDir()

	if err := CreateContext(dir, "showtest"); err != nil {
		t.Fatal(err)
	}

	content, err := ShowConfig(dir, "showtest")
	if err != nil {
		t.Fatal(err)
	}
	if content == "" {
		t.Fatal("config content is empty")
	}
}

func TestResolveAPIAddr(t *testing.T) {
	dir := t.TempDir()

	// Override takes precedence
	addr := ResolveAPIAddr(dir, "", "10.0.0.1:8080")
	if addr != "10.0.0.1:8080" {
		t.Fatalf("override should take precedence, got %q", addr)
	}

	// Fallback when no context
	addr = ResolveAPIAddr(dir, "", "")
	if addr != "100.64.0.1:80" {
		t.Fatalf("expected fallback, got %q", addr)
	}

	// Read from config
	if err := CreateContext(dir, "apitest"); err != nil {
		t.Fatal(err)
	}
	if err := SetCurrentContext(dir, "apitest"); err != nil {
		t.Fatal(err)
	}
	addr = ResolveAPIAddr(dir, "", "")
	if addr != "100.64.0.1:80" {
		t.Fatalf("expected 100.64.0.1:80 from template config, got %q", addr)
	}
}

func TestMultipleContextsSorted(t *testing.T) {
	dir := t.TempDir()

	for _, name := range []string{"charlie", "alpha", "bravo"} {
		if err := CreateContext(dir, name); err != nil {
			t.Fatal(err)
		}
	}

	names, err := ListContexts(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 3 {
		t.Fatalf("expected 3, got %d", len(names))
	}
	if names[0] != "alpha" || names[1] != "bravo" || names[2] != "charlie" {
		t.Fatalf("not sorted: %v", names)
	}
}
