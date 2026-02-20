package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateAndListContexts(t *testing.T) {
	dir := t.TempDir()

	names, err := ListContexts(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 0 {
		t.Fatalf("expected 0 contexts, got %d", len(names))
	}

	if err := CreateContext(dir, "work"); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(dir, "work", "config.yaml")); err != nil {
		t.Fatal("config.yaml not created")
	}
	if _, err := os.Stat(filepath.Join(dir, "work", "private.key")); err != nil {
		t.Fatal("private.key not created")
	}
	if _, err := os.Stat(filepath.Join(dir, "work", "data")); err != nil {
		t.Fatal("data dir not created")
	}

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

	origKey, err := os.ReadFile(filepath.Join(dir, "test", "private.key"))
	if err != nil {
		t.Fatal(err)
	}

	if err := CreateContext(dir, "test"); err == nil {
		t.Fatal("expected error for duplicate context")
	}

	afterKey, err := os.ReadFile(filepath.Join(dir, "test", "private.key"))
	if err != nil {
		t.Fatal(err)
	}
	if string(origKey) != string(afterKey) {
		t.Fatal("private.key was modified by failed duplicate create")
	}
}

func TestCurrentContext(t *testing.T) {
	dir := t.TempDir()

	_, err := CurrentContextName(dir)
	if err == nil {
		t.Fatal("expected error when no current set")
	}

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

	if _, err := os.Stat(filepath.Join(dir, "temp")); !os.IsNotExist(err) {
		t.Fatal("context dir should be deleted")
	}

	names, err := ListContexts(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 0 {
		t.Fatalf("expected 0 after delete, got %d", len(names))
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

	addr := ResolveAPIAddr(dir, "", "10.0.0.1:8080")
	if addr != "10.0.0.1:8080" {
		t.Fatalf("override should take precedence, got %q", addr)
	}

	addr = ResolveAPIAddr(dir, "", "")
	if addr != "100.64.0.1:80" {
		t.Fatalf("expected fallback, got %q", addr)
	}

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

func TestDefaultConfigDirEnvOverride(t *testing.T) {
	t.Setenv("ZIGOR_CONFIG_DIR", "/tmp/custom-zigor")
	dir, err := DefaultConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if dir != "/tmp/custom-zigor" {
		t.Fatalf("expected /tmp/custom-zigor, got %q", dir)
	}
}

func TestDefaultConfigDirDefault(t *testing.T) {
	t.Setenv("ZIGOR_CONFIG_DIR", "")
	dir, err := DefaultConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if dir == "" {
		t.Fatal("empty dir")
	}
	expected := filepath.Join(".config", "zigor")
	if !strings.HasSuffix(dir, expected) {
		t.Fatalf("unexpected dir: %q (expected suffix %q)", dir, expected)
	}
}

func TestCurrentContextNameEmptyFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "current"), []byte("  \n"), 0644)
	_, err := CurrentContextName(dir)
	if err == nil {
		t.Fatal("expected error for empty current file")
	}
}

func TestListContextsEmptyDir(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "notacontext"), 0700)
	names, err := ListContexts(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 0 {
		t.Fatalf("expected 0, got %d", len(names))
	}
}

func TestListContextsNonexistentDir(t *testing.T) {
	names, err := ListContexts(filepath.Join(t.TempDir(), "doesnotexist"))
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 0 {
		t.Fatalf("expected 0, got %d", len(names))
	}
}

func TestShowPublicKeyBadKey(t *testing.T) {
	dir := t.TempDir()
	if err := CreateContext(dir, "badkey"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "badkey", "private.key"), []byte("notahexkey\n"), 0600)
	_, err := ShowPublicKey(dir, "badkey")
	if err == nil {
		t.Fatal("expected error for bad key")
	}
}

func TestShowPublicKeyNoContext(t *testing.T) {
	dir := t.TempDir()
	_, err := ShowPublicKey(dir, "")
	if err == nil {
		t.Fatal("expected error when no current context")
	}
}

func TestGenerateKeyNoContext(t *testing.T) {
	dir := t.TempDir()
	_, err := GenerateKey(dir, "")
	if err == nil {
		t.Fatal("expected error when no current context")
	}
}

func TestContextConfigPathNoContext(t *testing.T) {
	dir := t.TempDir()
	_, err := ContextConfigPath(dir, "")
	if err == nil {
		t.Fatal("expected error when no current context")
	}
}

func TestContextConfigPathNotExist(t *testing.T) {
	dir := t.TempDir()
	_, err := ContextConfigPath(dir, "nope")
	if err == nil {
		t.Fatal("expected error for nonexistent context")
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

// ── Name validation tests ───────────────────────────────────────────────

func TestCtxCreate_InvalidName(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name string
		desc string
	}{
		{"", "empty name"},
		{"a/b", "contains slash"},
		{"a\\b", "contains backslash"},
		{"../evil", "path traversal"},
		{"a b", "contains space"},
		{"a\tb", "contains tab"},
		{".hidden", "starts with dot"},
		{"..double", "starts with dots"},
	}
	for _, tc := range cases {
		err := CreateContext(dir, tc.name)
		if err == nil {
			t.Errorf("expected error for %s (%q), got nil", tc.desc, tc.name)
		}
	}
}

func TestCtxCreate_KeyUniqueness(t *testing.T) {
	dir := t.TempDir()

	if err := CreateContext(dir, "test1"); err != nil {
		t.Fatal(err)
	}
	if err := CreateContext(dir, "test2"); err != nil {
		t.Fatal(err)
	}

	key1, err := os.ReadFile(filepath.Join(dir, "test1", "private.key"))
	if err != nil {
		t.Fatal(err)
	}
	key2, err := os.ReadFile(filepath.Join(dir, "test2", "private.key"))
	if err != nil {
		t.Fatal(err)
	}

	if string(key1) == string(key2) {
		t.Fatal("two contexts generated the same private key")
	}
}

func TestCtx_ConfigDirPermission(t *testing.T) {
	dir := t.TempDir()

	if err := CreateContext(dir, "permtest"); err != nil {
		t.Fatal(err)
	}

	keyInfo, err := os.Stat(filepath.Join(dir, "permtest", "private.key"))
	if err != nil {
		t.Fatal(err)
	}
	perm := keyInfo.Mode().Perm()
	if perm != 0600 {
		t.Fatalf("private.key permission = %o, want 0600", perm)
	}

	dirInfo, err := os.Stat(filepath.Join(dir, "permtest"))
	if err != nil {
		t.Fatal(err)
	}
	perm = dirInfo.Mode().Perm()
	if perm != 0700 {
		t.Fatalf("ctx dir permission = %o, want 0700", perm)
	}
}

func TestCtx_CorruptedCurrentFile(t *testing.T) {
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, "current"), []byte("nonexistent\n"), 0644)

	name, err := CurrentContextName(dir)
	if err != nil {
		t.Fatalf("unexpected error reading current: %v", err)
	}
	if name != "nonexistent" {
		t.Fatalf("expected 'nonexistent', got %q", name)
	}

	_, err = ContextConfigPath(dir, "")
	if err == nil {
		t.Fatal("expected error when current context dir doesn't exist")
	}
}

func TestCtxList_ShowCurrent(t *testing.T) {
	dir := t.TempDir()

	if err := CreateContext(dir, "test1"); err != nil {
		t.Fatal(err)
	}
	if err := CreateContext(dir, "test2"); err != nil {
		t.Fatal(err)
	}
	if err := SetCurrentContext(dir, "test2"); err != nil {
		t.Fatal(err)
	}

	current, _ := CurrentContextName(dir)
	if current != "test2" {
		t.Fatalf("expected current=test2, got %q", current)
	}

	names, err := ListContexts(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("expected 2, got %d", len(names))
	}
}

func TestCtxUse_NonExistent(t *testing.T) {
	dir := t.TempDir()

	if err := CreateContext(dir, "real"); err != nil {
		t.Fatal(err)
	}
	if err := SetCurrentContext(dir, "real"); err != nil {
		t.Fatal(err)
	}

	err := SetCurrentContext(dir, "ghost")
	if err == nil {
		t.Fatal("expected error for nonexistent context")
	}

	name, _ := CurrentContextName(dir)
	if name != "real" {
		t.Fatalf("current should still be 'real', got %q", name)
	}
}

func TestValidateContextName(t *testing.T) {
	valid := []string{"prod", "dev", "my-ctx", "node_1", "123"}
	for _, name := range valid {
		if err := ValidateContextName(name); err != nil {
			t.Errorf("expected %q to be valid, got error: %v", name, err)
		}
	}

	invalid := []string{"", "a/b", "a\\b", "../x", "a b", ".hidden", "..x"}
	for _, name := range invalid {
		if err := ValidateContextName(name); err == nil {
			t.Errorf("expected %q to be invalid", name)
		}
	}
}
