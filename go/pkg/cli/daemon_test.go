package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestShowConfigContent(t *testing.T) {
	dir := t.TempDir()
	if err := CreateContext(dir, "showtest"); err != nil {
		t.Fatal(err)
	}

	content, err := ShowConfig(dir, "showtest")
	if err != nil {
		t.Fatal(err)
	}
	if content == "" {
		t.Fatal("empty config")
	}
	if len(content) < 10 {
		t.Fatalf("config too short: %q", content)
	}
}

func TestShowConfigNotFound(t *testing.T) {
	dir := t.TempDir()
	_, err := ShowConfig(dir, "nope")
	if err == nil {
		t.Fatal("expected error for nonexistent context")
	}
}

func TestDownNoPidFile(t *testing.T) {
	dir := t.TempDir()
	if err := CreateContext(dir, "norun"); err != nil {
		t.Fatal(err)
	}
	if err := SetCurrentContext(dir, "norun"); err != nil {
		t.Fatal(err)
	}

	err := Down(dir, "")
	if err == nil {
		t.Fatal("expected error when no pid file")
	}
}

func TestDownInvalidPidFile(t *testing.T) {
	dir := t.TempDir()
	if err := CreateContext(dir, "badpid"); err != nil {
		t.Fatal(err)
	}

	// Write an invalid pid file
	pidDir := filepath.Join(dir, "badpid", "data")
	os.MkdirAll(pidDir, 0700)
	os.WriteFile(filepath.Join(pidDir, "zgrnetd.pid"), []byte("notanumber\n"), 0644)

	err := Down(dir, "badpid")
	if err == nil {
		t.Fatal("expected error for invalid pid")
	}
}

func TestDownDeadProcess(t *testing.T) {
	dir := t.TempDir()
	if err := CreateContext(dir, "dead"); err != nil {
		t.Fatal(err)
	}

	// Write a pid file with a very unlikely PID
	pidDir := filepath.Join(dir, "dead", "data")
	os.MkdirAll(pidDir, 0700)
	os.WriteFile(filepath.Join(pidDir, "zgrnetd.pid"), []byte("999999999\n"), 0644)

	// Should fail because process doesn't exist
	err := Down(dir, "dead")
	if err == nil {
		t.Fatal("expected error for dead process")
	}
}

func TestFindZgrnetdNotFound(t *testing.T) {
	// Save and clear PATH to ensure zgrnetd can't be found
	origPath := os.Getenv("PATH")
	os.Setenv("PATH", t.TempDir()) // empty dir with no binaries
	defer os.Setenv("PATH", origPath)

	_, err := findZgrnetd()
	if err == nil {
		t.Fatal("expected error when zgrnetd not in PATH")
	}
}

func TestResolveAPIAddrFromConfig(t *testing.T) {
	dir := t.TempDir()
	if err := CreateContext(dir, "custom"); err != nil {
		t.Fatal(err)
	}
	if err := SetCurrentContext(dir, "custom"); err != nil {
		t.Fatal(err)
	}

	// Write a custom config with different TUN IP
	cfgPath := filepath.Join(dir, "custom", "config.yaml")
	os.WriteFile(cfgPath, []byte(`net:
  private_key: "private.key"
  tun_ipv4: "100.64.1.1"
  tun_mtu: 1400
  listen_port: 51820
`), 0644)

	addr := ResolveAPIAddr(dir, "", "")
	if addr != "100.64.1.1:80" {
		t.Fatalf("expected 100.64.1.1:80, got %q", addr)
	}
}

func TestResolveAPIAddrQuotedIP(t *testing.T) {
	dir := t.TempDir()
	if err := CreateContext(dir, "quoted"); err != nil {
		t.Fatal(err)
	}
	if err := SetCurrentContext(dir, "quoted"); err != nil {
		t.Fatal(err)
	}

	// IP with single quotes
	cfgPath := filepath.Join(dir, "quoted", "config.yaml")
	os.WriteFile(cfgPath, []byte(`net:
  private_key: "private.key"
  tun_ipv4: '100.64.2.2'
  tun_mtu: 1400
  listen_port: 51820
`), 0644)

	addr := ResolveAPIAddr(dir, "", "")
	if addr != "100.64.2.2:80" {
		t.Fatalf("expected 100.64.2.2:80, got %q", addr)
	}
}
