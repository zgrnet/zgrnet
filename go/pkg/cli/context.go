// Package cli provides the zigor CLI tool functionality.
//
// It includes offline context/config management and an API client
// for interacting with a running zigor host daemon.
package cli

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vibing/zgrnet/pkg/noise"
)

// DefaultConfigDir returns the default zigor config directory.
// Uses $ZIGOR_CONFIG_DIR if set, otherwise ~/.config/zigor.
func DefaultConfigDir() (string, error) {
	if dir := os.Getenv("ZIGOR_CONFIG_DIR"); dir != "" {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".config", "zigor"), nil
}

// ContextDir returns the path to a specific context directory.
func ContextDir(baseDir, name string) string {
	return filepath.Join(baseDir, name)
}

// CurrentContextName reads the current context name from the "current" file.
func CurrentContextName(baseDir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(baseDir, "current"))
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("no current context set (run: zigor ctx create <name>)")
		}
		return "", err
	}
	name := strings.TrimSpace(string(data))
	if name == "" {
		return "", fmt.Errorf("current context file is empty")
	}
	return name, nil
}

// SetCurrentContext writes the current context name.
func SetCurrentContext(baseDir, name string) error {
	if err := ValidateContextName(name); err != nil {
		return err
	}
	dir := ContextDir(baseDir, name)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("context %q does not exist", name)
	}
	return os.WriteFile(filepath.Join(baseDir, "current"), []byte(name+"\n"), 0644)
}

// ListContexts returns all context names sorted alphabetically.
func ListContexts(baseDir string) ([]string, error) {
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// A valid context has a private.key file (language-agnostic marker).
		// Config format varies by language (config.yaml for Go/Rust, config.json for Zig).
		keyPath := filepath.Join(baseDir, e.Name(), "private.key")
		if _, err := os.Stat(keyPath); err == nil {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// contextTemplate is the minimal config.yaml for a new context.
const contextTemplate = `net:
  private_key: "private.key"
  tun_ipv4: "100.64.0.1"
  tun_mtu: 1400
  listen_port: 51820
`

// ValidateContextName checks that a context name is safe for use as a directory name.
func ValidateContextName(name string) error {
	if name == "" {
		return fmt.Errorf("context name cannot be empty")
	}
	if name == "current" {
		return fmt.Errorf("context name %q is reserved", name)
	}
	if strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("context name %q contains path separator", name)
	}
	if strings.Contains(name, "..") {
		return fmt.Errorf("context name %q contains path traversal", name)
	}
	if strings.ContainsAny(name, " \t\n\r") {
		return fmt.Errorf("context name %q contains whitespace", name)
	}
	if strings.HasPrefix(name, ".") {
		return fmt.Errorf("context name %q cannot start with dot", name)
	}
	return nil
}

// CreateContext creates a new context with a generated keypair and template config.
func CreateContext(baseDir, name string) error {
	if err := ValidateContextName(name); err != nil {
		return err
	}
	dir := ContextDir(baseDir, name)
	if _, err := os.Stat(dir); err == nil {
		return fmt.Errorf("context %q already exists", name)
	}

	// Create directory structure
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0700); err != nil {
		return fmt.Errorf("create context dir: %w", err)
	}

	// Generate keypair
	kp, err := noise.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}

	// Write private key
	keyHex := hex.EncodeToString(kp.Private[:]) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "private.key"), []byte(keyHex), 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	// Write template config
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(contextTemplate), 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	return nil
}

// DeleteContext removes a context directory.
// Refuses to delete the current context.
func DeleteContext(baseDir, name string) error {
	if err := ValidateContextName(name); err != nil {
		return err
	}
	current, _ := CurrentContextName(baseDir)
	if current == name {
		return fmt.Errorf("cannot delete the current context %q (switch to another first)", name)
	}

	dir := ContextDir(baseDir, name)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("context %q does not exist", name)
	}

	return os.RemoveAll(dir)
}

// ContextConfigPath returns the config.yaml path for the current (or given) context.
func ContextConfigPath(baseDir, name string) (string, error) {
	if name == "" {
		var err error
		name, err = CurrentContextName(baseDir)
		if err != nil {
			return "", err
		}
	}
	path := filepath.Join(ContextDir(baseDir, name), "config.yaml")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "", fmt.Errorf("config not found for context %q", name)
	}
	return path, nil
}

// ShowPublicKey reads the private key from the context and prints the public key.
func ShowPublicKey(baseDir, ctxName string) (string, error) {
	if ctxName == "" {
		var err error
		ctxName, err = CurrentContextName(baseDir)
		if err != nil {
			return "", err
		}
	}

	keyPath := filepath.Join(ContextDir(baseDir, ctxName), "private.key")
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("read private key: %w", err)
	}

	hexStr := strings.TrimSpace(string(data))
	pk, err := noise.KeyFromHex(hexStr)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}

	kp, err := noise.NewKeyPair(pk)
	if err != nil {
		return "", fmt.Errorf("derive public key: %w", err)
	}

	return hex.EncodeToString(kp.Public[:]), nil
}

// GenerateKey generates a new keypair and writes it to the current context.
// Returns the hex-encoded public key.
func GenerateKey(baseDir, ctxName string) (string, error) {
	if ctxName == "" {
		var err error
		ctxName, err = CurrentContextName(baseDir)
		if err != nil {
			return "", err
		}
	}

	kp, err := noise.GenerateKeyPair()
	if err != nil {
		return "", fmt.Errorf("generate keypair: %w", err)
	}

	keyPath := filepath.Join(ContextDir(baseDir, ctxName), "private.key")
	keyHex := hex.EncodeToString(kp.Private[:]) + "\n"
	if err := os.WriteFile(keyPath, []byte(keyHex), 0600); err != nil {
		return "", fmt.Errorf("write private key: %w", err)
	}

	return hex.EncodeToString(kp.Public[:]), nil
}
