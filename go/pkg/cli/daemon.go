package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// ShowConfig prints the config.yaml contents for the current context.
func ShowConfig(baseDir, ctxName string) (string, error) {
	path, err := ContextConfigPath(baseDir, ctxName)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read config: %w", err)
	}
	return string(data), nil
}

// EditConfig opens the config in $EDITOR.
func EditConfig(baseDir, ctxName string) error {
	path, err := ContextConfigPath(baseDir, ctxName)
	if err != nil {
		return err
	}

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}

	cmd := exec.Command(editor, path)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Up starts zgrnetd with the current context's config.
// If daemon is true, the process is started in the background.
func Up(baseDir, ctxName string, daemon bool) error {
	cfgPath, err := ContextConfigPath(baseDir, ctxName)
	if err != nil {
		return err
	}

	// Find zgrnetd binary — look in PATH and next to the zgrnet binary
	zgrnetd, err := findZgrnetd()
	if err != nil {
		return err
	}

	if daemon {
		return startDaemon(zgrnetd, cfgPath, baseDir, ctxName)
	}

	// Foreground: exec replaces current process
	return execProcess(zgrnetd, cfgPath)
}

// Down sends SIGTERM to the running zgrnetd process.
func Down(baseDir, ctxName string) error {
	if ctxName == "" {
		var err error
		ctxName, err = CurrentContextName(baseDir)
		if err != nil {
			return err
		}
	}

	pidPath := filepath.Join(ContextDir(baseDir, ctxName), "data", "zgrnetd.pid")
	data, err := os.ReadFile(pidPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no running zgrnetd found for context %q (no pid file)", ctxName)
		}
		return fmt.Errorf("read pid file: %w", err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return fmt.Errorf("invalid pid file: %w", err)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}

	if err := signalTerminate(proc); err != nil {
		return fmt.Errorf("terminate pid %d: %w", pid, err)
	}

	// Clean up pid file
	os.Remove(pidPath)

	return nil
}

// findZgrnetd locates the zgrnetd binary.
func findZgrnetd() (string, error) {
	// Try PATH first
	if path, err := exec.LookPath("zgrnetd"); err == nil {
		return path, nil
	}

	// Try next to the current executable
	self, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(self)
		candidate := filepath.Join(dir, "zgrnetd")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("zgrnetd not found in PATH or alongside this binary")
}

// startDaemon starts zgrnetd in the background and writes a PID file.
func startDaemon(zgrnetd, cfgPath, baseDir, ctxName string) error {
	if ctxName == "" {
		var err error
		ctxName, err = CurrentContextName(baseDir)
		if err != nil {
			return err
		}
	}

	cmd := exec.Command(zgrnetd, "-c", cfgPath)
	cmd.Stdout = nil
	cmd.Stderr = nil
	setSysProcAttr(cmd)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start zgrnetd: %w", err)
	}

	// Write PID file
	pidPath := filepath.Join(ContextDir(baseDir, ctxName), "data", "zgrnetd.pid")
	os.MkdirAll(filepath.Dir(pidPath), 0700)
	pidStr := fmt.Sprintf("%d\n", cmd.Process.Pid)
	if err := os.WriteFile(pidPath, []byte(pidStr), 0644); err != nil {
		return fmt.Errorf("write pid file: %w", err)
	}

	return nil
}

// ResolveAPIAddr determines the zgrnetd API address from context config.
func ResolveAPIAddr(baseDir, ctxName, override string) string {
	if override != "" {
		return override
	}

	// Try to read tun_ipv4 from config
	cfgPath, err := ContextConfigPath(baseDir, ctxName)
	if err == nil {
		data, err := os.ReadFile(cfgPath)
		if err == nil {
			// Quick parse: find tun_ipv4 line
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "tun_ipv4:") {
					ip := strings.Trim(strings.TrimPrefix(line, "tun_ipv4:"), " \"'")
					if ip != "" {
						return ip + ":80"
					}
				}
			}
		}
	}

	return "100.64.0.1:80"
}
