package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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

// PidfilePath returns the path to the pidfile for the given context.
func PidfilePath(baseDir, ctxName string) (string, error) {
	if ctxName == "" {
		var err error
		ctxName, err = CurrentContextName(baseDir)
		if err != nil {
			return "", err
		}
	}
	return filepath.Join(ContextDir(baseDir, ctxName), "data", "zigor.pid"), nil
}

// WritePidfile writes the current process PID to the context's pidfile.
func WritePidfile(baseDir, ctxName string, pid int) error {
	pidPath, err := PidfilePath(baseDir, ctxName)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(pidPath), 0700); err != nil {
		return fmt.Errorf("create pid dir: %w", err)
	}
	return os.WriteFile(pidPath, []byte(fmt.Sprintf("%d\n", pid)), 0644)
}

// ReadPidfile reads the PID from the context's pidfile.
// Returns 0 and an error if the pidfile doesn't exist or is invalid.
func ReadPidfile(baseDir, ctxName string) (int, error) {
	pidPath, err := PidfilePath(baseDir, ctxName)
	if err != nil {
		return 0, err
	}
	data, err := os.ReadFile(pidPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, fmt.Errorf("host is not running for context %q (no pidfile)", ctxName)
		}
		return 0, fmt.Errorf("read pidfile: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("invalid pidfile content: %w", err)
	}
	return pid, nil
}

// RemovePidfile removes the context's pidfile.
func RemovePidfile(baseDir, ctxName string) {
	pidPath, _ := PidfilePath(baseDir, ctxName)
	if pidPath != "" {
		os.Remove(pidPath)
	}
}

// Down sends SIGTERM to the running host process.
func Down(baseDir, ctxName string) error {
	if ctxName == "" {
		var err error
		ctxName, err = CurrentContextName(baseDir)
		if err != nil {
			return err
		}
	}

	pid, err := ReadPidfile(baseDir, ctxName)
	if err != nil {
		return err
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}

	if err := signalTerminate(proc); err != nil {
		if errors.Is(err, syscall.ESRCH) || errors.Is(err, os.ErrProcessDone) {
			RemovePidfile(baseDir, ctxName)
			return fmt.Errorf("host was not running (stale pidfile cleaned up)")
		}
		return fmt.Errorf("terminate pid %d: %w", pid, err)
	}

	RemovePidfile(baseDir, ctxName)
	return nil
}

// ResolveAPIAddr determines the host API address from context config.
func ResolveAPIAddr(baseDir, ctxName, override string) string {
	if override != "" {
		return override
	}

	cfgPath, err := ContextConfigPath(baseDir, ctxName)
	if err == nil {
		data, err := os.ReadFile(cfgPath)
		if err == nil {
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
