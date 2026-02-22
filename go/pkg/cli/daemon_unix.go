//go:build !windows

package cli

import (
	"os"
	"syscall"
)

func signalTerminate(proc *os.Process) error {
	return proc.Signal(syscall.SIGTERM)
}
