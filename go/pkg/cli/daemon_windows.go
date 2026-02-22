//go:build windows

package cli

import (
	"os"
)

func signalTerminate(proc *os.Process) error {
	return proc.Kill()
}
