//go:build !windows

package cli

import (
	"os"
	"os/exec"
	"syscall"
)

func setSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

func execProcess(program, cfgPath string) error {
	return syscall.Exec(program, []string{"zgrnetd", "-c", cfgPath}, os.Environ())
}

func signalTerminate(proc *os.Process) error {
	return proc.Signal(syscall.SIGTERM)
}
