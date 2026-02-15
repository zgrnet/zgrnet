//go:build windows

package cli

import (
	"os"
	"os/exec"
)

func setSysProcAttr(cmd *exec.Cmd) {
	// No Setsid equivalent needed on Windows
}

func execProcess(program, cfgPath string) error {
	cmd := exec.Command(program, "-c", cfgPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func signalTerminate(proc *os.Process) error {
	return proc.Kill()
}
