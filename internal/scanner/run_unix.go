//go:build unix

package scanner

import (
	"os/exec"
	"syscall"
	"time"
)

// configureCmd makes a timeout end the scanner and everything it started:
// the child gets its own process group, which is what gets killed.
func configureCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 3 * time.Second
}
