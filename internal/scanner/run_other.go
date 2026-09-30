//go:build !unix

package scanner

import (
	"os/exec"
	"time"
)

func configureCmd(cmd *exec.Cmd) { cmd.WaitDelay = 3 * time.Second }
