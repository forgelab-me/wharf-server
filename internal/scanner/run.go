package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const maxScannerOutput = 64 << 20

// limitedBuffer stops accepting data past its limit instead of growing without bound.
type limitedBuffer struct {
	buf   bytes.Buffer
	limit int
	over  bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > b.limit {
		b.over = true
		return 0, errors.New("output limit reached")
	}
	return b.buf.Write(p)
}

// scanEnv is the subprocess environment: a few variables of its own and the
// proxy settings, never the controller's, which holds the admin bootstrap
// credentials.
func scanEnv(home string, extra ...string) []string {
	env := []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + home}
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return append(env, extra...)
}

// run executes bin without a shell and returns its stdout. A failure carries
// the tail of stderr, which never includes the environment.
func run(ctx context.Context, bin string, args, env []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env
	configureCmd(cmd)
	stdout := &limitedBuffer{limit: maxScannerOutput}
	stderr := &limitedBuffer{limit: 1 << 20}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	if stdout.over {
		return nil, errors.New("the scanner's output is too large")
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("timed out: %w", ctx.Err())
		}
		return nil, fmt.Errorf("%s: %w", stderrTail(stderr.buf.String()), err)
	}
	return stdout.buf.Bytes(), nil
}

func stderrTail(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > 3 {
		lines = lines[len(lines)-3:]
	}
	return shorten(strings.Join(lines, " | "), 400)
}
