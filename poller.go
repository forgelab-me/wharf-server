// Polling trigger for Git stacks — kept separate from the already-large
// main.go. The controller does the checking itself: `git ls-remote` is
// cheap, read-only, and needs no clone, so there's no reason to route it
// through an agent. The controller already holds every Git credential in
// its custodian for exactly this kind of use (cf. resolveGitAuth in
// main.go, also used by commandsHandler).
package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/forgelab-me/wharf-server/internal/store"
	"github.com/robfig/cron/v3"
)

// pollRegistry tracks each polling-mode stack's live cron.EntryID --
// robfig/cron has no "find the entry for this stack" lookup of its own,
// so this is what lets registerPolling remove a stack's old schedule
// before adding its new one instead of accumulating a duplicate entry
// on every edit. Same mutex-guarded-map shape as tunnelRegistry
// (tunnel.go), for the same reason: read/written from HTTP handlers and
// the cron goroutine concurrently.
type pollRegistry struct {
	mu      sync.Mutex
	entries map[string]cron.EntryID
}

func newPollRegistry() *pollRegistry {
	return &pollRegistry{entries: map[string]cron.EntryID{}}
}

// registerPolling (re-)adds a cron entry for a polling-mode stack,
// replacing whichever entry it already had -- safe to call while the
// scheduler is already running (robfig/cron's AddFunc/Remove are both
// designed for that) at controller startup, right after a polling stack
// is created, or whenever its schedule is edited.
func registerPolling(a *app, st store.Stack) error {
	a.polls.mu.Lock()
	oldID, hadOld := a.polls.entries[st.ID]
	a.polls.mu.Unlock()
	if hadOld {
		a.cron.Remove(oldID)
	}

	id, err := a.cron.AddFunc(st.PollSchedule, func() { pollStack(a, st.ID) })
	if err != nil {
		return fmt.Errorf("register polling schedule %q for stack %q: %w", st.PollSchedule, st.ID, err)
	}
	a.polls.mu.Lock()
	a.polls.entries[st.ID] = id
	a.polls.mu.Unlock()
	return nil
}

// pollStack checks one stack's remote HEAD and enqueues a deploy if it
// moved. Errors are logged and swallowed — a transient network hiccup
// shouldn't crash the scheduler or take down polling for other stacks.
func pollStack(a *app, stackID string) {
	st, err := a.store.GetStack(stackID)
	if err != nil {
		log.Println("poll: load stack", stackID, "failed:", err)
		return
	}

	sha, err := lsRemoteSha(a, st)
	if err != nil {
		log.Println("poll:", st.ID, "ls-remote failed:", err)
		return
	}

	// A brand-new stack has never been polled (LastPolledSHA == ""), so
	// every commit currently on the branch looks "new" by comparison --
	// deploying right then, before the admin has had a chance to add the
	// deploy key to the Git host or push encrypted secrets, was a real
	// footgun found in practice. The very first poll only establishes
	// the baseline; only a commit seen *after* that baseline triggers a
	// deploy. "Deploy now" or "Check now" still work immediately if the
	// admin is ready sooner.
	firstPoll := st.LastPolledSHA == ""
	changed := sha != st.LastPolledSHA
	if err := a.store.RecordPoll(st.ID, sha); err != nil {
		log.Println("poll: record poll for", st.ID, "failed:", err)
		return
	}
	if !changed || firstPoll {
		return
	}

	log.Println("poll:", st.ID, "new commit", sha, "— enqueueing deploy")
	if _, err := a.store.EnqueueDeployment(st.ID, st.Host, "polling", "up"); err != nil {
		log.Println("poll: enqueue deploy for", st.ID, "failed:", err)
	}
}

// lsRemoteSha authenticates the same way commandsHandler resolves a
// credential for the agent (resolveGitAuth), then runs it locally as
// `git ls-remote` instead of shipping it off to be cloned.
func lsRemoteSha(a *app, st store.Stack) (string, error) {
	authKind, sshPriv, httpUser, httpPass, err := a.resolveGitAuth(st)
	if err != nil {
		return "", fmt.Errorf("resolve credential: %w", err)
	}

	var gitArgs []string
	env := os.Environ()

	switch authKind {
	case "http_password":
		auth := base64.StdEncoding.EncodeToString([]byte(httpUser + ":" + httpPass))
		gitArgs = append(gitArgs, "-c", "http.extraHeader=Authorization: Basic "+auth)
	default: // "ssh_key"
		keyFile, err := os.CreateTemp("", "wharf-poll-key-*")
		if err != nil {
			return "", fmt.Errorf("create temp key file: %w", err)
		}
		keyPath := keyFile.Name()
		defer os.Remove(keyPath) // never persisted beyond this check
		if err := keyFile.Chmod(0o600); err != nil {
			keyFile.Close()
			return "", fmt.Errorf("chmod temp key file: %w", err)
		}
		if _, err := keyFile.WriteString(sshPriv); err != nil {
			keyFile.Close()
			return "", fmt.Errorf("write temp key file: %w", err)
		}
		keyFile.Close()

		// Same known, documented gap as the agent's clone path — no host
		// key verification. Cf. ARCHITECTURE.md.
		sshCommand := fmt.Sprintf("ssh -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null", keyPath)
		env = append(env, "GIT_SSH_COMMAND="+sshCommand)
	}

	gitArgs = append(gitArgs, "ls-remote", "--heads", st.Repo, st.Branch)
	cmd := exec.Command("git", gitArgs...)
	cmd.Env = env

	// stdout only: SSH's own diagnostics (e.g. the "Warning: Permanently
	// added ... to the list of known hosts" line, still printed even with
	// UserKnownHostsFile=/dev/null) land on stderr and must never be
	// mistaken for the sha — a prior CombinedOutput() version parsed that
	// warning as the commit sha and silently corrupted last_polled_sha.
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git ls-remote: %s: %w", strings.TrimSpace(stderr.String()), err)
	}

	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return "", fmt.Errorf("branch %q not found at %s", st.Branch, st.Repo)
	}
	return fields[0], nil
}

// cronParser validates a 5-field standard cron expression (minute hour
// day month weekday, no seconds field) at stack-creation time.
var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
