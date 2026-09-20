package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/forgelab-me/wharf-server/internal/keys"
	"github.com/forgelab-me/wharf-server/internal/store"
)

func TestTruncateForNotify(t *testing.T) {
	short := "all good"
	if got := truncateForNotify(short); got != short {
		t.Errorf("short string should pass through unchanged, got %q", got)
	}
	long := make([]byte, 500)
	for i := range long {
		long[i] = 'x'
	}
	got := truncateForNotify(string(long))
	if len(got) != 303 { // 300 bytes + "…", which is 3 bytes in UTF-8
		t.Errorf("truncated length = %d, want 303 (300 + 3-byte ellipsis)", len(got))
	}
}

func TestSendNotificationPayloadShapes(t *testing.T) {
	cases := []struct {
		kind            string
		wantContentType string
		checkBody       func(t *testing.T, body []byte)
	}{
		{"slack", "application/json", func(t *testing.T, body []byte) {
			var m map[string]string
			if err := json.Unmarshal(body, &m); err != nil {
				t.Fatalf("slack body not JSON: %v", err)
			}
			if m["text"] != "hello" {
				t.Errorf("slack text = %q, want hello", m["text"])
			}
		}},
		{"discord", "application/json", func(t *testing.T, body []byte) {
			var m map[string]string
			if err := json.Unmarshal(body, &m); err != nil {
				t.Fatalf("discord body not JSON: %v", err)
			}
			if m["content"] != "hello" {
				t.Errorf("discord content = %q, want hello", m["content"])
			}
		}},
		{"ntfy", "text/plain; charset=utf-8", func(t *testing.T, body []byte) {
			if string(body) != "hello" {
				t.Errorf("ntfy body = %q, want hello", body)
			}
		}},
		{"generic", "application/json", func(t *testing.T, body []byte) {
			var m map[string]string
			if err := json.Unmarshal(body, &m); err != nil {
				t.Fatalf("generic body not JSON: %v", err)
			}
			if m["text"] != "hello" {
				t.Errorf("generic text = %q, want hello", m["text"])
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.kind, func(t *testing.T) {
			var gotContentType string
			var gotBody []byte
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotContentType = r.Header.Get("Content-Type")
				gotBody, _ = io.ReadAll(r.Body)
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			if err := sendNotification(c.kind, srv.URL, "hello"); err != nil {
				t.Fatalf("sendNotification: %v", err)
			}
			if gotContentType != c.wantContentType {
				t.Errorf("Content-Type = %q, want %q", gotContentType, c.wantContentType)
			}
			c.checkBody(t, gotBody)
		})
	}
}

func TestSendNotificationNonSuccessStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if err := sendNotification("generic", srv.URL, "hello"); err == nil {
		t.Fatal("expected an error for a 500 response, got nil")
	}
}

// newTestNotifyApp builds a minimal *app backed by real temp SQLite
// stores -- enough for checkNotifiableEvents (store + tunnels +
// notifyState), no HTTP server or cron involved.
func newTestNotifyApp(t *testing.T) *app {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "wharf.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	kc, err := keys.Open(filepath.Join(t.TempDir(), "keys.db"))
	if err != nil {
		t.Fatalf("open keys: %v", err)
	}
	t.Cleanup(func() { kc.Close() })
	return &app{store: st, keys: kc, tunnels: newTunnelRegistry(), notifyState: newNotifyState()}
}

// withVersions temporarily overrides the package-level version/latest
// globals for a test, restoring them on cleanup -- both are read
// directly by checkNotifiableEvents/semverLess, and tests must not leak
// state into each other or into other test files that also touch them
// (cf. versioncheck_test.go).
func withVersions(t *testing.T, runningVersion, latestServer, latestAgent string) {
	t.Helper()
	prevVersion := version
	prevServer, prevAgent := latest.get()
	version = runningVersion
	latest.set(latestServer, latestAgent)
	t.Cleanup(func() {
		version = prevVersion
		latest.set(prevServer, prevAgent)
	})
}

func TestCheckNotifiableEventsHostDownThenRecovers(t *testing.T) {
	a := newTestNotifyApp(t)
	withVersions(t, "dev", "", "")

	h, _, err := a.store.UpsertHostByFingerprint("test-host", "sha256:deadbeef")
	if err != nil {
		t.Fatalf("upsert host: %v", err)
	}
	if err := a.store.ApproveHost(h.ID, "admin"); err != nil {
		t.Fatalf("approve host: %v", err)
	}
	// Never registered in a.tunnels -- "down" from the very first check.

	checkNotifiableEvents(a)
	a.notifyState.mu.Lock()
	down := a.notifyState.hostDown[h.ID]
	a.notifyState.mu.Unlock()
	if !down {
		t.Fatal("expected host to be marked down after first check")
	}

	// A second check while still down must not need to do anything new --
	// the map entry simply stays, which is what "no repeat notification"
	// looks like from here (the actual a.notify call is separately
	// unobservable without a configured target, which is the point: this
	// test is about the state transition, not the network call).
	checkNotifiableEvents(a)
	a.notifyState.mu.Lock()
	stillDown := a.notifyState.hostDown[h.ID]
	a.notifyState.mu.Unlock()
	if !stillDown {
		t.Fatal("host should still be tracked as down")
	}

	// Reconnect: register a live tunnel, then the next check should clear
	// the down flag.
	a.tunnels.set(h.ID, &tunnelConn{pending: map[string]chan tunnelMessage{}})
	checkNotifiableEvents(a)
	a.notifyState.mu.Lock()
	_, stillTracked := a.notifyState.hostDown[h.ID]
	a.notifyState.mu.Unlock()
	if stillTracked {
		t.Fatal("expected the down flag to clear once the host reconnected")
	}
}

func TestCheckNotifiableEventsAgentOutdatedThenUpdated(t *testing.T) {
	a := newTestNotifyApp(t)
	withVersions(t, "dev", "", "0.5.0")

	h, _, err := a.store.UpsertHostByFingerprint("test-host", "sha256:deadbeef")
	if err != nil {
		t.Fatalf("upsert host: %v", err)
	}
	if err := a.store.ApproveHost(h.ID, "admin"); err != nil {
		t.Fatalf("approve host: %v", err)
	}
	a.tunnels.set(h.ID, &tunnelConn{pending: map[string]chan tunnelMessage{}}) // connected, so only the version matters
	if err := a.store.SetHostAgentVersion(h.ID, "0.4.0"); err != nil {
		t.Fatalf("set agent version: %v", err)
	}

	checkNotifiableEvents(a)
	a.notifyState.mu.Lock()
	outdated := a.notifyState.agentOutdated[h.ID]
	a.notifyState.mu.Unlock()
	if !outdated {
		t.Fatal("expected agent to be marked outdated")
	}

	// Agent updates to the latest version -- the flag should clear.
	if err := a.store.SetHostAgentVersion(h.ID, "0.5.0"); err != nil {
		t.Fatalf("set agent version: %v", err)
	}
	checkNotifiableEvents(a)
	a.notifyState.mu.Lock()
	_, stillTracked := a.notifyState.agentOutdated[h.ID]
	a.notifyState.mu.Unlock()
	if stillTracked {
		t.Fatal("expected the outdated flag to clear once the agent updated")
	}
}

func TestCheckNotifiableEventsServerUpdateNotifiesOnce(t *testing.T) {
	a := newTestNotifyApp(t)
	withVersions(t, "0.1.0", "0.2.0", "")

	checkNotifiableEvents(a)
	a.notifyState.mu.Lock()
	notified := a.notifyState.serverUpdateNotified
	a.notifyState.mu.Unlock()
	if !notified {
		t.Fatal("expected serverUpdateNotified to be set")
	}

	// It never resets, even across many more ticks -- the running
	// version can't change without a restart, so re-notifying forever
	// would just be repeated noise for something that hasn't changed.
	checkNotifiableEvents(a)
	checkNotifiableEvents(a)
	a.notifyState.mu.Lock()
	stillNotified := a.notifyState.serverUpdateNotified
	a.notifyState.mu.Unlock()
	if !stillNotified {
		t.Fatal("serverUpdateNotified should remain true")
	}
}
