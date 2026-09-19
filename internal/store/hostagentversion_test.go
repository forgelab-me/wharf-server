package store

import (
	"path/filepath"
	"testing"
)

// SetHostAgentVersion is the write side of the per-agent "update
// available" badge (cf. server/versioncheck.go, hosts.html) -- these
// tests only cover that the store actually persists and returns it,
// through both GetHost and ListHosts, since a badge that silently
// stayed on the old version after a real update would be worse than no
// badge at all.

func TestSetHostAgentVersionRoundTrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	h, _, err := s.UpsertHostByFingerprint("test-host", "sha256:deadbeef")
	if err != nil {
		t.Fatalf("upsert host: %v", err)
	}
	if h.AgentVersion != "" {
		t.Fatalf("AgentVersion = %q, want empty before any state push", h.AgentVersion)
	}

	if err := s.SetHostAgentVersion(h.ID, "0.2.0"); err != nil {
		t.Fatalf("set host agent version: %v", err)
	}

	got, err := s.GetHost(h.ID)
	if err != nil {
		t.Fatalf("get host: %v", err)
	}
	if got.AgentVersion != "0.2.0" {
		t.Fatalf("GetHost AgentVersion = %q, want 0.2.0", got.AgentVersion)
	}

	all, err := s.ListHosts()
	if err != nil {
		t.Fatalf("list hosts: %v", err)
	}
	if len(all) != 1 || all[0].AgentVersion != "0.2.0" {
		t.Fatalf("ListHosts AgentVersion = %q, want 0.2.0", all[0].AgentVersion)
	}
}
