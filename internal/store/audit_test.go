package store

import (
	"path/filepath"
	"testing"
)

// RecordAudit/ListAudit back the admin-facing audit trail (cf.
// server/audit.go) -- these tests cover the two things that actually
// matter: entries persist with all their fields intact, and ListAudit
// returns them newest-first (an audit log read in insertion order is
// the wrong way around for "what just happened").

func TestAuditRecordAndList(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	if err := s.RecordAudit("alice", "stack.deploy", "my-stack", ""); err != nil {
		t.Fatalf("record audit 1: %v", err)
	}
	if err := s.RecordAudit("bob", "stack.delete", "other-stack", "reason: cleanup"); err != nil {
		t.Fatalf("record audit 2: %v", err)
	}

	entries, err := s.ListAudit(10)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	// Newest first.
	if entries[0].Username != "bob" || entries[0].Action != "stack.delete" || entries[0].Target != "other-stack" || entries[0].Detail != "reason: cleanup" {
		t.Errorf("entries[0] = %+v, want bob/stack.delete/other-stack/reason: cleanup", entries[0])
	}
	if entries[1].Username != "alice" || entries[1].Action != "stack.deploy" || entries[1].Target != "my-stack" {
		t.Errorf("entries[1] = %+v, want alice/stack.deploy/my-stack", entries[1])
	}
	if entries[0].CreatedAt == "" {
		t.Error("CreatedAt should be set")
	}
}

func TestAuditListRespectsLimit(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	for i := 0; i < 5; i++ {
		if err := s.RecordAudit("alice", "test.action", "target", ""); err != nil {
			t.Fatalf("record audit: %v", err)
		}
	}
	entries, err := s.ListAudit(3)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
}
