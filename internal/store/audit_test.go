package store

import (
	"path/filepath"
	"testing"
	"time"
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

func TestAuditRetentionRoundTrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	all, err := s.GetAuditRetentionAll()
	if err != nil {
		t.Fatalf("get retention: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("expected no retention configured yet, got %+v", all)
	}

	if err := s.SetAuditRetention("stack", 30); err != nil {
		t.Fatalf("set retention: %v", err)
	}
	if err := s.SetAuditRetention("user", 90); err != nil {
		t.Fatalf("set retention: %v", err)
	}
	all, err = s.GetAuditRetentionAll()
	if err != nil {
		t.Fatalf("get retention: %v", err)
	}
	if all["stack"] != 30 || all["user"] != 90 {
		t.Fatalf("retention = %+v, want stack=30 user=90", all)
	}

	// Re-setting an existing category updates it, not a second row.
	if err := s.SetAuditRetention("stack", 7); err != nil {
		t.Fatalf("update retention: %v", err)
	}
	all, err = s.GetAuditRetentionAll()
	if err != nil {
		t.Fatalf("get retention: %v", err)
	}
	if all["stack"] != 7 {
		t.Fatalf("retention[stack] = %d, want 7", all["stack"])
	}
	if len(all) != 2 {
		t.Fatalf("expected exactly 2 categories configured, got %d: %+v", len(all), all)
	}
}

// PruneAuditOlderThan backdates rows by writing created_at directly --
// RecordAudit always stamps "now", there's no public way to backdate an
// entry, so this reaches into the same package's own db handle.
func TestPruneAuditOlderThan(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	insert := func(action string, when time.Time) {
		t.Helper()
		_, err := s.db.Exec(
			`INSERT INTO audit_log (username, action, target, detail, created_at) VALUES (?, ?, '', '', ?)`,
			"alice", action, when.UTC().Format("2006-01-02 15:04:05"),
		)
		if err != nil {
			t.Fatalf("insert backdated entry: %v", err)
		}
	}

	old := time.Now().Add(-48 * time.Hour)
	recent := time.Now().Add(-1 * time.Hour)
	insert("stack.deploy", old)    // old, "stack" category -- should be pruned
	insert("stack.delete", recent) // recent, "stack" category -- should survive
	insert("user.create", old)     // old, different category -- untouched by a "stack" prune

	n, err := s.PruneAuditOlderThan("stack", time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("pruned %d rows, want 1", n)
	}

	entries, err := s.ListAudit(10)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d remaining entries, want 2", len(entries))
	}
	for _, e := range entries {
		if e.Action == "stack.deploy" {
			t.Error("old stack.deploy entry should have been pruned")
		}
	}
}
