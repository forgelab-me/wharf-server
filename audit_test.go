package main

import (
	"path/filepath"
	"testing"

	"github.com/forgelab-me/wharf-server/internal/store"
)

// PruneAuditOlderThan's actual deletion behavior (including backdated
// rows) is covered at the store level (internal/store/audit_test.go,
// which can reach the raw db handle to backdate an entry). This is the
// orchestration half: pruneAuditLog reads whatever retention is
// configured and drives the store call correctly for each category --
// exercised here against a real store, with real (recent) entries that
// no correct retention setting should ever delete.
func TestPruneAuditLogIsANoopWithNothingConfigured(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "wharf.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.RecordAudit("alice", "stack.deploy", "web", ""); err != nil {
		t.Fatalf("record audit: %v", err)
	}

	pruneAuditLog(&app{store: st})

	entries, err := st.ListAudit(10)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries after pruning with nothing configured, want 1 (untouched)", len(entries))
	}
}

func TestPruneAuditLogLeavesRecentEntriesAlone(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "wharf.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	if err := st.RecordAudit("alice", "stack.deploy", "web", ""); err != nil {
		t.Fatalf("record audit: %v", err)
	}
	if err := st.RecordAudit("alice", "user.create", "bob", ""); err != nil {
		t.Fatalf("record audit: %v", err)
	}
	// A real, short retention on a category whose only entry was just
	// created a moment ago -- correct behavior is to leave it alone
	// (it isn't older than 1 day yet), not delete on sight.
	if err := st.SetAuditRetention("stack", 1); err != nil {
		t.Fatalf("set retention: %v", err)
	}
	// "user" stays at the implicit default (forever, no row at all).

	pruneAuditLog(&app{store: st})

	entries, err := st.ListAudit(10)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2 (both too recent to prune)", len(entries))
	}
}
