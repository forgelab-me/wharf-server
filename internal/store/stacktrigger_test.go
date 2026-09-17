package store

import (
	"path/filepath"
	"testing"
)

// UpdateStackTrigger is the write side of letting a stack's trigger mode
// be changed after creation (previously only settable at creation time).
// The handler that calls it (setStackTriggerHandler, cf. server/main.go)
// is responsible for deciding what pollSchedule/webhookSecret to pass --
// these tests only cover that the store actually persists whatever it's
// given, exactly, including the "preserve the old value" case a caller
// relies on when toggling back to a mode the stack was already in.

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func newTestStack(t *testing.T, s *Store, id string) Stack {
	t.Helper()
	st := Stack{ID: id, Name: id, SourceType: "git", Repo: "https://example.invalid/x.git", Branch: "main", Trigger: "manual"}
	if err := s.CreateStack(st); err != nil {
		t.Fatalf("create stack: %v", err)
	}
	return st
}

func TestUpdateStackTriggerSwitchesToPolling(t *testing.T) {
	s := newTestStore(t)
	newTestStack(t, s, "stack1")

	if err := s.UpdateStackTrigger("stack1", "polling", "*/15 * * * *", ""); err != nil {
		t.Fatalf("update trigger: %v", err)
	}
	got, err := s.GetStack("stack1")
	if err != nil {
		t.Fatalf("get stack: %v", err)
	}
	if got.Trigger != "polling" {
		t.Fatalf("Trigger = %q, want polling", got.Trigger)
	}
	if got.PollSchedule != "*/15 * * * *" {
		t.Fatalf("PollSchedule = %q, want */15 * * * *", got.PollSchedule)
	}
}

func TestUpdateStackTriggerSwitchesToWebhook(t *testing.T) {
	s := newTestStore(t)
	newTestStack(t, s, "stack1")

	if err := s.UpdateStackTrigger("stack1", "webhook", "", "sekret123"); err != nil {
		t.Fatalf("update trigger: %v", err)
	}
	got, err := s.GetStack("stack1")
	if err != nil {
		t.Fatalf("get stack: %v", err)
	}
	if got.Trigger != "webhook" {
		t.Fatalf("Trigger = %q, want webhook", got.Trigger)
	}
	if got.WebhookSecret != "sekret123" {
		t.Fatalf("WebhookSecret = %q, want sekret123", got.WebhookSecret)
	}
}

// A stack switching back to a mode it was already in (e.g. webhook ->
// manual -> webhook) should get its old schedule/secret back exactly --
// the handler passes the existing value through rather than regenerating,
// so this is really testing that UpdateStackTrigger doesn't clobber
// whatever it's handed.
func TestUpdateStackTriggerPreservesValueOnRoundTrip(t *testing.T) {
	s := newTestStore(t)
	newTestStack(t, s, "stack1")

	if err := s.UpdateStackTrigger("stack1", "webhook", "", "original-secret"); err != nil {
		t.Fatalf("switch to webhook: %v", err)
	}
	if err := s.UpdateStackTrigger("stack1", "manual", "", "original-secret"); err != nil {
		t.Fatalf("switch to manual: %v", err)
	}
	if err := s.UpdateStackTrigger("stack1", "webhook", "", "original-secret"); err != nil {
		t.Fatalf("switch back to webhook: %v", err)
	}
	got, err := s.GetStack("stack1")
	if err != nil {
		t.Fatalf("get stack: %v", err)
	}
	if got.WebhookSecret != "original-secret" {
		t.Fatalf("WebhookSecret = %q, want original-secret preserved across round trip", got.WebhookSecret)
	}
}
