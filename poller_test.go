package main

import (
	"testing"

	"github.com/forgelab-me/wharf-server/internal/store"
	"github.com/robfig/cron/v3"
)

// Only exercises the registry/cron bookkeeping (registerPolling,
// unregisterPolling) -- no real network, no real store, since neither
// function touches either. What matters here is that switching a stack
// out of polling mode actually removes its cron entry rather than
// leaving a stale schedule firing forever underneath a stack the UI now
// calls "manual"/"webhook".

func newTestApp() *app {
	return &app{polls: newPollRegistry(), cron: cron.New()}
}

func TestUnregisterPollingRemovesEntry(t *testing.T) {
	a := newTestApp()
	st := store.Stack{ID: "stack1", PollSchedule: "*/15 * * * *"}

	if err := registerPolling(a, st); err != nil {
		t.Fatalf("registerPolling: %v", err)
	}
	a.polls.mu.Lock()
	_, had := a.polls.entries["stack1"]
	a.polls.mu.Unlock()
	if !had {
		t.Fatal("expected a cron entry to be registered")
	}

	unregisterPolling(a, "stack1")

	a.polls.mu.Lock()
	_, stillHad := a.polls.entries["stack1"]
	a.polls.mu.Unlock()
	if stillHad {
		t.Fatal("expected the cron entry to be removed after unregisterPolling")
	}
	if len(a.cron.Entries()) != 0 {
		t.Fatalf("expected 0 live cron entries after unregister, got %d", len(a.cron.Entries()))
	}
}

// unregisterPolling on a stack that was never polling must be a no-op,
// not a panic/error -- the trigger handler calls it unconditionally for
// every switch to manual/webhook, whether or not the stack was polling
// before.
func TestUnregisterPollingNoopWhenNeverRegistered(t *testing.T) {
	a := newTestApp()
	unregisterPolling(a, "never-existed")
	if len(a.cron.Entries()) != 0 {
		t.Fatalf("expected 0 live cron entries, got %d", len(a.cron.Entries()))
	}
}

// registerPolling called twice for the same stack (e.g. polling ->
// manual -> polling, or just re-saving the same schedule) must replace
// the old entry, not accumulate a second one that would poll twice as
// often.
func TestRegisterPollingReplacesOldEntry(t *testing.T) {
	a := newTestApp()
	st := store.Stack{ID: "stack1", PollSchedule: "*/15 * * * *"}
	if err := registerPolling(a, st); err != nil {
		t.Fatalf("first registerPolling: %v", err)
	}
	st.PollSchedule = "0 * * * *"
	if err := registerPolling(a, st); err != nil {
		t.Fatalf("second registerPolling: %v", err)
	}
	if len(a.cron.Entries()) != 1 {
		t.Fatalf("expected exactly 1 live cron entry after re-registering, got %d", len(a.cron.Entries()))
	}
}
