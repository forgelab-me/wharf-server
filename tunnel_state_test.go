package main

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/forgelab-me/wharf-server/internal/store"
)

func newStateFixture(t *testing.T) (*app, store.Host) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "wharf.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	host, _, err := st.UpsertHostByFingerprint("h1", "sha256:1")
	if err != nil {
		t.Fatal(err)
	}
	return &app{store: st}, host
}

func statePush() tunnelMessage {
	return tunnelMessage{
		Type:       "state",
		Containers: []containerReport{{ID: "c1", Name: "web", Image: "nginx:1", State: "running", ImageID: "aaaaaaaaaaaa"}},
		Images:     []imageReport{{ID: "aaaaaaaaaaaa", Repository: "nginx", Tag: "1", Digest: "sha256:aaa"}},
		Volumes:    []volumeReport{{Name: "data", Driver: "local"}},
		Networks:   []networkReport{{Name: "bridge", Driver: "bridge", Scope: "local"}},
		Version:    "0.6.0",
		Arch:       "amd64",
	}
}

func TestApplyStateStoresEverythingTheFirstTime(t *testing.T) {
	a, host := newStateFixture(t)
	a.applyState(host.ID, statePush(), stateCache{})

	if c, _ := a.store.ListHostContainers(); len(c) != 1 || c[0].ImageID != "aaaaaaaaaaaa" {
		t.Errorf("containers = %+v", c)
	}
	if i, _ := a.store.ListHostImages(); len(i) != 1 || i[0].Digest != "sha256:aaa" {
		t.Errorf("images = %+v", i)
	}
	if v, _ := a.store.ListHostVolumes(); len(v) != 1 {
		t.Errorf("volumes = %+v", v)
	}
	if n, _ := a.store.ListHostNetworks(); len(n) != 1 {
		t.Errorf("networks = %+v", n)
	}
	if h, _ := a.store.GetHost(host.ID); h.AgentVersion != "0.6.0" {
		t.Errorf("agent version = %q", h.AgentVersion)
	}
	if arch, _ := a.store.HostArch(host.ID); arch != "amd64" {
		t.Errorf("arch = %q", arch)
	}
}

// An unchanged push must not touch the database. The test tampers with the
// stored rows: a rewrite would put the reported values back.
func TestApplyStateSkipsAnUnchangedPush(t *testing.T) {
	a, host := newStateFixture(t)
	cache := stateCache{}
	a.applyState(host.ID, statePush(), cache)

	a.store.ReplaceHostContainers(host.ID, []store.HostContainer{{HostID: host.ID, ContainerID: "c1", Name: "tampered"}})
	a.store.SetHostArch(host.ID, "tampered")

	a.applyState(host.ID, statePush(), cache)
	if c, _ := a.store.ListHostContainers(); len(c) != 1 || c[0].Name != "tampered" {
		t.Fatalf("an identical push rewrote the containers: %+v", c)
	}
	if arch, _ := a.store.HostArch(host.ID); arch != "tampered" {
		t.Fatalf("an identical push rewrote the architecture: %q", arch)
	}
}

func TestApplyStateRewritesOnlyWhatChanged(t *testing.T) {
	a, host := newStateFixture(t)
	cache := stateCache{}
	a.applyState(host.ID, statePush(), cache)

	a.store.ReplaceHostContainers(host.ID, []store.HostContainer{{HostID: host.ID, ContainerID: "c1", Name: "tampered"}})
	a.store.ReplaceHostVolumes(host.ID, []store.HostVolume{{HostID: host.ID, Name: "tampered-volume"}})

	push := statePush()
	push.Containers[0].State = "exited" // only the containers changed
	a.applyState(host.ID, push, cache)

	c, _ := a.store.ListHostContainers()
	if len(c) != 1 || c[0].Name != "web" || c[0].State != "exited" {
		t.Errorf("a changed table must be rewritten: %+v", c)
	}
	if v, _ := a.store.ListHostVolumes(); len(v) != 1 || v[0].Name != "tampered-volume" {
		t.Errorf("an unchanged table must be left alone: %+v", v)
	}
}

func TestApplyStateAnotherConnectionStartsFromScratch(t *testing.T) {
	a, host := newStateFixture(t)
	a.applyState(host.ID, statePush(), stateCache{})
	a.store.ReplaceHostContainers(host.ID, []store.HostContainer{{HostID: host.ID, ContainerID: "c1", Name: "tampered"}})

	a.applyState(host.ID, statePush(), stateCache{}) // a reconnect: no memory of what was written
	if c, _ := a.store.ListHostContainers(); len(c) != 1 || c[0].Name != "web" {
		t.Fatalf("the first push of a connection must always be written: %+v", c)
	}
}

func TestApplyStateDoesNotRememberAFailedWrite(t *testing.T) {
	a, host := newStateFixture(t)
	cache := stateCache{}

	a.store.Close() // every write fails from here on
	a.applyState(host.ID, statePush(), cache)
	if len(cache) != 0 {
		t.Fatalf("a failed write was remembered, the next push would be skipped: %v", cache)
	}
}

func TestStateCacheUnchanged(t *testing.T) {
	c := stateCache{}
	hash, same := c.unchanged("t", []string{"a"})
	if same || hash == "" {
		t.Fatalf("nothing remembered yet: %q %v", hash, same)
	}
	c["t"] = hash
	if _, same := c.unchanged("t", []string{"a"}); !same {
		t.Error("the same content must be recognized")
	}
	if _, same := c.unchanged("t", []string{"a", "b"}); same {
		t.Error("different content must not be")
	}
	if _, same := c.unchanged("other", []string{"a"}); same {
		t.Error("tables are remembered separately")
	}
}

func TestRetryOnBusy(t *testing.T) {
	defer func(old func(int)) { busyBackoff = old }(busyBackoff)
	busyBackoff = func(int) {}
	busy := errors.New("replace host images: clear old: database is locked (5) (SQLITE_BUSY)")

	calls := 0
	err := retryOnBusy(func() error {
		calls++
		if calls < 3 {
			return busy
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Errorf("a busy database must be retried until it frees up: err=%v calls=%d", err, calls)
	}

	calls = 0
	other := errors.New("UNIQUE constraint failed")
	if err := retryOnBusy(func() error { calls++; return other }); err != other || calls != 1 {
		t.Errorf("any other error must return at once: err=%v calls=%d", err, calls)
	}

	calls = 0
	if err := retryOnBusy(func() error { calls++; return busy }); err == nil || calls != 4 {
		t.Errorf("a database that stays busy gives up after four attempts: err=%v calls=%d", err, calls)
	}
}
