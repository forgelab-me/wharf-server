package main

import (
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/forgelab-me/wharf-server/internal/store"
)

// removeTestFixture wires up a real temp-file store with one host and
// one container row -- everything removeContainerHandler reads before
// it ever needs a live tunnel. containerID is fixed across tests so
// each test just varies the container's own state/stack_id.
const removeTestContainerID = "c0ffee00"

func removeTestFixture(t *testing.T, state, stackID string) *app {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "wharf.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	host, _, err := st.UpsertHostByFingerprint("test-host", "sha256:deadbeef")
	if err != nil {
		t.Fatalf("upsert host: %v", err)
	}

	err = st.ReplaceHostContainers(host.ID, []store.HostContainer{
		{
			HostID:      host.ID,
			ContainerID: removeTestContainerID,
			Name:        "faketest-web",
			Image:       "nginx:alpine",
			State:       state,
			Status:      state,
			StackID:     stackID,
		},
	})
	if err != nil {
		t.Fatalf("seed host container: %v", err)
	}

	// Deliberately no tunnel registered -- every case below either
	// rejects before reaching the tunnel lookup, or (the "reaches the
	// tunnel" case) is expected to fail with "not connected", which is
	// exactly as far as a test without a real/fake agent can go.
	return &app{store: st, tunnels: newTunnelRegistry()}
}

// callRemove drives removeContainerHandler exactly like the router would
// (path value set the same way ServeMux populates it), and hands back
// the redirect's status and decoded error message for the caller to
// assert on.
func callRemove(t *testing.T, a *app) (status int, errMsg string) {
	t.Helper()
	req := httptest.NewRequest("POST", "/containers/"+removeTestContainerID+"/remove", nil)
	req.SetPathValue("id", removeTestContainerID)
	w := httptest.NewRecorder()
	a.removeContainerHandler(w, req)

	loc := w.Header().Get("Location")
	msg, err := url.QueryUnescape(loc)
	if err != nil {
		t.Fatalf("unescape Location %q: %v", loc, err)
	}
	return w.Code, msg
}

func TestRemoveContainerHandlerRefusesManagedStack(t *testing.T) {
	a := removeTestFixture(t, "exited", "traefik")
	if err := a.store.CreateStack(store.Stack{ID: "traefik", Name: "traefik"}); err != nil {
		t.Fatalf("create stack: %v", err)
	}

	status, msg := callRemove(t, a)
	if status != 303 {
		t.Fatalf("status = %d, want 303", status)
	}
	if !strings.Contains(msg, "undeploy the stack") {
		t.Fatalf("Location = %q, want an error steering toward undeploy", msg)
	}
}

func TestRemoveContainerHandlerRefusesRunningContainer(t *testing.T) {
	a := removeTestFixture(t, "running", "")

	status, msg := callRemove(t, a)
	if status != 303 {
		t.Fatalf("status = %d, want 303", status)
	}
	if !strings.Contains(msg, "stop the container") {
		t.Fatalf("Location = %q, want an error asking to stop first", msg)
	}
}

// A stopped, unmanaged container clears both guards and reaches the
// tunnel lookup -- with no agent registered, that's as far as this
// (Docker-less) test can follow it, but it's exactly the boundary that
// matters: neither guard above should ever fire for this case.
func TestRemoveContainerHandlerReachesTunnelLookupWhenAllowed(t *testing.T) {
	a := removeTestFixture(t, "exited", "")

	status, msg := callRemove(t, a)
	if status != 303 {
		t.Fatalf("status = %d, want 303", status)
	}
	if !strings.Contains(msg, "not currently connected") {
		t.Fatalf("Location = %q, want the agent-not-connected error, not one of the earlier guards", msg)
	}
}
