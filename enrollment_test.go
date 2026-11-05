package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/forgelab-me/wharf-server/internal/identity"
	"github.com/forgelab-me/wharf-server/internal/store"
)

func newEnrollApp(t *testing.T) *app {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "wharf.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &app{store: st}
}

func withCert(req *http.Request, raw []byte) *http.Request {
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: raw}}}
	return req
}

func enroll(a *app, raw []byte, token string) *httptest.ResponseRecorder {
	req := withCert(httptest.NewRequest("POST", "/agent/enrollments", bytes.NewReader([]byte(`{"hostname":"box"}`))), raw)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	a.enrollCreateHandler(w, req)
	return w
}

func TestAgentAuthRefusesPendingHost(t *testing.T) {
	a := newEnrollApp(t)
	cert := []byte("pending-agent")
	h, _, err := a.store.UpsertHostByFingerprint("box", identity.Fingerprint(cert))
	if err != nil {
		t.Fatal(err)
	}
	called := false
	guarded := a.agentAuth(func(http.ResponseWriter, *http.Request) { called = true })

	w := httptest.NewRecorder()
	guarded(w, withCert(httptest.NewRequest("GET", "/agent/commands", nil), cert))
	if w.Code != http.StatusForbidden || called {
		t.Fatalf("pending host: status=%d called=%v, want 403 and no call", w.Code, called)
	}

	if err := a.store.ApproveHost(h.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	guarded(w, withCert(httptest.NewRequest("GET", "/agent/commands", nil), cert))
	if !called {
		t.Fatalf("approved host must pass, got %d", w.Code)
	}

	w = httptest.NewRecorder()
	called = false
	guarded(w, withCert(httptest.NewRequest("GET", "/agent/commands", nil), []byte("stranger")))
	if w.Code != http.StatusForbidden || called {
		t.Fatalf("unknown cert: status=%d called=%v, want 403", w.Code, called)
	}
}

func TestEnrollmentTokenIsSingleUseAndAutoApproves(t *testing.T) {
	a := newEnrollApp(t)
	token, err := a.store.CreateEnrollmentToken("admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	w := enroll(a, []byte("agent-1"), token)
	if w.Code != http.StatusCreated {
		t.Fatalf("first use: %d %s", w.Code, w.Body)
	}
	var out enrollResponse
	json.NewDecoder(w.Body).Decode(&out)
	if out.Status != "connected" {
		t.Fatalf("status = %q, want connected (token stands in for approval)", out.Status)
	}

	if w := enroll(a, []byte("agent-2"), token); w.Code != http.StatusUnauthorized {
		t.Fatalf("reused token: %d, want 401", w.Code)
	}
	if w := enroll(a, []byte("agent-3"), "wet_bogus"); w.Code != http.StatusUnauthorized {
		t.Fatalf("bogus token: %d, want 401", w.Code)
	}
	// A known agent reconnecting with a spent token is just a reconnect.
	if w := enroll(a, []byte("agent-1"), token); w.Code != http.StatusOK {
		t.Fatalf("reconnect: %d, want 200", w.Code)
	}
}

func TestEnrollmentWithoutTokenStaysPendingAndCanRequireToken(t *testing.T) {
	a := newEnrollApp(t)
	w := enroll(a, []byte("agent-1"), "")
	var out enrollResponse
	json.NewDecoder(w.Body).Decode(&out)
	if w.Code != http.StatusCreated || out.Status != "pending" {
		t.Fatalf("no token: %d status=%q, want 201 pending", w.Code, out.Status)
	}

	t.Setenv("WHARF_REQUIRE_ENROLLMENT_TOKEN", "true")
	if w := enroll(a, []byte("agent-2"), ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("token required: %d, want 401", w.Code)
	}
	if w := enroll(a, []byte("agent-1"), ""); w.Code != http.StatusOK {
		t.Fatalf("known agent must still reconnect: %d", w.Code)
	}
}

func auditActions(t *testing.T, a *app) []string {
	t.Helper()
	entries, err := a.store.ListAudit(50)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Action)
	}
	return out
}

func countAction(actions []string, want string) int {
	n := 0
	for _, a := range actions {
		if a == want {
			n++
		}
	}
	return n
}

func TestEnrollmentEventsAreAudited(t *testing.T) {
	refusalMu.Lock()
	refusalLast = map[string]time.Time{}
	refusalMu.Unlock()
	a := newEnrollApp(t)

	token, _ := a.store.CreateEnrollmentToken("admin", time.Hour)
	enroll(a, []byte("agent-1"), token)
	for i := 0; i < 5; i++ {
		enroll(a, []byte{byte('x'), byte(i)}, "wet_bogus")
	}
	got := auditActions(t, a)
	if countAction(got, "host.approve") != 1 {
		t.Fatalf("token approval must be audited once: %v", got)
	}
	if countAction(got, "host.enroll_refused") != 1 {
		t.Fatalf("5 identical refusals must produce a single throttled entry: %v", got)
	}

	// rotation
	cert, _ := identity.LoadOrGenerate(t.TempDir())
	body, _ := json.Marshal(map[string]string{"cert_pem": string(identity.PEM(cert))})
	w := httptest.NewRecorder()
	a.agentAuth(a.rotateHandler)(w, withCert(httptest.NewRequest("POST", "/agent/rotate", bytes.NewReader(body)), []byte("agent-1")))
	if w.Code != http.StatusNoContent {
		t.Fatalf("rotate: %d %s", w.Code, w.Body)
	}
	if countAction(auditActions(t, a), "host.rotate_cert") != 1 {
		t.Fatal("rotation must be audited")
	}
}

func TestPendingCap(t *testing.T) {
	a := newEnrollApp(t)
	t.Setenv("WHARF_MAX_PENDING", "2")
	for i, c := range []string{"a", "b"} {
		if w := enroll(a, []byte(c), ""); w.Code != http.StatusCreated {
			t.Fatalf("enroll %d: %d", i, w.Code)
		}
	}
	if w := enroll(a, []byte("c"), ""); w.Code != http.StatusTooManyRequests {
		t.Fatalf("over the cap: %d, want 429", w.Code)
	}
	// A token holder is an admin-vetted agent: not subject to the cap.
	token, _ := a.store.CreateEnrollmentToken("admin", time.Hour)
	if w := enroll(a, []byte("d"), token); w.Code != http.StatusCreated {
		t.Fatalf("token over the cap: %d, want 201", w.Code)
	}
}

func TestRotationAcceptsBothThenPromotes(t *testing.T) {
	a := newEnrollApp(t)
	oldRaw := []byte("old-cert")
	h, _, _ := a.store.UpsertHostByFingerprint("box", identity.Fingerprint(oldRaw))
	a.store.ApproveHost(h.ID, "admin")

	newCert, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	newRaw := newCert.Certificate[0]
	newFP := identity.Fingerprint(newRaw)

	body, _ := json.Marshal(map[string]string{"cert_pem": string(identity.PEM(newCert))})
	rotate := a.agentAuth(a.rotateHandler)
	w := httptest.NewRecorder()
	rotate(w, withCert(httptest.NewRequest("POST", "/agent/rotate", bytes.NewReader(body)), oldRaw))
	if w.Code != http.StatusNoContent {
		t.Fatalf("rotate: %d %s", w.Code, w.Body)
	}

	ok := a.agentAuth(func(http.ResponseWriter, *http.Request) {})
	// Ordered on purpose: the old certificate is only valid until the new
	// one has been presented once.
	for _, c := range []struct {
		name string
		raw  []byte
	}{{"old", oldRaw}, {"new", newRaw}} {
		w := httptest.NewRecorder()
		ok(w, withCert(httptest.NewRequest("GET", "/agent/commands", nil), c.raw))
		if w.Code != http.StatusOK {
			t.Fatalf("%s cert during rotation: %d, want accepted", c.name, w.Code)
		}
	}

	got, err := a.store.GetHost(h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CertFingerprint != newFP {
		t.Fatalf("pinned fingerprint = %s, want promoted %s", got.CertFingerprint, newFP)
	}
	w = httptest.NewRecorder()
	ok(w, withCert(httptest.NewRequest("GET", "/agent/commands", nil), oldRaw))
	if w.Code != http.StatusForbidden {
		t.Fatalf("old cert after promotion: %d, want 403", w.Code)
	}
}

func TestRotationRejectsSameOrForeignCertificate(t *testing.T) {
	a := newEnrollApp(t)
	cert, _ := identity.LoadOrGenerate(t.TempDir())
	other, _ := identity.LoadOrGenerate(t.TempDir())

	h1, _, _ := a.store.UpsertHostByFingerprint("one", identity.Fingerprint(cert.Certificate[0]))
	a.store.ApproveHost(h1.ID, "admin")
	h2, _, _ := a.store.UpsertHostByFingerprint("two", identity.Fingerprint(other.Certificate[0]))
	a.store.ApproveHost(h2.ID, "admin")

	post := func(raw []byte, c tls.Certificate) int {
		body, _ := json.Marshal(map[string]string{"cert_pem": string(identity.PEM(c))})
		w := httptest.NewRecorder()
		a.agentAuth(a.rotateHandler)(w, withCert(httptest.NewRequest("POST", "/agent/rotate", bytes.NewReader(body)), raw))
		return w.Code
	}
	if c := post(cert.Certificate[0], cert); c != http.StatusBadRequest {
		t.Fatalf("rotating to the same cert: %d, want 400", c)
	}
	if c := post(cert.Certificate[0], other); c != http.StatusConflict {
		t.Fatalf("rotating onto another host's cert: %d, want 409", c)
	}
}
