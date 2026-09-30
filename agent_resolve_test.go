package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/forgelab-me/wharf-server/internal/identity"
	"github.com/forgelab-me/wharf-server/internal/keys"
	"github.com/forgelab-me/wharf-server/internal/secrets"
	"github.com/forgelab-me/wharf-server/internal/store"
)

var (
	resolveTestCert      = []byte("agent-certificate")
	resolveTestOtherCert = []byte("another-agent-certificate")
)

type resolveFixture struct {
	a      *app
	depID  string
	encB64 string
}

// newResolveFixture builds a real store and custodian with one running
// deployment of stack "blog" on a host whose certificate is resolveTestCert.
func newResolveFixture(t *testing.T) *resolveFixture {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "wharf.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	kc, err := keys.Open(filepath.Join(t.TempDir(), "keys.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { kc.Close() })

	host, _, err := st.UpsertHostByFingerprint("h", identity.Fingerprint(resolveTestCert))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateStack(store.Stack{ID: "blog", Name: "blog", SourceType: "git", Branch: "main", Trigger: "manual"}); err != nil {
		t.Fatal(err)
	}
	if _, err := kc.GenerateKeypair("blog"); err != nil {
		t.Fatal(err)
	}
	enc, err := kc.Encrypt("blog", []byte("API_KEY=k1\nDB_PW=p1\nOTHER=o1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.EnqueueDeployment("blog", host.ID, "manual", "up"); err != nil {
		t.Fatal(err)
	}
	dep, ok, err := st.ClaimNextDeployment(host.ID)
	if err != nil || !ok {
		t.Fatalf("claim deployment: ok=%v err=%v", ok, err)
	}

	return &resolveFixture{
		a:      &app{store: st, keys: kc, resolver: secrets.NewResolver(secrets.SOPSProvider())},
		depID:  dep.ID,
		encB64: base64.StdEncoding.EncodeToString(enc),
	}
}

func (f *resolveFixture) call(t *testing.T, depID, refs string, cert []byte) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"deployment_id": depID,
		"refs_base64":   base64.StdEncoding.EncodeToString([]byte(refs)),
		"enc_base64":    f.encB64,
	})
	req := httptest.NewRequest("POST", "/agent/resolve", bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: cert}}}
	w := httptest.NewRecorder()
	f.a.resolveHandler(w, req)
	return w
}

func (f *resolveFixture) auditActions(t *testing.T) []string {
	t.Helper()
	entries, err := f.a.store.ListAudit(20)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range entries {
		actions = append(actions, e.Action)
	}
	return actions
}

func TestResolveHandlerReturnsOnlyReferencedKeys(t *testing.T) {
	f := newResolveFixture(t)
	w := f.call(t, f.depID, "PASSWORD: ref+sops://secrets.enc.yaml#/DB_PW\nAPI_KEY: ref+sops://secrets.enc.yaml#/API_KEY\n", resolveTestCert)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body)
	}
	var got struct {
		Env   map[string]string `json:"env"`
		Notes []string          `json:"notes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Env) != 2 || got.Env["PASSWORD"] != "p1" || got.Env["API_KEY"] != "k1" {
		t.Fatalf("env = %v", got.Env)
	}
	if strings.Contains(w.Body.String(), "o1") {
		t.Fatal("an unreferenced value reached the response")
	}
	if len(got.Notes) != 1 || !strings.Contains(got.Notes[0], "OTHER") {
		t.Fatalf("notes = %v", got.Notes)
	}
	if actions := f.auditActions(t); len(actions) != 1 || actions[0] != "secrets.resolve" {
		t.Fatalf("audit = %v", actions)
	}
}

func TestResolveHandlerAuditNeverHoldsValues(t *testing.T) {
	f := newResolveFixture(t)
	f.call(t, f.depID, "API_KEY: ref+sops://secrets.enc.yaml#/API_KEY\n", resolveTestCert)
	entries, _ := f.a.store.ListAudit(20)
	for _, e := range entries {
		if strings.Contains(e.Detail, "k1") || strings.Contains(e.Target, "k1") {
			t.Fatalf("audit entry holds a secret value: %+v", e)
		}
	}
}

func TestResolveHandlerRefusals(t *testing.T) {
	f := newResolveFixture(t)
	good := "API_KEY: ref+sops://secrets.enc.yaml#/API_KEY\n"

	cases := []struct {
		name  string
		depID string
		refs  string
		cert  []byte
		want  int
	}{
		{"unknown deployment", "nope", good, resolveTestCert, http.StatusNotFound},
		{"another agent's certificate", f.depID, good, resolveTestOtherCert, http.StatusForbidden},
		{"invalid refs file", f.depID, "PASSWORD: hunter2\n", resolveTestCert, http.StatusBadRequest},
		{"unresolvable reference", f.depID, "K: ref+sops://secrets.enc.yaml#/NOPE\n", resolveTestCert, http.StatusUnprocessableEntity},
		{"no provider for the scheme", f.depID, "K: ref+vault://secret/a#/b\n", resolveTestCert, http.StatusUnprocessableEntity},
	}
	for _, tc := range cases {
		w := f.call(t, tc.depID, tc.refs, tc.cert)
		if w.Code != tc.want {
			t.Errorf("%s: status = %d, want %d (body %q)", tc.name, w.Code, tc.want, w.Body)
		}
		if strings.Contains(w.Body.String(), "k1") || strings.Contains(w.Body.String(), "p1") {
			t.Errorf("%s: response leaks a secret value: %q", tc.name, w.Body)
		}
	}
}

func TestResolveHandlerOnlyWhileDeploymentRuns(t *testing.T) {
	f := newResolveFixture(t)
	if err := f.a.store.CompleteDeployment(f.depID, "succeeded", ""); err != nil {
		t.Fatal(err)
	}
	w := f.call(t, f.depID, "API_KEY: ref+sops://secrets.enc.yaml#/API_KEY\n", resolveTestCert)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 for a finished deployment", w.Code)
	}
}

func TestResolveHandlerFailureIsAudited(t *testing.T) {
	f := newResolveFixture(t)
	f.call(t, f.depID, "K: ref+sops://secrets.enc.yaml#/NOPE\n", resolveTestCert)
	if actions := f.auditActions(t); len(actions) != 1 || actions[0] != "secrets.resolve_failed" {
		t.Fatalf("audit = %v", actions)
	}
}

func TestResolveHandlerThroughAVaultBinding(t *testing.T) {
	f := newResolveFixture(t)
	f.a.resolver = secrets.NewResolver(secrets.SOPSProvider(), secrets.VaultProvider())

	var reads int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads++
		if r.Header.Get("X-Vault-Token") != "s.blog" || r.URL.Path != "/v1/secret/data/blog/db" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Write([]byte(`{"data":{"data":{"password":"from-openbao"}}}`))
	}))
	defer srv.Close()

	st := f.a.store
	if err := st.CreateSecretConnection(store.SecretConnection{ID: "c1", Name: "bao", Type: "vault", Config: map[string]string{"address": srv.URL}}); err != nil {
		t.Fatal(err)
	}
	if err := f.a.keys.SetSecretCredentials("c1", map[string]string{"token": "s.blog"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSecretBinding(store.SecretBinding{StackID: "blog", Type: "vault", ConnectionID: "c1", Prefixes: []string{"secret/blog"}}); err != nil {
		t.Fatal(err)
	}

	refs := "DB_PASSWORD: ref+vault://secret/blog/db#/password\nAPI_KEY: ref+sops://secrets.enc.yaml#/API_KEY\n"
	w := f.call(t, f.depID, refs, resolveTestCert)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body)
	}
	var got struct {
		Env map[string]string `json:"env"`
	}
	json.Unmarshal(w.Body.Bytes(), &got)
	if got.Env["DB_PASSWORD"] != "from-openbao" || got.Env["API_KEY"] != "k1" {
		t.Fatalf("env = %v", got.Env)
	}
	entries, _ := st.ListAudit(5)
	if len(entries) == 0 || !strings.Contains(entries[0].Detail, `vault: connection "bao"`) || strings.Contains(entries[0].Detail, "from-openbao") {
		t.Fatalf("audit = %+v", entries)
	}

	before := reads
	w = f.call(t, f.depID, "OTHER: ref+vault://secret/prod/db#/password\n", resolveTestCert)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "outside the prefixes allowed for this stack") {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body)
	}
	if reads != before {
		t.Fatal("a path outside the prefixes reached the server")
	}

	if err := st.DeleteSecretBinding("blog", "vault"); err != nil {
		t.Fatal(err)
	}
	w = f.call(t, f.depID, "K: ref+vault://secret/blog/db#/password\n", resolveTestCert)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "this stack has no vault connection") {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body)
	}
}

func TestCommandsHandlerRefusesAnAgentTooOldForSecretRefs(t *testing.T) {
	f := newResolveFixture(t)
	st := f.a.store
	host, err := st.GetHostByFingerprint(identity.Fingerprint(resolveTestCert))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSecretConnection(store.SecretConnection{ID: "c1", Name: "bao", Type: "vault", Config: map[string]string{"address": "https://x"}}); err != nil {
		t.Fatal(err)
	}

	claim := func() (int, string) {
		dep, err := st.EnqueueDeployment("blog", host.ID, "manual", "up")
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("GET", "/agent/commands", nil)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: resolveTestCert}}}
		w := httptest.NewRecorder()
		f.a.commandsHandler(w, req)
		got, _ := st.GetDeployment(dep.ID)
		return w.Code, got.Output
	}

	// No binding: the version gate is not involved, whatever the agent runs.
	st.SetHostAgentVersion(host.ID, "0.4.0")
	if _, out := claim(); strings.Contains(out, "secret providers") {
		t.Fatalf("a stack without a secret connection must not be gated: %q", out)
	}

	if err := st.SetSecretBinding(store.SecretBinding{StackID: "blog", Type: "vault", ConnectionID: "c1", Prefixes: []string{"a"}}); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"0.4.0", ""} {
		st.SetHostAgentVersion(host.ID, version)
		code, out := claim()
		if code != http.StatusConflict || !strings.Contains(out, "need agent 0.5.0") {
			t.Errorf("agent %q: status %d, output %q, want a refusal", version, code, out)
		}
	}

	st.SetHostAgentVersion(host.ID, "0.5.0")
	if _, out := claim(); strings.Contains(out, "secret providers") {
		t.Fatalf("an up-to-date agent must pass the gate: %q", out)
	}
}
