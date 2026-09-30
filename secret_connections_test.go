package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/forgelab-me/wharf-server/internal/keys"
	"github.com/forgelab-me/wharf-server/internal/secrets"
	"github.com/forgelab-me/wharf-server/internal/store"
)

type secretsFixture struct {
	a *app
}

func newSecretsFixture(t *testing.T) *secretsFixture {
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
	for _, id := range []string{"blog", "wiki"} {
		if err := st.CreateStack(store.Stack{ID: id, Name: id, SourceType: "git", Branch: "main", Trigger: "manual"}); err != nil {
			t.Fatal(err)
		}
	}
	return &secretsFixture{a: &app{
		store:    st,
		keys:     kc,
		resolver: secrets.NewResolver(secrets.SOPSProvider(), secrets.VaultProvider()),
	}}
}

// call drives a handler like the router would and returns the redirect target.
func call(h http.HandlerFunc, target string, form url.Values, pathValues map[string]string) (code int, location string) {
	req := httptest.NewRequest("POST", target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range pathValues {
		req.SetPathValue(k, v)
	}
	w := httptest.NewRecorder()
	h(w, req)
	return w.Code, w.Header().Get("Location")
}

func redirectParam(t *testing.T, location, name string) string {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("bad Location %q: %v", location, err)
	}
	return u.Query().Get(name)
}

// createGlobal creates a shared vault connection through the real handler.
func (f *secretsFixture) createGlobal(t *testing.T, name string, creds map[string]string) store.SecretConnection {
	t.Helper()
	form := url.Values{"type": {"vault"}, "name": {name}, "cfg_address": {"https://bao.example.lan:8200"}}
	for k, v := range creds {
		form.Set("cred_"+k, v)
	}
	code, loc := call(f.a.createSecretProviderHandler, "/settings/secret-providers", form, nil)
	if code != http.StatusSeeOther || redirectParam(t, loc, "error") != "" {
		t.Fatalf("create %s: %d %s", name, code, loc)
	}
	conns, _ := f.a.store.ListGlobalSecretConnections()
	for _, c := range conns {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("connection %s not stored", name)
	return store.SecretConnection{}
}

func (f *secretsFixture) saveBinding(stackID string, form url.Values) (code int, errMsg string) {
	code, loc := call(f.a.saveStackBindingHandler, "/stacks/"+stackID+"/secrets/bindings/vault", form, map[string]string{"id": stackID, "type": "vault"})
	u, _ := url.Parse(loc)
	return code, u.Query().Get("error")
}

func TestCreateSecretProviderValidatesAndStores(t *testing.T) {
	f := newSecretsFixture(t)

	conn := f.createGlobal(t, "openbao-home", map[string]string{"role_id": "r", "secret_id": "s3cret"})
	if conn.Config["address"] != "https://bao.example.lan:8200" || conn.Config["kv_version"] != "2" || conn.Type != "vault" {
		t.Fatalf("stored config = %+v (defaults must be applied)", conn.Config)
	}
	creds, _ := f.a.keys.SecretCredentials(conn.ID)
	if creds["secret_id"] != "s3cret" {
		t.Fatalf("credentials = %v", creds)
	}
	if strings.Contains(conn.Config["address"], "s3cret") {
		t.Fatal("a credential leaked into the config")
	}

	bad := map[string]url.Values{
		"no name":         {"type": {"vault"}, "cfg_address": {"https://x"}},
		"bad address":     {"type": {"vault"}, "name": {"a"}, "cfg_address": {"not-a-url"}},
		"half an AppRole": {"type": {"vault"}, "name": {"b"}, "cfg_address": {"https://x"}, "cred_role_id": {"r"}},
		"unknown type":    {"type": {"nope"}, "name": {"c"}},
	}
	for name, form := range bad {
		code, loc := call(f.a.createSecretProviderHandler, "/settings/secret-providers", form, nil)
		rejected := code == http.StatusBadRequest || redirectParam(t, loc, "error") != ""
		if !rejected {
			t.Errorf("%s: accepted (%d %s)", name, code, loc)
		}
	}
	if code, loc := call(f.a.createSecretProviderHandler, "/x", url.Values{"type": {"vault"}, "name": {"openbao-home"}, "cfg_address": {"https://x"}}, nil); code != http.StatusSeeOther || redirectParam(t, loc, "error") == "" {
		t.Errorf("a duplicate name must be refused (%d %s)", code, loc)
	}
}

func TestSharedBindingNeedsDefaultCredentials(t *testing.T) {
	f := newSecretsFixture(t)
	noCreds := f.createGlobal(t, "address-only", nil)

	_, msg := f.saveBinding("blog", url.Values{"mode": {"shared"}, "connection_id": {noCreds.ID}, "prefixes": {"secret/blog"}})
	if !strings.Contains(msg, "no default credentials") {
		t.Fatalf("error = %q", msg)
	}
	if _, err := f.a.store.GetSecretBinding("blog", "vault"); err == nil {
		t.Fatal("a refused binding must not be stored")
	}
}

func TestBindingModesAndCleanup(t *testing.T) {
	f := newSecretsFixture(t)
	global := f.createGlobal(t, "openbao-home", map[string]string{"token": "s.default"})
	prefixes := url.Values{"prefixes": {"secret/blog/*\nkv/app"}}
	with := func(kv ...string) url.Values {
		v := url.Values{"prefixes": prefixes["prefixes"]}
		for i := 0; i < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}

	// shared: points at the global connection, nothing private is created.
	if code, msg := f.saveBinding("blog", with("mode", "shared", "connection_id", global.ID)); msg != "" {
		t.Fatalf("shared: %d %s", code, msg)
	}
	b, _ := f.a.store.GetSecretBinding("blog", "vault")
	if b.ConnectionID != global.ID || strings.Join(b.Prefixes, ",") != "secret/blog,kv/app" {
		t.Fatalf("shared binding = %+v", b)
	}
	if local, _ := f.a.store.SecretConnectionsForStack("blog"); len(local) != 0 {
		t.Fatalf("private connections = %+v", local)
	}

	// own credentials: a private connection inheriting the global one.
	if _, msg := f.saveBinding("blog", with("mode", "own", "connection_id", global.ID, "cred_role_id", "r-blog", "cred_secret_id", "s-blog")); msg != "" {
		t.Fatalf("own: %s", msg)
	}
	b, _ = f.a.store.GetSecretBinding("blog", "vault")
	local, err := f.a.store.GetSecretConnection(b.ConnectionID)
	if err != nil || local.StackID != "blog" || local.ParentID != global.ID || len(local.Config) != 0 {
		t.Fatalf("own connection = %+v, %v", local, err)
	}
	eff, err := f.a.effectiveFor(local, b.Prefixes)
	if err != nil || eff.Config["address"] != "https://bao.example.lan:8200" || eff.Credentials["role_id"] != "r-blog" || eff.Credentials["token"] != "" {
		t.Fatalf("effective = %+v, %v: address inherited, credentials replaced as a whole", eff, err)
	}
	if !strings.Contains(eff.Source, "own credentials") {
		t.Errorf("source = %q", eff.Source)
	}

	// editing with empty credential fields keeps the stored ones.
	if _, msg := f.saveBinding("blog", with("mode", "own", "connection_id", global.ID, "prefixes", "secret/blog")); msg != "" {
		t.Fatalf("edit: %s", msg)
	}
	kept, _ := f.a.keys.SecretCredentials(local.ID)
	if kept["secret_id"] != "s-blog" {
		t.Fatalf("credentials after an edit with empty fields = %v", kept)
	}

	// separate: own address too; the previous private connection is dropped.
	if _, msg := f.saveBinding("blog", with("mode", "separate", "cfg_address", "https://other.example.lan:8200", "cred_token", "s.blog")); msg != "" {
		t.Fatalf("separate: %s", msg)
	}
	if _, err := f.a.store.GetSecretConnection(local.ID); err == nil {
		t.Error("the previous private connection must be dropped")
	}
	if creds, _ := f.a.keys.SecretCredentials(local.ID); creds != nil {
		t.Errorf("the previous private credentials must be dropped: %v", creds)
	}
	b, _ = f.a.store.GetSecretBinding("blog", "vault")
	sep, _ := f.a.store.GetSecretConnection(b.ConnectionID)
	if sep.ParentID != "" || sep.Config["address"] != "https://other.example.lan:8200" {
		t.Fatalf("separate connection = %+v", sep)
	}

	// back to shared: the private connection goes away again.
	if _, msg := f.saveBinding("blog", with("mode", "shared", "connection_id", global.ID)); msg != "" {
		t.Fatalf("shared again: %s", msg)
	}
	if local, _ := f.a.store.SecretConnectionsForStack("blog"); len(local) != 0 {
		t.Fatalf("private connections left behind: %+v", local)
	}
	if creds, _ := f.a.keys.SecretCredentials(sep.ID); creds != nil {
		t.Fatalf("private credentials left behind: %v", creds)
	}
}

func TestBindingRefusals(t *testing.T) {
	f := newSecretsFixture(t)
	global := f.createGlobal(t, "openbao-home", map[string]string{"token": "s.default"})

	cases := map[string]url.Values{
		"no prefixes":            {"mode": {"shared"}, "connection_id": {global.ID}},
		"traversal prefix":       {"mode": {"shared"}, "connection_id": {global.ID}, "prefixes": {"secret/../prod"}},
		"unknown mode":           {"mode": {"nope"}, "prefixes": {"secret/blog"}},
		"unknown connection":     {"mode": {"shared"}, "connection_id": {"missing"}, "prefixes": {"secret/blog"}},
		"own without creds":      {"mode": {"own"}, "connection_id": {global.ID}, "prefixes": {"secret/blog"}},
		"own with half a role":   {"mode": {"own"}, "connection_id": {global.ID}, "prefixes": {"secret/blog"}, "cred_role_id": {"r"}},
		"separate bad address":   {"mode": {"separate"}, "cfg_address": {"nope"}, "cred_token": {"t"}, "prefixes": {"a"}},
		"separate without creds": {"mode": {"separate"}, "cfg_address": {"https://x"}, "prefixes": {"a"}},
	}
	for name, form := range cases {
		if _, msg := f.saveBinding("blog", form); msg == "" {
			t.Errorf("%s: accepted", name)
		}
	}
	if list, _ := f.a.store.ListSecretBindings("blog"); len(list) != 0 {
		t.Errorf("refused bindings were stored: %+v", list)
	}
	if local, _ := f.a.store.SecretConnectionsForStack("blog"); len(local) != 0 {
		t.Errorf("refused bindings left private connections: %+v", local)
	}
}

func TestSecretProviderCannotBeDeletedWhileUsed(t *testing.T) {
	f := newSecretsFixture(t)
	global := f.createGlobal(t, "openbao-home", map[string]string{"token": "s.default"})
	f.saveBinding("blog", url.Values{"mode": {"shared"}, "connection_id": {global.ID}, "prefixes": {"a"}})
	f.saveBinding("wiki", url.Values{"mode": {"own"}, "connection_id": {global.ID}, "prefixes": {"b"}, "cred_token": {"s.wiki"}})

	_, loc := call(f.a.deleteSecretProviderHandler, "/x", nil, map[string]string{"id": global.ID})
	msg := redirectParam(t, loc, "error")
	if !strings.Contains(msg, "blog") || !strings.Contains(msg, "wiki") {
		t.Fatalf("error = %q, want both stacks named", msg)
	}
	if _, err := f.a.store.GetSecretConnection(global.ID); err != nil {
		t.Fatal("the connection must survive a refused delete")
	}

	for _, id := range []string{"blog", "wiki"} {
		call(f.a.deleteStackBindingHandler, "/x", nil, map[string]string{"id": id, "type": "vault"})
	}
	_, loc = call(f.a.deleteSecretProviderHandler, "/x", nil, map[string]string{"id": global.ID})
	if redirectParam(t, loc, "error") != "" {
		t.Fatalf("delete after unbinding: %s", loc)
	}
	if creds, _ := f.a.keys.SecretCredentials(global.ID); creds != nil {
		t.Errorf("default credentials left behind: %v", creds)
	}
}

func TestUpdateReplacesTheCredentialGroupAsAWhole(t *testing.T) {
	f := newSecretsFixture(t)
	global := f.createGlobal(t, "openbao-home", map[string]string{"role_id": "r", "secret_id": "old"})
	update := func(extra url.Values) string {
		form := url.Values{"name": {"openbao-home"}, "cfg_address": {"https://bao.example.lan:8200"}}
		for k, v := range extra {
			form[k] = v
		}
		_, loc := call(f.a.updateSecretProviderHandler, "/x", form, map[string]string{"id": global.ID})
		return redirectParam(t, loc, "error")
	}

	if msg := update(nil); msg != "" {
		t.Fatal(msg)
	}
	if got, _ := f.a.keys.SecretCredentials(global.ID); got["secret_id"] != "old" {
		t.Fatalf("empty fields must keep the credentials, got %v", got)
	}

	if msg := update(url.Values{"cred_token": {"s.new"}}); msg != "" {
		t.Fatal(msg)
	}
	got, _ := f.a.keys.SecretCredentials(global.ID)
	if len(got) != 1 || got["token"] != "s.new" {
		t.Fatalf("typing any field must replace the whole set, got %v", got)
	}

	if msg := update(url.Values{"cred_role_id": {"only-one"}}); msg == "" {
		t.Fatal("an incomplete replacement must be refused")
	}
	if got, _ := f.a.keys.SecretCredentials(global.ID); got["token"] != "s.new" {
		t.Fatalf("a refused update must not touch the credentials, got %v", got)
	}

	if msg := update(url.Values{"clear_credentials": {"1"}}); msg != "" {
		t.Fatal(msg)
	}
	if got, _ := f.a.keys.SecretCredentials(global.ID); got != nil {
		t.Fatalf("clear must remove the credentials, got %v", got)
	}
}

func TestDeletingAStackDropsItsPrivateCredentials(t *testing.T) {
	f := newSecretsFixture(t)
	global := f.createGlobal(t, "openbao-home", map[string]string{"token": "s.default"})
	f.saveBinding("blog", url.Values{"mode": {"own"}, "connection_id": {global.ID}, "prefixes": {"a"}, "cred_token": {"s.blog"}})
	b, _ := f.a.store.GetSecretBinding("blog", "vault")

	if _, loc := call(f.a.deleteStackHandler, "/stacks/blog/delete", nil, map[string]string{"id": "blog"}); redirectParam(t, loc, "error") != "" {
		t.Fatal(loc)
	}
	if creds, _ := f.a.keys.SecretCredentials(b.ConnectionID); creds != nil {
		t.Fatalf("the stack's private credentials outlived it: %v", creds)
	}
	if _, err := f.a.store.GetSecretConnection(global.ID); err != nil {
		t.Fatal("the shared connection must survive")
	}
}

func TestEffectiveForRefusesAConnectionWithoutCredentials(t *testing.T) {
	f := newSecretsFixture(t)
	noCreds := f.createGlobal(t, "address-only", nil)
	if _, err := f.a.effectiveFor(noCreds, []string{"a"}); err == nil || !strings.Contains(err.Error(), "no credentials") {
		t.Fatalf("err = %v", err)
	}
}

func TestAgentTooOldForSecretRefs(t *testing.T) {
	for version, want := range map[string]bool{
		"":       true, // predates version reporting
		"0.1.0":  true,
		"0.4.9":  true,
		"0.5.0":  false,
		"0.10.0": false,
		"1.0.0":  false,
		"dev":    false, // not a release build: never blocked
		"main":   false,
	} {
		if got := agentTooOldForSecretRefs(version); got != want {
			t.Errorf("agentTooOldForSecretRefs(%q) = %v, want %v", version, got, want)
		}
	}
	if msg := agentTooOldMessage("0.4.0"); !strings.Contains(msg, "0.5.0") || !strings.Contains(msg, "0.4.0") {
		t.Errorf("message = %q", msg)
	}
}
