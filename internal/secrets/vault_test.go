package secrets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	testRole   = "role-1"
	testSecret = "secret-id-1"
	testStatic = "s.static-token"
)

// fakeVault answers just enough of the OpenBao API for the provider.
type fakeVault struct {
	srv         *httptest.Server
	logins      atomic.Int32
	reads       atomic.Int32
	validTokens map[string]bool
	namespace   atomic.Value
	sealed      bool
}

func newFakeVault(t *testing.T) *fakeVault {
	t.Helper()
	f := &fakeVault{validTokens: map[string]bool{testStatic: true}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		f.logins.Add(1)
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["role_id"] != testRole || body["secret_id"] != testSecret {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"errors":["invalid role or secret ID"]}`))
			return
		}
		tok := "s.approle-" + string(rune('a'+f.logins.Load()))
		f.validTokens[tok] = true
		w.Write([]byte(`{"auth":{"client_token":"` + tok + `","lease_duration":3600}}`))
	})
	mux.HandleFunc("GET /v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		if !f.validTokens[r.Header.Get("X-Vault-Token")] {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"errors":["permission denied"]}`))
			return
		}
		w.Write([]byte(`{"data":{}}`))
	})
	mux.HandleFunc("GET /v1/secret/data/", func(w http.ResponseWriter, r *http.Request) {
		f.reads.Add(1)
		f.namespace.Store(r.Header.Get("X-Vault-Namespace"))
		if f.sealed {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"errors":["Vault is sealed"]}`))
			return
		}
		if !f.validTokens[r.Header.Get("X-Vault-Token")] {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"errors":["permission denied"]}`))
			return
		}
		switch strings.TrimPrefix(r.URL.Path, "/v1/secret/data/") {
		case "blog/db":
			w.Write([]byte(`{"data":{"data":{"password":"p4ss","port":5432,"tls":true,"nested":{"a":"b"}},"metadata":{"version":1}}}`))
		case "blog/deleted":
			w.Write([]byte(`{"data":{"data":null,"metadata":{"deletion_time":"2026-01-01T00:00:00Z"}}}`))
		case "blog/redirect":
			http.Redirect(w, r, "http://127.0.0.1:1/stolen", http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"errors":[]}`))
		}
	})
	mux.HandleFunc("GET /v1/kv1/blog/db", func(w http.ResponseWriter, r *http.Request) {
		if !f.validTokens[r.Header.Get("X-Vault-Token")] {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Write([]byte(`{"data":{"password":"v1-pass"}}`))
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeVault) effective(creds map[string]string, extra map[string]string) *Effective {
	config := map[string]string{"address": f.srv.URL, "kv_version": "2"}
	for k, v := range extra {
		config[k] = v
	}
	return NewEffective("vault", config, creds, []string{"secret/blog"}, "test connection")
}

func jobFor(eff *Effective) *Job {
	return &Job{StackID: "blog", Binding: func(string) (*Effective, error) { return eff, nil }}
}

func resolveOne(p Provider, job *Job, path, field string) (string, error) {
	return p.Resolve(context.Background(), job, Ref{Scheme: "vault", Path: path, Field: field})
}

func TestVaultStaticTokenReadsKV2Fields(t *testing.T) {
	f := newFakeVault(t)
	p := VaultProvider()
	job := jobFor(f.effective(map[string]string{"token": testStatic}, nil))

	for field, want := range map[string]string{"password": "p4ss", "port": "5432", "tls": "true"} {
		got, err := resolveOne(p, job, "secret/blog/db", field)
		if err != nil || got != want {
			t.Errorf("%s = %q, %v; want %q", field, got, err, want)
		}
	}
	if f.reads.Load() != 1 {
		t.Errorf("secret read %d times for three fields, want 1", f.reads.Load())
	}
	if _, err := resolveOne(p, job, "secret/blog/db", "nested"); err == nil || !strings.Contains(err.Error(), "not a string") {
		t.Errorf("nested field err = %v", err)
	}
	if _, err := resolveOne(p, job, "secret/blog/db", "absent"); err == nil || !strings.Contains(err.Error(), `field "absent" not found`) {
		t.Errorf("absent field err = %v", err)
	}
}

func TestVaultKV1(t *testing.T) {
	f := newFakeVault(t)
	job := jobFor(f.effective(map[string]string{"token": testStatic}, map[string]string{"kv_version": "1"}))
	got, err := resolveOne(VaultProvider(), job, "kv1/blog/db", "password")
	if err != nil || got != "v1-pass" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestVaultAppRoleCachesTheToken(t *testing.T) {
	f := newFakeVault(t)
	p := VaultProvider()
	creds := map[string]string{"role_id": testRole, "secret_id": testSecret}

	for i := 0; i < 3; i++ {
		job := jobFor(f.effective(creds, nil))
		if got, err := resolveOne(p, job, "secret/blog/db", "password"); err != nil || got != "p4ss" {
			t.Fatalf("read %d: %q, %v", i, got, err)
		}
	}
	if f.logins.Load() != 1 {
		t.Fatalf("logged in %d times across three deployments, want 1", f.logins.Load())
	}
}

func TestVaultTokenCacheIsPerIdentity(t *testing.T) {
	f := newFakeVault(t)
	p := VaultProvider()
	good := f.effective(map[string]string{"role_id": testRole, "secret_id": testSecret}, nil)
	bad := f.effective(map[string]string{"role_id": testRole, "secret_id": "another-secret-id"}, nil)

	if _, err := resolveOne(p, jobFor(good), "secret/blog/db", "password"); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveOne(p, jobFor(bad), "secret/blog/db", "password"); err == nil || !strings.Contains(err.Error(), "login refused") {
		t.Fatalf("a stack with different credentials must log in for itself, got %v", err)
	}
	if f.logins.Load() != 2 {
		t.Fatalf("logins = %d, want 2", f.logins.Load())
	}
}

func TestVaultReloginsOnceWhenTheCachedTokenIsRevoked(t *testing.T) {
	f := newFakeVault(t)
	p := VaultProvider()
	eff := f.effective(map[string]string{"role_id": testRole, "secret_id": testSecret}, nil)

	if _, err := resolveOne(p, jobFor(eff), "secret/blog/db", "password"); err != nil {
		t.Fatal(err)
	}
	for tok := range f.validTokens {
		if strings.HasPrefix(tok, "s.approle-") {
			delete(f.validTokens, tok)
		}
	}
	got, err := resolveOne(p, jobFor(eff), "secret/blog/db", "password")
	if err != nil || got != "p4ss" {
		t.Fatalf("got %q, %v", got, err)
	}
	if f.logins.Load() != 2 {
		t.Fatalf("logins = %d, want 2 (one re-login)", f.logins.Load())
	}
}

func TestVaultErrorsSayWhichStepFailed(t *testing.T) {
	f := newFakeVault(t)
	p := VaultProvider()
	creds := map[string]string{"token": testStatic}

	cases := []struct {
		name string
		eff  *Effective
		path string
		want string
	}{
		{"login refused", f.effective(map[string]string{"role_id": testRole, "secret_id": "wrong"}, nil), "secret/blog/db", "login refused: invalid role or secret ID"},
		{"policy denies", f.effective(map[string]string{"token": "s.revoked"}, nil), "secret/blog/db", "permission denied by the OpenBao policy for secret/blog/db"},
		{"no such secret", f.effective(creds, nil), "secret/blog/missing", "no secret at secret/blog/missing"},
		{"deleted version", f.effective(creds, nil), "secret/blog/deleted", "no current version"},
		{"redirect", f.effective(creds, nil), "secret/blog/redirect", "redirect (302), which is not followed"},
		{"unreachable", NewEffective("vault", map[string]string{"address": "http://127.0.0.1:1"}, creds, []string{"*"}, "x"), "secret/blog/db", "cannot reach OpenBao at http://127.0.0.1:1"},
		{"no mount", f.effective(creds, nil), "secret", "path must be <mount>/<secret path>"},
	}
	for _, tc := range cases {
		_, err := resolveOne(p, jobFor(tc.eff), tc.path, "password")
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to contain %q", tc.name, err, tc.want)
			continue
		}
		for _, secret := range []string{testStatic, testSecret, "wrong"} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%s: error leaks a credential: %v", tc.name, err)
			}
		}
	}

	f.sealed = true
	_, err := resolveOne(p, jobFor(f.effective(creds, nil)), "secret/blog/db", "password")
	if err == nil || !strings.Contains(err.Error(), "sealed or not ready (503)") {
		t.Errorf("sealed: err = %v", err)
	}
}

func TestVaultSendsNamespace(t *testing.T) {
	f := newFakeVault(t)
	job := jobFor(f.effective(map[string]string{"token": testStatic}, map[string]string{"namespace": "team/blog"}))
	if _, err := resolveOne(VaultProvider(), job, "secret/blog/db", "password"); err != nil {
		t.Fatal(err)
	}
	if got := f.namespace.Load(); got != "team/blog" {
		t.Fatalf("namespace header = %v", got)
	}
}

func TestVaultCheck(t *testing.T) {
	f := newFakeVault(t)
	p := VaultProvider()
	ctx := context.Background()

	if err := p.Check(ctx, f.effective(map[string]string{"token": testStatic}, nil)); err != nil {
		t.Errorf("valid token: %v", err)
	}
	if err := p.Check(ctx, f.effective(map[string]string{"token": "s.revoked"}, nil)); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("revoked token: %v", err)
	}
	if err := p.Check(ctx, f.effective(map[string]string{"role_id": testRole, "secret_id": testSecret}, nil)); err != nil {
		t.Errorf("valid AppRole: %v", err)
	}
	if err := p.Check(ctx, f.effective(map[string]string{"role_id": testRole, "secret_id": "wrong"}, nil)); err == nil || !strings.Contains(err.Error(), "login refused") {
		t.Errorf("wrong secret id: %v", err)
	}
	if err := p.Check(ctx, f.effective(map[string]string{}, nil)); err == nil {
		t.Error("no credentials must fail the check")
	}
}

func TestVaultValidation(t *testing.T) {
	p := VaultProvider()

	for _, ok := range []map[string]string{
		{"address": "https://bao.example.lan:8200"},
		{"address": "http://10.0.0.5:8200/", "kv_version": "1", "namespace": "team/blog", "approle_mount": "wharf"},
	} {
		if err := p.ValidateConfig(ok); err != nil {
			t.Errorf("ValidateConfig(%v) = %v", ok, err)
		}
	}
	for _, bad := range []map[string]string{
		{},
		{"address": "bao.example.lan:8200"},
		{"address": "ftp://bao.example.lan"},
		{"address": "https://user:pass@bao.example.lan"},
		{"address": "https://bao.example.lan?x=1"},
		{"address": "https://bao.example.lan", "kv_version": "3"},
		{"address": "https://bao.example.lan", "namespace": "../x"},
		{"address": "https://bao.example.lan", "ca_pem": "not a certificate"},
	} {
		if err := p.ValidateConfig(bad); err == nil {
			t.Errorf("ValidateConfig(%v) accepted it", bad)
		}
	}

	for _, ok := range []map[string]string{
		{"token": "s.abc"},
		{"role_id": "r", "secret_id": "s"},
	} {
		if err := p.ValidateCredentials(ok); err != nil {
			t.Errorf("ValidateCredentials(%v) = %v", ok, err)
		}
	}
	for _, bad := range []map[string]string{
		{},
		{"role_id": "r"},
		{"secret_id": "s"},
		{"token": "s.abc", "role_id": "r", "secret_id": "s"},
	} {
		if err := p.ValidateCredentials(bad); err == nil {
			t.Errorf("ValidateCredentials(%v) accepted it", bad)
		}
	}
}

func TestResolverEnforcesPrefixesAndBindings(t *testing.T) {
	f := newFakeVault(t)
	eff := f.effective(map[string]string{"token": testStatic}, nil) // prefix: secret/blog
	r := NewResolver(SOPSProvider(), VaultProvider())

	res, err := r.Resolve(context.Background(), jobFor(eff), []Entry{
		{"DB_PASSWORD", Ref{"vault", "secret/blog/db", "password"}},
	})
	if err != nil || res.Env["DB_PASSWORD"] != "p4ss" {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if len(res.Sources) != 1 || res.Sources[0] != "vault: test connection" {
		t.Fatalf("Sources = %v", res.Sources)
	}

	_, err = r.Resolve(context.Background(), jobFor(eff), []Entry{
		{"OUTSIDE", Ref{"vault", "secret/prod/db", "password"}},
		{"SIBLING", Ref{"vault", "secret/blogger/db", "password"}},
		{"INSIDE", Ref{"vault", "secret/blog/db", "password"}},
	})
	var rerr *ResolveError
	if !asResolveError(err, &rerr) || len(rerr.Failures) != 2 {
		t.Fatalf("err = %v, want two prefix failures", err)
	}
	if !strings.Contains(err.Error(), "outside the prefixes allowed for this stack") {
		t.Errorf("err = %v", err)
	}
	// One read for the first job, one for INSIDE; the two out-of-prefix
	// paths must not have reached the server.
	if f.reads.Load() != 2 {
		t.Errorf("reads = %d, want 2: a path outside the prefixes must never reach the server", f.reads.Load())
	}

	noBinding := &Job{StackID: "blog", Binding: func(s string) (*Effective, error) { return nil, &NoBindingError{Scheme: s} }}
	_, err = r.Resolve(context.Background(), noBinding, []Entry{{"K", Ref{"vault", "secret/blog/db", "password"}}})
	if err == nil || !strings.Contains(err.Error(), "this stack has no vault connection") {
		t.Errorf("err = %v", err)
	}
}

func TestPrefixes(t *testing.T) {
	got, err := NormalizePrefixes("secret/blog/*\nsecret/shared/, kv/app\r\nsecret/blog")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"secret/blog", "secret/shared", "kv/app"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v, want %v", got, want)
	}
	if all, err := NormalizePrefixes("*"); err != nil || len(all) != 1 || all[0] != "*" {
		t.Fatalf("* = %v, %v", all, err)
	}
	for _, bad := range []string{"", "  \n ", "secret/../prod", "secret//x", "sec ret", "%2e%2e"} {
		if _, err := NormalizePrefixes(bad); err == nil {
			t.Errorf("NormalizePrefixes(%q) accepted it", bad)
		}
	}

	prefixes := []string{"secret/blog", "kv/app"}
	for path, want := range map[string]bool{
		"secret/blog":       true,
		"secret/blog/db":    true,
		"secret/blog/a/b":   true,
		"secret/blogger":    false,
		"secret/blogger/db": false,
		"secret":            false,
		"secret/prod/blog":  false,
		"kv/app/token":      true,
		"other/secret/blog": false,
	} {
		if PathAllowed(prefixes, path) != want {
			t.Errorf("PathAllowed(%q) = %v, want %v", path, !want, want)
		}
	}
	if !PathAllowed([]string{"*"}, "any/path") {
		t.Error("* must allow every path")
	}
}

func TestEffectiveIdentityFollowsConfigAndCredentials(t *testing.T) {
	base := NewEffective("vault", map[string]string{"address": "a"}, map[string]string{"token": "t"}, nil, "s")
	same := NewEffective("vault", map[string]string{"address": "a"}, map[string]string{"token": "t"}, []string{"x"}, "other source")
	otherCred := NewEffective("vault", map[string]string{"address": "a"}, map[string]string{"token": "u"}, nil, "s")
	otherAddr := NewEffective("vault", map[string]string{"address": "b"}, map[string]string{"token": "t"}, nil, "s")

	if base.Identity != same.Identity {
		t.Error("prefixes and source must not change the identity")
	}
	if base.Identity == otherCred.Identity || base.Identity == otherAddr.Identity {
		t.Error("a different credential or address must change the identity")
	}
}
