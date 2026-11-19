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
	testClientID     = "client-1"
	testClientSecret = "client-secret-1"
	testInfisicalTok = "static-access-token"
)

// fakeInfisical answers just enough of the Infisical API for the provider.
type fakeInfisical struct {
	srv         *httptest.Server
	logins      atomic.Int32
	reads       atomic.Int32
	validTokens map[string]bool
}

func newFakeInfisical(t *testing.T) *fakeInfisical {
	t.Helper()
	f := &fakeInfisical{validTokens: map[string]bool{testInfisicalTok: true}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/universal-auth/login", func(w http.ResponseWriter, r *http.Request) {
		f.logins.Add(1)
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["clientId"] != testClientID || body["clientSecret"] != testClientSecret {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"message":"invalid client id or secret"}`))
			return
		}
		tok := "uaid-" + string(rune('a'+f.logins.Load()))
		f.validTokens[tok] = true
		w.Write([]byte(`{"accessToken":"` + tok + `","expiresIn":3600,"accessTokenMaxTTL":7200,"tokenType":"Bearer"}`))
	})
	mux.HandleFunc("GET /api/v1/identities/details", func(w http.ResponseWriter, r *http.Request) {
		if !f.validTokens[bearerOf(r)] {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"message":"permission denied"}`))
			return
		}
		w.Write([]byte(`{"identityDetails":{"organization":{"id":"org-1","name":"org","slug":"org"}}}`))
	})
	mux.HandleFunc("GET /api/v4/secrets/", func(w http.ResponseWriter, r *http.Request) {
		f.reads.Add(1)
		if !f.validTokens[bearerOf(r)] {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"message":"permission denied"}`))
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/api/v4/secrets/")
		project, environment, path := r.URL.Query().Get("projectId"), r.URL.Query().Get("environment"), r.URL.Query().Get("secretPath")
		switch {
		case project == "proj-1" && environment == "prod" && path == "/db" && name == "password":
			w.Write([]byte(`{"secret":{"secretKey":"password","secretValue":"p4ss"}}`))
		case project == "proj-1" && environment == "prod" && path == "/" && name == "api_key":
			w.Write([]byte(`{"secret":{"secretKey":"api_key","secretValue":"root-key"}}`))
		case project == "proj-1" && environment == "prod" && path == "/db" && name == "redirect":
			http.Redirect(w, r, "http://127.0.0.1:1/stolen", http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"message":"secret not found"}`))
		}
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func bearerOf(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func (f *fakeInfisical) effective(creds map[string]string, extra map[string]string) *Effective {
	config := map[string]string{"site_url": f.srv.URL}
	for k, v := range extra {
		config[k] = v
	}
	return NewEffective("infisical", config, creds, []string{"proj-1"}, "test connection")
}

func TestInfisicalStaticTokenReadsASecret(t *testing.T) {
	f := newFakeInfisical(t)
	p := InfisicalProvider()
	job := jobFor(f.effective(map[string]string{"token": testInfisicalTok}, nil))

	got, err := p.Resolve(context.Background(), job, Ref{Scheme: "infisical", Path: "proj-1/prod/db", Field: "password"})
	if err != nil || got != "p4ss" {
		t.Fatalf("got %q, %v", got, err)
	}
	got, err = p.Resolve(context.Background(), job, Ref{Scheme: "infisical", Path: "proj-1/prod", Field: "api_key"})
	if err != nil || got != "root-key" {
		t.Fatalf("root secret: got %q, %v", got, err)
	}
}

func TestInfisicalMemoizesEachReference(t *testing.T) {
	f := newFakeInfisical(t)
	p := InfisicalProvider()
	job := jobFor(f.effective(map[string]string{"token": testInfisicalTok}, nil))

	for i := 0; i < 3; i++ {
		if _, err := p.Resolve(context.Background(), job, Ref{Scheme: "infisical", Path: "proj-1/prod/db", Field: "password"}); err != nil {
			t.Fatal(err)
		}
	}
	if f.reads.Load() != 1 {
		t.Errorf("reads = %d, want 1 (same reference asked three times)", f.reads.Load())
	}
}

func TestInfisicalUniversalAuthCachesTheToken(t *testing.T) {
	f := newFakeInfisical(t)
	p := InfisicalProvider()
	creds := map[string]string{"client_id": testClientID, "client_secret": testClientSecret}

	for i := 0; i < 3; i++ {
		job := jobFor(f.effective(creds, nil))
		if got, err := p.Resolve(context.Background(), job, Ref{Scheme: "infisical", Path: "proj-1/prod/db", Field: "password"}); err != nil || got != "p4ss" {
			t.Fatalf("read %d: %q, %v", i, got, err)
		}
	}
	if f.logins.Load() != 1 {
		t.Fatalf("logged in %d times across three deployments, want 1", f.logins.Load())
	}
}

func TestInfisicalTokenCacheIsPerIdentity(t *testing.T) {
	f := newFakeInfisical(t)
	p := InfisicalProvider()
	good := f.effective(map[string]string{"client_id": testClientID, "client_secret": testClientSecret}, nil)
	bad := f.effective(map[string]string{"client_id": testClientID, "client_secret": "wrong"}, nil)

	if _, err := p.Resolve(context.Background(), jobFor(good), Ref{Scheme: "infisical", Path: "proj-1/prod/db", Field: "password"}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Resolve(context.Background(), jobFor(bad), Ref{Scheme: "infisical", Path: "proj-1/prod/db", Field: "password"}); err == nil || !strings.Contains(err.Error(), "login refused") {
		t.Fatalf("a stack with different credentials must log in for itself, got %v", err)
	}
	if f.logins.Load() != 2 {
		t.Fatalf("logins = %d, want 2", f.logins.Load())
	}
}

func TestInfisicalReloginsOnceWhenTheCachedTokenIsRevoked(t *testing.T) {
	f := newFakeInfisical(t)
	p := InfisicalProvider()
	creds := map[string]string{"client_id": testClientID, "client_secret": testClientSecret}
	eff := f.effective(creds, nil)

	if _, err := p.Resolve(context.Background(), jobFor(eff), Ref{Scheme: "infisical", Path: "proj-1/prod/db", Field: "password"}); err != nil {
		t.Fatal(err)
	}
	for tok := range f.validTokens {
		if strings.HasPrefix(tok, "uaid-") {
			delete(f.validTokens, tok)
		}
	}
	got, err := p.Resolve(context.Background(), jobFor(eff), Ref{Scheme: "infisical", Path: "proj-1/prod/db", Field: "password"})
	if err != nil || got != "p4ss" {
		t.Fatalf("got %q, %v", got, err)
	}
	if f.logins.Load() != 2 {
		t.Fatalf("logins = %d, want 2 (one re-login)", f.logins.Load())
	}
}

func TestInfisicalErrorsSayWhichStepFailed(t *testing.T) {
	f := newFakeInfisical(t)
	p := InfisicalProvider()
	creds := map[string]string{"token": testInfisicalTok}

	cases := []struct {
		name string
		eff  *Effective
		path string
		want string
	}{
		{"login refused", f.effective(map[string]string{"client_id": testClientID, "client_secret": "wrong"}, nil), "proj-1/prod/db", "login refused: invalid client id or secret"},
		{"forbidden", f.effective(map[string]string{"token": "revoked"}, nil), "proj-1/prod/db", "permission denied by Infisical for proj-1/prod/db"},
		{"no such secret", f.effective(creds, nil), "proj-1/prod/missing", "no secret at proj-1/prod/missing"},
		{"redirect", f.effective(creds, nil), "proj-1/prod/db", "redirect (302), which is not followed"},
		{"unreachable", NewEffective("infisical", map[string]string{"site_url": "http://127.0.0.1:1"}, creds, []string{"*"}, "x"), "proj-1/prod/db", "cannot reach Infisical at http://127.0.0.1:1"},
		{"no environment", f.effective(creds, nil), "proj-1", "path must be <project id>/<environment>"},
	}
	for _, tc := range cases {
		field := "password"
		if tc.name == "redirect" {
			field = "redirect"
		}
		_, err := p.Resolve(context.Background(), jobFor(tc.eff), Ref{Scheme: "infisical", Path: tc.path, Field: field})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to contain %q", tc.name, err, tc.want)
			continue
		}
		for _, secret := range []string{testInfisicalTok, testClientSecret, "wrong"} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%s: error leaks a credential: %v", tc.name, err)
			}
		}
	}
}

func TestInfisicalCheck(t *testing.T) {
	f := newFakeInfisical(t)
	p := InfisicalProvider()
	ctx := context.Background()

	if err := p.Check(ctx, f.effective(map[string]string{"token": testInfisicalTok}, nil)); err != nil {
		t.Errorf("valid token: %v", err)
	}
	if err := p.Check(ctx, f.effective(map[string]string{"token": "revoked"}, nil)); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("revoked token: %v", err)
	}
	if err := p.Check(ctx, f.effective(map[string]string{"client_id": testClientID, "client_secret": testClientSecret}, nil)); err != nil {
		t.Errorf("valid Universal Auth: %v", err)
	}
	if err := p.Check(ctx, f.effective(map[string]string{"client_id": testClientID, "client_secret": "wrong"}, nil)); err == nil || !strings.Contains(err.Error(), "login refused") {
		t.Errorf("wrong client secret: %v", err)
	}
	if err := p.Check(ctx, f.effective(map[string]string{}, nil)); err == nil {
		t.Error("no credentials must fail the check")
	}
}

func TestInfisicalValidation(t *testing.T) {
	p := InfisicalProvider()

	for _, ok := range []map[string]string{
		{"site_url": "https://app.infisical.com"},
		{"site_url": "https://infisical.example.lan/"},
	} {
		if err := p.ValidateConfig(ok); err != nil {
			t.Errorf("ValidateConfig(%v) = %v", ok, err)
		}
	}
	for _, bad := range []map[string]string{
		{},
		{"site_url": "infisical.example.lan"},
		{"site_url": "ftp://infisical.example.lan"},
		{"site_url": "https://user:pass@infisical.example.lan"},
		{"site_url": "https://infisical.example.lan?x=1"},
		{"site_url": "https://infisical.example.lan", "ca_pem": "not a certificate"},
	} {
		if err := p.ValidateConfig(bad); err == nil {
			t.Errorf("ValidateConfig(%v) accepted it", bad)
		}
	}

	for _, ok := range []map[string]string{
		{"token": "tok"},
		{"client_id": "id", "client_secret": "secret"},
	} {
		if err := p.ValidateCredentials(ok); err != nil {
			t.Errorf("ValidateCredentials(%v) = %v", ok, err)
		}
	}
	for _, bad := range []map[string]string{
		{},
		{"client_id": "id"},
		{"client_secret": "secret"},
		{"token": "tok", "client_id": "id", "client_secret": "secret"},
	} {
		if err := p.ValidateCredentials(bad); err == nil {
			t.Errorf("ValidateCredentials(%v) accepted it", bad)
		}
	}
}

func TestInfisicalResolverEnforcesPrefixes(t *testing.T) {
	f := newFakeInfisical(t)
	eff := f.effective(map[string]string{"token": testInfisicalTok}, nil) // prefix: proj-1
	r := NewResolver(InfisicalProvider())

	res, err := r.Resolve(context.Background(), jobFor(eff), []Entry{
		{Key: "DB_PASSWORD", Ref: Ref{Scheme: "infisical", Path: "proj-1/prod/db", Field: "password"}},
	})
	if err != nil || res.Env["DB_PASSWORD"] != "p4ss" {
		t.Fatalf("res = %+v, err = %v", res, err)
	}

	_, err = r.Resolve(context.Background(), jobFor(eff), []Entry{
		{Key: "OUTSIDE", Ref: Ref{Scheme: "infisical", Path: "proj-2/prod/db", Field: "password"}},
	})
	var rerr *ResolveError
	if !asResolveError(err, &rerr) || len(rerr.Failures) != 1 {
		t.Fatalf("err = %v, want a prefix failure", err)
	}
	if !strings.Contains(err.Error(), "outside the prefixes allowed for this stack") {
		t.Errorf("err = %v", err)
	}
}
