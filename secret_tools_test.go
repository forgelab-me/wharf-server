package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/forgelab-me/wharf-server/internal/keys"
	"github.com/forgelab-me/wharf-server/internal/secrets"
	"github.com/forgelab-me/wharf-server/internal/store"
)

const testBwsToken = "0.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.s3cr3tpart:a2V5a2V5a2V5"

// bwsFixture is a controller that can read Bitwarden, with a fake bws binary.
func newBwsFixture(t *testing.T) (*app, *secrets.BwsTool) {
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
	tool := secrets.NewBwsTool(t.TempDir())
	a := &app{store: st, keys: kc, bws: tool,
		resolver: secrets.NewResolver(secrets.SOPSProvider(), secrets.VaultProvider(), secrets.BwsProvider(tool))}
	return a, tool
}

// installFakeBws puts a script where the tool is looked for. It lists a project
// per stack and, in each, a secret named after it.
func installFakeBws(t *testing.T, tool *secrets.BwsTool) {
	t.Helper()
	script := `#!/bin/sh
case "$1 $2" in
  "project list") echo '[{"id":"11111111-1111-1111-1111-111111111111","name":"blog"},{"id":"22222222-2222-2222-2222-222222222222","name":"wiki"},{"id":"33333333-3333-3333-3333-333333333333","name":"homelab"}]' ;;
  "secret list") case "$3" in
      11111111-1111-1111-1111-111111111111) echo '[{"id":"a","key":"db_password","value":"blog-pass","note":""}]' ;;
      22222222-2222-2222-2222-222222222222) echo '[{"id":"b","key":"db_password","value":"wiki-pass","note":""}]' ;;
      33333333-3333-3333-3333-333333333333) echo '[{"id":"c","key":"blog_smtp","value":"blog-mail","note":""},{"id":"d","key":"wiki_smtp","value":"wiki-mail","note":""}]' ;;
    esac ;;
esac
`
	if err := os.MkdirAll(filepath.Dir(tool.Path()), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tool.Path(), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func (a *app) createBws(t *testing.T, name, rules string) store.SecretConnection {
	t.Helper()
	form := url.Values{"type": {"bws"}, "name": {name}, "cfg_region": {"us"}, "cfg_path_rules": {rules}, "cred_access_token": {testBwsToken}}
	code, loc := call(a.createSecretProviderHandler, "/settings/secret-providers", form, nil)
	if code != 303 || strings.Contains(loc, "error=") {
		t.Fatalf("create bws connection: %d %s", code, loc)
	}
	conns, _ := a.store.ListGlobalSecretConnections()
	for _, c := range conns {
		if c.Name == name {
			return c
		}
	}
	t.Fatal("not stored")
	return store.SecretConnection{}
}

func (a *app) bindBws(stack string, form url.Values) (int, string) {
	code, loc := call(a.saveStackBindingHandler, "/stacks/"+stack+"/secrets/bindings/bws", form, map[string]string{"id": stack, "type": "bws"})
	u, _ := url.Parse(loc)
	return code, u.Query().Get("error")
}

func (a *app) resolveFor(stack string, entries []secrets.Entry) (secrets.Result, error) {
	job := &secrets.Job{StackID: stack, Binding: a.stackBinding(stack)}
	return a.resolver.Resolve(context.Background(), job, entries)
}

func TestBitwardenAProjectPerStack(t *testing.T) {
	a, tool := newBwsFixture(t)
	installFakeBws(t, tool)
	conn := a.createBws(t, "bitwarden", "{stack}")

	for _, stack := range []string{"blog", "wiki"} {
		if code, msg := a.bindBws(stack, url.Values{"mode": {"shared"}, "connection_id": {conn.ID}}); code != 303 || msg != "" {
			t.Fatalf("%s: %d %q", stack, code, msg)
		}
	}
	res, err := a.resolveFor("blog", []secrets.Entry{{Key: "DB_PASSWORD", Ref: secrets.Ref{Scheme: "bws", Path: "blog/db_password", Field: "value"}}})
	if err != nil || res.Env["DB_PASSWORD"] != "blog-pass" {
		t.Fatalf("blog reads its own project: %+v %v", res, err)
	}
	_, err = a.resolveFor("blog", []secrets.Entry{{Key: "STOLEN", Ref: secrets.Ref{Scheme: "bws", Path: "wiki/db_password", Field: "value"}}})
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("blog must not read wiki's project: %v", err)
	}
	if res, err := a.resolveFor("wiki", []secrets.Entry{{Key: "DB_PASSWORD", Ref: secrets.Ref{Scheme: "bws", Path: "wiki/db_password", Field: "value"}}}); err != nil || res.Env["DB_PASSWORD"] != "wiki-pass" {
		t.Fatalf("and wiki reads its own: %+v %v", res, err)
	}
}

func TestBitwardenASharedProjectWithNamePrefixes(t *testing.T) {
	a, tool := newBwsFixture(t)
	installFakeBws(t, tool)
	conn := a.createBws(t, "bitwarden", "homelab/{stack}_*")
	for _, stack := range []string{"blog", "wiki"} {
		if code, msg := a.bindBws(stack, url.Values{"mode": {"shared"}, "connection_id": {conn.ID}}); code != 303 || msg != "" {
			t.Fatalf("%s: %d %q", stack, code, msg)
		}
	}
	res, err := a.resolveFor("blog", []secrets.Entry{{Key: "SMTP", Ref: secrets.Ref{Scheme: "bws", Path: "homelab/blog_smtp", Field: "value"}}})
	if err != nil || res.Env["SMTP"] != "blog-mail" {
		t.Fatalf("a secret named after the stack: %+v %v", res, err)
	}
	if _, err := a.resolveFor("blog", []secrets.Entry{{Key: "SMTP", Ref: secrets.Ref{Scheme: "bws", Path: "homelab/wiki_smtp", Field: "value"}}}); err == nil || !strings.Contains(err.Error(), "rule homelab/blog_*") {
		t.Fatalf("a secret named after another stack is refused, and the message says which rule applied: %v", err)
	}
	// a stack with a longer id that starts like another's gets nothing of it
	if err := a.store.CreateStack(store.Stack{ID: "blog-staging", Name: "blog-staging", SourceType: "git", Branch: "main", Trigger: "manual"}); err != nil {
		t.Fatal(err)
	}
	if code, msg := a.bindBws("blog-staging", url.Values{"mode": {"shared"}, "connection_id": {conn.ID}}); code != 303 || msg != "" {
		t.Fatal(code, msg)
	}
	if _, err := a.resolveFor("blog-staging", []secrets.Entry{{Key: "X", Ref: secrets.Ref{Scheme: "bws", Path: "homelab/blog_smtp", Field: "value"}}}); err == nil {
		t.Error("blog-staging must not read what blog_ names")
	}
}

func TestBitwardenConnectionIsValidatedWhenCreated(t *testing.T) {
	a, _ := newBwsFixture(t)
	for name, form := range map[string]url.Values{
		"a bad token":    {"type": {"bws"}, "name": {"x"}, "cfg_region": {"us"}, "cred_access_token": {"hunter2"}},
		"a bad region":   {"type": {"bws"}, "name": {"x"}, "cfg_region": {"mars"}, "cred_access_token": {testBwsToken}},
		"custom, no url": {"type": {"bws"}, "name": {"x"}, "cfg_region": {"custom"}, "cred_access_token": {testBwsToken}},
		"a wrong rule":   {"type": {"bws"}, "name": {"x"}, "cfg_region": {"us"}, "cfg_path_rules": {"{stack}-*"}, "cred_access_token": {testBwsToken}},
	} {
		if _, loc := call(a.createSecretProviderHandler, "/settings/secret-providers", form, nil); !strings.Contains(loc, "error=") {
			t.Errorf("%s must be refused: %s", name, loc)
		}
	}
	if _, loc := call(a.createSecretProviderHandler, "/settings/secret-providers",
		url.Values{"type": {"bws"}, "name": {"ok"}, "cfg_region": {"eu"}, "cred_access_token": {testBwsToken}}, nil); strings.Contains(loc, "error=") {
		t.Errorf("a good connection is accepted: %s", loc)
	}
}

func TestBitwardenTokenIsWriteOnly(t *testing.T) {
	a, _ := newBwsFixture(t)
	conn := a.createBws(t, "bitwarden", "{stack}")
	set, _ := a.keys.SecretCredentialFields(conn.ID)
	if len(set) != 1 || set[0] != "access_token" {
		t.Errorf("stored credential fields = %v", set)
	}
	stored, _ := a.store.GetSecretConnection(conn.ID)
	for k, v := range stored.Config {
		if strings.Contains(v, "s3cr3tpart") {
			t.Errorf("the token must not be in the connection's visible config (%s)", k)
		}
	}
	body := get(a.secretProvidersHandler, "/settings/secret-providers", nil).Body.String()
	if strings.Contains(body, "s3cr3tpart") {
		t.Error("the token is never shown")
	}
}

func bwsZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("bws")
	w.Write([]byte("#!/bin/sh\necho 2.1.0\n"))
	zw.Close()
	return buf.Bytes()
}

func TestInstallBwsNeedsTheLicenceAccepted(t *testing.T) {
	a, tool := newBwsFixture(t)
	archive := bwsZip(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(archive) }))
	defer srv.Close()
	sum := sha256.Sum256(archive)
	tool.Override(secrets.BwsRelease{URL: srv.URL, SHA256: hex.EncodeToString(sum[:])})

	if _, loc := call(a.installBwsHandler, "/settings/secret-providers/bws/install", url.Values{}, nil); !strings.Contains(loc, "licence") || !strings.Contains(loc, "error=") {
		t.Errorf("without accepting: %s", loc)
	}
	if tool.Installed() {
		t.Fatal("nothing is downloaded before the licence is accepted")
	}
	code, loc := call(a.installBwsHandler, "/settings/secret-providers/bws/install", url.Values{"accept_license": {"1"}}, nil)
	if code != 303 || strings.Contains(loc, "error=") || !tool.Installed() {
		t.Fatalf("accepting installs it: %d %s installed=%v", code, loc, tool.Installed())
	}
}

func TestInstallBwsRefusesADownloadThatDoesNotMatch(t *testing.T) {
	a, tool := newBwsFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(bwsZip(t)) }))
	defer srv.Close()
	tool.Override(secrets.BwsRelease{URL: srv.URL, SHA256: strings.Repeat("a", 64)})
	_, loc := call(a.installBwsHandler, "/settings/secret-providers/bws/install", url.Values{"accept_license": {"1"}}, nil)
	if !strings.Contains(loc, "pinned+checksum") && !strings.Contains(loc, "pinned%20checksum") && !strings.Contains(loc, "checksum") {
		t.Errorf("loc = %s", loc)
	}
	if tool.Installed() {
		t.Error("a download that does not match is never kept")
	}
}

func TestProvidersPageSaysWhetherTheBitwardenToolIsThere(t *testing.T) {
	a, tool := newBwsFixture(t)
	body := get(a.secretProvidersHandler, "/settings/secret-providers", nil).Body.String()
	for _, want := range []string{"Bitwarden tool", "accept_license", "Download bws", secrets.BwsLicenseURL, "Bitwarden Secrets Manager"} {
		if !strings.Contains(body, want) {
			t.Errorf("not installed: missing %q", want)
		}
	}
	installFakeBws(t, tool)
	body = get(a.secretProvidersHandler, "/settings/secret-providers", nil).Body.String()
	if !strings.Contains(body, ">installed<") || strings.Contains(body, "accept_license") {
		t.Error("installed: the page says so and no longer asks for the licence")
	}
}

func TestProvidersPageWithoutABitwardenProviderHasNoToolPanel(t *testing.T) {
	f := newSecretsFixture(t) // this controller has no bws
	body := get(f.a.secretProvidersHandler, "/settings/secret-providers", nil).Body.String()
	if strings.Contains(body, "Bitwarden tool") {
		t.Error("no Bitwarden provider, no panel")
	}
	if code, _ := call(f.a.installBwsHandler, "/settings/secret-providers/bws/install", url.Values{"accept_license": {"1"}}, nil); code != http.StatusNotFound {
		t.Errorf("code = %d", code)
	}
}
