package secrets

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	pidBlog = "11111111-1111-1111-1111-111111111111"
	pidShop = "22222222-2222-2222-2222-222222222222"
	pidDup1 = "33333333-3333-3333-3333-333333333333"
	pidDup2 = "44444444-4444-4444-4444-444444444444"
	bwsTok  = "0.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.s3cr3tpart:a2V5a2V5a2V5"
)

// fakeBws is a stand-in for the bws binary: a shell script that records how it
// was called and answers from fixture files.
type fakeBws struct {
	dir  string
	tool *BwsTool
	log  string
}

func newFakeBws(t *testing.T) *fakeBws {
	t.Helper()
	dir := t.TempDir()
	f := &fakeBws{dir: dir, tool: NewBwsTool(filepath.Join(dir, "cache")), log: filepath.Join(dir, "calls.log")}
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("projects.json", fmt.Sprintf(`[{"object":"project","id":%q,"name":"blog"},{"object":"project","id":%q,"name":"shop"},{"object":"project","id":%q,"name":"twice"},{"object":"project","id":%q,"name":"twice"}]`, pidBlog, pidShop, pidDup1, pidDup2))
	write(pidBlog+".json", `[{"id":"s1","key":"db_password","value":"p4ss","note":"the database"},{"id":"s2","key":"smtp","value":"mail","note":""},{"id":"s3","key":"same","value":"a","note":""},{"id":"s4","key":"same","value":"b","note":""}]`)
	write(pidShop+".json", `[{"id":"s5","key":"db_password","value":"shop-pass","note":""}]`)
	write(pidDup1+".json", `[]`)
	script := `#!/bin/sh
{ echo "ARGS: $*"; env | sort | sed 's/^/ENV: /'; } >> "` + f.log + `"
case "$1 $2" in
  "project list") cat "` + dir + `/projects.json" ;;
  "secret list") cat "` + dir + `/$3.json" 2>/dev/null || { echo "Error: " >&2; echo "   0: Unauthorized" >&2; exit 1; } ;;
  *) echo "Error: " >&2; echo "   0: unexpected usage" >&2; exit 1 ;;
esac
`
	if err := os.MkdirAll(filepath.Dir(f.tool.Path()), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.tool.Path(), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fakeBws) effective(config map[string]string) *Effective {
	if config == nil {
		config = map[string]string{}
	}
	return NewEffective("bws", config, map[string]string{"access_token": bwsTok}, []string{"blog", "twice"}, "test connection")
}

func (f *fakeBws) calls(t *testing.T) string {
	t.Helper()
	b, _ := os.ReadFile(f.log)
	return string(b)
}

func resolveBws(f *fakeBws, job *Job, path, field string) (string, error) {
	return BwsProvider(f.tool).Resolve(context.Background(), job, Ref{Scheme: "bws", Path: path, Field: field})
}

func TestBwsResolvesAValueAndANote(t *testing.T) {
	f := newFakeBws(t)
	job := jobFor(f.effective(nil))
	if got, err := resolveBws(f, job, "blog/db_password", "value"); err != nil || got != "p4ss" {
		t.Fatalf("value = %q, %v", got, err)
	}
	if got, err := resolveBws(f, job, "blog/db_password", "note"); err != nil || got != "the database" {
		t.Fatalf("note = %q, %v", got, err)
	}
	if got, err := resolveBws(f, job, "blog/smtp", "note"); err != nil || got != "" {
		t.Fatalf("an empty note is an empty string, not an error: %q, %v", got, err)
	}
}

func TestBwsReadsEachProjectOncePerDeployment(t *testing.T) {
	f := newFakeBws(t)
	job := jobFor(f.effective(nil))
	for _, path := range []string{"blog/db_password", "blog/smtp", "blog/db_password"} {
		if _, err := resolveBws(f, job, path, "value"); err != nil {
			t.Fatal(err)
		}
	}
	log := f.calls(t)
	if n := strings.Count(log, "ARGS: project list"); n != 1 {
		t.Errorf("project list ran %d times, want 1 for three references", n)
	}
	if n := strings.Count(log, "ARGS: secret list "+pidBlog); n != 1 {
		t.Errorf("secret list ran %d times, want 1", n)
	}
}

func TestBwsNeverPutsTheTokenOnTheCommandLineOrLeaksTheControllerEnvironment(t *testing.T) {
	t.Setenv("WHARF_ADMIN_PASSWORD", "controller-secret-sentinel")
	t.Setenv("SSL_CERT_FILE", "/etc/ssl/private-ca.pem")
	f := newFakeBws(t)
	if _, err := resolveBws(f, jobFor(f.effective(nil)), "blog/smtp", "value"); err != nil {
		t.Fatal(err)
	}
	log := f.calls(t)
	for _, line := range strings.Split(log, "\n") {
		if strings.HasPrefix(line, "ARGS:") && strings.Contains(line, "s3cr3tpart") {
			t.Errorf("the token is on the command line: %s", line)
		}
	}
	for _, want := range []string{"ENV: BWS_ACCESS_TOKEN=" + bwsTok, "ENV: BWS_SERVER_URL=https://vault.bitwarden.com", "ENV: SSL_CERT_FILE=/etc/ssl/private-ca.pem", "ENV: NO_COLOR=1"} {
		if !strings.Contains(log, want) {
			t.Errorf("the environment lacks %q", want)
		}
	}
	if strings.Contains(log, "controller-secret-sentinel") || strings.Contains(log, "WHARF_ADMIN_PASSWORD") {
		t.Error("nothing of the controller's own environment may reach bws")
	}
	if !strings.Contains(log, "ENV: HOME=") || strings.Contains(log, "ENV: HOME=/root") {
		t.Error("bws gets a private home")
	}
	home := ""
	for _, line := range strings.Split(log, "\n") {
		if strings.HasPrefix(line, "ENV: HOME=") {
			home = strings.TrimPrefix(line, "ENV: HOME=")
		}
	}
	if _, err := os.Stat(home); err == nil {
		t.Errorf("the private home %s is removed afterwards", home)
	}
}

func TestBwsServerURLPerRegion(t *testing.T) {
	for name, tc := range map[string]struct {
		config map[string]string
		want   string
	}{
		"default":       {nil, "https://vault.bitwarden.com"},
		"us":            {map[string]string{"region": "us"}, "https://vault.bitwarden.com"},
		"eu":            {map[string]string{"region": "eu"}, "https://vault.bitwarden.eu"},
		"custom":        {map[string]string{"region": "custom", "server_url": "https://vault.example.lan/"}, "https://vault.example.lan"},
		"custom spaces": {map[string]string{"region": "custom", "server_url": " http://10.0.0.5:8080 "}, "http://10.0.0.5:8080"},
	} {
		f := newFakeBws(t)
		if _, err := resolveBws(f, jobFor(f.effective(tc.config)), "blog/smtp", "value"); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(f.calls(t), "ENV: BWS_SERVER_URL="+tc.want+"\n") {
			t.Errorf("%s: server url is not %s:\n%s", name, tc.want, f.calls(t))
		}
	}
}

func TestBwsAmbiguousAndMissingNamesFail(t *testing.T) {
	f := newFakeBws(t)
	job := jobFor(f.effective(nil))
	for path, want := range map[string]string{
		"twice/anything":      "2 projects are named",
		"blog/same":           "2 secrets are named",
		"blog/nothing":        `no secret named "nothing" in project "blog"`,
		"missing/db_password": `no project named "missing"`,
	} {
		got, err := resolveBws(f, job, path, "value")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", path, err, want)
		}
		if got != "" {
			t.Errorf("%s: a failed reference gives no value, got %q", path, got)
		}
	}
}

func TestBwsRefusesWhatIsNotAProjectSlashKey(t *testing.T) {
	f := newFakeBws(t)
	job := jobFor(f.effective(nil))
	for _, path := range []string{"blog", "blog/a/b", "a/b/c/d"} {
		if _, err := resolveBws(f, job, path, "value"); err == nil || !strings.Contains(err.Error(), "<project>/<secret key>") {
			t.Errorf("%q: %v", path, err)
		}
	}
	if _, err := resolveBws(f, job, "blog/smtp", "password"); err == nil || !strings.Contains(err.Error(), "#/value or #/note") {
		t.Errorf("a bws secret has no other field: %v", err)
	}
	if strings.Contains(f.calls(t), "ARGS:") {
		t.Error("a malformed reference must not even start bws")
	}
}

func TestBwsRefusesAProjectIdItCannotTrust(t *testing.T) {
	f := newFakeBws(t)
	// a project id is handed to bws as an argument: it must look like an id
	if err := os.WriteFile(filepath.Join(f.dir, "projects.json"), []byte(`[{"id":"--output=env","name":"evil"}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveBws(f, jobFor(f.effective(nil)), "evil/x", "value"); err == nil || !strings.Contains(err.Error(), "does not look like") {
		t.Errorf("err = %v", err)
	}
	if strings.Contains(f.calls(t), "secret list") {
		t.Error("an id that is not one must never become an argument")
	}
}

func TestBwsSurfacesTheToolsOwnMessageWithoutTheToken(t *testing.T) {
	f := newFakeBws(t)
	// a project listed by the fixture whose secrets file does not exist: the script fails
	if err := os.Remove(filepath.Join(f.dir, pidShop+".json")); err != nil {
		t.Fatal(err)
	}
	_, err := resolveBws(f, jobFor(f.effective(nil)), "shop/db_password", "value")
	if err == nil || err.Error() != "bws: Unauthorized" {
		t.Errorf("err = %v, want the line bws printed", err)
	}

	msg := bwsError(context.Background(), fmt.Errorf("exit status 1"), "Error: \n   0: failed with token "+bwsTok+"\n", bwsTok)
	if strings.Contains(msg.Error(), "s3cr3tpart") || !strings.Contains(msg.Error(), "***") {
		t.Errorf("a token that leaks into an error message is blanked: %v", msg)
	}
}

func TestBwsNotInstalled(t *testing.T) {
	tool := NewBwsTool(t.TempDir())
	eff := NewEffective("bws", nil, map[string]string{"access_token": bwsTok}, []string{"blog"}, "x")
	if _, err := BwsProvider(tool).Resolve(context.Background(), jobFor(eff), Ref{Scheme: "bws", Path: "blog/x", Field: "value"}); err != ErrBwsNotInstalled {
		t.Errorf("err = %v", err)
	}
	if err := BwsProvider(tool).Check(context.Background(), eff); err != ErrBwsNotInstalled {
		t.Errorf("check = %v", err)
	}
	if tool.Installed() {
		t.Error("nothing downloaded yet")
	}
}

func TestBwsCheckLogsInWithoutReadingASecret(t *testing.T) {
	f := newFakeBws(t)
	if err := BwsProvider(f.tool).Check(context.Background(), f.effective(nil)); err != nil {
		t.Fatal(err)
	}
	log := f.calls(t)
	if !strings.Contains(log, "ARGS: project list") || strings.Contains(log, "secret list") {
		t.Errorf("a check only lists projects:\n%s", log)
	}
	bad := NewEffective("bws", nil, map[string]string{"access_token": "nope"}, nil, "x")
	if err := BwsProvider(f.tool).Check(context.Background(), bad); err == nil || !strings.Contains(err.Error(), "does not look like") {
		t.Errorf("a malformed token is refused before bws runs: %v", err)
	}
}

func TestBwsEnforcesPathRulesThroughTheResolver(t *testing.T) {
	f := newFakeBws(t)
	// a project per stack
	eff := NewEffective("bws", map[string]string{PathRulesKey: "{stack}"}, map[string]string{"access_token": bwsTok}, nil, "test")
	if err := eff.ApplyPathRules("blog"); err != nil {
		t.Fatal(err)
	}
	r := NewResolver(BwsProvider(f.tool))
	res, err := r.Resolve(context.Background(), jobFor(eff), []Entry{{"DB", Ref{"bws", "blog/db_password", "value"}}})
	if err != nil || res.Env["DB"] != "p4ss" {
		t.Fatalf("%+v %v", res, err)
	}
	before := strings.Count(f.calls(t), "ARGS:")
	if _, err := r.Resolve(context.Background(), jobFor(eff), []Entry{{"DB", Ref{"bws", "shop/db_password", "value"}}}); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("another stack's project is refused: %v", err)
	}
	if strings.Count(f.calls(t), "ARGS:") != before {
		t.Error("a refused path must never reach bws")
	}

	// a shared project, secrets named after the stack
	shared := NewEffective("bws", map[string]string{PathRulesKey: "twice/{stack}_*"}, map[string]string{"access_token": bwsTok}, nil, "test")
	shared.ApplyPathRules("blog")
	if !shared.PathAllowed("twice/blog_db") || shared.PathAllowed("twice/shop_db") || shared.PathAllowed("twice/blog-staging_db") {
		t.Error("the prefix rule keeps one stack's names apart from another's")
	}
}

func TestBwsConfigAndCredentialValidation(t *testing.T) {
	p := BwsProvider(NewBwsTool(t.TempDir()))
	for config, ok := range map[string]bool{
		"":                      true,
		"us":                    true,
		"eu":                    true,
		"mars":                  false,
		"custom":                false,
		"custom|http://a.lan":   true,
		"custom|ftp://a.lan":    false,
		"custom|https://u:p@a/": false,
		"custom|https://a/?x=1": false,
	} {
		region, server, _ := strings.Cut(config, "|")
		err := p.ValidateConfig(map[string]string{"region": region, "server_url": server})
		if (err == nil) != ok {
			t.Errorf("config %q: err = %v, want ok = %v", config, err, ok)
		}
	}
	if err := p.ValidateConfig(map[string]string{"region": "us", PathRulesKey: "{stack}-*"}); err == nil {
		t.Error("a wrong rule is refused")
	}
	for token, ok := range map[string]bool{bwsTok: true, "": false, "abc": false, "1.x:y": false, "0.a b:c": false, "0.nocolon": false} {
		if err := p.ValidateCredentials(map[string]string{"access_token": token}); (err == nil) != ok {
			t.Errorf("token %q: err = %v", token, err)
		}
	}
	names := map[string]bool{}
	for _, f := range p.Fields() {
		names[f.Name] = f.Credential
	}
	if cred, ok := names["access_token"]; !ok || !cred {
		t.Error("the token is a credential field, write-only")
	}
	if _, ok := names[PathRulesKey]; !ok {
		t.Error("the connection form offers the rules field")
	}
}

// ---- the download

func zipWith(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	zw.Close()
	return buf.Bytes()
}

func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestBwsInstallVerifiesThePinnedChecksumThenUnpacks(t *testing.T) {
	archive := zipWith(t, map[string]string{"bws": "#!/bin/sh\necho hi\n", "README": "x"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(archive) }))
	defer srv.Close()

	tool := NewBwsTool(t.TempDir())
	tool.Override(BwsRelease{URL: srv.URL + "/bws.zip", SHA256: hashOf(archive)})
	if tool.Installed() {
		t.Fatal("not yet")
	}
	if err := tool.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(tool.Path())
	if err != nil || !tool.Installed() {
		t.Fatalf("installed = %v, %v", tool.Installed(), err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o755 {
		t.Errorf("mode = %v", info.Mode())
	}
	if b, _ := os.ReadFile(tool.Path()); string(b) != "#!/bin/sh\necho hi\n" {
		t.Errorf("content = %q", b)
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(tool.Path()), "*-*"))
	if len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

func TestBwsInstallRefusesAWrongChecksumAndRunsNothing(t *testing.T) {
	archive := zipWith(t, map[string]string{"bws": "malicious"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(archive) }))
	defer srv.Close()

	tool := NewBwsTool(t.TempDir())
	tool.Override(BwsRelease{URL: srv.URL, SHA256: strings.Repeat("0", 64)})
	if err := tool.Install(context.Background()); err == nil || !strings.Contains(err.Error(), "pinned checksum") {
		t.Fatalf("err = %v", err)
	}
	if tool.Installed() {
		t.Error("a download that does not match is never put in place")
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(tool.Path()), "*"))
	if len(left) != 0 {
		t.Errorf("the discarded download is removed: %v", left)
	}
}

func TestBwsInstallRefusesAnArchiveWithoutTheBinaryAndAFailingServer(t *testing.T) {
	archive := zipWith(t, map[string]string{"README": "no binary here"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/gone" {
			http.NotFound(w, r)
			return
		}
		w.Write(archive)
	}))
	defer srv.Close()

	tool := NewBwsTool(t.TempDir())
	tool.Override(BwsRelease{URL: srv.URL + "/ok", SHA256: hashOf(archive)})
	if err := tool.Install(context.Background()); err == nil || !strings.Contains(err.Error(), "does not contain a bws binary") {
		t.Errorf("err = %v", err)
	}
	tool.Override(BwsRelease{URL: srv.URL + "/gone", SHA256: hashOf(archive)})
	if err := tool.Install(context.Background()); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("err = %v", err)
	}
	if tool.Installed() {
		t.Error("nothing installed")
	}
}

func TestBwsPinnedReleasesAreWellFormed(t *testing.T) {
	for arch, rel := range bwsReleases {
		if !strings.HasPrefix(rel.URL, "https://github.com/bitwarden/sdk-sm/releases/download/bws-v"+BwsVersion+"/") ||
			!strings.Contains(rel.URL, "linux-musl-"+BwsVersion+".zip") {
			t.Errorf("%s: %s", arch, rel.URL)
		}
		if len(rel.SHA256) != 64 || strings.Trim(rel.SHA256, "0123456789abcdef") != "" {
			t.Errorf("%s: the checksum is not a SHA-256: %q", arch, rel.SHA256)
		}
	}
	if _, ok := bwsReleases["amd64"]; !ok {
		t.Error("amd64 is pinned")
	}
	if _, ok := bwsReleases["arm64"]; !ok {
		t.Error("arm64 is pinned")
	}
}

func TestBwsToolPath(t *testing.T) {
	tool := NewBwsTool("/cache")
	if got := filepath.ToSlash(tool.Path()); got != "/cache/secret-tools/bws/"+BwsVersion+"/bws" {
		t.Errorf("path = %s", got)
	}
}

// What bws prints when the controller cannot reach Bitwarden: the cause is in the lines below the first.
func TestBwsErrorKeepsTheWholeChainOfCauses(t *testing.T) {
	stderr := `Error: 
   0: error sending request for url (https://vault.bitwarden.com/identity/connect/token)
   1: client error (Connect)
   2: dns error
   3: failed to lookup address information: Name does not resolve

Location:
   crates/bws/src/main.rs:107

Backtrace omitted. Run with RUST_BACKTRACE=1 environment variable to display it.
`
	got := bwsError(context.Background(), fmt.Errorf("exit status 1"), stderr, "").Error()
	want := "bws: error sending request for url (https://vault.bitwarden.com/identity/connect/token): client error (Connect): dns error: failed to lookup address information: Name does not resolve"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}

	one := "Error: \n   0: Received error message from server: [400 Bad Request] {\"error\":\"invalid_client\"}\n\nLocation:\n   x.rs:1\n"
	if got := bwsError(context.Background(), fmt.Errorf("exit status 1"), one, "").Error(); !strings.Contains(got, "invalid_client") || strings.Contains(got, "Location") {
		t.Errorf("a single line stays a single line: %q", got)
	}
}
