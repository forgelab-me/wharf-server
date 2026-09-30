package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/forgelab-me/wharf-server/internal/keys"
	"github.com/forgelab-me/wharf-server/internal/scanner"
	"github.com/forgelab-me/wharf-server/internal/store"
)

// fakeScanner is a Scanner that reads canned results, so the engine can be
// exercised without downloading anything.
type fakeScanner struct {
	name      string
	mu        sync.Mutex
	installed bool
	dbBuilt   string
	installs  int
	updates   int
	scans     []scanner.Target
	auths     []*scanner.Auth
	report    func(t scanner.Target) (scanner.Report, error)
}

func (f *fakeScanner) Name() string               { return f.name }
func (f *fakeScanner) Label() string              { return strings.ToUpper(f.name[:1]) + f.name[1:] }
func (f *fakeScanner) Version() string            { return "1.0.0" }
func (f *fakeScanner) DataDirs(c string) []string { return []string{filepath.Join(c, "fake-"+f.name)} }
func (f *fakeScanner) Installed(string) bool      { f.mu.Lock(); defer f.mu.Unlock(); return f.installed }
func (f *fakeScanner) Install(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.installs++
	f.installed = true
	return nil
}
func (f *fakeScanner) UpdateDB(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updates++
	if f.dbBuilt == "" {
		f.dbBuilt = "2026-09-30T00:00:00Z"
	}
	return nil
}
func (f *fakeScanner) DBBuiltAt(context.Context, string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dbBuilt, nil
}
func (f *fakeScanner) Scan(_ context.Context, _ string, t scanner.Target, auth *scanner.Auth) (scanner.Report, error) {
	f.mu.Lock()
	f.scans = append(f.scans, t)
	f.auths = append(f.auths, auth)
	built := f.dbBuilt
	f.mu.Unlock()
	if f.report != nil {
		return f.report(t)
	}
	return scanner.Report{DBBuiltAt: built, Findings: []scanner.Finding{
		{ID: "CVE-1", Severity: scanner.SevCritical, Package: "openssl", Installed: "1", FixedIn: "2"},
		{ID: "CVE-2", Severity: scanner.SevHigh, Package: "zlib", Installed: "1"},
		{ID: "CVE-3", Severity: scanner.SevLow, Package: "busybox", Installed: "1"},
	}}, nil
}

func digestOf(c string) string { return "sha256:" + strings.Repeat(c, 64) }

type vulnFixture struct {
	a    *app
	fake *fakeScanner
}

func newVulnFixture(t *testing.T) *vulnFixture {
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

	a := &app{store: st, keys: kc}
	a.vuln = newVulnEngine(a, t.TempDir())
	fake := &fakeScanner{name: "trivy"}
	a.vuln.scanners = []scanner.Scanner{fake, &fakeScanner{name: "grype"}}
	if err := st.SetVulnSettingsChoice(true, "trivy"); err != nil {
		t.Fatal(err)
	}
	return &vulnFixture{a: a, fake: fake}
}

// seedFleet creates two hosts and the images and containers of the tests below:
//
//	h1 (amd64): nginx (digest A, in use), redis (digest B, in use), unused image (digest C), a local build, a dangling image
//	h2 (arm64): nginx (digest A, in use)   -> same digest, another platform
//	stack "blog" on h1, image policy on grafana: applied D, latest E
func (f *vulnFixture) seedFleet(t *testing.T) {
	t.Helper()
	st := f.a.store
	h1, _, _ := st.UpsertHostByFingerprint("h1", "sha256:1")
	h2, _, _ := st.UpsertHostByFingerprint("h2", "sha256:2")
	st.SetHostArch(h1.ID, "amd64")
	st.SetHostArch(h2.ID, "arm64")
	st.SetHostAgentVersion(h1.ID, "0.6.0")
	st.SetHostAgentVersion(h2.ID, "0.6.0")

	st.ReplaceHostImages(h1.ID, []store.HostImage{
		{HostID: h1.ID, ImageID: "aaaaaaaaaaaa", Repository: "nginx", Tag: "1.27", Digest: digestOf("a")},
		{HostID: h1.ID, ImageID: "bbbbbbbbbbbb", Repository: "ghcr.io/acme/redis", Tag: "7", Digest: digestOf("b")},
		{HostID: h1.ID, ImageID: "cccccccccccc", Repository: "postgres", Tag: "16", Digest: digestOf("c")}, // no container
		{HostID: h1.ID, ImageID: "dddddddddddd", Repository: "myapp", Tag: "dev"},                          // local build
		{HostID: h1.ID, ImageID: "eeeeeeeeeeee", Repository: "<none>", Tag: "<none>", Digest: digestOf("f")},
	})
	st.ReplaceHostContainers(h1.ID, []store.HostContainer{
		{HostID: h1.ID, ContainerID: "c1", Name: "web", Image: "nginx:1.27", ImageID: "aaaaaaaaaaaa"},
		{HostID: h1.ID, ContainerID: "c2", Name: "cache", Image: "ghcr.io/acme/redis:7", ImageID: "bbbbbbbbbbbb"},
		{HostID: h1.ID, ContainerID: "c3", Name: "app", Image: "myapp:dev", ImageID: "dddddddddddd"},
		{HostID: h1.ID, ContainerID: "c4", Name: "old", Image: "<none>", ImageID: "eeeeeeeeeeee"},
	})
	st.ReplaceHostImages(h2.ID, []store.HostImage{{HostID: h2.ID, ImageID: "aaaaaaaaaaaa", Repository: "nginx", Tag: "1.27", Digest: digestOf("a")}})
	st.ReplaceHostContainers(h2.ID, []store.HostContainer{{HostID: h2.ID, ContainerID: "c5", Name: "web2", Image: "nginx:1.27", ImageID: "aaaaaaaaaaaa"}})

	if err := st.CreateStack(store.Stack{ID: "blog", Name: "blog", SourceType: "git", Host: h1.ID, Trigger: "manual"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertImagePolicy("blog", "grafana", "grafana/grafana:11.2.0"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetAppliedDigest("blog", "grafana", digestOf("d")); err != nil {
		t.Fatal(err)
	}
	if err := st.SetImageDigestCache("docker.io/grafana/grafana:11.2.0", digestOf("e")); err != nil {
		t.Fatal(err)
	}
}

func targetKeys(ts []scanner.Target) []string {
	var out []string
	for _, t := range ts {
		out = append(out, t.Registry+"/"+t.Repository+"@"+t.Digest[7:8]+"/"+t.Platform)
	}
	return out
}

func TestTargetsCoverPoliciesAndEveryRunningImage(t *testing.T) {
	f := newVulnFixture(t)
	f.seedFleet(t)

	ts, err := f.a.vuln.targets()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, k := range targetKeys(ts) {
		got[k] = true
	}
	want := []string{
		"docker.io/grafana/grafana@d/linux/amd64", // applied digest of a policy, on the stack's host platform
		"docker.io/grafana/grafana@e/linux/amd64", // the latest digest a deploy would bring
		"docker.io/library/nginx@a/linux/amd64",   // running image
		"docker.io/library/nginx@a/linux/arm64",   // same digest, the other host's platform
		"ghcr.io/acme/redis@b/linux/amd64",        // not managed by any stack: still scanned
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing target %s in %v", w, targetKeys(ts))
		}
	}
	if len(ts) != len(want) {
		t.Errorf("got %d targets %v, want exactly %d: an unused image, a local build and a dangling image are not scanned", len(ts), targetKeys(ts), len(want))
	}
}

func TestPassInstallsUpdatesScansAndStores(t *testing.T) {
	f := newVulnFixture(t)
	f.seedFleet(t)

	msg, err := f.a.vuln.pass(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if f.fake.installs != 1 || f.fake.updates != 1 {
		t.Fatalf("installs=%d updates=%d: a missing scanner is installed and a missing database downloaded", f.fake.installs, f.fake.updates)
	}
	if !strings.Contains(msg, "5 image(s): 5 scanned, 0 already current, 0 failed") {
		t.Fatalf("msg = %q", msg)
	}

	sc, ok, _ := f.a.store.GetImageScan("trivy", digestOf("a"), "linux/amd64")
	if !ok || sc.Status != "ok" || sc.Critical != 1 || sc.High != 1 || sc.Low != 1 || sc.FixableCritical != 1 || sc.Repository != "docker.io/library/nginx" {
		t.Fatalf("stored scan = %+v", sc)
	}
	if !strings.Contains(sc.Findings, "CVE-1") || sc.DBBuiltAt != "2026-09-30T00:00:00Z" {
		t.Fatalf("findings/db date not stored: %+v", sc)
	}
	if st, _ := f.a.store.GetVulnSettings(); st.LastPassAt == "" || !strings.Contains(st.LastPassMsg, "5 scanned") {
		t.Fatalf("last pass not recorded: %+v", st)
	}
}

func TestSecondPassOnlyScansWhatChanged(t *testing.T) {
	f := newVulnFixture(t)
	f.seedFleet(t)
	if _, err := f.a.vuln.pass(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	first := len(f.fake.scans)

	msg, err := f.a.vuln.pass(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.fake.scans) != first || f.fake.updates != 1 || !strings.Contains(msg, "0 scanned, 5 already current") {
		t.Fatalf("an unchanged database must rescan nothing: scans %d->%d, updates %d, %q", first, len(f.fake.scans), f.fake.updates, msg)
	}

	// a rebuilt database invalidates every result
	f.fake.dbBuilt = "2026-10-01T00:00:00Z"
	msg, _ = f.a.vuln.pass(context.Background(), false)
	if !strings.Contains(msg, "5 scanned") {
		t.Fatalf("a newer database must rescan everything: %q", msg)
	}

	// a new digest is scanned alone
	f.a.store.SetImageDigestCache("docker.io/grafana/grafana:11.2.0", digestOf("9"))
	before := len(f.fake.scans)
	f.a.vuln.pass(context.Background(), false)
	if len(f.fake.scans) != before+1 {
		t.Fatalf("only the new digest must be scanned, %d scans ran", len(f.fake.scans)-before)
	}
	if _, ok, _ := f.a.store.GetImageScan("trivy", digestOf("e"), "linux/amd64"); ok {
		t.Fatal("the digest that is no longer a target must be pruned")
	}
}

func TestPassRefreshesTheDatabaseWhenAsked(t *testing.T) {
	f := newVulnFixture(t)
	f.seedFleet(t)
	f.a.vuln.pass(context.Background(), false)
	f.a.vuln.pass(context.Background(), true)
	if f.fake.updates != 2 {
		t.Fatalf("updates = %d, want the explicit refresh to run", f.fake.updates)
	}
}

func TestFailedScansAreRecordedAndRetried(t *testing.T) {
	f := newVulnFixture(t)
	f.seedFleet(t)
	fail := true
	f.fake.report = func(tg scanner.Target) (scanner.Report, error) {
		if tg.Repository == "acme/redis" && fail {
			return scanner.Report{}, errors.New("unauthorized: authentication required")
		}
		return scanner.Report{DBBuiltAt: "2026-09-30T00:00:00Z", Findings: []scanner.Finding{{ID: "CVE-9", Severity: scanner.SevMedium, Package: "p"}}}, nil
	}

	msg, err := f.a.vuln.pass(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "4 scanned") || !strings.Contains(msg, "1 failed") {
		t.Fatalf("msg = %q", msg)
	}
	bad, ok, _ := f.a.store.GetImageScan("trivy", digestOf("b"), "linux/amd64")
	if !ok || bad.Status != "error" || !strings.Contains(bad.Error, "authentication required") || bad.Critical != 0 {
		t.Fatalf("a failed scan must be stored as a failure, never as a clean image: %+v", bad)
	}

	fail = false
	msg, _ = f.a.vuln.pass(context.Background(), false)
	if !strings.Contains(msg, "1 scanned") {
		t.Fatalf("a failed scan must be retried on the next pass: %q", msg)
	}
	if good, _, _ := f.a.store.GetImageScan("trivy", digestOf("b"), "linux/amd64"); good.Status != "ok" {
		t.Fatalf("still failing after the retry succeeded: %+v", good)
	}

	// a later failure must not erase a good result
	fail = true
	f.fake.dbBuilt = "2026-10-05T00:00:00Z"
	f.a.vuln.pass(context.Background(), false)
	if kept, _, _ := f.a.store.GetImageScan("trivy", digestOf("b"), "linux/amd64"); kept.Status != "ok" || kept.Medium != 1 {
		t.Fatalf("a failed refresh must keep the previous good result: %+v", kept)
	}
}

func TestRegistryCredentialsAreHandedToTheScanner(t *testing.T) {
	f := newVulnFixture(t)
	f.seedFleet(t)
	if err := f.a.keys.SetRegistryCredential("GHCR", "ghcr.io", "ghcr", "bot", "s3cret-token"); err != nil {
		t.Fatal(err)
	}
	f.a.vuln.pass(context.Background(), false)

	var ghcr, hub int
	for i, tg := range f.fake.scans {
		switch tg.Registry {
		case "ghcr.io":
			ghcr++
			if f.fake.auths[i] == nil || f.fake.auths[i].Username != "bot" || f.fake.auths[i].Password != "s3cret-token" {
				t.Errorf("ghcr.io scan got %+v", f.fake.auths[i])
			}
		case "docker.io":
			hub++
			if f.fake.auths[i] != nil {
				t.Errorf("a registry without a credential must be scanned anonymously, got %+v", f.fake.auths[i])
			}
		}
	}
	if ghcr != 1 || hub == 0 {
		t.Fatalf("ghcr=%d hub=%d", ghcr, hub)
	}
}

func TestPassRefusesWhileDisabledOrWithoutACache(t *testing.T) {
	f := newVulnFixture(t)
	f.a.store.SetVulnSettingsChoice(false, "trivy")
	if _, err := f.a.vuln.pass(context.Background(), false); err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("err = %v", err)
	}

	f.a.store.SetVulnSettingsChoice(true, "trivy")
	f.a.vuln.cacheDir = "/proc/wharf-cannot-write-here"
	if _, err := f.a.vuln.pass(context.Background(), false); err == nil || !strings.Contains(err.Error(), "cache directory") {
		t.Fatalf("err = %v", err)
	}
}

func TestOnlyOneBackgroundTaskAtATime(t *testing.T) {
	f := newVulnFixture(t)
	release := make(chan struct{})
	started := make(chan struct{})
	if !f.a.vuln.start("first", func(context.Context) error { close(started); <-release; return nil }) {
		t.Fatal("the first task must start")
	}
	<-started
	if f.a.vuln.start("second", func(context.Context) error { return nil }) {
		t.Fatal("a second task must be refused while one runs")
	}
	if st := f.a.vuln.snapshot(); !st.Busy || st.Phase != "first" {
		t.Fatalf("status = %+v", st)
	}
	close(release)
	for i := 0; i < 100 && f.a.vuln.snapshot().Busy; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if f.a.vuln.snapshot().Busy {
		t.Fatal("the task never finished")
	}
	f.a.vuln.start("failing", func(context.Context) error { return errors.New("boom") })
	for i := 0; i < 100 && f.a.vuln.snapshot().Busy; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if st := f.a.vuln.snapshot(); st.Err != "boom" {
		t.Fatalf("a failed task must leave its reason: %+v", st)
	}
}

func TestPlatformFor(t *testing.T) {
	for in, want := range map[string]string{"amd64": "linux/amd64", "arm64": "linux/arm64", "arm": "linux/arm/v7", "riscv64": "linux/riscv64"} {
		if got := platformFor(in); got != want {
			t.Errorf("platformFor(%q) = %q, want %q", in, got, want)
		}
	}
	if got := platformFor(""); !strings.HasPrefix(got, "linux/") {
		t.Errorf("an unknown architecture must fall back to a linux platform, got %q", got)
	}
}

func TestBadgeFromScan(t *testing.T) {
	cases := []struct {
		name        string
		scan        store.ImageScan
		level, text string
	}{
		{"critical wins", store.ImageScan{Status: "ok", Critical: 2, High: 5, Medium: 9}, "critical", "2 critical · 5 high"},
		{"high", store.ImageScan{Status: "ok", High: 3, Medium: 1}, "high", "3 high"},
		{"medium and low", store.ImageScan{Status: "ok", Medium: 4, Low: 2}, "medium", "4 medium · 2 low"},
		{"clean", store.ImageScan{Status: "ok"}, "clean", "clean"},
		{"nothing detected is not clean", store.ImageScan{Status: "ok", Notice: scanner.NoOSNotice}, "none", "nothing detected"},
		{"a notice does not hide findings", store.ImageScan{Status: "ok", High: 1, Notice: "x"}, "high", "1 high"},
		{"failed", store.ImageScan{Status: "error", Error: "registry down"}, "none", "scan failed"},
	}
	for _, tc := range cases {
		b := badgeFromScan(tc.scan, "Trivy")
		if b.Level != tc.level || b.Label != tc.text {
			t.Errorf("%s: level=%q label=%q, want %q %q", tc.name, b.Level, b.Label, tc.level, tc.text)
		}
	}
	ok := badgeFromScan(store.ImageScan{Status: "ok", Digest: "sha256:abc", Platform: "linux/amd64", High: 1, FixableHigh: 1}, "Trivy")
	if ok.Link != "/scans/sha256:abc?platform=linux/amd64" || !strings.Contains(ok.Tooltip, "High 1 (1 fixable)") || !strings.Contains(ok.Tooltip, "Trivy") {
		t.Errorf("link/tooltip = %q / %q", ok.Link, ok.Tooltip)
	}
	if failed := badgeFromScan(store.ImageScan{Status: "error", Error: "registry down"}, "Trivy"); failed.Link != "" || failed.Tooltip != "registry down" {
		t.Errorf("a failed scan has nothing to open: %+v", failed)
	}
}

func TestScanIndexStates(t *testing.T) {
	f := newVulnFixture(t)
	f.seedFleet(t)
	f.a.store.SetHostAgentVersion("h2", "0.5.0") // predates digest reporting
	f.a.vuln.pass(context.Background(), false)
	ix := f.a.newScanIndex()

	if b := ix.forImage("h1", "aaaaaaaaaaaa"); b == nil || b.Level != "critical" || b.Link == "" {
		t.Errorf("a scanned image: %+v", b)
	}
	if b := ix.forImage("h1", "dddddddddddd"); b == nil || b.Label != "local image" {
		t.Errorf("a local build in use: %+v", b)
	}
	if b := ix.forImage("h1", "cccccccccccc"); b != nil {
		t.Errorf("an unused image that was not scanned shows nothing, got %+v", b)
	}
	if b := ix.forImage("h2", "zzzzzzzzzzzz"); b == nil || b.Label != "update agent" {
		t.Errorf("an image on an old agent must say so: %+v", b)
	}
	if b := ix.forDigest(digestOf("d"), "h1"); b == nil || b.Level == "none" {
		t.Errorf("a policy digest: %+v", b)
	}
	if b := ix.forDigest(digestOf("7"), "h1"); b == nil || b.Label != "not scanned yet" {
		t.Errorf("an unknown digest is pending: %+v", b)
	}

	var off *scanIndex
	if off.forImage("h1", "aaaaaaaaaaaa") != nil || off.forDigest(digestOf("a"), "h1") != nil {
		t.Error("with scanning off an index answers nothing")
	}
	f.a.store.SetVulnSettingsChoice(false, "trivy")
	if f.a.newScanIndex() != nil {
		t.Error("scanning off must give no index")
	}
}

func post(h http.HandlerFunc, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/x", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

func TestSaveVulnHandler(t *testing.T) {
	f := newVulnFixture(t)
	f.a.store.SetVulnSettingsChoice(false, "")

	if loc := post(f.a.saveVulnHandler, url.Values{"scanner": {"clair"}}).Header().Get("Location"); !strings.Contains(loc, "error=") {
		t.Errorf("an unknown scanner must be refused: %s", loc)
	}

	f.a.vuln.cacheDir = "/proc/wharf-cannot-write-here"
	loc := post(f.a.saveVulnHandler, url.Values{"scanner": {"trivy"}, "enabled": {"1"}}).Header().Get("Location")
	if !strings.Contains(loc, "error=") || !strings.Contains(loc, "cache") {
		t.Errorf("enabling without a usable cache must be refused with the reason: %s", loc)
	}
	if st, _ := f.a.store.GetVulnSettings(); st.Enabled {
		t.Error("a refused enable must not be saved")
	}

	f.a.vuln.cacheDir = t.TempDir()
	loc = post(f.a.saveVulnHandler, url.Values{"scanner": {"trivy"}, "enabled": {"1"}}).Header().Get("Location")
	if strings.Contains(loc, "error=") {
		t.Fatalf("enable: %s", loc)
	}
	for i := 0; i < 200 && f.a.vuln.snapshot().Busy; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if st, _ := f.a.store.GetVulnSettings(); !st.Enabled || st.Scanner != "trivy" {
		t.Errorf("settings = %+v", st)
	}
	if f.fake.installs != 1 {
		t.Errorf("enabling must set the scanner up in the background, installs = %d", f.fake.installs)
	}

	// switching scanner drops the other one's results
	f.a.store.UpsertImageScan(store.ImageScan{Scanner: "trivy", Digest: digestOf("a"), Platform: "linux/amd64", Status: "ok"})
	post(f.a.saveVulnHandler, url.Values{"scanner": {"grype"}})
	if list, _ := f.a.store.ListImageScans("trivy"); len(list) != 0 {
		t.Errorf("switching scanners must drop the previous results: %+v", list)
	}

	post(f.a.saveVulnHandler, url.Values{"scanner": {"grype"}}) // no "enabled": off
	if st, _ := f.a.store.GetVulnSettings(); st.Enabled {
		t.Error("an unchecked box must turn scanning off")
	}
}

func TestPurgeVulnHandlerDeletesEverything(t *testing.T) {
	f := newVulnFixture(t)
	dir := f.fake.DataDirs(f.a.vuln.cacheDir)[0]
	if err := mkfile(filepath.Join(dir, "db", "x")); err != nil {
		t.Fatal(err)
	}
	f.a.store.UpsertImageScan(store.ImageScan{Scanner: "trivy", Digest: digestOf("a"), Platform: "linux/amd64", Status: "ok"})

	post(f.a.purgeVulnHandler, nil)
	if st, _ := f.a.store.GetVulnSettings(); st.Enabled {
		t.Error("purging must turn scanning off")
	}
	if list, _ := f.a.store.ListImageScans("trivy"); len(list) != 0 {
		t.Error("results left behind")
	}
	if scanner.DiskUsage(dir) != 0 {
		t.Error("scanner data left behind")
	}
}

func TestScanDetailAndSettingsPagesRender(t *testing.T) {
	f := newVulnFixture(t)
	f.seedFleet(t)
	f.a.vuln.pass(context.Background(), false)

	get := func(h http.HandlerFunc, target string, path map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", target, nil)
		for k, v := range path {
			req.SetPathValue(k, v)
		}
		w := httptest.NewRecorder()
		h(w, req)
		return w
	}

	d := digestOf("a")
	w := get(f.a.scanDetailHandler, "/scans/"+d+"?platform=linux/amd64", map[string]string{"digest": d})
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "CVE-1") || !strings.Contains(body, "https://nvd.nist.gov/vuln/detail/CVE-1") || !strings.Contains(body, "openssl") {
		t.Fatalf("detail: %d\n%.400s", w.Code, body)
	}
	w = get(f.a.scanDetailHandler, "/scans/"+d+"?platform=linux/amd64&fixable=1", map[string]string{"digest": d})
	if b := w.Body.String(); !strings.Contains(b, "CVE-1") || strings.Contains(b, "zlib") {
		t.Errorf("fixable filter must keep the fixable one only:\n%.600s", b)
	}
	w = get(f.a.scanDetailHandler, "/scans/"+d+"?platform=linux/amd64&severity=low", map[string]string{"digest": d})
	if b := w.Body.String(); !strings.Contains(b, "busybox") || strings.Contains(b, "openssl") {
		t.Errorf("severity filter:\n%.600s", b)
	}
	if w := get(f.a.scanDetailHandler, "/scans/"+digestOf("0")+"?platform=linux/amd64", map[string]string{"digest": digestOf("0")}); w.Code != http.StatusNotFound {
		t.Errorf("an unknown scan must be a 404, got %d", w.Code)
	}

	w = get(f.a.settingsVulnHandler, "/settings/vulnerability-scanning", nil)
	if b := w.Body.String(); w.Code != 200 || !strings.Contains(b, "Vulnerability scanning") || !strings.Contains(b, "Trivy") || !strings.Contains(b, "Scan now") {
		t.Fatalf("settings: %d\n%.400s", w.Code, b)
	}

	f.a.store.SetVulnSettingsChoice(false, "trivy")
	if w := get(f.a.scanDetailHandler, "/scans/"+d+"?platform=linux/amd64", map[string]string{"digest": d}); w.Code != http.StatusNotFound {
		t.Errorf("with scanning off the findings page must not exist, got %d", w.Code)
	}
}

func TestAdvisoryURL(t *testing.T) {
	for id, want := range map[string]string{
		"CVE-2026-1234":       "https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
		"GHSA-abcd-efgh-ijkl": "https://github.com/advisories/GHSA-abcd-efgh-ijkl",
		"ALPINE-2026-1":       "",
		"":                    "",
	} {
		if got := advisoryURL(id); got != want {
			t.Errorf("advisoryURL(%q) = %q, want %q", id, got, want)
		}
	}
}

func mkfile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte("x"), 0o644)
}

func TestVulnActionHandlers(t *testing.T) {
	f := newVulnFixture(t)
	f.seedFleet(t)

	f.a.store.SetVulnSettingsChoice(false, "trivy")
	if loc := post(f.a.vulnActionHandler("scan"), nil).Header().Get("Location"); !strings.Contains(loc, "error=") {
		t.Errorf("scanning while off must be refused: %s", loc)
	}

	f.a.store.SetVulnSettingsChoice(true, "trivy")
	for action, want := range map[string]string{"scan": "scan.run", "update-db": "scan.update_db"} {
		loc := post(f.a.vulnActionHandler(action), nil).Header().Get("Location")
		if strings.Contains(loc, "error=") {
			t.Fatalf("%s: %s", action, loc)
		}
		for i := 0; i < 200 && f.a.vuln.snapshot().Busy; i++ {
			time.Sleep(10 * time.Millisecond)
		}
		entries, _ := f.a.store.ListAudit(20)
		found := false
		for _, e := range entries {
			found = found || e.Action == want
		}
		if !found {
			t.Errorf("%s: no %q audit entry in %+v", action, want, entries)
		}
	}
	if f.fake.updates < 2 {
		t.Errorf("the database update action must refresh the database, updates = %d", f.fake.updates)
	}
}
