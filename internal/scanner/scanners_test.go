package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseTrivyRealReport(t *testing.T) {
	findings, notice, err := parseTrivy(fixture(t, "trivy-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if notice != "" {
		t.Errorf("an Alpine image with findings has nothing to warn about, got %q", notice)
	}
	if len(findings) != 6 {
		t.Fatalf("got %d findings, want the fixture's 6", len(findings))
	}
	// most severe first
	if findings[0].Severity != SevHigh {
		t.Errorf("first finding = %+v, want the HIGH one first", findings[0])
	}
	var busybox *Finding
	for i := range findings {
		if findings[i].ID == "CVE-2024-58251" {
			busybox = &findings[i]
		}
	}
	if busybox == nil || busybox.Package != "busybox" && busybox.Package != "ssl_client" && busybox.Package != "busybox-binsh" ||
		busybox.Installed != "1.36.1-r20" || busybox.FixedIn != "1.36.1-r21" || busybox.Severity != SevMedium || busybox.Title == "" {
		t.Errorf("CVE-2024-58251 = %+v", busybox)
	}
	for _, f := range findings {
		if f.ID == "" || f.Package == "" {
			t.Errorf("incomplete finding %+v", f)
		}
	}
	if _, _, err := parseTrivy([]byte("not json")); err == nil {
		t.Error("garbage must be an error")
	}
	// a clean Alpine image: packages were examined, nothing vulnerable
	got, notice, err := parseTrivy([]byte(`{"SchemaVersion":2,"Metadata":{"OS":{"Family":"alpine","Name":"3.19"}},"Results":[{"Target":"x","Class":"os-pkgs"}]}`))
	if err != nil || len(got) != 0 || notice != "" {
		t.Errorf("a clean image = %v, %q, %v; want no findings, no notice, no error", got, notice, err)
	}
}

func TestTrivyReportsAnImageWithNothingToInspect(t *testing.T) {
	// the real report for busybox: no OS, no package database, so no Results at all
	findings, notice, err := parseTrivy(fixture(t, "trivy-no-os.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 || notice != NoOSNotice {
		t.Fatalf("findings=%d notice=%q: an image the scanner could not read must not pass for a clean one", len(findings), notice)
	}
}

func TestGrypeNoticeWhenNoDistroAndNoMatches(t *testing.T) {
	_, notice, err := parseGrype([]byte(`{"matches":[],"distro":{"name":"","version":""}}`))
	if err != nil || notice != NoOSNotice {
		t.Fatalf("notice = %q, %v", notice, err)
	}
	_, notice, _ = parseGrype([]byte(`{"matches":[],"distro":{"name":"alpine","version":"3.19"}}`))
	if notice != "" {
		t.Fatalf("a recognized distribution with no match is clean, got %q", notice)
	}
}

func TestParseGrypeRealReport(t *testing.T) {
	findings, _, err := parseGrype(fixture(t, "grype-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 8 {
		t.Fatalf("got %d findings, want the fixture's 8", len(findings))
	}
	var fixed, unfixed int
	for _, f := range findings {
		if f.ID == "" || f.Package == "" || f.Installed == "" {
			t.Errorf("incomplete finding %+v", f)
		}
		if f.FixedIn != "" {
			fixed++
		} else {
			unfixed++
		}
	}
	if fixed == 0 || unfixed == 0 {
		t.Errorf("the fixture has both fixed and unfixed matches, got fixed=%d unfixed=%d", fixed, unfixed)
	}
	for _, f := range findings {
		if f.ID == "CVE-2026-40200" && (f.Severity != SevHigh || f.FixedIn == "") {
			t.Errorf("CVE-2026-40200 = %+v, want high with a fix", f)
		}
	}
	if _, _, err := parseGrype([]byte("<html>")); err == nil {
		t.Error("garbage must be an error")
	}
}

func TestSameImageGivesComparableCountsAcrossScanners(t *testing.T) {
	tf, _, _ := parseTrivy(fixture(t, "trivy-report.json"))
	gf, _, _ := parseGrype(fixture(t, "grype-report.json"))
	tc, gc := Summarize(tf), Summarize(gf)
	if tc.High+tc.Medium+tc.Low+tc.Critical+tc.Unknown == 0 || gc.High+gc.Medium+gc.Low+gc.Critical+gc.Unknown == 0 {
		t.Fatalf("both fixtures have findings: %+v %+v", tc, gc)
	}
}

func TestDBBuiltAtReadsRealMetadata(t *testing.T) {
	cache := t.TempDir()
	tr := newTrivy(trivyRelease, nil)
	if built, err := tr.DBBuiltAt(context.Background(), cache); err != nil || built != "" {
		t.Fatalf("no database yet: %q, %v", built, err)
	}
	dir := filepath.Join(tr.dbDir(cache), "db")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "metadata.json"), fixture(t, "trivy-db-metadata.json"), 0o644)
	built, err := tr.DBBuiltAt(context.Background(), cache)
	if err != nil || built != "2026-09-30T07:10:47.109177017Z" {
		t.Fatalf("built = %q, %v", built, err)
	}
	os.WriteFile(filepath.Join(dir, "metadata.json"), []byte("{broken"), 0o644)
	if _, err := tr.DBBuiltAt(context.Background(), cache); err == nil {
		t.Fatal("a corrupt metadata file must be reported")
	}
}

// fakeBinary installs a shell script standing in for the scanner. It logs its
// arguments and environment next to itself and prints reply.
func fakeBinary(t *testing.T, s Scanner, cache, reply string, exit int) (log string) {
	t.Helper()
	var bin string
	switch v := s.(type) {
	case *trivy:
		bin = v.binPath(cache)
	case *grype:
		bin = v.binPath(cache)
	}
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	log = filepath.Join(filepath.Dir(bin), "invocation.log")
	script := "#!/bin/sh\n{ for a in \"$@\"; do echo \"ARG:$a\"; done; env | sort | sed 's/^/ENV:/'; } >> '" + log + "'\n" + reply + "\nexit " + string(rune('0'+exit)) + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return log
}

func target() Target {
	return Target{Registry: "ghcr.io", Repository: "acme/app", Digest: "sha256:" + strings.Repeat("b", 64), Platform: "linux/arm64"}
}

func TestTrivyScanCommandLineAndEnvironment(t *testing.T) {
	t.Setenv("WHARF_ADMIN_PASSWORD", "controller-secret")
	t.Setenv("HTTPS_PROXY", "http://proxy.lan:3128")
	cache := t.TempDir()
	s := newTrivy(trivyRelease, nil)
	log := fakeBinary(t, s, cache, "cat '"+filepath.Join("testdata", "trivy-report.json")+"'", 0)
	// the fake runs from a temp dir, so the fixture path must be absolute
	abs, _ := filepath.Abs(filepath.Join("testdata", "trivy-report.json"))
	fakeBinary(t, s, cache, "cat '"+abs+"'", 0)

	rep, err := s.Scan(context.Background(), cache, target(), &Auth{Username: "bot", Password: "hunter2-registry"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 6 {
		t.Fatalf("findings = %d", len(rep.Findings))
	}

	raw, _ := os.ReadFile(log)
	out := string(raw)
	for _, want := range []string{
		"ARG:image", "ARG:--image-src", "ARG:remote", "ARG:--platform", "ARG:linux/arm64",
		"ARG:--skip-db-update", "ARG:--scanners", "ARG:vuln", "ARG:--format", "ARG:json",
		"ARG:ghcr.io/acme/app@sha256:" + strings.Repeat("b", 64),
		"ENV:TRIVY_USERNAME=bot", "ENV:TRIVY_PASSWORD=hunter2-registry", "ENV:HTTPS_PROXY=http://proxy.lan:3128",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "controller-secret") || strings.Contains(out, "WHARF_ADMIN_PASSWORD") {
		t.Errorf("the controller's environment reached the scanner:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "ARG:") && strings.Contains(line, "hunter2-registry") {
			t.Errorf("the registry password is on the command line: %s", line)
		}
	}
}

func TestGrypeScanCommandLineAndEnvironment(t *testing.T) {
	t.Setenv("WHARF_ADMIN_PASSWORD", "controller-secret")
	cache := t.TempDir()
	s := newGrype(grypeRelease, nil)
	abs, _ := filepath.Abs(filepath.Join("testdata", "grype-report.json"))
	log := fakeBinary(t, s, cache, "cat '"+abs+"'", 0)

	rep, err := s.Scan(context.Background(), cache, target(), &Auth{Username: "bot", Password: "hunter2-registry"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 8 {
		t.Fatalf("findings = %d", len(rep.Findings))
	}
	raw, _ := os.ReadFile(log)
	out := string(raw)
	for _, want := range []string{
		"ARG:registry:ghcr.io/acme/app@sha256:" + strings.Repeat("b", 64), "ARG:--platform", "ARG:linux/arm64", "ARG:-o", "ARG:json",
		"ENV:GRYPE_REGISTRY_AUTH_AUTHORITY=ghcr.io", "ENV:GRYPE_REGISTRY_AUTH_USERNAME=bot", "ENV:GRYPE_REGISTRY_AUTH_PASSWORD=hunter2-registry",
		"ENV:GRYPE_DB_AUTO_UPDATE=false", "ENV:GRYPE_CHECK_FOR_APP_UPDATE=false", "ENV:GRYPE_DB_CACHE_DIR=" + s.dbDir(cache),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "controller-secret") {
		t.Errorf("the controller's environment reached the scanner:\n%s", out)
	}
}

func TestScanWithoutAuthSetsNoCredentials(t *testing.T) {
	cache := t.TempDir()
	s := newTrivy(trivyRelease, nil)
	abs, _ := filepath.Abs(filepath.Join("testdata", "trivy-report.json"))
	log := fakeBinary(t, s, cache, "cat '"+abs+"'", 0)
	if _, err := s.Scan(context.Background(), cache, target(), nil); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(log)
	if strings.Contains(string(raw), "TRIVY_USERNAME") || strings.Contains(string(raw), "TRIVY_PASSWORD") {
		t.Errorf("a public scan must not carry credentials:\n%s", raw)
	}
}

func TestScanFailuresAreReportedWithTheReason(t *testing.T) {
	cache := t.TempDir()
	s := newTrivy(trivyRelease, nil)

	if _, err := s.Scan(context.Background(), cache, target(), nil); err != ErrNotInstalled {
		t.Errorf("a missing binary must be ErrNotInstalled, got %v", err)
	}

	fakeBinary(t, s, cache, "echo 'FATAL unauthorized: authentication required' >&2", 1)
	_, err := s.Scan(context.Background(), cache, target(), nil)
	if err == nil || !strings.Contains(err.Error(), "authentication required") {
		t.Errorf("stderr must explain the failure, got %v", err)
	}

	fakeBinary(t, s, cache, "echo 'this is not json'", 0)
	if _, err := s.Scan(context.Background(), cache, target(), nil); err == nil {
		t.Error("unparsable output must fail, never read as a clean image")
	}

	if _, err := s.Scan(context.Background(), cache, Target{Registry: "--x"}, nil); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Errorf("an invalid target must be refused before anything runs, got %v", err)
	}
}

func TestScanHonoursTheContextDeadline(t *testing.T) {
	cache := t.TempDir()
	s := newGrype(grypeRelease, nil)
	fakeBinary(t, s, cache, "sleep 30", 0)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := s.Scan(ctx, cache, target(), nil)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v, want a timeout", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the scan was not interrupted")
	}
}

func TestUpdateDBRunsTheRightCommands(t *testing.T) {
	cache := t.TempDir()

	tr := newTrivy(trivyRelease, nil)
	if err := tr.UpdateDB(context.Background(), cache); err != ErrNotInstalled {
		t.Fatalf("update without a binary = %v", err)
	}
	log := fakeBinary(t, tr, cache, "true", 0)
	if err := tr.UpdateDB(context.Background(), cache); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(log)
	if !strings.Contains(string(raw), "ARG:--download-db-only") || !strings.Contains(string(raw), "ARG:"+tr.dbDir(cache)) {
		t.Errorf("trivy update:\n%s", raw)
	}

	gr := newGrype(grypeRelease, nil)
	log = fakeBinary(t, gr, cache, "true", 0)
	if err := gr.UpdateDB(context.Background(), cache); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(log)
	if !strings.Contains(string(raw), "ARG:db") || !strings.Contains(string(raw), "ARG:update") || !strings.Contains(string(raw), "ENV:GRYPE_DB_AUTO_UPDATE=true") {
		t.Errorf("grype update:\n%s", raw)
	}

	fakeBinary(t, gr, cache, "echo 'network unreachable' >&2", 1)
	if err := gr.UpdateDB(context.Background(), cache); err == nil || !strings.Contains(err.Error(), "network unreachable") {
		t.Errorf("a failed update must explain itself, got %v", err)
	}
}

func TestGrypeDBBuiltAtParsesStatus(t *testing.T) {
	cache := t.TempDir()
	s := newGrype(grypeRelease, nil)
	if built, _ := s.DBBuiltAt(context.Background(), cache); built != "" {
		t.Fatalf("no binary: %q", built)
	}
	abs, _ := filepath.Abs(filepath.Join("testdata", "grype-db-status.json"))
	fakeBinary(t, s, cache, "cat '"+abs+"'", 0)
	if built, err := s.DBBuiltAt(context.Background(), cache); err != nil || built != "2026-09-30T06:32:47Z" {
		t.Fatalf("built = %q, %v", built, err)
	}
	fakeBinary(t, s, cache, "echo 'no database' >&2", 1)
	if built, err := s.DBBuiltAt(context.Background(), cache); err != nil || built != "" {
		t.Fatalf("no database yet must be empty, not an error: %q, %v", built, err)
	}
}
