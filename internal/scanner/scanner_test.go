package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSummarizeCountsDistinctIDs(t *testing.T) {
	findings := []Finding{
		{ID: "CVE-1", Severity: SevCritical, Package: "a", FixedIn: "2"},
		{ID: "CVE-1", Severity: SevCritical, Package: "a-sub"}, // same CVE, sibling package
		{ID: "CVE-2", Severity: SevCritical, Package: "b"},
		{ID: "CVE-3", Severity: SevHigh, Package: "c", FixedIn: "9"},
		{ID: "CVE-4", Severity: SevMedium, Package: "d"},
		{ID: "CVE-5", Severity: SevLow, Package: "e"},
		{ID: "CVE-6", Severity: SevUnknown, Package: "f"},
	}
	got := Summarize(findings)
	want := Counts{Critical: 2, High: 1, Medium: 1, Low: 1, Unknown: 1, FixableCritical: 1, FixableHigh: 1}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if (Summarize(nil) != Counts{}) {
		t.Fatal("no findings must be all zeroes")
	}
}

func TestSortOrdersBySeverityAndDropsDuplicates(t *testing.T) {
	in := []Finding{
		{ID: "CVE-2", Severity: SevLow, Package: "b"},
		{ID: "CVE-1", Severity: SevCritical, Package: "z"},
		{ID: "CVE-1", Severity: SevCritical, Package: "a"},
		{ID: "CVE-1", Severity: SevCritical, Package: "a"},
		{ID: "CVE-3", Severity: SevHigh, Package: "c"},
	}
	got := Sort(in)
	var order []string
	for _, f := range got {
		order = append(order, f.ID+"/"+f.Package)
	}
	if strings.Join(order, " ") != "CVE-1/a CVE-1/z CVE-3/c CVE-2/b" {
		t.Fatalf("order = %v", order)
	}
}

func TestTargetValidate(t *testing.T) {
	good := Target{Registry: "docker.io", Repository: "library/nginx", Digest: "sha256:" + strings.Repeat("a", 64), Platform: "linux/amd64"}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := good.Ref(); got != "docker.io/library/nginx@sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("Ref = %s", got)
	}
	for _, ok := range []Target{
		{"registry.example.lan:5000", "team/app-1.x_y", good.Digest, "linux/arm64"},
		{"ghcr.io", "forgelab-me/wharf-server", good.Digest, "linux/arm/v7"},
	} {
		if err := ok.Validate(); err != nil {
			t.Errorf("%+v: %v", ok, err)
		}
	}
	bad := map[string]Target{
		"option as registry":    {"--help", "library/nginx", good.Digest, "linux/amd64"},
		"option as repository":  {"docker.io", "--server=evil", good.Digest, "linux/amd64"},
		"tag instead of digest": {"docker.io", "library/nginx", "latest", "linux/amd64"},
		"short digest":          {"docker.io", "library/nginx", "sha256:abc", "linux/amd64"},
		"uppercase repository":  {"docker.io", "Library/Nginx", good.Digest, "linux/amd64"},
		"space in repository":   {"docker.io", "library/ng inx", good.Digest, "linux/amd64"},
		"traversal":             {"docker.io", "library/../x", good.Digest, "linux/amd64"},
		"option as platform":    {"docker.io", "library/nginx", good.Digest, "--platform"},
		"empty":                 {},
	}
	for name, tgt := range bad {
		if err := tgt.Validate(); err == nil {
			t.Errorf("%s: accepted %+v", name, tgt)
		}
	}
}

func TestNormalizeSeverityAndShorten(t *testing.T) {
	for in, want := range map[string]string{
		"CRITICAL": SevCritical, "High": SevHigh, "medium": SevMedium, "LOW": SevLow,
		"Negligible": SevLow, "UNKNOWN": SevUnknown, "": SevUnknown, "weird": SevUnknown,
	} {
		if got := normalizeSeverity(in); got != want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
	if got := shorten("  a   b\nc  ", 50); got != "a b c" {
		t.Errorf("shorten = %q", got)
	}
	if got := shorten(strings.Repeat("x", 30), 10); len([]rune(got)) != 10 || !strings.HasSuffix(got, "…") {
		t.Errorf("shorten of a long text = %q", got)
	}
}

func TestByNameAndAll(t *testing.T) {
	names := map[string]bool{}
	for _, s := range All() {
		names[s.Name()] = true
		if s.Version() == "" || s.Label() == "" {
			t.Errorf("%s: missing version or label", s.Name())
		}
		if got, ok := ByName(s.Name()); !ok || got.Name() != s.Name() {
			t.Errorf("ByName(%q) failed", s.Name())
		}
	}
	if !names["trivy"] || !names["grype"] || len(names) != 2 {
		t.Fatalf("scanners = %v", names)
	}
	if _, ok := ByName("clair"); ok {
		t.Fatal("an unsupported scanner must not resolve")
	}
}

func TestPinnedReleasesLookSane(t *testing.T) {
	for name, rel := range map[string]release{"trivy": trivyRelease, "grype": grypeRelease} {
		for arch, a := range rel.Assets {
			if !strings.HasPrefix(a.URL, "https://github.com/") || !strings.Contains(a.URL, rel.Version) {
				t.Errorf("%s/%s: URL %q does not point at the pinned release", name, arch, a.URL)
			}
			if len(a.SHA256) != 64 || strings.Trim(a.SHA256, "0123456789abcdef") != "" {
				t.Errorf("%s/%s: SHA256 %q is not a lowercase hex digest", name, arch, a.SHA256)
			}
		}
		if rel.Assets["amd64"].URL == "" || rel.Assets["arm64"].URL == "" {
			t.Errorf("%s: both amd64 and arm64 must be pinned", name)
		}
	}
}

func TestDiskUsage(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "a", "b"), 0o755)
	os.WriteFile(filepath.Join(dir, "a", "one"), make([]byte, 100), 0o644)
	os.WriteFile(filepath.Join(dir, "a", "b", "two"), make([]byte, 50), 0o644)
	if got := DiskUsage(dir, filepath.Join(dir, "missing")); got != 150 {
		t.Fatalf("DiskUsage = %d, want 150", got)
	}
}
