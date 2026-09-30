// Package scanner runs an image vulnerability scanner (Trivy or Grype) as a
// subprocess and normalizes what it reports. The scanner binary is
// downloaded on demand, cf. install.go: it is never part of the image.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Severity names, lower case, most severe first.
const (
	SevCritical = "critical"
	SevHigh     = "high"
	SevMedium   = "medium"
	SevLow      = "low"
	SevUnknown  = "unknown"
)

var severityRank = map[string]int{SevCritical: 0, SevHigh: 1, SevMedium: 2, SevLow: 3, SevUnknown: 4}

// Finding is one vulnerability in one package of an image.
type Finding struct {
	ID        string `json:"id"`
	Severity  string `json:"severity"`
	Package   string `json:"package"`
	Installed string `json:"installed,omitempty"`
	FixedIn   string `json:"fixed_in,omitempty"`
	Title     string `json:"title,omitempty"`
}

// Report is the normalized result of one scan.
type Report struct {
	Findings  []Finding
	DBBuiltAt string
	// Notice qualifies an empty result: the scanner recognized nothing to check,
	// which is not the same as an image without vulnerabilities.
	Notice string
}

// NoOSNotice is set when no operating system was detected and nothing was found.
const NoOSNotice = "No operating system was detected in this image, so the scanner may have checked little or nothing."

// Counts are per distinct vulnerability id: one CVE affecting three
// sub-packages of the same source counts once.
type Counts struct {
	Critical, High, Medium, Low, Unknown int
	FixableCritical, FixableHigh         int
}

// Auth is a registry credential for a private image.
type Auth struct{ Username, Password string }

// Target names one image by registry digest, for one platform.
type Target struct {
	Registry   string // docker.io, ghcr.io, registry.example.lan:5000
	Repository string // library/nginx
	Digest     string // sha256:...
	Platform   string // linux/amd64
}

var (
	registryRe   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?$`)
	repositoryRe = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$`)
	digestRe     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	platformRe   = regexp.MustCompile(`^[a-z]+/[a-z0-9]+(/[a-z0-9]+)?$`)
)

// Validate rejects anything that could be read as an option or that is not a
// plain registry reference: the values end up in a subprocess command line.
func (t Target) Validate() error {
	switch {
	case !registryRe.MatchString(t.Registry):
		return fmt.Errorf("invalid registry %q", t.Registry)
	case !repositoryRe.MatchString(t.Repository):
		return fmt.Errorf("invalid repository %q", t.Repository)
	case !digestRe.MatchString(t.Digest):
		return fmt.Errorf("invalid digest %q", t.Digest)
	case !platformRe.MatchString(t.Platform):
		return fmt.Errorf("invalid platform %q", t.Platform)
	}
	return nil
}

// Ref is registry/repository@digest.
func (t Target) Ref() string { return t.Registry + "/" + t.Repository + "@" + t.Digest }

// Scanner is one supported scanner.
type Scanner interface {
	Name() string    // "trivy" | "grype"
	Label() string   // "Trivy"
	Version() string // the pinned release
	Installed(cacheDir string) bool
	Install(ctx context.Context, cacheDir string) error
	UpdateDB(ctx context.Context, cacheDir string) error
	// DBBuiltAt is when the vulnerability database was built, empty when none is present.
	DBBuiltAt(ctx context.Context, cacheDir string) (string, error)
	Scan(ctx context.Context, cacheDir string, t Target, auth *Auth) (Report, error)
	// DataDirs lists what Install and UpdateDB write under cacheDir.
	DataDirs(cacheDir string) []string
}

// All returns every supported scanner.
func All() []Scanner { return []Scanner{Trivy(), Grype()} }

// ByName returns the scanner with that name.
func ByName(name string) (Scanner, bool) {
	for _, s := range All() {
		if s.Name() == name {
			return s, true
		}
	}
	return nil, false
}

// Summarize counts distinct vulnerability ids per severity, and how many
// of the critical and high ones have a fix.
func Summarize(findings []Finding) Counts {
	type seen struct {
		severity string
		fixable  bool
	}
	byID := map[string]*seen{}
	for _, f := range findings {
		s, ok := byID[f.ID]
		if !ok {
			s = &seen{severity: f.Severity}
			byID[f.ID] = s
		}
		if f.FixedIn != "" {
			s.fixable = true
		}
	}
	var c Counts
	for _, s := range byID {
		switch s.severity {
		case SevCritical:
			c.Critical++
			if s.fixable {
				c.FixableCritical++
			}
		case SevHigh:
			c.High++
			if s.fixable {
				c.FixableHigh++
			}
		case SevMedium:
			c.Medium++
		case SevLow:
			c.Low++
		default:
			c.Unknown++
		}
	}
	return c
}

// Sort orders findings most severe first, then by id and package, and drops
// exact duplicates.
func Sort(findings []Finding) []Finding {
	seen := map[Finding]bool{}
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] < severityRank[b.Severity]
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Package < b.Package
	})
	return out
}

func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SevCritical
	case "high":
		return SevHigh
	case "medium":
		return SevMedium
	case "low", "negligible":
		return SevLow
	default:
		return SevUnknown
	}
}

func shorten(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

// DiskUsage returns the bytes under dirs.
func DiskUsage(dirs ...string) int64 {
	var total int64
	for _, dir := range dirs {
		_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if info, err := d.Info(); err == nil {
				total += info.Size()
			}
			return nil
		})
	}
	return total
}

// ErrNotInstalled means the scanner binary is not present.
var ErrNotInstalled = errors.New("the scanner is not installed")
