package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

var grypeRelease = release{
	Version: "0.119.0",
	Assets: map[string]asset{
		"amd64": {
			URL:    "https://github.com/anchore/grype/releases/download/v0.119.0/grype_0.119.0_linux_amd64.tar.gz",
			SHA256: "3fa2dc4b924621ab65404cf08d0b8438d896d80ab949c9d5a4ca283c36004c9b",
		},
		"arm64": {
			URL:    "https://github.com/anchore/grype/releases/download/v0.119.0/grype_0.119.0_linux_arm64.tar.gz",
			SHA256: "29f0ec7c549ddb0e2b6a0ca714851f7399438afc399b80c12808e065edc9a8f8",
		},
	},
}

type grype struct{ base }

// Grype is the Anchore scanner.
func Grype() Scanner { return newGrype(grypeRelease, nil) }

func newGrype(rel release, client *http.Client) *grype {
	return &grype{base{name: "grype", label: "Grype", rel: rel, client: client}}
}

// env pins the database location and stops Grype from reaching out on its own.
func (g *grype) env(cacheDir string, autoUpdate bool, extra ...string) []string {
	update := "false"
	if autoUpdate {
		update = "true"
	}
	return scanEnv(g.dbDir(cacheDir), append([]string{
		"GRYPE_DB_CACHE_DIR=" + g.dbDir(cacheDir),
		"GRYPE_DB_AUTO_UPDATE=" + update,
		"GRYPE_CHECK_FOR_APP_UPDATE=false",
	}, extra...)...)
}

func (g *grype) UpdateDB(ctx context.Context, cacheDir string) error {
	if !g.Installed(cacheDir) {
		return ErrNotInstalled
	}
	if _, err := run(ctx, g.binPath(cacheDir), []string{"db", "update"}, g.env(cacheDir, true)); err != nil {
		return fmt.Errorf("update the Grype database: %w", err)
	}
	return nil
}

func (g *grype) DBBuiltAt(ctx context.Context, cacheDir string) (string, error) {
	if !g.Installed(cacheDir) {
		return "", nil
	}
	out, err := run(ctx, g.binPath(cacheDir), []string{"db", "status", "-o", "json"}, g.env(cacheDir, false))
	if err != nil {
		return "", nil // no database yet
	}
	var st struct {
		Built string `json:"built"`
		Valid bool   `json:"valid"`
	}
	if json.Unmarshal(out, &st) != nil || !st.Valid {
		return "", nil
	}
	return st.Built, nil
}

func (g *grype) Scan(ctx context.Context, cacheDir string, target Target, auth *Auth) (Report, error) {
	if !g.Installed(cacheDir) {
		return Report{}, ErrNotInstalled
	}
	if err := target.Validate(); err != nil {
		return Report{}, err
	}
	var extra []string
	if auth != nil {
		extra = []string{
			"GRYPE_REGISTRY_AUTH_AUTHORITY=" + target.Registry,
			"GRYPE_REGISTRY_AUTH_USERNAME=" + auth.Username,
			"GRYPE_REGISTRY_AUTH_PASSWORD=" + auth.Password,
		}
	}
	out, err := run(ctx, g.binPath(cacheDir),
		[]string{"registry:" + target.Ref(), "--platform", target.Platform, "-o", "json", "--quiet"},
		g.env(cacheDir, false, extra...))
	if err != nil {
		return Report{}, fmt.Errorf("Grype: %w", err)
	}
	findings, notice, err := parseGrype(out)
	if err != nil {
		return Report{}, err
	}
	built, _ := g.DBBuiltAt(ctx, cacheDir)
	return Report{Findings: findings, DBBuiltAt: built, Notice: notice}, nil
}

func parseGrype(raw []byte) ([]Finding, string, error) {
	var doc struct {
		Distro struct {
			Name string `json:"name"`
		} `json:"distro"`
		Matches []struct {
			Vulnerability struct {
				ID          string `json:"id"`
				Severity    string `json:"severity"`
				Description string `json:"description"`
				Fix         struct {
					Versions []string `json:"versions"`
					State    string   `json:"state"`
				} `json:"fix"`
			} `json:"vulnerability"`
			Artifact struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"artifact"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, "", fmt.Errorf("Grype returned output that is not a report: %w", err)
	}
	var findings []Finding
	for _, m := range doc.Matches {
		fixed := ""
		if m.Vulnerability.Fix.State == "fixed" {
			fixed = strings.Join(m.Vulnerability.Fix.Versions, ", ")
		}
		findings = append(findings, Finding{
			ID: m.Vulnerability.ID, Severity: normalizeSeverity(m.Vulnerability.Severity), Package: m.Artifact.Name,
			Installed: m.Artifact.Version, FixedIn: fixed, Title: shorten(m.Vulnerability.Description, 160),
		})
	}
	notice := ""
	if len(findings) == 0 && doc.Distro.Name == "" {
		notice = NoOSNotice
	}
	return Sort(findings), notice, nil
}
