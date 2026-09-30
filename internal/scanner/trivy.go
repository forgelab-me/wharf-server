package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

var trivyRelease = release{
	Version: "0.74.0",
	Assets: map[string]asset{
		"amd64": {
			URL:    "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz",
			SHA256: "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a",
		},
		"arm64": {
			URL:    "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-ARM64.tar.gz",
			SHA256: "b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5",
		},
	},
}

type trivy struct{ base }

// Trivy is the Aqua Security scanner.
func Trivy() Scanner { return newTrivy(trivyRelease, nil) }

func newTrivy(rel release, client *http.Client) *trivy {
	return &trivy{base{name: "trivy", label: "Trivy", rel: rel, client: client}}
}

func (t *trivy) UpdateDB(ctx context.Context, cacheDir string) error {
	if !t.Installed(cacheDir) {
		return ErrNotInstalled
	}
	_, err := run(ctx, t.binPath(cacheDir),
		[]string{"image", "--download-db-only", "--quiet", "--no-progress", "--cache-dir", t.dbDir(cacheDir)},
		scanEnv(t.dbDir(cacheDir)))
	if err != nil {
		return fmt.Errorf("update the Trivy database: %w", err)
	}
	return nil
}

func (t *trivy) DBBuiltAt(_ context.Context, cacheDir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(t.dbDir(cacheDir), "db", "metadata.json"))
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var meta struct {
		UpdatedAt string `json:"UpdatedAt"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return "", fmt.Errorf("read the Trivy database metadata: %w", err)
	}
	return meta.UpdatedAt, nil
}

func (t *trivy) Scan(ctx context.Context, cacheDir string, target Target, auth *Auth) (Report, error) {
	if !t.Installed(cacheDir) {
		return Report{}, ErrNotInstalled
	}
	if err := target.Validate(); err != nil {
		return Report{}, err
	}
	var extra []string
	if auth != nil {
		extra = []string{"TRIVY_USERNAME=" + auth.Username, "TRIVY_PASSWORD=" + auth.Password}
	}
	out, err := run(ctx, t.binPath(cacheDir), []string{
		"image", "--image-src", "remote", "--platform", target.Platform,
		"--skip-db-update", "--skip-java-db-update", "--scanners", "vuln",
		"--quiet", "--no-progress", "--format", "json", "--timeout", "5m",
		"--cache-dir", t.dbDir(cacheDir), target.Ref(),
	}, scanEnv(t.dbDir(cacheDir), extra...))
	if err != nil {
		return Report{}, fmt.Errorf("Trivy: %w", err)
	}
	findings, notice, err := parseTrivy(out)
	if err != nil {
		return Report{}, err
	}
	built, _ := t.DBBuiltAt(ctx, cacheDir)
	return Report{Findings: findings, DBBuiltAt: built, Notice: notice}, nil
}

func parseTrivy(raw []byte) ([]Finding, string, error) {
	var doc struct {
		Metadata struct {
			OS *struct {
				Family string `json:"Family"`
			} `json:"OS"`
		} `json:"Metadata"`
		Results []struct {
			Vulnerabilities []struct {
				ID        string `json:"VulnerabilityID"`
				Package   string `json:"PkgName"`
				Installed string `json:"InstalledVersion"`
				Fixed     string `json:"FixedVersion"`
				Severity  string `json:"Severity"`
				Title     string `json:"Title"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, "", fmt.Errorf("Trivy returned output that is not a report: %w", err)
	}
	var findings []Finding
	for _, r := range doc.Results {
		for _, v := range r.Vulnerabilities {
			findings = append(findings, Finding{
				ID: v.ID, Severity: normalizeSeverity(v.Severity), Package: v.Package,
				Installed: v.Installed, FixedIn: v.Fixed, Title: shorten(v.Title, 160),
			})
		}
	}
	notice := ""
	if len(findings) == 0 && len(doc.Results) == 0 && (doc.Metadata.OS == nil || doc.Metadata.OS.Family == "") {
		notice = NoOSNotice
	}
	return Sort(findings), notice, nil
}
