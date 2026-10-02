package secrets

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const (
	bwsScheme = "bws"

	// BwsVersion is the bws release the controller downloads on request.
	BwsVersion = "2.1.0"
	// BwsLicenseURL is the licence that governs the Bitwarden tool.
	BwsLicenseURL = "https://github.com/bitwarden/sdk-sm/blob/main/LICENSE"

	bwsMaxArchive = 64 << 20
	bwsMaxBinary  = 128 << 20
	bwsMaxOutput  = 16 << 20
)

// BwsRelease is one pinned download.
type BwsRelease struct {
	URL    string
	SHA256 string
}

// bwsReleases are the musl builds Bitwarden publishes (statically linked, so
// they run on Alpine), with the SHA-256 from their published checksum file.
var bwsReleases = map[string]BwsRelease{
	"amd64": {
		URL:    "https://github.com/bitwarden/sdk-sm/releases/download/bws-v2.1.0/bws-x86_64-unknown-linux-musl-2.1.0.zip",
		SHA256: "f59ee150e42b82128d437087e9bac920053c6bfddcb960d20ce9386e5ac9bba6",
	},
	"arm64": {
		URL:    "https://github.com/bitwarden/sdk-sm/releases/download/bws-v2.1.0/bws-aarch64-unknown-linux-musl-2.1.0.zip",
		SHA256: "eb0f1ae61d1c3b74244d2841233276e05c77e8be4da197ed90fc6248387005e1",
	},
}

// ErrBwsNotInstalled is returned while the Bitwarden tool has not been downloaded.
var ErrBwsNotInstalled = errors.New("the Bitwarden tool (bws) is not installed: download it under Settings, Secret providers")

// BwsTool is the bws binary: downloaded when an administrator asks for it,
// never bundled with Wharf, since Bitwarden's licence does not allow
// redistributing it.
type BwsTool struct {
	CacheDir string

	release *BwsRelease // set by tests
	client  *http.Client
	run     bwsRunner
}

func NewBwsTool(cacheDir string) *BwsTool {
	return &BwsTool{CacheDir: cacheDir, client: &http.Client{Timeout: 3 * time.Minute}, run: runBws}
}

// Override replaces the pinned download, for tests.
func (t *BwsTool) Override(rel BwsRelease) { t.release = &rel }

func (t *BwsTool) Version() string { return BwsVersion }

func (t *BwsTool) Path() string {
	return filepath.Join(t.CacheDir, "secret-tools", "bws", BwsVersion, "bws")
}

func (t *BwsTool) Installed() bool {
	info, err := os.Stat(t.Path())
	return err == nil && info.Mode().IsRegular()
}

// Install downloads the pinned release for this machine, checks its SHA-256 and
// unpacks the binary. A download that does not match is discarded, never run.
func (t *BwsTool) Install(ctx context.Context) error {
	rel, ok := bwsReleases[runtime.GOARCH]
	if t.release != nil {
		rel, ok = *t.release, true
	}
	if !ok {
		return fmt.Errorf("Bitwarden publishes no pinned bws release for %s", runtime.GOARCH)
	}
	dir := filepath.Dir(t.Path())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create the tool directory: %w", err)
	}
	archive, err := os.CreateTemp(dir, "download-*")
	if err != nil {
		return err
	}
	defer os.Remove(archive.Name())
	defer archive.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rel.URL, nil)
	if err != nil {
		return err
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("download bws: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download bws: the server answered %s", resp.Status)
	}
	sum := sha256.New()
	n, err := io.Copy(io.MultiWriter(archive, sum), io.LimitReader(resp.Body, bwsMaxArchive+1))
	if err != nil {
		return fmt.Errorf("download bws: %w", err)
	}
	if n > bwsMaxArchive {
		return errors.New("download bws: the file is larger than expected, refusing it")
	}
	if got := hex.EncodeToString(sum.Sum(nil)); got != rel.SHA256 {
		return errors.New("the download does not match the pinned checksum: refusing it")
	}
	return t.extract(archive.Name(), dir)
}

// extract takes the bws binary out of the archive and puts it in place.
func (t *BwsTool) extract(archive, dir string) error {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return fmt.Errorf("open the bws archive: %w", err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || path.Base(f.Name) != "bws" {
			continue
		}
		if f.UncompressedSize64 > bwsMaxBinary {
			return errors.New("the bws binary is larger than expected, refusing it")
		}
		src, err := f.Open()
		if err != nil {
			return err
		}
		defer src.Close()
		out, err := os.CreateTemp(dir, "bws-*")
		if err != nil {
			return err
		}
		defer os.Remove(out.Name())
		if _, err := io.Copy(out, io.LimitReader(src, bwsMaxBinary)); err != nil {
			out.Close()
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
		if err := os.Chmod(out.Name(), 0o755); err != nil {
			return err
		}
		return os.Rename(out.Name(), t.Path())
	}
	return errors.New("the archive does not contain a bws binary")
}

// ---- running it

type bwsRunner func(ctx context.Context, bin string, args, env []string) (stdout []byte, stderr string, err error)

// limitedBuffer refuses to grow past max.
type limitedBuffer struct {
	bytes.Buffer
	max int
}

var errTooMuchOutput = errors.New("bws printed more than expected")

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.max {
		return 0, errTooMuchOutput
	}
	return b.Buffer.Write(p)
}

func runBws(ctx context.Context, bin string, args, env []string) ([]byte, string, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env
	cmd.WaitDelay = 2 * time.Second
	out, errb := &limitedBuffer{max: bwsMaxOutput}, &limitedBuffer{max: 64 << 10}
	cmd.Stdout, cmd.Stderr = out, errb
	err := cmd.Run()
	return out.Bytes(), errb.String(), err
}

var bwsErrLine = regexp.MustCompile(`(?m)^\s*0:\s*(.+)$`)

// bwsError turns what bws printed into a message, without ever echoing the token.
func bwsError(ctx context.Context, err error, stderr, token string) error {
	if ctx.Err() != nil {
		return fmt.Errorf("bws did not answer in time: %w", ctx.Err())
	}
	msg := ""
	if m := bwsErrLine.FindStringSubmatch(stderr); m != nil {
		msg = strings.TrimSpace(m[1])
	}
	if msg == "" {
		for _, line := range strings.Split(stderr, "\n") {
			if line = strings.TrimSpace(line); line != "" && line != "Error:" {
				msg = line
				break
			}
		}
	}
	if msg == "" {
		msg = err.Error()
	}
	if token != "" {
		msg = strings.ReplaceAll(msg, token, "***")
	}
	return fmt.Errorf("bws: %s", msg)
}

// ---- the provider

var bwsID = regexp.MustCompile(`^[0-9a-fA-F-]{36}$`)

// BwsProvider serves ref+bws://<project>/<secret key>#/value (or #/note) from
// Bitwarden Secrets Manager, through the bws tool.
func BwsProvider(tool *BwsTool) Connector { return &bwsProvider{tool: tool} }

type bwsProvider struct{ tool *BwsTool }

func (*bwsProvider) Scheme() string { return bwsScheme }
func (*bwsProvider) Label() string  { return "Bitwarden Secrets Manager" }

func (*bwsProvider) Fields() []Field {
	return []Field{
		{Name: "region", Label: "Region", Input: "select", Options: []string{"us", "eu", "custom"}, Default: "us",
			Help: "us is vault.bitwarden.com, eu is vault.bitwarden.eu. Use custom for another server."},
		{Name: "server_url", Label: "Server URL", Placeholder: "https://vault.example.com", Help: "Only with the custom region."},
		PathRulesField,
		{Name: "access_token", Label: "Machine account access token", Credential: true,
			Help: "From Secrets Manager, Machine accounts. Give the account read access to the stack's project only."},
	}
}

// Summary is the address shown in the connections list.
func (*bwsProvider) Summary(config map[string]string) string { return bwsServerURL(config) }

func bwsServerURL(config map[string]string) string {
	switch config["region"] {
	case "eu":
		return "https://vault.bitwarden.eu"
	case "custom":
		return strings.TrimRight(strings.TrimSpace(config["server_url"]), "/")
	}
	return "https://vault.bitwarden.com"
}

func (*bwsProvider) ValidateConfig(config map[string]string) error {
	switch config["region"] {
	case "", "us", "eu":
	case "custom":
		u, err := url.Parse(bwsServerURL(config))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return errors.New("the server URL must be a full http(s) URL")
		}
		if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("the server URL must not contain credentials, a query or a fragment")
		}
	default:
		return errors.New("region must be us, eu or custom")
	}
	return ValidatePathRules(config)
}

func (*bwsProvider) ValidateCredentials(creds map[string]string) error {
	t := creds["access_token"]
	if t == "" {
		return errors.New("provide the machine account's access token")
	}
	if !strings.HasPrefix(t, "0.") || !strings.Contains(t, ":") || strings.ContainsAny(t, " \t\r\n") {
		return errors.New("that does not look like a Secrets Manager access token (0.<id>.<secret>:<key>)")
	}
	return nil
}

// call runs bws once, with nothing of the controller's environment, a private
// home directory that is removed afterwards, and the token in the environment.
func (p *bwsProvider) call(ctx context.Context, eff *Effective, args ...string) ([]byte, error) {
	if !p.tool.Installed() {
		return nil, ErrBwsNotInstalled
	}
	home, err := os.MkdirTemp("", "wharf-bws-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(home)
	token := eff.Credentials["access_token"]
	env := []string{
		"HOME=" + home,
		"BWS_CONFIG_FILE=" + filepath.Join(home, "config"),
		"BWS_ACCESS_TOKEN=" + token,
		"BWS_SERVER_URL=" + bwsServerURL(eff.Config),
		"NO_COLOR=1",
	}
	if v := os.Getenv("SSL_CERT_FILE"); v != "" {
		env = append(env, "SSL_CERT_FILE="+v)
	}
	out, stderr, err := p.tool.run(ctx, p.tool.Path(), args, env)
	if err != nil {
		return nil, bwsError(ctx, err, stderr, token)
	}
	return out, nil
}

type bwsProject struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type bwsSecret struct {
	ID    string `json:"id"`
	Key   string `json:"key"`
	Value string `json:"value"`
	Note  string `json:"note"`
}

func (p *bwsProvider) projects(ctx context.Context, eff *Effective) ([]bwsProject, error) {
	out, err := p.call(ctx, eff, "project", "list", "--output", "json")
	if err != nil {
		return nil, err
	}
	var list []bwsProject
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, errors.New("bws answered something that is not a list of projects")
	}
	return list, nil
}

func (p *bwsProvider) secrets(ctx context.Context, eff *Effective, projectID string) ([]bwsSecret, error) {
	if !bwsID.MatchString(projectID) {
		return nil, errors.New("bws returned a project id that does not look like one")
	}
	out, err := p.call(ctx, eff, "secret", "list", projectID, "--output", "json")
	if err != nil {
		return nil, err
	}
	var list []bwsSecret
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, errors.New("bws answered something that is not a list of secrets")
	}
	return list, nil
}

func (p *bwsProvider) Check(ctx context.Context, eff *Effective) error {
	if err := p.ValidateConfig(eff.Config); err != nil {
		return err
	}
	if err := p.ValidateCredentials(eff.Credentials); err != nil {
		return err
	}
	_, err := p.projects(ctx, eff)
	return err
}

// Resolve reads one secret. The path is <project>/<secret key>; both names must
// be unique, because Bitwarden does not enforce it and a rule written around a
// name must never read some other item that happens to share it.
func (p *bwsProvider) Resolve(ctx context.Context, job *Job, ref Ref) (string, error) {
	eff, err := job.Effective(bwsScheme)
	if err != nil {
		return "", err
	}
	segs := strings.Split(ref.Path, "/")
	if len(segs) != 2 {
		return "", errors.New("a bws reference is ref+bws://<project>/<secret key>#/value")
	}
	project, key := segs[0], segs[1]
	if ref.Field != "value" && ref.Field != "note" {
		return "", fmt.Errorf("a bws secret has a value and a note: use #/value or #/note, not #/%s", ref.Field)
	}

	v, err := job.Memo("bws-projects:"+eff.Identity, func() (any, error) { return p.projects(ctx, eff) })
	if err != nil {
		return "", err
	}
	var projectIDs []string
	for _, pr := range v.([]bwsProject) {
		if pr.Name == project {
			projectIDs = append(projectIDs, pr.ID)
		}
	}
	switch len(projectIDs) {
	case 0:
		return "", fmt.Errorf("no project named %q (the machine account may not have access to it)", project)
	case 1:
	default:
		return "", fmt.Errorf("%d projects are named %q: rename all but one", len(projectIDs), project)
	}

	v, err = job.Memo("bws-secrets:"+eff.Identity+":"+projectIDs[0], func() (any, error) { return p.secrets(ctx, eff, projectIDs[0]) })
	if err != nil {
		return "", err
	}
	var found []bwsSecret
	for _, s := range v.([]bwsSecret) {
		if s.Key == key {
			found = append(found, s)
		}
	}
	switch len(found) {
	case 0:
		return "", fmt.Errorf("no secret named %q in project %q", key, project)
	case 1:
	default:
		return "", fmt.Errorf("%d secrets are named %q in project %q: rename all but one", len(found), key, project)
	}
	if ref.Field == "note" {
		return found[0].Note, nil
	}
	return found[0].Value, nil
}
