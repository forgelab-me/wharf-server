// Version-available detection for wharf-server and wharf-agent --
// informational only, no auto-apply. The controller deliberately has no
// Docker socket access (only the agent runs DooD, cf. ARCHITECTURE.md),
// so it has no way to redeploy itself even if it wanted to; and unlike a
// managed stack's image, there's no external supervisor to recover a
// controller that self-updates badly, since the controller *is* the
// thing that would normally do the recovering.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// versionCheckInterval: unlike an image digest, a release doesn't move
// during the day -- checking every few hours is plenty and keeps this
// comfortably under GitHub's unauthenticated rate limit (60 req/h; this
// is 2 requests every 6h).
const versionCheckInterval = "0 */6 * * *"

// latest is a small process-wide cache of the newest published release
// per repo, read by render() (server badge) and hostsHandler/
// hostViewHandler (per-agent badge) -- a package-level var rather than
// a field threaded through render() the same way the `version` var
// above already sidesteps that for the running build's own version.
var latest = &latestVersions{}

type latestVersions struct {
	mu     sync.RWMutex
	server string
	agent  string
}

func (v *latestVersions) get() (server, agent string) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.server, v.agent
}

func (v *latestVersions) set(server, agent string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if server != "" {
		v.server = server
	}
	if agent != "" {
		v.agent = agent
	}
}

// registerVersionChecking schedules the recurring check and fires one
// off immediately in the background -- not synchronously, so a slow or
// unreachable network (air-gapped homelab, GitHub hiccup) never delays
// startup waiting on an HTTP call that has nothing to do with the
// controller being ready to serve.
func registerVersionChecking(a *app) error {
	go checkLatestVersions(a)
	_, err := a.cron.AddFunc(versionCheckInterval, func() { checkLatestVersions(a) })
	return err
}

func checkLatestVersions(a *app) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server, err := latestGitHubTag(ctx, "forgelab-me/wharf-server")
	if err != nil {
		log.Println("version check: wharf-server:", err)
	}
	agentVer, err := latestGitHubTag(ctx, "forgelab-me/wharf-agent")
	if err != nil {
		log.Println("version check: wharf-agent:", err)
	}
	latest.set(server, agentVer)
}

type githubTag struct {
	Name string `json:"name"`
}

// latestGitHubTag hits the public, unauthenticated tags API -- no token
// needed, both repos are public. Deliberately not the Releases API
// (/releases/latest): that needs an actual GitHub Release object, which
// this project doesn't publish, only the plain "git tag vX.Y.Z && git
// push origin vX.Y.Z" the release workflows key off. per_page=100
// comfortably covers this project's tag count for the foreseeable
// future without needing to paginate. Every returned tag is parsed as
// semver and the highest wins -- GitHub doesn't sort tags by version,
// only by whatever order its own heuristic picks.
func latestGitHubTag(ctx context.Context, repo string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/"+repo+"/tags?per_page=100", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github tags API for %s: %s", repo, resp.Status)
	}
	var tags []githubTag
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return "", fmt.Errorf("decode github tags for %s: %w", repo, err)
	}
	best := ""
	for _, t := range tags {
		v := strings.TrimPrefix(t.Name, "v")
		if _, ok := parseSemver(v); !ok {
			continue
		}
		if best == "" || semverLess(best, v) {
			best = v
		}
	}
	if best == "" {
		return "", fmt.Errorf("no semver tag found for %s", repo)
	}
	return best, nil
}

// semverLess reports whether a < b, comparing X.Y.Z numerically --
// plain string comparison gets "0.9.0" > "0.10.0" wrong the moment
// either project crosses a double-digit minor/patch. Anything that
// doesn't parse as X.Y.Z (a "dev"/"dev-local" build, a malformed
// response) is never considered less than a real release -- no update
// nagging on a build that didn't come from a tagged release to begin
// with.
func semverLess(a, b string) bool {
	pa, oka := parseSemver(a)
	pb, okb := parseSemver(b)
	if !oka || !okb {
		return false
	}
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func parseSemver(v string) ([3]int, bool) {
	var out [3]int
	parts := strings.SplitN(v, ".", 3)
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
