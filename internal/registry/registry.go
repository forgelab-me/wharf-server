// Package registry fetches the current digest for an image:tag reference
// from a container registry, without pulling the image itself — used to
// detect when a mutable tag (e.g. "mysql:latest") has moved.
//
// Any registry implementing the Docker Registry HTTP API v2 protocol
// works — Docker Hub, GHCR, GitLab's container registry, Azure
// Container Registry, a self-hosted Harbor/Nexus/Distribution, etc.
// Nothing about a specific vendor is hardcoded: the auth scheme (bearer
// token vs. plain HTTP Basic, and — for bearer — which realm/service to
// request a token from) is discovered per host from the WWW-Authenticate
// challenge on an unauthenticated GET of /v2/, exactly how `docker login`
// itself figures this out. The one vendor-specific fact that *is*
// hardcoded is docker.io itself not serving /v2/ on its own domain —
// registryHostFor remaps it to registry-1.docker.io, verified against
// Docker Hub's own docs, not guessed.
package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Ref is a normalized image reference: the registry host, the repository
// path on that host, and the tag — e.g. "mysql:latest" on Docker Hub
// normalizes to {docker.io, library/mysql, latest}.
type Ref struct {
	Host       string
	Repository string
	Tag        string
}

// Canonical is the cache key shared by every stack/service that happens
// to reference the same image — the whole point of the shared
// image_digest_cache table: N stacks on "mysql:latest" collapse to one
// entry instead of N.
func (r Ref) Canonical() string {
	return r.Host + "/" + r.Repository + ":" + r.Tag
}

// ErrDigestPinned marks a reference already pinned by digest
// (image@sha256:...) — nothing to detect, callers should skip tracking it
// entirely rather than call ParseRef.
var ErrDigestPinned = errors.New("image reference is pinned by digest")

// ParseRef normalizes a compose "image:" value into a Ref. supported is
// false only for a digest-pinned reference (image@sha256:...) — every
// other host is attempted via runtime discovery in Digest, so the
// caller no longer needs to know in advance which hosts are reachable.
func ParseRef(image string) (ref Ref, supported bool) {
	image = strings.TrimSpace(image)
	if strings.Contains(image, "@sha256:") {
		return Ref{}, false
	}

	name, tag := image, "latest"
	if slash := strings.LastIndex(image, "/"); slash >= 0 {
		if colon := strings.LastIndex(image[slash:], ":"); colon >= 0 {
			name, tag = image[:slash+colon], image[slash+colon+1:]
		}
	} else if colon := strings.LastIndex(image, ":"); colon >= 0 {
		name, tag = image[:colon], image[colon+1:]
	}

	var host, repo string
	parts := strings.SplitN(name, "/", 2)
	firstLooksLikeHost := strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost"
	switch {
	case len(parts) == 1:
		host, repo = "docker.io", "library/"+parts[0]
	case !firstLooksLikeHost:
		host, repo = "docker.io", name
	default:
		host, repo = parts[0], parts[1]
	}

	return Ref{Host: host, Repository: repo, Tag: tag}, true
}

// registryHostFor returns the actual host to send /v2/ requests to.
// docker.io is the one vendor-specific exception: the domain used in
// image references doesn't itself serve the registry API.
func registryHostFor(host string) string {
	if host == "docker.io" {
		return "registry-1.docker.io"
	}
	return host
}

// manifestAccept covers single-arch manifests, multi-arch manifest lists,
// and their OCI equivalents — the registry returns whichever kind the tag
// actually points to, and we only care about the Docker-Content-Digest
// header, never the body, so accepting all of them avoids having to guess
// or filter by platform.
const manifestAccept = "application/vnd.docker.distribution.manifest.v2+json, " +
	"application/vnd.docker.distribution.manifest.list.v2+json, " +
	"application/vnd.oci.image.manifest.v1+json, " +
	"application/vnd.oci.image.index.v1+json"

// Digest fetches the current manifest digest for ref from its registry.
// username/password authenticate to whichever auth scheme discoverAuth
// finds for ref.Host — pass "" for both to request anonymous/public
// access exactly as before. The caller (not this package) decides
// whether a credential exists for ref.Host; this package only knows how
// to use one once handed it, the same separation keys.Custodian already
// has from the main app DB.
func Digest(ctx context.Context, ref Ref, username, password string) (string, error) {
	registryHost := registryHostFor(ref.Host)

	auth, err := discoverAuth(ctx, registryHost)
	if err != nil {
		return "", fmt.Errorf("discover auth for %q: %w", ref.Host, err)
	}

	manifestURL := fmt.Sprintf("https://%s/v2/%s/manifests/%s", registryHost, ref.Repository, ref.Tag)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", manifestAccept)

	switch auth.scheme {
	case authBearer:
		token, err := fetchToken(ctx, auth, ref.Repository, username, password)
		if err != nil {
			return "", fmt.Errorf("fetch token: %w", err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	case authBasic:
		if username != "" || password != "" {
			req.SetBasicAuth(username, password)
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("get manifest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("get manifest: unexpected status %s", resp.Status)
	}

	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return "", errors.New("get manifest: no Docker-Content-Digest header in response")
	}
	return digest, nil
}

type authScheme int

const (
	authNone authScheme = iota
	authBasic
	authBearer
)

type discoveredAuth struct {
	scheme  authScheme
	realm   string
	service string
}

// authParamRe pulls key="value" pairs out of a WWW-Authenticate header,
// e.g. `Bearer realm="https://auth.docker.io/token",service="registry.docker.io"`.
var authParamRe = regexp.MustCompile(`(\w+)="([^"]*)"`)

// discoverAuth is the same probe `docker login`/`docker pull` themselves
// make: an unauthenticated GET of /v2/ on the registry. A 200 means the
// registry needs no auth at all for this call; a 401 carries a
// WWW-Authenticate challenge naming the scheme (and, for Bearer, the
// token realm/service to request one from) — verified against Docker
// Hub's and GHCR's real challenges while building this, not guessed.
func discoverAuth(ctx context.Context, registryHost string) (discoveredAuth, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+registryHost+"/v2/", nil)
	if err != nil {
		return discoveredAuth{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return discoveredAuth{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return discoveredAuth{scheme: authNone}, nil
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return discoveredAuth{}, fmt.Errorf("unexpected status from %s/v2/: %s", registryHost, resp.Status)
	}

	header := resp.Header.Get("WWW-Authenticate")
	switch {
	case strings.HasPrefix(strings.ToLower(header), "bearer"):
		params := map[string]string{}
		for _, m := range authParamRe.FindAllStringSubmatch(header, -1) {
			params[m[1]] = m[2]
		}
		if params["realm"] == "" {
			return discoveredAuth{}, fmt.Errorf("%s advertised Bearer auth with no realm", registryHost)
		}
		return discoveredAuth{scheme: authBearer, realm: params["realm"], service: params["service"]}, nil
	case strings.HasPrefix(strings.ToLower(header), "basic"):
		return discoveredAuth{scheme: authBasic}, nil
	default:
		return discoveredAuth{}, fmt.Errorf("%s returned 401 with an unsupported or missing WWW-Authenticate challenge %q", registryHost, header)
	}
}

// fetchToken requests a bearer token scoped to pull repository from the
// realm/service discoverAuth found. With empty username/password this is
// exactly the anonymous request most registries already grant read
// access to for a public repo; with credentials, HTTP Basic auth on this
// same request is how the token endpoint authenticates a private one —
// the same mechanism Docker Hub and GHCR use, and the Docker Registry
// v2 spec's own documented flow for any other compliant registry.
func fetchToken(ctx context.Context, auth discoveredAuth, repository, username, password string) (string, error) {
	q := url.Values{}
	if auth.service != "" {
		q.Set("service", auth.service)
	}
	q.Set("scope", "repository:"+repository+":pull")

	tokenURL := auth.realm
	if strings.Contains(tokenURL, "?") {
		tokenURL += "&" + q.Encode()
	} else {
		tokenURL += "?" + q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", err
	}
	if username != "" || password != "" {
		req.SetBasicAuth(username, password)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %s", resp.Status)
	}

	var body struct {
		Token string `json:"token"`
		// Docker Hub's token endpoint historically used this field name;
		// GHCR and newer Docker Hub responses use "token" — accept both.
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if body.Token != "" {
		return body.Token, nil
	}
	return body.AccessToken, nil
}
