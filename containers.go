// Real container listing — replaces the original mockContainers()
// preview. Data comes from host_containers, kept in sync by each agent's
// persistent tunnel (cf. tunnel.go), not queried on page load: the
// controller never reaches out to an agent, only ever reads what was
// last pushed.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/forgelab-me/wharf-server/internal/registry"
	"github.com/forgelab-me/wharf-server/internal/store"
	"github.com/goccy/go-yaml"
)

// Container is the containers-page view model. ID is the short Docker
// container id (used in URLs — unlike a name, it's unique across the
// whole fleet, not just within one host). Stack holds the raw stack id
// from the compose project label, empty for a container Wharf didn't
// deploy at all. ManagedStack is only true when that id also has a row
// in Wharf's own stacks table -- something like Portainer stamps the
// exact same compose labels on what it deploys, so Stack alone can't
// tell "Wharf-managed" from "some other tool's compose project"; the
// template links to /stacks/{id} only when this is true, to avoid
// linking to a stack page that 404s. UpdateStatus is "" (not tracked by
// any image policy — most containers on a real host, cf.
// containersHandler), "current", or "outdated" — never guessed, only
// ever set from the same applied/latest-digest comparison the stack
// page already uses.
type Container struct {
	ID, Name, ImageDisplay, Host, State, Status, Created, Stack, UpdateStatus string
	ManagedStack                                                              bool
	Ports                                                                     []portLink
}

// cleanImageName strips the digest half of a container's Image field --
// docker ps prints "repo@sha256:<64 hex chars>" instead of "repo:tag"
// once a container's tag has since moved or been removed locally, and
// that raw digest is unreadable in a table column. shortDigest already
// does the truncation the stack page's own digest display uses.
func cleanImageName(image string) string {
	repo, digest, ok := strings.Cut(image, "@")
	if !ok {
		return image
	}
	return repo + "@" + shortDigest(digest)
}

func containerViewFromRow(c store.HostContainer, address string, updateStatus string, managedStack bool) Container {
	return Container{
		ID:           c.ContainerID,
		Name:         c.Name,
		ImageDisplay: cleanImageName(c.Image),
		Host:         c.HostName,
		State:        c.State,
		Status:       c.Status,
		Ports:        parsePorts(c.Ports, address),
		Created:      trimCreatedAt(c.Created),
		Stack:        c.StackID,
		ManagedStack: managedStack,
		UpdateStatus: updateStatus,
	}
}

// managedStackSet loads every Wharf-tracked stack id currently in the
// store, once, so callers rendering a whole page of containers can
// answer "is this compose label ours?" with a map lookup instead of one
// query per row. A failure here just means nothing renders as
// Wharf-managed for this request -- same fail-open-to-plain-text
// treatment containerUpdateStatuses already gives a failed policy load.
func managedStackSet(a *app) map[string]bool {
	stacks, err := a.store.ListStacks()
	if err != nil {
		return nil
	}
	set := make(map[string]bool, len(stacks))
	for _, s := range stacks {
		set[s.ID] = true
	}
	return set
}

// trimCreatedAt drops the "+0000 UTC" tail `docker ps`'s own CreatedAt
// format always carries -- every other date already shown across the
// app (LastSeenAt, deployment timestamps) is a plain SQLite
// "YYYY-MM-DD HH:MM:SS", so this just matches that instead of leaking
// docker's own Go time.Time.String() format onto one page.
func trimCreatedAt(s string) string {
	fields := strings.Fields(s)
	if len(fields) >= 2 {
		return fields[0] + " " + fields[1]
	}
	return s
}

// containerUpdateStatuses computes "current"/"outdated" for every
// (stack, service) pair with an active image policy, across the whole
// fleet in one pass -- reusing exactly the applied-vs-latest-digest
// comparison imagePolicyViewRows already does for the stack page,
// rather than a second source of truth. Deliberately does NOT reach out
// to a registry for images with no policy (most containers on a real
// host aren't Wharf-managed at all) -- an untracked image gets no badge,
// not a guessed one.
func containerUpdateStatuses(a *app) map[string]map[string]string {
	policies, err := a.store.ListImagePolicies()
	if err != nil {
		return nil
	}
	out := map[string]map[string]string{}
	for _, p := range policies {
		ref, supported := registry.ParseRef(p.ImageRef)
		if !supported {
			continue
		}
		digest, ok, err := a.store.GetImageDigestCache(ref.Canonical())
		if err != nil || !ok {
			continue
		}
		if out[p.StackID] == nil {
			out[p.StackID] = map[string]string{}
		}
		if digest == p.AppliedDigest {
			out[p.StackID][p.ServiceName] = "current"
		} else {
			out[p.StackID][p.ServiceName] = "outdated"
		}
	}
	return out
}

func (a *app) containersHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := a.store.ListHostContainers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	hosts, err := a.store.ListHosts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	addresses := make(map[string]string, len(hosts))
	for _, h := range hosts {
		addresses[h.ID] = h.Address
	}
	updateStatuses := containerUpdateStatuses(a)
	managedStacks := managedStackSet(a)

	containers := make([]Container, 0, len(rows))
	for _, c := range rows {
		status := updateStatuses[c.StackID][c.ServiceName]
		containers = append(containers, containerViewFromRow(c, addresses[c.HostID], status, managedStacks[c.StackID]))
	}

	data := map[string]any{
		"Title":      "Containers",
		"Nav":        "containers",
		"Containers": containers,
		"Hosts":      hosts,
	}
	render(w, r, "layout", "containers.html", data)
}

// containerDetailHandler fetches logs and a full docker inspect on page
// load, both over the same tunnel command channel built for restart/stop
// (cf. tunnel.go) — fired concurrently so a disconnected/slow host costs
// one ~15s wait, not two back to back. Either falls back to the
// template's placeholder message on failure/disconnection.
func (a *app) containerDetailHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, err := a.store.GetHostContainerByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	var logs string
	var detail containerDetailInfo
	var envVars []EnvVar
	var volumes []volumeMount
	var networks []connectedNetwork
	var processes string

	var address string
	if h, err := a.store.GetHost(c.HostID); err == nil {
		address = h.Address
	}
	updateStatus := containerUpdateStatuses(a)[c.StackID][c.ServiceName]
	managedStack := managedStackSet(a)[c.StackID]

	if tc, ok := a.tunnels.get(c.HostID); ok {
		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			if result, err := tc.sendCommand(r.Context(), "logs", c.ContainerID); err == nil && result.OK {
				logs = result.Output
			}
		}()
		go func() {
			defer wg.Done()
			if result, err := tc.sendCommand(r.Context(), "inspect", c.ContainerID); err == nil && result.OK {
				detail, envVars, volumes, networks = parseInspect(a, c.StackID, result.Output)
			}
		}()
		go func() {
			defer wg.Done()
			if result, err := tc.sendCommand(r.Context(), "top", c.ContainerID); err == nil && result.OK {
				processes = result.Output
			}
		}()
		wg.Wait()
	}

	data := map[string]any{
		"Title":     c.Name,
		"Nav":       "containers",
		"Container": containerViewFromRow(c, address, updateStatus, managedStack),
		"Detail":    detail,
		"EnvVars":   envVars,
		"Volumes":   volumes,
		"Networks":  networks,
		"Logs":      logs,
		"Processes": processes,
	}
	render(w, r, "layout", "container_detail.html", data)
}

// validLogTails is the ?tail= allowlist for the full logs page/raw
// endpoint -- an allowlist rather than "must parse as a positive int"
// both keeps the choices to values worth offering in a <select> and
// keeps a request query param from being forwarded to the agent's
// exec.Command as anything other than one of these exact strings.
var validLogTails = map[string]bool{"100": true, "200": true, "500": true, "1000": true, "2000": true, "all": true}

func logTailFromQuery(r *http.Request) string {
	if tail := r.URL.Query().Get("tail"); validLogTails[tail] {
		return tail
	}
	return "500"
}

// containerLogsPageHandler serves GET /containers/{id}/logs -- the full
// logs page (cf. container_detail.html's own embedded, fixed-at-200,
// never-refreshing preview). Same server-rendered-then-polled shape as
// containerStatsHandler's live chart: an initial render here, refreshed
// client-side by containerLogsRawHandler so this handler only ever
// blocks on one agent round trip, not one per poll tick.
func (a *app) containerLogsPageHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, err := a.store.GetHostContainerByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	tail := logTailFromQuery(r)
	var logs string
	if tc, ok := a.tunnels.get(c.HostID); ok {
		if result, err := tc.sendLogsCommand(r.Context(), c.ContainerID, tail); err == nil && result.OK {
			logs = result.Output
		}
	}
	data := map[string]any{
		"Title":     c.Name + " · Logs",
		"Nav":       "containers",
		"Container": containerViewFromRow(c, "", "", false),
		"Logs":      logs,
		"Lines":     splitLogLines(logs),
		"Tail":      tail,
	}
	render(w, r, "layout", "container_logs.html", data)
}

// containerLogsRawHandler serves GET /containers/{id}/logs/raw -- plain
// text, polled by container_logs.html's own script to refresh without a
// full page reload. ?download=1 (the page's Download link) adds
// Content-Disposition so a click saves a file instead of a fetch()
// silently discarding text nothing would otherwise render.
func (a *app) containerLogsRawHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, err := a.store.GetHostContainerByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	tc, ok := a.tunnels.get(c.HostID)
	if !ok {
		http.Error(w, "host not connected", http.StatusServiceUnavailable)
		return
	}
	result, err := tc.sendLogsCommand(r.Context(), c.ContainerID, logTailFromQuery(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusGatewayTimeout)
		return
	}
	if !result.OK {
		http.Error(w, result.Output, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if r.URL.Query().Get("download") != "" {
		// Docker itself only ever names a container [a-zA-Z0-9][a-zA-Z0-9_.-]*
		// (enforced by the daemon, not by this app), so c.Name can't carry a
		// '"'/CR/LF to begin with -- stripped anyway as a second line of
		// defense against a header-injection-shaped value reaching a raw
		// Content-Disposition header, rather than trusting that invariant
		// holds forever.
		safeName := strings.NewReplacer(`"`, "", "\r", "", "\n", "").Replace(c.Name)
		w.Header().Set("Content-Disposition", `attachment; filename="`+safeName+`.log"`)
	}
	w.Write([]byte(result.Output))
}

// splitLogLines turns raw "docker logs" output into one entry per line
// for container_logs.html's per-line search filter -- a single <pre>
// blob has no per-line boundary a client-side filter could hide/show
// against. Trims exactly one trailing newline (docker logs always ends
// with one) rather than every trailing blank line, so a log that
// genuinely ends with blank output isn't silently eaten.
func splitLogLines(logs string) []string {
	if logs == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(logs, "\n"), "\n")
}

// containerDetailInfo is the "Container details" card's view model,
// straight from `docker inspect` — no masking needed here (image,
// command, entrypoint, labels and restart policy are never secrets).
type containerDetailInfo struct {
	Image         string
	ImageID       string // the actual image this container was created from -- cf. dockerInspectRaw.Image
	Cmd           string
	Entrypoint    string
	RestartPolicy string
	Labels        []kvPair
}

type kvPair struct{ Key, Value string }

// volumeMount is one entry of the "Volumes" card.
type volumeMount struct {
	Type, Source, Destination, Mode string
}

// connectedNetwork is one entry of the "Connected Networks" card.
type connectedNetwork struct {
	Name, IPAddress, Gateway string
}

// dockerInspectRaw is the small slice of `docker inspect`'s (large) JSON
// shape this page actually uses. `docker inspect <id>` always returns a
// one-element JSON array, never a bare object.
type dockerInspectRaw struct {
	// Image is the id of the image this container actually runs, resolved
	// at create time -- distinct from Config.Image below, which is only
	// the reference string that was asked for ("traefik:latest") and
	// never changes just because that tag now points somewhere else in
	// the registry. Comparing this against /images's own listing for the
	// same host is how a still-running container turns out to be on an
	// image nothing else pulled through Wharf (cf. ARCHITECTURE.md).
	Image  string `json:"Image"`
	Config struct {
		Image      string            `json:"Image"`
		Cmd        []string          `json:"Cmd"`
		Entrypoint []string          `json:"Entrypoint"`
		Env        []string          `json:"Env"`
		Labels     map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		RestartPolicy struct {
			Name              string `json:"Name"`
			MaximumRetryCount int    `json:"MaximumRetryCount"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		Mode        string `json:"Mode"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress string `json:"IPAddress"`
			Gateway   string `json:"Gateway"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

// parseInspect turns raw `docker inspect` JSON into the three cards'
// view models. stackID drives env var masking (cf. buildEnvVars) — the
// only field here that can ever be a secret.
func parseInspect(a *app, stackID, raw string) (containerDetailInfo, []EnvVar, []volumeMount, []connectedNetwork) {
	var arr []dockerInspectRaw
	if err := json.Unmarshal([]byte(raw), &arr); err != nil || len(arr) == 0 {
		return containerDetailInfo{}, nil, nil, nil
	}
	info := arr[0]

	detail := containerDetailInfo{
		Image:         info.Config.Image,
		ImageID:       shortDigest(info.Image),
		Cmd:           strings.Join(info.Config.Cmd, " "),
		Entrypoint:    strings.Join(info.Config.Entrypoint, " "),
		RestartPolicy: info.HostConfig.RestartPolicy.Name,
	}
	if detail.RestartPolicy == "" {
		detail.RestartPolicy = "no"
	}
	if info.HostConfig.RestartPolicy.Name == "on-failure" && info.HostConfig.RestartPolicy.MaximumRetryCount > 0 {
		detail.RestartPolicy = fmt.Sprintf("on-failure (max %d retries)", info.HostConfig.RestartPolicy.MaximumRetryCount)
	}

	labelKeys := make([]string, 0, len(info.Config.Labels))
	for k := range info.Config.Labels {
		labelKeys = append(labelKeys, k)
	}
	sort.Strings(labelKeys)
	for _, k := range labelKeys {
		detail.Labels = append(detail.Labels, kvPair{Key: k, Value: info.Config.Labels[k]})
	}

	envVars := buildEnvVars(a, stackID, info.Config.Env)

	volumes := make([]volumeMount, 0, len(info.Mounts))
	for _, m := range info.Mounts {
		src := m.Source
		if m.Type == "volume" && m.Name != "" {
			src = m.Name // the volume's name reads better than its /var/lib/docker/volumes/... mountpoint
		}
		mode := m.Mode
		if mode == "" {
			if m.RW {
				mode = "rw"
			} else {
				mode = "ro"
			}
		}
		volumes = append(volumes, volumeMount{Type: m.Type, Source: src, Destination: m.Destination, Mode: mode})
	}

	networkNames := make([]string, 0, len(info.NetworkSettings.Networks))
	for name := range info.NetworkSettings.Networks {
		networkNames = append(networkNames, name)
	}
	sort.Strings(networkNames)
	networks := make([]connectedNetwork, 0, len(networkNames))
	for _, name := range networkNames {
		n := info.NetworkSettings.Networks[name]
		networks = append(networks, connectedNetwork{Name: name, IPAddress: n.IPAddress, Gateway: n.Gateway})
	}

	return detail, envVars, volumes, networks
}

// buildEnvVars masks by provenance, not by guesswork or convention.
//   - A container from a *local* Wharf stack: the controller already
//     holds that stack's secret ciphertext centrally, so it can decrypt it
//     right here and mask any env var whose *value* matches one of those
//     secrets. Everything else shows in clear.
//   - A container from a *Git* stack: the controller never retains that
//     stack's secrets.enc.yaml ciphertext centrally, so exact-value
//     matching isn't available -- instead it masks whichever keys the
//     last successful deploy's compose file actually set via a
//     ${...}/$VAR reference (cf. Stack.SubstitutedEnvKeys), leaving a
//     literal compose value or an image's own baked-in default (PATH,
//     FTL_CMD, ...) shown in clear rather than masked on principle. An
//     earlier version masked every value unconditionally for any Git
//     stack "to be safe" -- found in practice to make the whole panel
//     useless (PATH and TZ masked identically to a real password).
//   - A container Wharf never deployed: nothing was ever decrypted for
//     it, shown in clear -- the same as running `docker inspect` yourself.
//
// The local-stack path matches by value, not by key name: a compose
// file is free to feed a secret into a differently-named variable
// (`MYSQL_PASSWORD: ${DB_PASSWORD}`, `secrets: db_password:
// environment: DB_PASSWORD`, etc.) -- extremely common in practice (an
// app's own env var is rarely spelled the same as the secret it's fed
// from). Matching the env var's *name* against the stack's secret *key*
// names missed exactly this case: found by testing a real compose file
// that did precisely this, where the substituted value showed up in
// clear because "MYSQL_PASSWORD" is not "DB_PASSWORD". A `*_FILE` var
// pointing at a path (the other delivery mechanism, cf. agent's
// writeSecretFiles) is correctly left unmasked either way -- a path
// isn't the secret value itself.
func buildEnvVars(a *app, stackID string, rawEnv []string) []EnvVar {
	secrets, maskKeys := stackSecrets(a, stackID)
	secretValues := make(map[string]bool, len(secrets))
	for _, v := range secrets {
		if v != "" {
			secretValues[v] = true
		}
	}
	out := make([]EnvVar, 0, len(rawEnv))
	for _, kv := range rawEnv {
		k, v, _ := strings.Cut(kv, "=")
		switch {
		case maskKeys[k]:
			out = append(out, EnvVar{Key: k, Secret: true, Source: "set via ${...} in compose"})
		case secretValues[v]:
			out = append(out, EnvVar{Key: k, Secret: true, Source: "Wharf secrets"})
		default:
			out = append(out, EnvVar{Key: k, Value: v})
		}
	}
	return out
}

// stackSecrets decrypts a local stack's secret ciphertext into its
// key/value pairs -- used both to mask container env vars by value (cf.
// buildEnvVars) and to list key *names* on the stack page's Secrets
// panel (cf. stackViewHandler in main.go); values from this map are
// never sent to a template, only compared against or discarded.
//
// maskKeys is the Git-stack counterpart: the controller never holds a
// Git stack's decrypted secret values centrally (by design), so exact
// value matching isn't available there -- instead it masks whichever
// keys the last successfully deployed compose file actually set via
// ${...}/$VAR substitution (cf. Stack.SubstitutedEnvKeys), leaving a
// literal compose value or an image's own baked-in default (PATH,
// FTL_CMD, ...) shown in plain text instead of masked on principle.
func stackSecrets(a *app, stackID string) (secrets map[string]string, maskKeys map[string]bool) {
	if stackID == "" {
		return nil, nil
	}
	st, err := a.store.GetStack(stackID)
	if err != nil {
		return nil, nil
	}
	if st.SourceType == "git" {
		maskKeys = map[string]bool{}
		for _, k := range strings.Split(st.SubstitutedEnvKeys, ",") {
			if k != "" {
				maskKeys[k] = true
			}
		}
		return nil, maskKeys
	}
	if len(st.EncryptedSecret) == 0 {
		return nil, nil
	}
	plaintext, err := a.keys.Decrypt(stackID, st.EncryptedSecret)
	if err != nil {
		return nil, nil
	}
	secrets = map[string]string{}
	for _, line := range strings.Split(string(plaintext), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			secrets[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return secrets, nil
}

// composeEnvDoc is the minimal shape read out of a compose file to find
// substituted environment variable names -- cf. substitutedEnvKeys.
type composeEnvDoc struct {
	Services map[string]struct {
		Environment any `yaml:"environment"`
	} `yaml:"services"`
}

// composeVarPattern matches a $VAR or ${VAR} reference anywhere inside
// a string value -- doesn't need to capture the referenced name, only
// detect that substitution happened at all.
var composeVarPattern = regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*`)

// substitutedEnvKeys returns the set of environment variable names any
// service in composeYAML sets via ${...}/$VAR substitution, across
// both compose environment forms (a "KEY: value" map, or a "KEY=value"
// list) -- cf. buildEnvVars, the only consumer. A literal value
// ("TZ: 'America/Toronto'") or a key the compose file never mentions at
// all (an image's own Dockerfile default) is never included.
func substitutedEnvKeys(composeYAML string) ([]string, error) {
	var doc composeEnvDoc
	if err := yaml.Unmarshal([]byte(composeYAML), &doc); err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, svc := range doc.Services {
		switch env := svc.Environment.(type) {
		case map[string]any:
			for k, v := range env {
				if s, ok := v.(string); ok && composeVarPattern.MatchString(s) {
					set[k] = true
				}
			}
		case []any:
			for _, item := range env {
				s, ok := item.(string)
				if !ok {
					continue
				}
				if k, v, found := strings.Cut(s, "="); found {
					if composeVarPattern.MatchString(v) {
						set[k] = true
					}
				} else if composeVarPattern.MatchString(s) {
					// Bare "- ${VAR}" form: compose passes through the
					// host/agent's own environment variable of that name.
					set[strings.Trim(s, "${}")] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out, nil
}

// portLink is one entry of a container's Ports column — Text is always
// a human-readable port, URL is only set for a published port when the
// host's reachable address is known.
type portLink struct {
	Text string
	URL  string
}

// parsePorts turns docker ps's raw comma-separated Ports string (e.g.
// "0.0.0.0:8098->80/tcp, [::]:8098->80/tcp, 3306/tcp") into one entry per
// distinct port — the IPv4 and IPv6 binds of the same published port
// collapse into a single entry instead of showing twice. Scheme is
// always a guess (http): Wharf doesn't track what a given port actually
// speaks.
func parsePorts(raw, address string) []portLink {
	if raw == "" {
		return nil
	}

	type key struct{ hostPort, containerPort, proto string }
	seen := map[key]bool{}
	var out []portLink

	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		bind, rest, published := strings.Cut(entry, "->")
		if !published {
			containerPort, proto, _ := strings.Cut(bind, "/")
			k := key{containerPort: containerPort, proto: proto}
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, portLink{Text: containerPort + "/" + proto})
			continue
		}

		containerPort, proto, _ := strings.Cut(rest, "/")
		lastColon := strings.LastIndex(bind, ":")
		if lastColon == -1 {
			continue
		}
		hostPort := bind[lastColon+1:]

		k := key{hostPort, containerPort, proto}
		if seen[k] {
			continue
		}
		seen[k] = true

		link := portLink{Text: hostPort + ":" + containerPort + "/" + proto}
		if address != "" {
			link.URL = "http://" + address + ":" + hostPort
		}
		out = append(out, link)
	}
	return out
}

// stackContainerRow is what the stack detail page shows — a narrower,
// stack-scoped view than the fleet-wide Container above, with ports
// already resolved to clickable links where possible.
type stackContainerRow struct {
	ID, Name, ServiceName, Image, State, Status string
	Ports                                       []portLink
}

func stackContainerRows(a *app, stackID string) ([]stackContainerRow, error) {
	rows, err := a.store.ListHostContainersByStack(stackID)
	if err != nil {
		return nil, err
	}

	hostAddr := map[string]string{} // memoized per host, a stack usually has all its services on one host
	out := make([]stackContainerRow, 0, len(rows))
	for _, c := range rows {
		addr, ok := hostAddr[c.HostID]
		if !ok {
			if h, err := a.store.GetHost(c.HostID); err == nil {
				addr = h.Address
			}
			hostAddr[c.HostID] = addr
		}
		out = append(out, stackContainerRow{
			ID:          c.ContainerID,
			Name:        c.Name,
			ServiceName: c.ServiceName,
			Image:       c.Image,
			State:       c.State,
			Status:      c.Status,
			Ports:       parsePorts(c.Ports, addr),
		})
	}
	return out, nil
}
