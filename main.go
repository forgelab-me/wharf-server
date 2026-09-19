// wharf-server — cf. ARCHITECTURE.md. Les stacks, containers, images,
// volumes, réseaux et le dashboard sont désormais réels (SQLite +
// secrets-service + tunnel agent, cf. containers.go/images.go/volumes.go/
// networks.go/tunnel.go/dashboardHandler). Seule la navigation dans un
// volume (bouton "Browse") reste mockée — nécessite un container helper
// éphémère, hors scope ici.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/forgelab-me/wharf-server/internal/identity"
	"github.com/forgelab-me/wharf-server/internal/keys"
	"github.com/forgelab-me/wharf-server/internal/store"
	"github.com/robfig/cron/v3"
)

//go:embed web/templates/*.html
var templatesFS embed.FS

//go:embed web/static/*
var staticFS embed.FS

// version is overridden at build time via
// -ldflags "-X main.version=$VERSION" (cf. Dockerfile) -- CI sets it from
// the git tag on a release build, a branch+sha otherwise. "dev" is what
// anyone building straight from source without that flag actually sees,
// which is the honest answer rather than a fake-looking placeholder.
var version = "dev"

type app struct {
	store       *store.Store
	keys        *keys.Custodian
	fingerprint string // empreinte de l'identité auto-signée du contrôleur
	cron        *cron.Cron
	tunnels     *tunnelRegistry // connexions agent live, cf. tunnel.go
	polls       *pollRegistry   // cron.EntryID par stack en polling, cf. poller.go
}

type Stat struct {
	Label, Value, Hint string
}

// stackRow is the stacks-list view model — deployment history doesn't
// exist yet (no agent), so status/sha are always the "never deployed"
// placeholder for now.
type stackRow struct {
	ID, Name, Host, Trigger, LastStatusClass, LastStatusLabel, LastSha string
}

type EnvVar struct {
	Key, Value, Source string
	Secret             bool
}

func render(w http.ResponseWriter, r *http.Request, layoutTmpl, page string, data any) {
	// Username/Role aren't threaded through every handler's own data map --
	// injected here instead, from the session middleware's context (cf.
	// auth.go), so the topbar's chip and any {{if eq .Role "admin"}} guard
	// in a template work everywhere without touching each handler that
	// builds a map[string]any.
	if m, ok := data.(map[string]any); ok {
		if _, exists := m["Username"]; !exists {
			m["Username"] = usernameFromContext(r.Context())
		}
		if _, exists := m["Role"]; !exists {
			m["Role"] = roleFromContext(r.Context())
		}
		// Same auto-injection for a one-shot error banner (cf.
		// redirectWithError) -- a handler that refuses an action (e.g.
		// deleteStackHandler on a still-deployed stack) redirects back to
		// the page the user was already on with ?error=..., instead of
		// http.Error's bare text response replacing the whole UI. Only
		// ever read from the query string, never stored -- a reload drops
		// it, same as it would never having been there.
		if _, exists := m["Error"]; !exists {
			m["Error"] = r.URL.Query().Get("error")
		}
		// Same one-shot idea as Error, for a save that succeeded but
		// whose result isn't otherwise obvious on the reloaded page (cf.
		// redirectWithSaved) -- rendered as a toast rather than a banner,
		// since it's good news, not something the user needs to act on.
		if _, exists := m["Saved"]; !exists {
			m["Saved"] = r.URL.Query().Get("saved") != ""
		}
		// SavedMessage lets a redirect say what actually happened (cf.
		// redirectWithSavedMessage, used by restart/stop -- a bare
		// "Saved" reads wrong for an action, and by the time the
		// redirect lands the container has already finished restarting,
		// so the toast is the only sign it happened at all) instead of
		// the generic "Saved" every other redirectWithSaved call site
		// is fine with.
		if _, exists := m["SavedMessage"]; !exists {
			m["SavedMessage"] = "Saved"
			if msg := r.URL.Query().Get("saved_msg"); msg != "" {
				m["SavedMessage"] = msg
			}
		}
		// CSRFToken lets every "<form method=post>" carry a hidden
		// csrf_token field without each handler building one itself --
		// requireAuth checks it against the same session cookie on the
		// way back in (cf. auth.go). Empty before login (no session
		// cookie yet to derive it from), which is fine: /login isn't
		// behind requireAuth, so nothing ever checks it there.
		if _, exists := m["CSRFToken"]; !exists {
			m["CSRFToken"] = ""
			if cookie, err := r.Cookie(sessionCookieName); err == nil {
				m["CSRFToken"] = csrfTokenFor(cookie.Value)
			}
		}
		if _, exists := m["Version"]; !exists {
			m["Version"] = version
		}
		// Same auto-injection as Version, for the "update available"
		// badge next to it (cf. versioncheck.go) -- every page gets it
		// since the sidebar footer is shared layout, not per-page.
		if _, exists := m["LatestServerVersion"]; !exists {
			latestServer, _ := latest.get()
			m["LatestServerVersion"] = latestServer
			m["ServerUpdateAvailable"] = latestServer != "" && semverLess(version, latestServer)
		}
	}
	tmpl, err := template.ParseFS(templatesFS, "web/templates/layout.html", "web/templates/"+page)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Rendered into a buffer first: a mid-template error must not reach the
	// client as a silently truncated page.
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, layoutTmpl, data); err != nil {
		log.Println("render error:", err)
		http.Error(w, "render error (preview): "+err.Error(), http.StatusInternalServerError)
		return
	}
	buf.WriteTo(w)
}

// appendQuery joins a query fragment ("k=v" or "k1=v1&k2=v2") onto path
// with "?" or "&" as appropriate -- several redirect targets in this
// codebase already carry their own query string (a volume browser's
// backTo's "?path=...", a bulk delete's "?refreshing=1"), and a second
// bare "?" there doesn't start a new parameter, it gets appended onto
// the *value* of whatever came before it (found precisely this way:
// redirectWithError against a volumebrowse.go backTo was producing
// ".../browse?path=foo?error=bar", one query value instead of two
// params -- both the error message and the path navigation broke).
func appendQuery(path, query string) string {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + query
}

// redirectWithError sends the user back to path with message shown as a
// banner on arrival (cf. render's Error auto-injection) instead of
// http.Error's bare-text response replacing the whole page -- for a
// refused action the user can act on right there (e.g. "undeploy this
// stack before deleting it," where the undeploy button is one click
// away on the very page this redirects back to), not an actual server
// failure.
func redirectWithError(w http.ResponseWriter, r *http.Request, path, message string) {
	http.Redirect(w, r, appendQuery(path, "error="+url.QueryEscape(message)), http.StatusSeeOther)
}

// redirectWithSaved is redirectWithError's success counterpart, for a
// save whose result isn't otherwise obvious from the reloaded page (an
// address, a name, a schedule, a credential -- as opposed to e.g.
// deploying a stack, which already gets its own status badge and
// toast). render's Saved auto-injection turns the query flag into a
// one-shot showToast('Saved', 'success') on arrival, same one-reload
// lifetime as Error.
func redirectWithSaved(w http.ResponseWriter, r *http.Request, path string) {
	http.Redirect(w, r, appendQuery(path, "saved=1"), http.StatusSeeOther)
}

// redirectWithSavedMessage is redirectWithSaved with a specific toast
// instead of the generic "Saved" -- for a redirect where "Saved" would
// be the wrong word (nothing was saved, an action ran) but the same
// one-shot "this succeeded" feedback is still needed.
func redirectWithSavedMessage(w http.ResponseWriter, r *http.Request, path, message string) {
	http.Redirect(w, r, appendSavedMessage(path, message), http.StatusSeeOther)
}

// appendSavedMessage is redirectWithSavedMessage's query-building half,
// exposed directly for a caller whose redirect target already carries
// its own query string.
func appendSavedMessage(path, message string) string {
	return appendQuery(path, "saved=1&saved_msg="+url.QueryEscape(message))
}

// dashboardHandler was the last mocked page -- every stat and every row
// here now comes from the same store the rest of the app already reads
// (cf. ARCHITECTURE.md, "Le tableau de bord devient réel").
func (a *app) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	hosts, err := a.store.ListHosts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var connected, pending int
	for _, h := range hosts {
		if h.Status == "connected" {
			connected++
		} else {
			pending++
		}
	}
	hostsHint := ""
	if pending > 0 {
		hostsHint = fmt.Sprintf("%d pending approval", pending)
	}

	stacks, err := a.store.ListStacks()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	activeStacks := 0
	for _, s := range stacks {
		if dep, ok, err := a.store.LatestDeploymentForStack(s.ID); err == nil && ok {
			if dep.Action == "up" && dep.Status == "succeeded" {
				activeStacks++
			}
		}
	}

	deploys24h, err := a.store.CountDeploymentsSince24h()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	importedKeys, err := a.keys.CountImportedKeys()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	importedHint := ""
	if importedKeys > 0 {
		importedHint = "cleanup needed"
	}

	recent, err := a.store.ListRecentDeployments(10)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"Title": "Dashboard",
		"Nav":   "dashboard",
		"Stats": []Stat{
			{Label: "Connected hosts", Value: fmt.Sprintf("%d / %d", connected, len(hosts)), Hint: hostsHint},
			{Label: "Active stacks", Value: strconv.Itoa(activeStacks)},
			{Label: "Deployments (24h)", Value: strconv.Itoa(deploys24h)},
			{Label: "Imported keys not rotated", Value: strconv.Itoa(importedKeys), Hint: importedHint},
		},
		"Deployments": recent,
	}
	render(w, r, "layout", "dashboard.html", data)
}

// hostRow adds the version-check verdict to a store.Host for the
// template -- kept out of store.Host itself since "outdated" is a UI-only
// judgment against versioncheck.go's cache, not a fact persisted about
// the host.
type hostRow struct {
	store.Host
	AgentOutdated bool
}

func newHostRow(h store.Host, latestAgent string) hostRow {
	return hostRow{
		Host:          h,
		AgentOutdated: h.AgentVersion != "" && latestAgent != "" && semverLess(h.AgentVersion, latestAgent),
	}
}

// hostsHandler est réel depuis l'implémentation de l'enrôlement mTLS —
// cf. ARCHITECTURE.md, "Enrôlement d'un nouvel agent". Tout le reste de
// cette page (containers/images/... plus bas) reste mocké.
func (a *app) hostsHandler(w http.ResponseWriter, r *http.Request) {
	all, err := a.store.ListHosts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, latestAgent := latest.get()
	var pending, connected []hostRow
	for _, h := range all {
		row := newHostRow(h, latestAgent)
		if h.Status == "pending" {
			pending = append(pending, row)
		} else {
			connected = append(connected, row)
		}
	}

	// Best-effort : dérive l'adresse du canal agent (:8443) du Host de la
	// requête UI (:9443/:8080). Suffisant pour la commande docker run en
	// local ; un vrai déploiement voudra une adresse publique configurée
	// explicitement plutôt que devinée.
	host, _, splitErr := net.SplitHostPort(r.Host)
	if splitErr != nil {
		host = r.Host
	}
	controllerAddr := fmt.Sprintf("https://%s:8443", host)

	data := map[string]any{
		"Title":                 "Hosts",
		"Nav":                   "hosts",
		"Pending":               pending,
		"Connected":             connected,
		"ControllerFingerprint": a.fingerprint,
		"ControllerAddr":        controllerAddr,
		"LatestAgentVersion":    latestAgent,
	}
	render(w, r, "layout", "hosts.html", data)
}

// hostViewHandler serves GET /hosts/{id} -- the same overview fields
// already shown as a row on /hosts, plus a live CPU/mem/disk Resources
// panel (cf. stats.go) that only makes sense with room of its own, not
// crammed into the fleet-wide table.
func (a *app) hostViewHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	h, err := a.store.GetHost(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_, connected := a.tunnels.get(id)
	_, latestAgent := latest.get()
	data := map[string]any{
		"Title":              h.Name,
		"Nav":                "hosts",
		"Host":               newHostRow(h, latestAgent),
		"Connected":          connected,
		"LatestAgentVersion": latestAgent,
	}
	render(w, r, "layout", "host_view.html", data)
}

func (a *app) approveHostHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.store.ApproveHost(id, usernameFromContext(r.Context())); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redirectWithSavedMessage(w, r, "/hosts", "Agent approved")
}

// rejectHostHandler serves POST /hosts/{id}/reject — the "Reject"
// button was a disabled placeholder until now; wired straight to
// RejectPendingHost's own status='pending' guard rather than repeating
// that check here.
func (a *app) rejectHostHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.store.RejectPendingHost(id); err != nil {
		redirectWithError(w, r, "/hosts", "could not reject this host: "+err.Error())
		return
	}
	redirectWithSavedMessage(w, r, "/hosts", "Agent rejected")
}

// setHostAddressHandler serves POST /hosts/{id}/address — a reachable
// network address for the host, admin-set, used only to build clickable
// published-port links on the stack/containers pages. Separate from
// approval on purpose: approval stays a single click, the address can be
// set or changed any time afterward.
func (a *app) setHostAddressHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	address := strings.TrimSpace(r.FormValue("address"))
	if err := a.store.SetHostAddress(id, address); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redirectWithSaved(w, r, "/hosts")
}

// setHostNameHandler serves POST /hosts/{id}/name -- a host's name is
// purely a display label (cf. Store.SetHostName), so this is safe to
// change any time, unlike the id every foreign key actually references.
func (a *app) setHostNameHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		redirectWithError(w, r, "/hosts/"+id, "name can't be empty")
		return
	}
	if err := a.store.SetHostName(id, name); err != nil {
		redirectWithError(w, r, "/hosts/"+id, err.Error())
		return
	}
	redirectWithSaved(w, r, "/hosts/"+id)
}

type enrollRequest struct {
	Hostname string `json:"hostname"`
}

type enrollResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// callerFingerprint reads the certificate that actually backed this TLS
// connection — never a client-supplied field — and returns its
// fingerprint. Security fix vs. the initial enrollment chunk: that first
// pass trusted a `cert_pem` JSON field with no cryptographic link to the
// connection at all.
func callerFingerprint(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", fmt.Errorf("no client certificate presented")
	}
	return identity.Fingerprint(r.TLS.PeerCertificates[0].Raw), nil
}

// verifyCaller checks that the certificate backing this connection
// belongs to hostID — used by every :8443 handler after enrollment so an
// agent can only ever poll/report for itself.
func verifyCaller(r *http.Request, st *store.Store, hostID string) error {
	fp, err := callerFingerprint(r)
	if err != nil {
		return err
	}
	h, err := st.GetHost(hostID)
	if err != nil {
		return err
	}
	if h.CertFingerprint != fp {
		return fmt.Errorf("certificate does not match host %q", hostID)
	}
	return nil
}

// enrollCreateHandler serves POST /agent/enrollments on the agent channel
// (:8443) — never gated by an accepted client certificate since the agent
// has no accepted identity yet at this point. Cf. ARCHITECTURE.md,
// "connect-first, approve-later". The fingerprint comes from the TLS
// connection itself (see callerFingerprint), not from anything the client
// claims in the body.
func (a *app) enrollCreateHandler(w http.ResponseWriter, r *http.Request) {
	fp, err := callerFingerprint(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var req enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	hostname := strings.TrimSpace(req.Hostname)
	if hostname == "" {
		hostname = "agent"
	}

	h, created, err := a.store.UpsertHostByFingerprint(hostname, fp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if created {
		w.WriteHeader(http.StatusCreated)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	json.NewEncoder(w).Encode(enrollResponse{ID: h.ID, Status: h.Status})
}

// enrollStatusHandler serves GET /agent/enrollments/{id} — the agent calls
// this in a loop once enrolled; it doubles as a lightweight heartbeat
// (last_seen_at). 404 if the id is unknown (e.g. the database was reset),
// an explicit signal for the agent to re-enroll instead of polling
// forever; 403 if the caller's certificate doesn't match this host.
// enrollStatusHandler serves GET /agent/enrollments/{id}. Existence is
// checked before the certificate match: if the id itself is unknown
// (e.g. the controller's DB was reset or the host was removed), the
// agent needs a real 404 to trigger its own re-enrollment (cf.
// pollLoop's re-enroll-on-404 logic) — checking the cert first, as a
// prior version did, turned an unknown id into a 403 instead, and an
// agent stuck in that state could never self-heal. Neither id existence
// nor status is sensitive: both already appear in the plaintext
// docker-run snippet the UI hands out.
func (a *app) enrollStatusHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := a.store.GetHost(id); errors.Is(err, store.ErrNotFound) {
		http.Error(w, "unknown enrollment id", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := verifyCaller(r, a.store, id); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	h, err := a.store.TouchHost(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(enrollResponse{ID: h.ID, Status: h.Status})
}

// commandsHandler serves GET /agent/commands — the calling agent (verified
// by TLS client certificate) claims its next queued deployment, if any.
// Local stacks get their secrets decrypted right here, server-side (the
// controller already holds the ciphertext from creation); Git stacks get
// a deploy key and clone parameters instead — the agent discovers and
// relays secrets.enc.yaml itself via /agent/decrypt after cloning.
func (a *app) commandsHandler(w http.ResponseWriter, r *http.Request) {
	fp, err := callerFingerprint(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	host, err := a.store.GetHostByFingerprint(fp)
	if err != nil {
		http.Error(w, "unknown caller", http.StatusForbidden)
		return
	}

	dep, ok, err := a.store.ClaimNextDeployment(host.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	st, err := a.store.GetStack(dep.StackID)
	if err != nil {
		_ = a.store.CompleteDeployment(dep.ID, "failed", "stack no longer exists: "+err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := struct {
		DeploymentID   string                       `json:"deployment_id"`
		StackID        string                       `json:"stack_id"`
		SourceType     string                       `json:"source_type"`
		Action         string                       `json:"action"`
		ComposeContent string                       `json:"compose_content,omitempty"`
		Env            map[string]string            `json:"env,omitempty"`
		RepoURL        string                       `json:"repo_url,omitempty"`
		Branch         string                       `json:"branch,omitempty"`
		ComposePath    string                       `json:"compose_path,omitempty"`
		AuthKind       string                       `json:"auth_kind,omitempty"`
		SSHPrivateKey  string                       `json:"ssh_private_key,omitempty"`
		HTTPUsername   string                       `json:"http_username,omitempty"`
		HTTPPassword   string                       `json:"http_password,omitempty"`
		RegistryAuths  map[string]keys.RegistryAuth `json:"registry_auths,omitempty"`
	}{
		DeploymentID: dep.ID,
		StackID:      st.ID,
		SourceType:   st.SourceType,
		Action:       dep.Action,
	}

	// Every configured registry credential rides along on every deploy
	// that isn't a teardown -- not just the ones a compose file happens
	// to reference. For a local stack Wharf could in principle parse
	// resp.ComposeContent and filter, but a Git stack's compose isn't
	// known here at all (the agent hasn't cloned yet, cf. the RepoURL
	// branch above) -- there's no way to filter precisely for one source
	// type without the other silently getting everything anyway, so
	// both get everything, same as a real Docker host's persistent
	// `~/.docker/config.json` logins aren't scoped per compose file
	// either.
	if dep.Action != "down" {
		auths, err := a.keys.AllRegistryCredentials()
		if err != nil {
			_ = a.store.CompleteDeployment(dep.ID, "failed", "could not load registry credentials: "+err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(auths) > 0 {
			resp.RegistryAuths = auths
		}
	}

	if st.SourceType == "git" {
		resp.RepoURL = st.Repo
		resp.Branch = st.Branch
		resp.ComposePath = st.ComposePath

		// Teardown never clones -- no credential fetched or sent, so a
		// revoked deploy key/connection never blocks an undeploy. cf. the
		// plan for this chunk.
		if dep.Action != "down" {
			authKind, sshPriv, httpUser, httpPass, err := a.resolveGitAuth(st)
			if err != nil {
				_ = a.store.CompleteDeployment(dep.ID, "failed", "could not load git credential: "+err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			resp.AuthKind = authKind
			resp.SSHPrivateKey = sshPriv
			resp.HTTPUsername = httpUser
			resp.HTTPPassword = httpPass
		}
	} else {
		// Local stack: sent even for a "down" (cheap, and covers the case
		// where the on-disk copy was somehow lost) but never re-decrypted
		// -- teardown doesn't need secret values.
		resp.ComposeContent = st.ComposeContent
		if dep.Action != "down" {
			env := map[string]string{}
			if len(st.EncryptedSecret) > 0 {
				plaintext, err := a.keys.Decrypt(st.ID, st.EncryptedSecret)
				if err != nil {
					_ = a.store.CompleteDeployment(dep.ID, "failed", "could not decrypt secrets: "+err.Error())
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				env = parseEnvLines(string(plaintext))
			}
			resp.Env = env
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// resolveGitAuth resolves the actual credential to hand the agent for a
// Git stack: a shared connection if the stack references one, otherwise
// the stack's own dedicated SSH key (the only path that existed before
// shared connections — unchanged for every stack created before this).
func (a *app) resolveGitAuth(st store.Stack) (authKind, sshPrivateKey, httpUsername, httpPassword string, err error) {
	if st.GitConnectionID == "" {
		priv, err := a.keys.SSHPrivateKey(st.ID)
		if err != nil {
			return "", "", "", "", err
		}
		return "ssh_key", priv, "", "", nil
	}

	conn, err := a.store.GetGitConnection(st.GitConnectionID)
	if err != nil {
		return "", "", "", "", fmt.Errorf("load git connection: %w", err)
	}

	switch conn.AuthKind {
	case "http_password":
		user, pass, err := a.keys.ConnectionHTTPCredential(conn.ID)
		if err != nil {
			return "", "", "", "", err
		}
		return "http_password", "", user, pass, nil
	default:
		priv, err := a.keys.ConnectionSSHPrivateKey(conn.ID)
		if err != nil {
			return "", "", "", "", err
		}
		return "ssh_key", priv, "", "", nil
	}
}

// parseEnvLines parses "KEY=value" lines (blank lines and #-comments
// skipped) as produced by decrypting a stack's secrets — shared between
// the local-stack path here and the Git path in the agent itself.
func parseEnvLines(s string) map[string]string {
	env := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			env[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return env
}

// deploymentResultHandler serves POST /agent/deployments/{id}/result.
func (a *app) deploymentResultHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	dep, err := a.store.GetDeployment(id)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "unknown deployment id", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := verifyCaller(r, a.store, dep.HostID); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	var req struct {
		Status         string `json:"status"`
		Output         string `json:"output"`
		ComposeContent string `json:"compose_content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := a.store.CompleteDeployment(id, req.Status, req.Output); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Fire-and-forget: image policy discovery/digest resync is bookkeeping
	// for the auto-update feature, not part of the deployment itself — a
	// registry hiccup here must never make an already-succeeded deployment
	// look like it failed to the agent waiting on this response.
	if req.Status == "succeeded" && req.ComposeContent != "" {
		go syncImagePolicies(a, dep.StackID, req.ComposeContent)

		// Refreshed on every successful deploy so a compose edit that adds
		// or removes a ${...} reference is reflected the very next time
		// this stack's container detail page renders -- cf. containers.go's
		// buildEnvVars, the only reader of SubstitutedEnvKeys.
		if keys, err := substitutedEnvKeys(req.ComposeContent); err == nil {
			if err := a.store.SetSubstitutedEnvKeys(dep.StackID, keys); err != nil {
				log.Println("deployment result:", dep.StackID, "set substituted env keys:", err)
			}
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// decryptHandler serves POST /agent/decrypt — the DecryptRequest/
// DecryptResponse round trip from ARCHITECTURE.md, used by Git-sourced
// deployments where the agent discovers secrets.enc.yaml itself after
// cloning (a local stack's secrets are decrypted proactively by
// commandsHandler instead, since the controller already holds the
// ciphertext there).
//
// Scoped by deployment_id, not a bare stack_id: the caller is verified
// against the deployment's own host_id, the same anchor used by
// deploymentResultHandler and the claim in commandsHandler. A bare
// stack_id would let any enrolled agent request decryption for any
// stack regardless of which host it's actually assigned to.
func (a *app) decryptHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeploymentID     string `json:"deployment_id"`
		CiphertextBase64 string `json:"ciphertext_base64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	dep, err := a.store.GetDeployment(req.DeploymentID)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "unknown deployment id", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := verifyCaller(r, a.store, dep.HostID); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	ciphertext, err := base64.StdEncoding.DecodeString(req.CiphertextBase64)
	if err != nil {
		http.Error(w, "invalid base64 ciphertext: "+err.Error(), http.StatusBadRequest)
		return
	}

	plaintext, err := a.keys.Decrypt(dep.StackID, ciphertext)
	if err != nil {
		http.Error(w, "decrypt failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		PlaintextBase64 string `json:"plaintext_base64"`
	}{PlaintextBase64: base64.StdEncoding.EncodeToString(plaintext)})
}

func (a *app) stacksHandler(w http.ResponseWriter, r *http.Request) {
	stacks, err := a.store.ListStacks()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows := make([]stackRow, 0, len(stacks))
	for _, s := range stacks {
		row := stackRow{
			ID: s.ID, Name: s.Name, Host: a.hostLabel(s.Host), Trigger: s.Trigger,
			LastStatusClass: "never", LastStatusLabel: "never deployed", LastSha: "—",
		}
		if dep, ok, err := a.store.LatestDeploymentForStack(s.ID); err == nil && ok {
			row.LastStatusClass = dep.Status
			row.LastStatusLabel = dep.Status
		}
		// Only ever populated for a polling-mode stack -- the last commit
		// its own poll loop saw (cf. poller.go's RecordPoll), not
		// necessarily what's actually running if a deploy since then
		// failed. Manual/webhook-triggered git stacks have no commit
		// tracked anywhere yet (the agent never reports one back), so
		// they correctly stay "—" rather than showing something stale or
		// guessed.
		if s.LastPolledSHA != "" {
			row.LastSha = shortDigest(s.LastPolledSHA)
		}
		rows = append(rows, row)
	}
	data := map[string]any{
		"Title":  "Stacks",
		"Nav":    "stacks",
		"Stacks": rows,
	}
	render(w, r, "layout", "stacks.html", data)
}

// hostLabel resolves a stored host id to its display name, falling back
// to the id itself (e.g. for the handful of demo stacks created before
// real host targeting existed).
func (a *app) hostLabel(hostID string) string {
	if hostID == "" {
		return "—"
	}
	h, err := a.store.GetHost(hostID)
	if err != nil {
		return hostID
	}
	return h.Name
}

func (a *app) gitConnectionsHandler(w http.ResponseWriter, r *http.Request) {
	connections, err := a.store.ListGitConnections()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Title":       "Git connections",
		"Nav":         "git-connections",
		"Connections": connections,
	}
	render(w, r, "layout", "git_connections.html", data)
}

func (a *app) gitConnectionViewHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	conn, err := a.store.GetGitConnection(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := map[string]any{
		"Title":      conn.Name,
		"Nav":        "git-connections",
		"Connection": conn,
	}
	if conn.AuthKind == "ssh_key" {
		pub, err := a.keys.ConnectionSSHPublicKey(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		data["PublicKey"] = pub
	} else {
		// Username isn't secret (unlike the password, never re-fetched
		// here) -- shown so the "replace credential" form can pre-fill it
		// instead of asking the user to remember and retype it.
		username, _, err := a.keys.ConnectionHTTPCredential(id)
		if err == nil {
			data["HTTPUsername"] = username
		}
	}
	inUse, err := a.store.GitConnectionInUse(id)
	if err == nil {
		data["InUse"] = inUse
	}
	render(w, r, "layout", "git_connection_view.html", data)
}

// regenerateGitConnectionKeyHandler serves POST
// /git-connections/{id}/regenerate-key -- the fix for a key that was
// generated in the wrong format (cf. ARCHITECTURE.md: Azure DevOps
// rejects the ed25519 keys Wharf used to generate) or is suspected
// compromised. Always regenerates fresh (RSA-4096, cf.
// GenerateConnectionSSHKeypair) rather than restoring an import -- a
// connection that started as an imported key becomes a generated one
// after this, same as if it were being set up for the first time. The
// old public key stops working the instant this returns; every Git
// host that had it as a Deploy Key needs the new one pasted in too,
// which is why this redirects back to the page that displays it rather
// than anywhere else.
func (a *app) regenerateGitConnectionKeyHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	conn, err := a.store.GetGitConnection(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if conn.AuthKind != "ssh_key" {
		http.Error(w, "this connection does not use an SSH key", http.StatusBadRequest)
		return
	}
	if _, err := a.keys.GenerateConnectionSSHKeypair(id); err != nil {
		http.Error(w, "could not regenerate key: "+err.Error(), http.StatusInternalServerError)
		return
	}
	redirectWithSavedMessage(w, r, "/git-connections/"+id, "SSH key regenerated")
}

// renameGitConnectionHandler serves POST /git-connections/{id}/rename.
func (a *app) renameGitConnectionHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		redirectWithError(w, r, "/git-connections/"+id, "name can't be empty")
		return
	}
	if err := a.store.RenameGitConnection(id, name); err != nil {
		redirectWithError(w, r, "/git-connections/"+id, err.Error())
		return
	}
	redirectWithSaved(w, r, "/git-connections/"+id)
}

// updateGitConnectionCredentialHandler serves POST
// /git-connections/{id}/credential -- replaces an http_password
// connection's username/password. Blank password keeps the existing
// one, same "re-typing the username shouldn't force re-typing an
// unchanged secret" pattern as the registry credential edit form.
func (a *app) updateGitConnectionCredentialHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	conn, err := a.store.GetGitConnection(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if conn.AuthKind != "http_password" {
		redirectWithError(w, r, "/git-connections/"+id, "this connection does not use a username/password credential")
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if username == "" {
		redirectWithError(w, r, "/git-connections/"+id, "username can't be empty")
		return
	}
	if password == "" {
		_, existing, err := a.keys.ConnectionHTTPCredential(id)
		if err != nil {
			redirectWithError(w, r, "/git-connections/"+id, "could not load the existing credential: "+err.Error())
			return
		}
		password = existing
	}
	if err := a.keys.ImportConnectionHTTPCredential(id, username, password); err != nil {
		redirectWithError(w, r, "/git-connections/"+id, "could not store credential: "+err.Error())
		return
	}
	redirectWithSaved(w, r, "/git-connections/"+id)
}

// deleteGitConnectionHandler serves POST /git-connections/{id}/delete --
// guarded by GitConnectionInUse the same way deleteStackHandler guards
// against deleting a still-deployed stack, so a connection several
// stacks share can't be pulled out from under them by mistake.
func (a *app) deleteGitConnectionHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := a.store.GetGitConnection(id); err != nil {
		http.NotFound(w, r)
		return
	}
	inUse, err := a.store.GitConnectionInUse(id)
	if err != nil {
		redirectWithError(w, r, "/git-connections/"+id, err.Error())
		return
	}
	if inUse {
		redirectWithError(w, r, "/git-connections/"+id, "one or more stacks still use this connection — repoint them first")
		return
	}
	if err := a.keys.DeleteConnectionKeys(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.store.DeleteGitConnection(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redirectWithSavedMessage(w, r, "/git-connections", "Git connection deleted")
}

func (a *app) newGitConnectionFormHandler(w http.ResponseWriter, r *http.Request) {
	render(w, r, "layout", "git_connection_form.html", map[string]any{
		"Title": "New Git connection",
		"Nav":   "git-connections",
	})
}

// createGitConnectionHandler covers all three credential-creation paths
// for a shared connection: generate an SSH key, import an existing SSH
// key, or import an HTTP username/password. Cf. ARCHITECTURE.md,
// "Séparation des rôles" — meant to be admin-only, but there is no real
// session/auth system yet to actually enforce that; stated here rather
// than pretended.
func (a *app) createGitConnectionHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	id := slugify(name)
	if id == "" {
		http.Error(w, "missing or invalid connection name", http.StatusBadRequest)
		return
	}

	authKind := r.FormValue("auth_kind")
	if authKind != "http_password" {
		authKind = "ssh_key"
	}

	if err := a.store.CreateGitConnection(id, name, authKind); err != nil {
		http.Error(w, "could not create connection (name already taken?): "+err.Error(), http.StatusConflict)
		return
	}

	switch authKind {
	case "http_password":
		username := r.FormValue("username")
		password := r.FormValue("password")
		if username == "" || password == "" {
			http.Error(w, "username and password are required", http.StatusBadRequest)
			return
		}
		if err := a.keys.ImportConnectionHTTPCredential(id, username, password); err != nil {
			http.Error(w, "could not store credential: "+err.Error(), http.StatusInternalServerError)
			return
		}
	default:
		if r.FormValue("key_source") == "import" {
			if _, err := a.keys.ImportConnectionSSHKey(id, r.FormValue("private_key")); err != nil {
				http.Error(w, "could not import key: "+err.Error(), http.StatusBadRequest)
				return
			}
		} else if _, err := a.keys.GenerateConnectionSSHKeypair(id); err != nil {
			http.Error(w, "could not generate key: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	http.Redirect(w, r, "/git-connections/"+id, http.StatusSeeOther)
}

func (a *app) newStackFormHandler(w http.ResponseWriter, r *http.Request) {
	all, err := a.store.ListHosts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var connected []store.Host
	for _, h := range all {
		if h.Status == "connected" {
			connected = append(connected, h)
		}
	}
	connections, err := a.store.ListGitConnections()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Title":       "New stack",
		"Nav":         "stacks",
		"Hosts":       connected,
		"Connections": connections,
	}
	render(w, r, "layout", "stack_form.html", data)
}

// editStackFormHandler serves GET /stacks/{id}/edit — local stacks only.
// A Git stack's compose file lives in its repo; editing it through the
// UI would undermine the whole point of GitOps for that stack, so this
// form doesn't offer that path at all.
func (a *app) editStackFormHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, err := a.store.GetStack(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if st.SourceType != "local" {
		http.Error(w, "only local stacks can be edited here — a Git stack's compose file lives in its repo", http.StatusBadRequest)
		return
	}
	data := map[string]any{
		"Title": "Edit " + st.Name,
		"Nav":   "stacks",
		"Stack": st,
	}
	render(w, r, "layout", "stack_edit.html", data)
}

// updateStackHandler serves POST /stacks/{id}/edit. Only ever changes
// compose_content — not secrets, not trigger, not host — keeping this
// chunk to exactly what was asked for. The prior content is always
// recorded as a revision first, even if the new content turns out to be
// identical, so "how many times has this been edited" stays honest.
func (a *app) updateStackHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, err := a.store.GetStack(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if st.SourceType != "local" {
		http.Error(w, "only local stacks can be edited here", http.StatusBadRequest)
		return
	}
	newContent := r.FormValue("compose_content")

	if err := a.store.RecordStackRevision(id, st.ComposeContent); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.store.UpdateStackCompose(id, newContent); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redirectWithSavedMessage(w, r, "/stacks/"+id, "Compose file saved")
}

// updateStackSecretHandler serves POST /stacks/{id}/secrets — local
// stacks only, same scoping reason as compose editing. Two distinct
// actions on purpose, not one form that treats blank-and-submit as
// "clear everything": the textarea is never pre-filled with existing
// values (cf. "aucun endpoint ne renvoie jamais la valeur d'un secret
// après stockage", ARCHITECTURE.md), so a blank submit is far more
// likely an accidental click than a deliberate wipe. action=clear is
// the only way to actually remove all secrets; action=save with an
// empty textarea is rejected instead of silently doing that.
func (a *app) updateStackSecretHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, err := a.store.GetStack(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if st.SourceType != "local" {
		http.Error(w, "only local stacks can have secrets managed here", http.StatusBadRequest)
		return
	}

	if r.FormValue("action") == "clear" {
		if err := a.store.UpdateStackSecret(id, nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		redirectWithSaved(w, r, "/stacks/"+id)
		return
	}

	secrets := r.FormValue("secrets")
	if strings.TrimSpace(secrets) == "" {
		http.Error(w, "no secrets entered — use \"Remove all secrets\" if that's what you meant", http.StatusBadRequest)
		return
	}
	ciphertext, err := a.keys.Encrypt(id, []byte(secrets))
	if err != nil {
		http.Error(w, "could not encrypt secrets: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.store.UpdateStackSecret(id, ciphertext); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redirectWithSaved(w, r, "/stacks/"+id)
}

// restoreStackRevisionHandler serves POST
// /stacks/{id}/revisions/{revisionID}/restore. Restoring is itself
// undoable: the current content is recorded as a new revision before
// being overwritten, so restoring never destroys anything, it just adds
// to the history.
func (a *app) restoreStackRevisionHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	revID, err := strconv.ParseInt(r.PathValue("revisionID"), 10, 64)
	if err != nil {
		http.Error(w, "invalid revision id", http.StatusBadRequest)
		return
	}
	st, err := a.store.GetStack(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if st.SourceType != "local" {
		http.Error(w, "only local stacks have revision history", http.StatusBadRequest)
		return
	}
	rev, err := a.store.GetStackRevision(id, revID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if err := a.store.RecordStackRevision(id, st.ComposeContent); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.store.UpdateStackCompose(id, rev.ComposeContent); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redirectWithSavedMessage(w, r, "/stacks/"+id, "Revision restored")
}

var slugRe = regexp.MustCompile(`[^a-z0-9-]+`)

func slugify(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = strings.ReplaceAll(s, " ", "-")
	s = slugRe.ReplaceAllString(s, "")
	return strings.Trim(s, "-")
}

// randomHex returns n random bytes, hex-encoded. Used for the webhook
// secret — not a secrets-service credential (cf. ARCHITECTURE.md, this
// chunk's plan), so a plain random token in the main store is enough.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (a *app) createStackHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	id := slugify(name)
	if id == "" {
		http.Error(w, "missing or invalid stack name", http.StatusBadRequest)
		return
	}

	sourceType := r.FormValue("source")
	if sourceType != "local" {
		sourceType = "git" // default/fallback
	}

	trigger := r.FormValue("trigger")
	if trigger != "webhook" && trigger != "polling" {
		trigger = "manual"
	}

	var pollSchedule string
	if trigger == "polling" {
		pollSchedule = strings.TrimSpace(r.FormValue("poll_schedule"))
		if _, err := cronParser.Parse(pollSchedule); err != nil {
			http.Error(w, "invalid cron schedule: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	st := store.Stack{
		ID:           id,
		Name:         name,
		SourceType:   sourceType,
		Host:         r.FormValue("host"),
		Trigger:      trigger,
		ComposePath:  r.FormValue("compose_path"),
		Repo:         r.FormValue("repo"),
		Branch:       r.FormValue("branch"),
		PollSchedule: pollSchedule,
	}

	if sourceType == "git" {
		secret, err := randomHex(32)
		if err != nil {
			http.Error(w, "could not generate webhook secret: "+err.Error(), http.StatusInternalServerError)
			return
		}
		st.WebhookSecret = secret
	}

	if sourceType == "local" {
		st.ComposeContent = r.FormValue("compose_content")
	}

	pub, err := a.keys.GenerateKeypair(id)
	if err != nil {
		http.Error(w, "could not generate key: "+err.Error(), http.StatusInternalServerError)
		return
	}
	st.PublicKey = pub

	if sourceType == "local" {
		if secrets := r.FormValue("secrets"); secrets != "" {
			ciphertext, err := a.keys.Encrypt(id, []byte(secrets))
			if err != nil {
				http.Error(w, "could not encrypt secrets: "+err.Error(), http.StatusInternalServerError)
				return
			}
			st.EncryptedSecret = ciphertext
			// Le clair (variable `secrets`) n'est jamais écrit nulle part
			// à partir d'ici — seul `ciphertext` rejoint le store.
		}
	} else if connID := r.FormValue("git_connection_id"); connID != "" {
		if _, err := a.store.GetGitConnection(connID); err != nil {
			http.Error(w, "unknown git connection: "+err.Error(), http.StatusBadRequest)
			return
		}
		st.GitConnectionID = connID
	} else {
		sshPub, err := a.keys.GenerateSSHKeypair(id)
		if err != nil {
			http.Error(w, "could not generate deploy key: "+err.Error(), http.StatusInternalServerError)
			return
		}
		st.SSHPublicKey = sshPub
	}

	if err := a.store.CreateStack(st); err != nil {
		http.Error(w, "could not create stack (name already taken?): "+err.Error(), http.StatusConflict)
		return
	}

	if trigger == "polling" {
		// Live immediately, no controller restart needed — AddFunc is
		// safe to call on an already-running scheduler.
		if err := registerPolling(a, st); err != nil {
			log.Println("register polling for new stack", st.ID, "failed:", err)
		}
	}

	http.Redirect(w, r, "/stacks/"+id, http.StatusSeeOther)
}

func (a *app) stackViewHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, err := a.store.GetStack(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := map[string]any{
		"Title":     st.Name,
		"Nav":       "stacks",
		"Stack":     st,
		"HostLabel": a.hostLabel(st.Host),
	}
	if dep, ok, err := a.store.LatestDeploymentForStack(id); err == nil && ok {
		data["Deployment"] = dep
	}
	if rows, err := imagePolicyViewRows(a, id); err == nil {
		data["ImagePolicies"] = rows
	}
	if rows, err := stackContainerRows(a, id); err == nil {
		data["Containers"] = rows
	}
	if st.SourceType == "git" && st.GitConnectionID != "" {
		// A stack on a shared connection never has its own SSHPublicKey
		// (cf. createStackHandler) -- the template shows the connection's
		// own key instead of an always-empty stack-specific one.
		if conn, err := a.store.GetGitConnection(st.GitConnectionID); err == nil {
			data["GitConnection"] = conn
			if conn.AuthKind == "ssh_key" {
				if pub, err := a.keys.ConnectionSSHPublicKey(conn.ID); err == nil {
					data["ConnectionPublicKey"] = pub
				}
			}
		}
	}
	if st.SourceType == "local" {
		if revs, err := a.store.ListStackRevisions(id); err == nil {
			data["Revisions"] = revs
		}
		// Key names only, never values -- same stackSecrets used to mask
		// env vars by value on the container detail page
		// (server/containers.go). maskAll is meaningless for a local
		// stack (only ever true for git stacks), so it's discarded here.
		if secrets, _ := stackSecrets(a, id); len(secrets) > 0 {
			names := make([]string, 0, len(secrets))
			for k := range secrets {
				names = append(names, k)
			}
			sort.Strings(names)
			data["SecretKeys"] = names
		}
	}
	if st.Trigger == "webhook" {
		// Same derivation heuristic as hostsHandler's agent-channel
		// address: best-effort from the request's own Host, pointed at
		// :9443 since a real internet-facing webhook needs HTTPS.
		host, _, splitErr := net.SplitHostPort(r.Host)
		if splitErr != nil {
			host = r.Host
		}
		data["WebhookURL"] = fmt.Sprintf("https://%s:9443/hooks/%s", host, st.ID)
	}
	render(w, r, "layout", "stack_view.html", data)
}

// deploymentStatusHandler serves GET /stacks/{id}/deployment-status --
// a tiny JSON poll target for the stack page's own script, so it can
// notice a deploy/undeploy finishing (queued/running -> succeeded/
// failed) without the user having to reload the page themselves to
// find out. Not meant for anything but that one script; no auth
// concerns beyond the same session check every other UI route already
// gets from requireAuth.
func (a *app) deploymentStatusHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dep, ok, err := a.store.LatestDeploymentForStack(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if !ok {
		json.NewEncoder(w).Encode(struct {
			Status string `json:"status"`
		}{Status: ""})
		return
	}
	json.NewEncoder(w).Encode(struct {
		Status string `json:"status"`
		Action string `json:"action"`
	}{Status: dep.Status, Action: dep.Action})
}

// setPollScheduleHandler serves POST /stacks/{id}/poll-schedule -- there
// was no way to change a polling-mode stack's cron expression after
// creation until now. Validated with the same parser createStackHandler
// already uses, then re-registered on the live scheduler immediately
// (registerPolling replaces the stack's existing cron entry rather than
// adding a second one, cf. poller.go) -- no controller restart needed,
// same as a brand new polling stack.
func (a *app) setPollScheduleHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, err := a.store.GetStack(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if st.Trigger != "polling" {
		http.Error(w, "this stack is not in polling mode", http.StatusBadRequest)
		return
	}
	schedule := strings.TrimSpace(r.FormValue("poll_schedule"))
	if _, err := cronParser.Parse(schedule); err != nil {
		http.Error(w, "invalid cron schedule: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := a.store.SetPollSchedule(id, schedule); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	st.PollSchedule = schedule
	if err := registerPolling(a, st); err != nil {
		http.Error(w, "schedule saved but could not be applied: "+err.Error(), http.StatusInternalServerError)
		return
	}
	redirectWithSaved(w, r, "/stacks/"+id)
}

// setStackTriggerHandler serves POST /stacks/{id}/trigger -- there was no
// way to change a stack's trigger mode after creation until now, only
// its schedule/secret once already in that mode (cf. setPollScheduleHandler
// above, hooksHandler below). Git stacks only: manual/webhook/polling all
// key off having a repository to check or receive a hook for, which a
// local stack doesn't have (cf. createStackHandler's own webhook-secret
// generation, git-only for the same reason).
func (a *app) setStackTriggerHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, err := a.store.GetStack(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if st.SourceType != "git" {
		redirectWithError(w, r, "/stacks/"+id, "only Git stacks can use a webhook or polling trigger")
		return
	}
	trigger := r.FormValue("trigger")
	if trigger != "manual" && trigger != "webhook" && trigger != "polling" {
		redirectWithError(w, r, "/stacks/"+id, "invalid trigger")
		return
	}

	// Preserve whatever this stack already had -- toggling back to a mode
	// it was in before (e.g. webhook -> manual -> webhook) shouldn't force
	// re-pasting a new secret into the Git host, or re-picking a schedule
	// that was already fine. Only generate/default when there's nothing
	// to preserve.
	pollSchedule := st.PollSchedule
	webhookSecret := st.WebhookSecret
	switch trigger {
	case "polling":
		if pollSchedule == "" {
			pollSchedule = "*/15 * * * *" // same cadence as the image-poller; edit right after via the schedule form below
		}
	case "webhook":
		if webhookSecret == "" {
			secret, err := randomHex(32)
			if err != nil {
				http.Error(w, "could not generate webhook secret: "+err.Error(), http.StatusInternalServerError)
				return
			}
			webhookSecret = secret
		}
	}

	if err := a.store.UpdateStackTrigger(id, trigger, pollSchedule, webhookSecret); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if trigger == "polling" {
		st.Trigger, st.PollSchedule = trigger, pollSchedule
		if err := registerPolling(a, st); err != nil {
			http.Error(w, "trigger saved but could not be scheduled: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		unregisterPolling(a, id)
	}
	redirectWithSaved(w, r, "/stacks/"+id)
}

// renameStackHandler serves POST /stacks/{id}/rename.
func (a *app) renameStackHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		redirectWithError(w, r, "/stacks/"+id, "name can't be empty")
		return
	}
	if err := a.store.RenameStack(id, name); err != nil {
		redirectWithError(w, r, "/stacks/"+id, err.Error())
		return
	}
	redirectWithSaved(w, r, "/stacks/"+id)
}

// forcePollHandler serves POST /stacks/{id}/poll-now -- runs the exact
// same check the cron schedule would (pollStack), synchronously, so an
// admin doesn't have to wait for or fiddle with the schedule just to see
// "did it move?" right now. Enqueues a deploy exactly like a real
// scheduled tick would if the remote HEAD moved since the last check --
// this is not a preview/dry-run, it's the real poll running early.
func (a *app) forcePollHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, err := a.store.GetStack(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if st.Trigger != "polling" {
		http.Error(w, "this stack is not in polling mode", http.StatusBadRequest)
		return
	}
	pollStack(a, id)
	redirectWithSavedMessage(w, r, "/stacks/"+id, "Poll triggered")
}

// hooksHandler serves POST /hooks/{id} — the webhook receiver, on the UI
// ports rather than the agent mTLS channel: the caller is GitHub/GitLab's
// own servers, not an enrolled agent, so authentication is a shared
// secret rather than a pinned client certificate. Accepts whichever of
// three schemes the caller sends: GitHub's HMAC-SHA256 signature,
// GitLab's plain token header, or a generic shared-secret header for
// anything else. Cf. ARCHITECTURE.md, "Déclenchement du déploiement".
func (a *app) hooksHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, err := a.store.GetStack(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if st.Trigger != "webhook" || st.WebhookSecret == "" {
		http.Error(w, "webhook not enabled for this stack", http.StatusNotFound)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "could not read body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if !verifyWebhookAuth(r, body, st.WebhookSecret) {
		http.Error(w, "invalid or missing signature", http.StatusUnauthorized)
		return
	}

	if st.Host == "" {
		http.Error(w, "this stack has no target host assigned", http.StatusBadRequest)
		return
	}
	if _, err := a.store.EnqueueDeployment(st.ID, st.Host, "webhook", "up"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// verifyWebhookAuth checks whichever of the three provider schemes is
// present against secret, blind to which provider actually sent the
// request. Blind trigger: the payload itself is never parsed — a stack
// has exactly one configured branch, so any authenticated call just
// re-enqueues that stack's deploy (cf. the plan for this chunk).
func verifyWebhookAuth(r *http.Request, body []byte, secret string) bool {
	if sig := r.Header.Get("X-Hub-Signature-256"); sig != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		return subtle.ConstantTimeCompare([]byte(sig), []byte(want)) == 1
	}
	if tok := r.Header.Get("X-Gitlab-Token"); tok != "" {
		return subtle.ConstantTimeCompare([]byte(tok), []byte(secret)) == 1
	}
	if tok := r.Header.Get("X-Webhook-Secret"); tok != "" {
		return subtle.ConstantTimeCompare([]byte(tok), []byte(secret)) == 1
	}
	return false
}

// deployStackHandler serves POST /stacks/{id}/deploy — the "Deploy now"
// button.
func (a *app) deployStackHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, err := a.store.GetStack(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if st.Host == "" {
		http.Error(w, "this stack has no target host assigned", http.StatusBadRequest)
		return
	}
	if _, err := a.store.EnqueueDeployment(st.ID, st.Host, "manual", "up"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redirectWithSavedMessage(w, r, "/stacks/"+id, "Deployment queued")
}

// undeployStackHandler serves POST /stacks/{id}/undeploy — the "Undeploy"
// button. Reuses the same command channel as deploy (action="down"
// instead of "up"); the agent tears down whatever is already on disk
// from the last deploy rather than re-cloning, so a revoked Git
// credential never blocks tearing a stack down. Cf. the plan for this
// chunk in ARCHITECTURE.md's history.
func (a *app) undeployStackHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, err := a.store.GetStack(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if st.Host == "" {
		redirectWithError(w, r, "/stacks/"+id, "this stack has no target host assigned")
		return
	}
	if _, err := a.store.EnqueueDeployment(st.ID, st.Host, "manual", "down"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redirectWithSavedMessage(w, r, "/stacks/"+id, "Undeploy queued")
}

// deleteStackHandler serves POST /stacks/{id}/delete. Refuses to delete
// a stack whose latest known deployment looks like it might still be
// running (action "up", status "succeeded") — Undeploy first is the
// required path, rather than this handler trying to orchestrate an
// implicit async teardown-then-delete. Also refuses while a deployment
// is merely queued/running, whatever its action: DeleteStack cascades
// into the deployments table, and deleting a just-enqueued "down" before
// the agent ever claims it would silently wipe the only record of that
// teardown, orphaning a running container with no stack left to undeploy
// it from (caught by testing — Undeploy then an immediate Delete raced
// the agent's own poll tick). A stack that was never successfully
// deployed (failed, or already undeployed) deletes clean.
func (a *app) deleteStackHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := a.store.GetStack(id); err != nil {
		http.NotFound(w, r)
		return
	}
	if dep, ok, err := a.store.LatestDeploymentForStack(id); err == nil && ok {
		switch {
		case dep.Status == "queued" || dep.Status == "running":
			redirectWithError(w, r, "/stacks/"+id, "a deployment is in progress for this stack — wait for it to finish before deleting")
			return
		case dep.Action == "up" && dep.Status == "succeeded":
			redirectWithError(w, r, "/stacks/"+id, "undeploy this stack before deleting it")
			return
		}
	}
	if err := a.keys.DeleteStackKeys(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.store.DeleteStack(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redirectWithSavedMessage(w, r, "/stacks", "Stack deleted")
}

// containersHandler and containerDetailHandler moved to containers.go —
// they read real data (host_containers, populated by the agent tunnel)
// instead of mockContainers(), cf. ARCHITECTURE.md.

// imagesHandler moved to images.go — reads real data (host_images,
// populated by the agent tunnel) instead of a hard-coded list.

// volumesHandler moved to volumes.go — reads real data (host_volumes,
// populated by the agent tunnel) instead of a hard-coded list.

// networksHandler moved to networks.go — reads real data (host_networks,
// populated by the agent tunnel) instead of a hard-coded list.

func main() {
	log.Println("wharf-server", version)
	dataDir := os.Getenv("WHARF_DATA_DIR")
	if dataDir == "" {
		dataDir = "/data"
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		log.Fatal("data dir: ", err)
	}

	// Deux fichiers SQLite distincts : le store applicatif et le store du
	// secrets-service ne partagent ni process logique ni accès — cf.
	// ARCHITECTURE.md, "Garde des clés".
	st, err := store.Open(filepath.Join(dataDir, "wharf.db"))
	if err != nil {
		log.Fatal("store: ", err)
	}
	defer st.Close()

	// Local auth bootstrap: no signup flow, so the first admin account
	// (cf. auth.go, users.go) comes from env vars read at startup rather
	// than a first-run "create your account" page -- that would mean a
	// real unauthenticated window on every fresh deploy, however brief.
	// Required, fail-closed: there is no sane default password.
	// EnsureFirstUser only ever uses these to create that first row --
	// once any user exists (including one migrated from the pre-multi-
	// user admin_user singleton), an ordinary redeploy with the same .env
	// must not silently revert a password since changed via the UI (cf.
	// its own comment in internal/store/store.go for the bug this
	// replaced). Every account after the first is created from /users,
	// not from an env var.
	adminUser := os.Getenv("WHARF_ADMIN_USER")
	adminPassword := os.Getenv("WHARF_ADMIN_PASSWORD")
	if adminUser == "" || adminPassword == "" {
		log.Fatal("WHARF_ADMIN_USER and WHARF_ADMIN_PASSWORD must both be set")
	}
	if err := st.EnsureFirstUser(adminUser, adminPassword); err != nil {
		log.Fatal("admin user: ", err)
	}

	kc, err := keys.Open(filepath.Join(dataDir, "keys.db"))
	if err != nil {
		log.Fatal("keys: ", err)
	}
	defer kc.Close()

	// Identité TLS auto-signée du contrôleur lui-même — doit survivre aux
	// recréations du container (sous /data, déjà un volume monté), sinon
	// chaque redéploiement changerait le fingerprint et casserait
	// l'épinglage déjà approuvé côté agents. Cf. ARCHITECTURE.md.
	cert, err := identity.LoadOrGenerate(filepath.Join(dataDir, "identity"))
	if err != nil {
		log.Fatal("identity: ", err)
	}
	fingerprint := identity.Fingerprint(cert.Certificate[0])
	log.Println("controller identity:", fingerprint)

	a := &app{store: st, keys: kc, fingerprint: fingerprint, tunnels: newTunnelRegistry(), polls: newPollRegistry()}

	// Same 5-field parser used to validate a schedule at stack-creation
	// time (cronParser in poller.go) — registration must never accept a
	// spec its own validation already approved.
	a.cron = cron.New(cron.WithParser(cronParser))
	existingStacks, err := st.ListStacks()
	if err != nil {
		log.Fatal("list stacks for polling registration: ", err)
	}
	for _, s := range existingStacks {
		if s.Trigger != "polling" || s.PollSchedule == "" {
			continue
		}
		if err := registerPolling(a, s); err != nil {
			log.Println("register polling for stack", s.ID, "failed:", err)
		}
	}
	if err := registerImagePolling(a); err != nil {
		log.Fatal("register image polling: ", err)
	}
	if err := registerVersionChecking(a); err != nil {
		log.Fatal("register version checking: ", err)
	}
	a.cron.Start()
	defer a.cron.Stop()

	staticRoot, err := fs.Sub(staticFS, "web/static")
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticRoot))))
	mux.HandleFunc("GET /login", a.loginFormHandler)
	mux.HandleFunc("POST /login", a.loginHandler)
	mux.HandleFunc("GET /auth/oidc/login", a.oidcLoginHandler)
	mux.HandleFunc("GET /auth/oidc/callback", a.oidcCallbackHandler)
	mux.HandleFunc("POST /logout", a.logoutHandler)
	mux.HandleFunc("GET /change-password", a.changePasswordFormHandler)
	mux.HandleFunc("POST /change-password", a.changePasswordHandler)
	mux.HandleFunc("GET /{$}", a.dashboardHandler)
	mux.HandleFunc("GET /hosts", a.hostsHandler)
	mux.HandleFunc("GET /hosts/{id}", a.hostViewHandler)
	mux.HandleFunc("GET /hosts/{id}/stats", a.hostStatsHandler)
	mux.HandleFunc("POST /hosts/{id}/approve", a.approveHostHandler)
	mux.HandleFunc("POST /hosts/{id}/reject", a.rejectHostHandler)
	mux.HandleFunc("POST /hosts/{id}/address", a.setHostAddressHandler)
	mux.HandleFunc("POST /hosts/{id}/name", a.setHostNameHandler)
	mux.HandleFunc("GET /git-connections", a.gitConnectionsHandler)
	mux.HandleFunc("GET /git-connections/new", requireAdmin(a.newGitConnectionFormHandler))
	mux.HandleFunc("POST /git-connections", requireAdmin(a.createGitConnectionHandler))
	mux.HandleFunc("GET /git-connections/{id}", a.gitConnectionViewHandler)
	mux.HandleFunc("POST /git-connections/{id}/regenerate-key", requireAdmin(a.regenerateGitConnectionKeyHandler))
	mux.HandleFunc("POST /git-connections/{id}/rename", requireAdmin(a.renameGitConnectionHandler))
	mux.HandleFunc("POST /git-connections/{id}/credential", requireAdmin(a.updateGitConnectionCredentialHandler))
	mux.HandleFunc("POST /git-connections/{id}/delete", requireAdmin(a.deleteGitConnectionHandler))
	mux.HandleFunc("GET /stacks", a.stacksHandler)
	mux.HandleFunc("GET /stacks/new", a.newStackFormHandler)
	mux.HandleFunc("POST /stacks", a.createStackHandler)
	mux.HandleFunc("GET /stacks/{id}", a.stackViewHandler)
	mux.HandleFunc("POST /hooks/{id}", a.hooksHandler)
	mux.HandleFunc("POST /stacks/{id}/deploy", a.deployStackHandler)
	mux.HandleFunc("POST /stacks/{id}/undeploy", a.undeployStackHandler)
	mux.HandleFunc("POST /stacks/{id}/delete", a.deleteStackHandler)
	mux.HandleFunc("GET /stacks/{id}/edit", a.editStackFormHandler)
	mux.HandleFunc("POST /stacks/{id}/edit", a.updateStackHandler)
	mux.HandleFunc("POST /stacks/{id}/revisions/{revisionID}/restore", a.restoreStackRevisionHandler)
	mux.HandleFunc("POST /stacks/{id}/secrets", a.updateStackSecretHandler)
	mux.HandleFunc("POST /stacks/{id}/images/{service}/policy", a.setImagePolicyHandler)
	mux.HandleFunc("POST /stacks/{id}/images/{service}/apply", a.applyImageUpdateHandler)
	mux.HandleFunc("POST /stacks/{id}/rename", a.renameStackHandler)
	mux.HandleFunc("POST /stacks/{id}/trigger", a.setStackTriggerHandler)
	mux.HandleFunc("POST /stacks/{id}/poll-schedule", a.setPollScheduleHandler)
	mux.HandleFunc("POST /stacks/{id}/poll-now", a.forcePollHandler)
	mux.HandleFunc("GET /stacks/{id}/deployment-status", a.deploymentStatusHandler)
	mux.HandleFunc("GET /containers", a.containersHandler)
	mux.HandleFunc("GET /containers/{id}", a.containerDetailHandler)
	mux.HandleFunc("GET /containers/{id}/logs", a.containerLogsPageHandler)
	mux.HandleFunc("GET /containers/{id}/logs/raw", a.containerLogsRawHandler)
	mux.HandleFunc("GET /containers/{id}/stats", a.containerStatsHandler)
	mux.HandleFunc("POST /containers/{id}/restart", a.restartContainerHandler)
	mux.HandleFunc("POST /containers/{id}/stop", a.stopContainerHandler)
	mux.HandleFunc("GET /images", a.imagesHandler)
	mux.HandleFunc("GET /images/{hostID}/{id}", a.imageDetailHandler)
	mux.HandleFunc("POST /images/delete", requireAdmin(a.deleteImagesHandler))
	mux.HandleFunc("GET /volumes", a.volumesHandler)
	mux.HandleFunc("GET /volumes/sizes", a.volumeSizesHandler)
	mux.HandleFunc("POST /volumes/delete", requireAdmin(a.deleteVolumesHandler))
	mux.HandleFunc("GET /volumes/{hostID}/{name}", a.volumeDetailHandler)
	mux.HandleFunc("GET /volumes/{hostID}/{name}/browse", requireAdmin(a.volumeBrowseHandler))
	mux.HandleFunc("POST /volumes/{hostID}/{name}/browse/rename", requireAdmin(a.volumeBrowseRenameHandler))
	mux.HandleFunc("POST /volumes/{hostID}/{name}/browse/delete", requireAdmin(a.volumeBrowseDeleteHandler))
	mux.HandleFunc("POST /volumes/{hostID}/{name}/browse/upload", requireAdmin(a.volumeBrowseUploadHandler))
	mux.HandleFunc("GET /volumes/{hostID}/{name}/browse/edit", requireAdmin(a.volumeBrowseEditHandler))
	mux.HandleFunc("POST /volumes/{hostID}/{name}/browse/edit", requireAdmin(a.volumeBrowseSaveHandler))
	mux.HandleFunc("GET /volumes/{hostID}/{name}/browse/download", requireAdmin(a.volumeBrowseDownloadHandler))
	mux.HandleFunc("GET /networks", a.networksHandler)
	mux.HandleFunc("GET /networks/{hostID}/{name}", a.networkDetailHandler)
	mux.HandleFunc("POST /networks/delete", requireAdmin(a.deleteNetworksHandler))
	mux.HandleFunc("GET /settings", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/settings/authentication", http.StatusMovedPermanently)
	})
	mux.HandleFunc("GET /settings/authentication", requireAdmin(a.settingsAuthenticationHandler))
	mux.HandleFunc("POST /settings/oidc", requireAdmin(a.setOIDCConfigHandler))
	mux.HandleFunc("POST /settings/oidc/delete", requireAdmin(a.deleteOIDCConfigHandler))
	mux.HandleFunc("GET /settings/registries", requireAdmin(a.settingsRegistriesHandler))
	mux.HandleFunc("POST /settings/registries", requireAdmin(a.setRegistryCredentialHandler))
	mux.HandleFunc("POST /settings/registries/{host}/delete", requireAdmin(a.deleteRegistryCredentialHandler))
	mux.HandleFunc("GET /users", requireAdmin(a.usersHandler))
	mux.HandleFunc("GET /users/new", requireAdmin(a.newUserFormHandler))
	mux.HandleFunc("POST /users", requireAdmin(a.createUserHandler))
	mux.HandleFunc("POST /users/{username}/role", requireAdmin(a.setUserRoleHandler))
	mux.HandleFunc("POST /users/{username}/reset-password", requireAdmin(a.resetUserPasswordHandler))
	mux.HandleFunc("POST /users/{username}/delete", requireAdmin(a.deleteUserHandler))

	// Canal agent, séparé de l'UI : enrôlement + commandes de déploiement.
	// HTTPS uniquement — l'épinglage par empreinte n'a de sens qu'avec TLS.
	agentMux := http.NewServeMux()
	agentMux.HandleFunc("POST /agent/enrollments", a.enrollCreateHandler)
	agentMux.HandleFunc("GET /agent/enrollments/{id}", a.enrollStatusHandler)
	agentMux.HandleFunc("GET /agent/commands", a.commandsHandler)
	agentMux.HandleFunc("POST /agent/deployments/{id}/result", a.deploymentResultHandler)
	agentMux.HandleFunc("POST /agent/decrypt", a.decryptHandler)
	agentMux.HandleFunc("GET /agent/tunnel", a.tunnelHandler)

	// RequestClientCert (not Require/RequireAndVerify): there is no CA to
	// verify against by design (cf. ARCHITECTURE.md, épinglage par
	// empreinte). We still want Go to capture whatever certificate the
	// agent presents into r.TLS.PeerCertificates so callerFingerprint/
	// verifyCaller can check it ourselves.
	agentTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequestClientCert,
	}
	uiTLSConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	// requireAuth wraps the whole UI mux once here, not per-route: every
	// UI route needs a session except the handful publicPath() names
	// (login, static assets, inbound webhooks) — cf. auth.go.
	protectedMux := a.requireAuth(mux)

	go func() {
		srv := &http.Server{Addr: ":8443", Handler: agentMux, TLSConfig: agentTLSConfig}
		log.Println("wharf-server (agents, HTTPS) on :8443")
		log.Fatal(srv.ListenAndServeTLS("", ""))
	}()

	go func() {
		srv := &http.Server{Addr: ":9443", Handler: protectedMux, TLSConfig: uiTLSConfig}
		log.Println("wharf-server (UI, HTTPS) on :9443")
		log.Fatal(srv.ListenAndServeTLS("", ""))
	}()

	// Plain UI also exposed, on a separate port: it's the operator's call
	// what to publish via `docker run -p` (Portainer's own model), not the
	// app's to force HTTPS. Cf. ARCHITECTURE.md.
	log.Println("wharf-server (UI, HTTP) on :8080 — data:", dataDir)
	log.Fatal(http.ListenAndServe(":8080", protectedMux))
}
