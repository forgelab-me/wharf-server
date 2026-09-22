// wharf-server — see ARCHITECTURE.md. Stacks, containers, images,
// volumes, networks, the dashboard, and the volume file browser are all
// backed by real data (SQLite + the secrets service + the agent tunnel,
// cf. containers.go/images.go/volumes.go/networks.go/volumebrowse.go/
// tunnel.go/dashboardHandler) — nothing left mocked.

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
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
	dataDir     string          // cf. backup.go -- where wharf.db/keys.db/identity actually live
	notifyState *notifyState    // cf. notifications.go -- "already notified" tracking, level-triggered events
}

type Stat struct {
	Label, Value, Hint string
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

var slugRe = regexp.MustCompile(`[^a-z0-9-]+`)

// slugify turns a display name into an id -- shared by stacks.go and
// git_connections.go, neither of which owns it more than the other.
func slugify(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = strings.ReplaceAll(s, " ", "-")
	s = slugRe.ReplaceAllString(s, "")
	return strings.Trim(s, "-")
}

// randomHex returns n random bytes, hex-encoded. Used for the webhook
// secret — not a secrets-service credential (cf. ARCHITECTURE.md, this
// chunk's plan), so a plain random token in the main store is enough.
// Also reused for the OIDC state/nonce (oidc.go) and tunnel command
// request ids (tunnel.go).
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
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

func main() {
	log.Println("wharf-server", version)
	dataDir := os.Getenv("WHARF_DATA_DIR")
	if dataDir == "" {
		dataDir = "/data"
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		log.Fatal("data dir: ", err)
	}

	// Applied before anything below opens a database or binds the TLS
	// identity into a listener -- neither can be safely swapped out from
	// under an open connection or a live HTTPS server, so a restore (cf.
	// backup.go's restoreBackupHandler) only ever stages files here and
	// waits for the next process start to actually move them into place.
	if err := applyPendingRestore(dataDir); err != nil {
		log.Fatal("restore: ", err)
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

	a := &app{store: st, keys: kc, fingerprint: fingerprint, tunnels: newTunnelRegistry(), polls: newPollRegistry(), dataDir: dataDir, notifyState: newNotifyState()}

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
	if err := registerNotificationChecks(a); err != nil {
		log.Fatal("register notification checks: ", err)
	}
	if err := registerAuditRetention(a); err != nil {
		log.Fatal("register audit retention: ", err)
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
	mux.HandleFunc("POST /containers/{id}/remove", a.removeContainerHandler)
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
	mux.HandleFunc("GET /settings/backup", requireAdmin(a.settingsBackupHandler))
	mux.HandleFunc("POST /settings/backup/download", requireAdmin(a.downloadBackupHandler))
	mux.HandleFunc("POST /settings/backup/restore", requireAdmin(a.restoreBackupHandler))
	mux.HandleFunc("GET /settings/notifications", requireAdmin(a.settingsNotificationsHandler))
	mux.HandleFunc("POST /settings/notifications", requireAdmin(a.setNotificationTargetHandler))
	mux.HandleFunc("POST /settings/notifications/delete", requireAdmin(a.deleteNotificationTargetHandler))
	mux.HandleFunc("POST /settings/notifications/test", requireAdmin(a.testNotificationHandler))
	mux.HandleFunc("GET /users", requireAdmin(a.usersHandler))
	mux.HandleFunc("GET /users/new", requireAdmin(a.newUserFormHandler))
	mux.HandleFunc("POST /users", requireAdmin(a.createUserHandler))
	mux.HandleFunc("POST /users/{username}/role", requireAdmin(a.setUserRoleHandler))
	mux.HandleFunc("POST /users/{username}/reset-password", requireAdmin(a.resetUserPasswordHandler))
	mux.HandleFunc("POST /users/{username}/delete", requireAdmin(a.deleteUserHandler))
	mux.HandleFunc("GET /audit-log", requireAdmin(a.auditLogHandler))
	mux.HandleFunc("POST /audit-log/retention", requireAdmin(a.setAuditRetentionHandler))

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
