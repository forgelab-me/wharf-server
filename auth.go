// Local session-cookie authentication for the UI (ports :8080/:9443) —
// cf. ARCHITECTURE.md, "Authentification locale". The agent channel
// (:8443) is untouched: it authenticates by mTLS client-certificate
// fingerprint (cf. tunnel.go/main.go's enrollment handlers), a separate
// and already-real mechanism this package doesn't need to duplicate.
//
// Multi-user with two roles (admin/operator, cf. ARCHITECTURE.md,
// "Séparation des rôles") — role isn't cached in the session cookie,
// only ever looked up fresh per request via GetUserByUsername, so a
// role change or a forced password reset takes effect on the very next
// request, not after the session naturally expires. OIDC login is
// separate future work; this covers local accounts only.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/forgelab-me/wharf-server/internal/store"
)

const sessionCookieName = "wharf_session"

type ctxKey int

const (
	usernameCtxKey ctxKey = 0
	roleCtxKey     ctxKey = 1
)

func usernameFromContext(ctx context.Context) string {
	if u, ok := ctx.Value(usernameCtxKey).(string); ok {
		return u
	}
	return ""
}

func roleFromContext(ctx context.Context) string {
	if r, ok := ctx.Value(roleCtxKey).(string); ok {
		return r
	}
	return ""
}

func isAdmin(ctx context.Context) bool {
	return roleFromContext(ctx) == "admin"
}

// requireAdmin wraps a single handler (not the whole mux, unlike
// requireAuth) for the handful of routes only an admin may use — git
// connection management, registry credentials, user management (cf.
// ARCHITECTURE.md, "Séparation des rôles": the admin gates *managing* a
// shared credential, never the mere listing/use of one). Must run
// behind requireAuth, which is what actually populates the role in
// context — this middleware only ever reads it.
func requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isAdmin(r.Context()) {
			http.Error(w, "admin role required", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// publicPath reports whether a request path must stay reachable without a
// session: the login page itself (or the redirect loop never ends),
// static assets (the login page's own CSS), inbound Git-host webhooks
// (authenticated separately, by HMAC signature against the stack's own
// secret — cf. verifyWebhookAuth — a browser session is meaningless
// there since the caller is GitHub/GitLab, not an operator), and the
// OIDC login/callback pair (cf. oidc.go) — by definition reached by
// someone who doesn't have a Wharf session yet.
func publicPath(path string) bool {
	return path == "/login" || strings.HasPrefix(path, "/static/") || strings.HasPrefix(path, "/hooks/") ||
		path == "/auth/oidc/login" || path == "/auth/oidc/callback"
}

// requireAuth wraps the UI mux so every non-public route needs a live
// session. Failure always redirects to /login rather than returning 401:
// every current caller is a browser following a link or submitting an
// HTML form, never a fetch/XHR client that would need a JSON error.
func (a *app) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if publicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		username, ok, err := a.store.GetSessionUsername(cookie.Value)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			clearSessionCookie(w, r)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		user, err := a.store.GetUserByUsername(username)
		if err != nil {
			// Session outlived the account -- deleted mid-session (its own
			// sessions are wiped on delete, cf. store.DeleteUser, but a
			// cookie issued a moment earlier could still be in flight) or
			// similar. Treat exactly like an invalid session, not a 500.
			clearSessionCookie(w, r)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.URL.Path != "/change-password" && r.URL.Path != "/logout" && user.MustChangePassword {
			http.Redirect(w, r, "/change-password", http.StatusSeeOther)
			return
		}
		// CSRF check for every state-changing request except the one
		// multipart route (volume upload): r.ParseForm() only ever reads
		// an application/x-www-form-urlencoded body (bounded, and a
		// documented no-op against multipart/form-data — verified against
		// net/http directly rather than assumed), so it can't collide
		// with a handler's own later, size-capped ParseMultipartForm call.
		// The upload handler verifies its own token after that call
		// instead (cf. volumeBrowseUploadHandler).
		if r.Method == http.MethodPost && !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
			if err := r.ParseForm(); err != nil {
				redirectWithError(w, r, "/", "could not read form data")
				return
			}
			if !verifyCSRF(cookie.Value, r.PostForm.Get("csrf_token")) {
				// "/" (not r.Referer(), attacker-influenceable and would
				// make this an open redirect) -- always a safe, valid GET
				// destination regardless of which POST route failed.
				redirectWithError(w, r, "/", "Your session or this form is stale — please reload the page and try again.")
				return
			}
		}
		ctx := context.WithValue(r.Context(), usernameCtxKey, username)
		ctx = context.WithValue(ctx, roleCtxKey, user.Role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// csrfSecret is a fresh random key per process, not persisted anywhere.
// A token only ever needs to outlive one page render up to its own form
// submission (seconds to minutes), never a controller restart, so
// there's nothing to gain from storing it and every reason not to add a
// DB round trip to something checked on every single POST.
var csrfSecret = func() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("csrf: reading random secret: " + err.Error())
	}
	return b
}()

// csrfTokenFor derives a form token from the caller's own session
// cookie value via HMAC -- nothing to store, nothing to look up.
// Forging a valid token requires the session cookie's actual value,
// which is HttpOnly (unreadable by any script, same-site or not) and
// only ever transmitted to wharf itself, so a cross-site page can never
// compute the token needed to make its own forged form pass
// verifyCSRF, even though the browser would still attach the cookie
// itself to a same-site top-level GET under SameSite=Lax.
func csrfTokenFor(sessionValue string) string {
	mac := hmac.New(sha256.New, csrfSecret)
	mac.Write([]byte(sessionValue))
	return hex.EncodeToString(mac.Sum(nil))
}

func verifyCSRF(sessionValue, token string) bool {
	if token == "" {
		return false
	}
	want := csrfTokenFor(sessionValue)
	return subtle.ConstantTimeCompare([]byte(want), []byte(token)) == 1
}

// loginLimiter throttles repeated failed logins per username with
// escalating backoff -- bcrypt's own per-attempt cost already slows a
// single guess, but nothing previously stopped a script from just
// making many of them back to back. Keyed by username rather than by
// caller IP: the realistic threat here is guessing one specific known
// account's password, not a distributed spray, and a per-IP limiter is
// trivially defeated by rotating source addresses while a per-username
// one isn't. In-memory and per-process on purpose -- a restart clearing
// every lockout is an acceptable, even desirable, escape hatch for a
// self-hosted single-controller tool, not a gap worth a DB table over.
type loginLimiter struct {
	mu    sync.Mutex
	byKey map[string]*loginAttempts
}

type loginAttempts struct {
	failures    int
	lockedUntil time.Time
	lastSeen    time.Time
}

const (
	loginFreeAttempts  = 5
	loginLockoutBase   = 5 * time.Second
	loginLockoutCap    = 5 * time.Minute
	loginAttemptsStale = time.Hour
)

var globalLoginLimiter = &loginLimiter{byKey: map[string]*loginAttempts{}}

// check reports whether username is currently locked out, and if so for
// how much longer.
func (l *loginLimiter) check(username string) (locked bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a, ok := l.byKey[username]
	if !ok {
		return false, 0
	}
	if remaining := time.Until(a.lockedUntil); remaining > 0 {
		return true, remaining
	}
	return false, 0
}

// recordFailure counts one more failed attempt and, past
// loginFreeAttempts, locks the account for an exponentially growing
// duration (capped) -- a handful of typos never lock anyone out, but a
// sustained guessing script quickly slows to a few attempts per hour.
// Also sweeps entries nobody has touched in a while so the map can't
// grow without bound from an attacker trying many distinct usernames.
func (l *loginLimiter) recordFailure(username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for k, v := range l.byKey {
		if now.Sub(v.lastSeen) > loginAttemptsStale {
			delete(l.byKey, k)
		}
	}
	a, ok := l.byKey[username]
	if !ok {
		a = &loginAttempts{}
		l.byKey[username] = a
	}
	a.failures++
	a.lastSeen = now
	if a.failures > loginFreeAttempts {
		backoff := loginLockoutBase * time.Duration(1<<uint(a.failures-loginFreeAttempts-1))
		if backoff > loginLockoutCap {
			backoff = loginLockoutCap
		}
		a.lockedUntil = now.Add(backoff)
	}
}

// clear resets a username's failure count on successful login.
func (l *loginLimiter) clear(username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.byKey, username)
}

// setSessionCookie/clearSessionCookie share the Secure decision: Secure
// only when the request itself arrived over TLS, since :8080 plain HTTP
// is a deliberate, operator-chosen exposure (cf. ARCHITECTURE.md) and a
// Secure cookie set there would silently never come back.
func setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(store.SessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
}

// loginPageData adds SSO button info to the login page's own data map --
// shared by the initial GET and the POST failure re-render, both of
// which need it, rather than querying OIDC config twice.
func (a *app) loginPageData(extra map[string]any) map[string]any {
	data := map[string]any{"Title": "Sign in"}
	for k, v := range extra {
		data[k] = v
	}
	if cfg, ok, err := a.keys.GetOIDCConfig(); err == nil && ok {
		data["OIDCDisplayName"] = cfg.DisplayName
		data["LocalAuthDisabled"] = cfg.DisableLocalAuth
	}
	return data
}

func (a *app) loginFormHandler(w http.ResponseWriter, r *http.Request) {
	render(w, r, "auth_layout", "login.html", a.loginPageData(nil))
}

func (a *app) loginHandler(w http.ResponseWriter, r *http.Request) {
	// Enforced here too, not just by hiding the form (cf. login.html) --
	// a direct POST must not succeed just because the admin's own
	// browser still has the page cached from before this was turned on.
	if cfg, ok, err := a.keys.GetOIDCConfig(); err == nil && ok && cfg.DisableLocalAuth {
		render(w, r, "auth_layout", "login.html", a.loginPageData(map[string]any{
			"Error": "Local sign-in is disabled — use SSO.",
		}))
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	if locked, retryAfter := globalLoginLimiter.check(username); locked {
		render(w, r, "auth_layout", "login.html", a.loginPageData(map[string]any{
			"Error": fmt.Sprintf("Too many failed attempts. Try again in %s.", retryAfter.Round(time.Second)),
		}))
		return
	}

	ok, err := a.store.VerifyUserCredentials(username, password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		globalLoginLimiter.recordFailure(username)
		render(w, r, "auth_layout", "login.html", a.loginPageData(map[string]any{
			"Error": "Invalid username or password.",
		}))
		return
	}
	globalLoginLimiter.clear(username)
	if err := a.store.TouchUserLogin(username); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	token, err := a.store.CreateSession(username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	setSessionCookie(w, r, token)
	// Not a.audit(r, ...): this request is what *establishes* the session
	// -- there's no username in context yet for a.audit to read (that's
	// only ever set by requireAuth on a *later* request), so the
	// just-authenticated username is passed straight to RecordAudit.
	if err := a.store.RecordAudit(username, "auth.login", username, "local"); err != nil {
		log.Println("audit:", err)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *app) logoutHandler(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		// Looked up before deleting the session, same reason login can't
		// use a.audit -- /logout isn't behind requireAuth either, so
		// there's no username in context; the session row itself is the
		// only place to still get it from once the cookie is cleared.
		if username, ok, err := a.store.GetSessionUsername(cookie.Value); err == nil && ok {
			if err := a.store.RecordAudit(username, "auth.logout", username, ""); err != nil {
				log.Println("audit:", err)
			}
		}
		if err := a.store.DeleteSession(cookie.Value); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	clearSessionCookie(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// changePasswordFormHandler/changePasswordHandler serve the gate
// requireAuth redirects to while the logged-in user's own
// MustChangePassword is true (first login, or after an admin reset --
// cf. store.EnsureFirstUser/CreateUser/AdminResetUserPassword) -- also
// reachable any time afterward as a normal "change my password" action,
// since nothing about the form itself depends on the flag.
func (a *app) changePasswordFormHandler(w http.ResponseWriter, r *http.Request) {
	render(w, r, "auth_layout", "change_password.html", map[string]any{"Title": "Change password"})
}

func (a *app) changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	username := usernameFromContext(r.Context())
	current := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	fail := func(msg string) {
		render(w, r, "auth_layout", "change_password.html", map[string]any{
			"Title": "Change password",
			"Error": msg,
		})
	}

	ok, err := a.store.VerifyUserCredentials(username, current)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		fail("Current password is incorrect.")
		return
	}
	if len(newPassword) < 8 {
		fail("New password must be at least 8 characters.")
		return
	}
	if newPassword != confirm {
		fail("New password and confirmation don't match.")
		return
	}

	if err := a.store.SetUserPassword(username, newPassword); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
