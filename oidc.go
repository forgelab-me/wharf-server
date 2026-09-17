// OIDC login — a second way onto the same session system auth.go
// already builds, not a parallel one. Any standard-compliant provider
// works (verified against Authelia specifically, cf. ARCHITECTURE.md),
// since this only ever speaks the OIDC discovery + authorization code
// protocol, never anything provider-specific.
//
// New accounts provisioned on first login start as "operator" unless
// the optional AdminGroup setting matches one of the provider's groups
// claim, in which case they start (and, on every later login, stay
// synced to) "admin" — cf. oidcCallbackHandler's role resolution below.
// With neither AdminGroup nor OperatorGroup configured, nothing here
// ever touches a role or gates sign-in: an admin promotes/demotes
// deliberately via /users, and anyone who can authenticate against the
// provider gets an operator account, same as before either setting
// existed. Configuring EITHER group turns sign-in itself into an
// allowlist — cf. keys.OIDCConfig's doc comment.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/forgelab-me/wharf-server/internal/keys"
	"github.com/forgelab-me/wharf-server/internal/store"
)

const oidcStateCookieName = "wharf_oidc_state"

// oidcRedirectURL derives the callback URL Wharf will hand to the
// provider from the request that's actually hitting it -- the same
// derive-from-the-request pattern hostsHandler already uses for the
// agent enrollment command, rather than a second configured "base URL"
// setting that could drift from reality. The admin registers whatever
// this resolves to as the client's redirect URI on the provider's side.
func oidcRedirectURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host + "/auth/oidc/callback"
}

// oidcNewConfig builds the oauth2/OIDC client for the currently
// configured provider. Discovery (the provider's /.well-known/
// openid-configuration) runs fresh on every login rather than being
// cached -- login is not a hot path, and re-discovering avoids ever
// acting on a stale provider config after an admin changes it in
// /settings.
func oidcNewConfig(ctx context.Context, cfg keys.OIDCConfig, redirectURL string) (*oidc.Provider, *oauth2.Config, error) {
	// Trimmed again here, not just on save (cf. settings.go's
	// setOIDCConfigHandler) -- a config already stored with a trailing
	// slash before that fix existed would otherwise keep failing
	// discovery's exact issuer-string match forever, never self-healing
	// until an admin happened to re-save the form.
	issuerURL := strings.TrimSuffix(cfg.IssuerURL, "/")
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, nil, err
	}
	scopes := []string{oidc.ScopeOpenID, "profile", "email"}
	if cfg.AdminGroup != "" || cfg.OperatorGroup != "" {
		// Only requested when group-based role/access mapping is
		// actually configured — a provider whose client registration
		// hasn't been updated to permit this scope (cf.
		// settings_authentication.html's note on Authelia) would
		// otherwise reject or silently drop it, breaking a login that
		// worked fine before either setting existed.
		scopes = append(scopes, "groups")
	}
	oauthCfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}
	return provider, oauthCfg, nil
}

// oidcLoginHandler serves GET /auth/oidc/login -- the "Continue with
// {DisplayName}" button on /login. state and nonce are generated here
// and round-tripped through a short-lived cookie rather than server-side
// storage: this is a single redirect-and-back a browser completes
// within seconds, not something worth a database row and a cleanup job
// for.
func (a *app) oidcLoginHandler(w http.ResponseWriter, r *http.Request) {
	cfg, ok, err := a.keys.GetOIDCConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "SSO is not configured", http.StatusNotFound)
		return
	}

	_, oauthCfg, err := oidcNewConfig(r.Context(), cfg, oidcRedirectURL(r))
	if err != nil {
		http.Error(w, "could not reach identity provider: "+err.Error(), http.StatusBadGateway)
		return
	}

	state, err := randomHex(16)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	nonce, err := randomHex(16)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    state + "." + nonce,
		Path:     "/auth/oidc",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, oauthCfg.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusSeeOther)
}

// oidcCallbackHandler serves GET /auth/oidc/callback. state defends
// against CSRF (a forged callback the user never actually started);
// nonce, checked inside the ID token itself by go-oidc's Verifier,
// defends against a replayed token. Both are single-use: the cookie
// carrying them is cleared here regardless of outcome.
func (a *app) oidcCallbackHandler(w http.ResponseWriter, r *http.Request) {
	clearOIDCStateCookie(w, r)

	cfg, ok, err := a.keys.GetOIDCConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "SSO is not configured", http.StatusNotFound)
		return
	}

	stateCookie, err := r.Cookie(oidcStateCookieName)
	if err != nil {
		http.Error(w, "missing or expired SSO login attempt — please try again", http.StatusBadRequest)
		return
	}
	wantState, wantNonce, ok := strings.Cut(stateCookie.Value, ".")
	if !ok || wantState == "" || wantNonce == "" {
		http.Error(w, "invalid SSO login attempt — please try again", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("state") != wantState {
		http.Error(w, "SSO state mismatch — please try signing in again", http.StatusBadRequest)
		return
	}

	provider, oauthCfg, err := oidcNewConfig(r.Context(), cfg, oidcRedirectURL(r))
	if err != nil {
		http.Error(w, "could not reach identity provider: "+err.Error(), http.StatusBadGateway)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "identity provider did not return an authorization code", http.StatusBadRequest)
		return
	}
	token, err := oauthCfg.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		http.Error(w, "identity provider did not return an ID token", http.StatusBadGateway)
		return
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}).Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "ID token verification failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	if idToken.Nonce != wantNonce {
		http.Error(w, "ID token nonce mismatch — please try signing in again", http.StatusBadRequest)
		return
	}

	var claims struct {
		Subject           string   `json:"sub"`
		PreferredUsername string   `json:"preferred_username"`
		Email             string   `json:"email"`
		Groups            []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "could not read ID token claims: "+err.Error(), http.StatusBadGateway)
		return
	}

	// The ID token alone is often just {sub, iss, aud, exp, ...} with no
	// preferred_username/email at all -- confirmed against a real
	// Authelia instance while testing this, which puts both only in the
	// userinfo response despite the profile/email scopes being granted.
	// Per spec, userinfo's sub MUST match the ID token's; a mismatch here
	// would mean the provider handed back a different identity than the
	// one just verified, so it's treated as a hard failure, not a
	// fallback to ID-token-only data.
	userInfo, err := provider.UserInfo(r.Context(), oauth2.StaticTokenSource(token))
	if err == nil {
		if userInfo.Subject != claims.Subject {
			http.Error(w, "identity provider returned inconsistent subject between ID token and userinfo", http.StatusBadGateway)
			return
		}
		var uiClaims struct {
			PreferredUsername string   `json:"preferred_username"`
			Email             string   `json:"email"`
			Groups            []string `json:"groups"`
		}
		if err := userInfo.Claims(&uiClaims); err == nil {
			if uiClaims.PreferredUsername != "" {
				claims.PreferredUsername = uiClaims.PreferredUsername
			}
			if uiClaims.Email != "" {
				claims.Email = uiClaims.Email
			}
			if len(uiClaims.Groups) > 0 {
				claims.Groups = uiClaims.Groups
			}
		}
	}

	username := claims.PreferredUsername
	if username == "" {
		username = claims.Email
	}
	if username == "" {
		username = claims.Subject
	}

	// The group mapping is opt-in and live: with neither field set,
	// nothing here ever touches an account's role or blocks a sign-in,
	// exactly the original "always operator, promote manually, anyone
	// who authenticates gets in" behavior. Set either one, and every
	// sign-in (not just the first) resolves the role fresh from the
	// current groups claim -- losing AD group membership demotes (or,
	// per the gate below, locks out) on the very next login, the same
	// way it would revoke any other AD-backed access, rather than
	// leaving a stale grant from a past group membership.
	//
	// Gate, not just role hint: once an admin has bothered to name a
	// specific group at all, the reasonable reading is "only these
	// people should get in" -- not "these people get promoted, but
	// literally anyone else with an AD account still gets an operator
	// seat for free." So AdminGroup/OperatorGroup double as an
	// allowlist the moment either is non-empty; leaving both blank keeps
	// the door open, same as always.
	role := "operator"
	gated := cfg.AdminGroup != "" || cfg.OperatorGroup != ""
	allowed := !gated
	for _, g := range claims.Groups {
		if cfg.AdminGroup != "" && g == cfg.AdminGroup {
			role = "admin"
			allowed = true
		}
		if cfg.OperatorGroup != "" && g == cfg.OperatorGroup {
			allowed = true
		}
	}
	if !allowed {
		http.Error(w, "your account is not a member of a group authorized to sign in to Wharf", http.StatusForbidden)
		return
	}

	user, found, err := a.store.GetUserByOIDCSubject(cfg.IssuerURL, claims.Subject)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		// A username collision here would mean silently handing an SSO
		// login control of an unrelated existing account (local, or a
		// different provider's identity) just because a name happens to
		// match -- refused outright rather than guessed at.
		if _, err := a.store.GetUserByUsername(username); err == nil {
			http.Error(w, fmt.Sprintf("an account named %q already exists and isn't linked to this identity — ask an admin to resolve this before signing in with SSO", username), http.StatusConflict)
			return
		} else if !errors.Is(err, store.ErrNotFound) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := a.store.CreateOIDCUser(username, cfg.IssuerURL, claims.Subject, role); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		user.Username = username
	} else if gated && user.Role != role {
		// A demotion that would remove the last admin is refused by the
		// store itself (ErrLastAdmin) -- treated as a no-op here, not a
		// login failure: the account just keeps its current (admin) role
		// until a human resolves the situation via /users, same as the
		// manual path already behaves.
		if err := a.store.SetUserRole(user.Username, role); err != nil && !errors.Is(err, store.ErrLastAdmin) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if err := a.store.TouchUserLogin(user.Username); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session, err := a.store.CreateSession(user.Username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	setSessionCookie(w, r, session)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func clearOIDCStateCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    "",
		Path:     "/auth/oidc",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
}
