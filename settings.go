// Authentication settings: single sign-on (OIDC) configuration, plus the
// optional AD/LDAP-group-to-Wharf-role mapping that rides along with it
// (cf. ARCHITECTURE.md, "Connexion OIDC (SSO)" and its "Rôles depuis les
// groupes AD" addendum). Lives at /settings/authentication, a sibling of
// /settings/registries under the "Settings" nav section rather than a
// single combined /settings page — the two configure unrelated things
// and were only ever on one page because there was nothing else to
// split them from yet.
package main

import (
	"net/http"
	"strings"
)

func (a *app) settingsAuthenticationHandler(w http.ResponseWriter, r *http.Request) {
	oidcCfg, oidcConfigured, err := a.keys.GetOIDCConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Title":           "Authentication",
		"Nav":             "authentication",
		"OIDC":            oidcCfg,
		"OIDCConfigured":  oidcConfigured,
		"OIDCRedirectURL": oidcRedirectURL(r),
	}
	render(w, r, "layout", "settings_authentication.html", data)
}

// setOIDCConfigHandler serves POST /settings/oidc. Every field except
// the secret is now pre-filled by the form when replacing an existing
// config (cf. settings_authentication.html), and the secret itself is
// optional on a replace -- leaving it blank keeps whatever's already
// stored instead of forcing it to be pasted in again on every edit
// (found to be real friction: changing just the admin group meant
// digging the client secret back out of the provider's own console
// each time). Still required the first time a provider is configured,
// since there's nothing existing to fall back to yet.
func (a *app) setOIDCConfigHandler(w http.ResponseWriter, r *http.Request) {
	// A trailing slash here is a real, easy-to-hit footgun: go-oidc's
	// discovery compares this string byte-for-byte against the "issuer"
	// field the provider's own /.well-known/openid-configuration
	// document reports, which providers (Authelia included) never
	// publish with a trailing slash -- confirmed against a real Authelia
	// instance returning exactly this mismatch. Trimmed here rather than
	// documented as a gotcha for the admin to remember.
	issuerURL := strings.TrimSuffix(strings.TrimSpace(r.FormValue("issuer_url")), "/")
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	clientSecret := r.FormValue("client_secret")
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	adminGroup := strings.TrimSpace(r.FormValue("admin_group"))
	operatorGroup := strings.TrimSpace(r.FormValue("operator_group"))
	disableLocalAuth := r.FormValue("disable_local_auth") != ""
	if issuerURL == "" || clientID == "" {
		http.Error(w, "issuer URL and client ID are required", http.StatusBadRequest)
		return
	}
	if clientSecret == "" {
		existing, ok, err := a.keys.GetOIDCConfig()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "client secret is required to configure SSO for the first time", http.StatusBadRequest)
			return
		}
		clientSecret = existing.ClientSecret
	}
	if err := a.keys.SetOIDCConfig(issuerURL, clientID, clientSecret, displayName, adminGroup, operatorGroup, disableLocalAuth); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redirectWithSaved(w, r, "/settings/authentication")
}

// deleteOIDCConfigHandler serves POST /settings/oidc/delete. Accounts
// already provisioned via this provider (oidc_subject/oidc_issuer on
// their row) are untouched -- they simply lose their SSO login method
// until/unless a provider is configured again, unless an admin already
// gave them a fallback local password via /users' "Set local password"
// action (cf. users.go's resetUserPasswordHandler, which works on an
// OIDC account exactly like a local one -- there's no separate flow for
// it, the existing admin reset just happens to double as one).
func (a *app) deleteOIDCConfigHandler(w http.ResponseWriter, r *http.Request) {
	if err := a.keys.DeleteOIDCConfig(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redirectWithSavedMessage(w, r, "/settings/authentication", "SSO configuration removed")
}
