// Private registry credentials, at /settings/registries. Portainer-style:
// any number of named entries, each a host + username/password, with a
// "type" that's purely a display hint (which logo/label to show, and
// which placeholder host to suggest) -- resolution against an actual
// registry (cf. internal/registry's WWW-Authenticate discovery, and the
// docker-login-at-deploy-time path in main.go's commandsHandler) is
// always by host, never by type, so a "Custom" entry against a
// self-hosted Harbor works exactly like a "GitHub" entry against ghcr.io.
package main

import (
	"net/http"
	"strings"
)

// registryType is one entry in the settings page's "Registry type"
// dropdown -- purely cosmetic (an admin picking "GitHub" instead of
// "Custom" just gets a friendlier label and a filled-in host
// suggestion), never consulted by the credential-resolution or
// digest-check code paths.
type registryType struct {
	Value    string
	Label    string
	HostHint string // pre-filled into the host field when this type is picked; "" for Custom
}

var registryTypes = []registryType{
	{Value: "dockerhub", Label: "Docker Hub", HostHint: "docker.io"},
	{Value: "ghcr", Label: "GitHub Container Registry (GHCR)", HostHint: "ghcr.io"},
	{Value: "gitlab", Label: "GitLab Container Registry", HostHint: "registry.gitlab.com"},
	{Value: "acr", Label: "Azure Container Registry", HostHint: ""},
	{Value: "custom", Label: "Custom / self-hosted", HostHint: ""},
}

func registryTypeLabel(value string) string {
	for _, t := range registryTypes {
		if t.Value == value {
			return t.Label
		}
	}
	return value
}

func (a *app) settingsRegistriesHandler(w http.ResponseWriter, r *http.Request) {
	registries, err := a.keys.ListRegistries()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	type registryRow struct {
		Name, Host, Username, Type, TypeLabel string
	}
	rows := make([]registryRow, 0, len(registries))
	for _, reg := range registries {
		name := reg.Name
		if name == "" {
			name = reg.Host
		}
		rows = append(rows, registryRow{Name: name, Host: reg.Host, Username: reg.Username, Type: reg.Type, TypeLabel: registryTypeLabel(reg.Type)})
	}
	data := map[string]any{
		"Title":         "Registries",
		"Nav":           "registries",
		"Registries":    rows,
		"RegistryTypes": registryTypes,
	}
	render(w, r, "layout", "settings_registries.html", data)
}

// setRegistryCredentialHandler serves POST /settings/registries. Always
// an import, same as a Git connection's HTTP credential — Wharf has no
// way to mint a registry password/PAT itself, only the registry does.
// host is free text (unlike the old two-option dropdown): any host that
// speaks the Docker Registry v2 protocol works, cf.
// internal/registry.Digest's WWW-Authenticate discovery.
//
// password is optional when host already has a credential (the
// settings page's "Edit" action pre-fills name/type/username but never
// the password back, cf. settings_registries.html) -- blank keeps
// whatever's already stored instead of forcing it to be re-pasted just
// to rename an entry or fix a typo'd username. Still required the first
// time a host is configured.
func (a *app) setRegistryCredentialHandler(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	host := strings.TrimSpace(strings.ToLower(r.FormValue("host")))
	regType := r.FormValue("type")
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if host == "" || username == "" {
		http.Error(w, "host and username are required", http.StatusBadRequest)
		return
	}
	if password == "" {
		_, existingPassword, ok, err := a.keys.RegistryCredential(host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "password/token is required to add a new registry", http.StatusBadRequest)
			return
		}
		password = existingPassword
	}
	if name == "" {
		name = host
	}
	if err := a.keys.SetRegistryCredential(name, host, regType, username, password); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Never the password/token -- host/username are already how the
	// registry itself identifies this credential.
	a.audit(r, "registry.set", host, "username "+username)
	redirectWithSaved(w, r, "/settings/registries")
}

// deleteRegistryCredentialHandler serves POST
// /settings/registries/{host}/delete. Deleting a credential doesn't
// touch image_digest_cache -- the next poll simply goes back to
// anonymous access for that host, which fails cleanly (private repos
// 401/403) rather than serving a stale cached digest as if it were
// still being checked with authority. It also stops being sent to
// agents on future deploys.
func (a *app) deleteRegistryCredentialHandler(w http.ResponseWriter, r *http.Request) {
	host := r.PathValue("host")
	if err := a.keys.DeleteRegistryCredential(host); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.audit(r, "registry.delete", host, "")
	redirectWithSavedMessage(w, r, "/settings/registries", "Registry credential removed")
}
