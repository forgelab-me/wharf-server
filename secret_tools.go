// The Bitwarden tool (bws): Bitwarden's licence does not let Wharf bundle it, so
// the controller downloads it when an administrator asks, after showing the
// licence, cf. ARCHITECTURE.md, "Bitwarden Secrets Manager et règles de chemin".
package main

import (
	"context"
	"net/http"
	"time"

	"github.com/forgelab-me/wharf-server/internal/secrets"
)

const bwsInstallTimeout = 3 * time.Minute

// bwsView is what the providers page shows about the tool.
type bwsView struct {
	Installed  bool
	Version    string
	LicenseURL string
}

// bwsStatus is nil when this controller has no Bitwarden provider.
func (a *app) bwsStatus() *bwsView {
	if a.bws == nil {
		return nil
	}
	return &bwsView{Installed: a.bws.Installed(), Version: a.bws.Version(), LicenseURL: secrets.BwsLicenseURL}
}

// installBwsHandler serves POST /settings/secret-providers/bws/install.
func (a *app) installBwsHandler(w http.ResponseWriter, r *http.Request) {
	const back = "/settings/secret-providers"
	if a.bws == nil {
		http.NotFound(w, r)
		return
	}
	if r.FormValue("accept_license") != "1" {
		redirectWithError(w, r, back, "read and accept Bitwarden's licence before downloading its tool")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), bwsInstallTimeout)
	defer cancel()
	if err := a.bws.Install(ctx); err != nil {
		redirectWithError(w, r, back, err.Error())
		return
	}
	a.audit(r, "secrets.tool_install", "bws", a.bws.Version()+", licence accepted")
	redirectWithSavedMessage(w, r, back, "Bitwarden tool "+a.bws.Version()+" installed")
}
