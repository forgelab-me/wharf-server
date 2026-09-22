// UI-facing host management (/hosts) -- browsing the fleet, approving or
// rejecting a pending agent, and the two admin-editable display fields
// (name, address). Enrollment itself (the agent-facing :8443 side of
// getting a host into this table in the first place) lives in
// agent_protocol.go instead -- different caller, different trust model.
package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/forgelab-me/wharf-server/internal/store"
)

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
	a.audit(r, "host.approve", id, "")
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
	a.audit(r, "host.reject", id, "")
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
	a.audit(r, "host.set_address", id, address)
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
	a.audit(r, "host.rename", id, name)
	redirectWithSaved(w, r, "/hosts/"+id)
}
