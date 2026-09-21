// Restart/Stop container actions — the controller->agent direction of
// the tunnel (cf. tunnel.go's tunnelConn/tunnelRegistry). Not a GitOps
// deployment, so nothing here touches the deployments table: the result
// of a restart/stop is already visible for free through the next
// docker-events-triggered state push, same as any other container
// change.
package main

import (
	"net/http"
	"net/url"
)

func (a *app) restartContainerHandler(w http.ResponseWriter, r *http.Request) {
	a.runContainerAction(w, r, "restart")
}

func (a *app) stopContainerHandler(w http.ResponseWriter, r *http.Request) {
	a.runContainerAction(w, r, "stop")
}

// removeContainerHandler serves POST /containers/{id}/remove -- for a
// container Wharf didn't deploy (no matching row in the stacks table,
// e.g. something left over from Portainer), since there's otherwise no
// clean way to get rid of it from this UI at all: a Wharf-managed
// service is expected to go through undeploy instead, which tears down
// its whole stack together rather than one container at a time.
func (a *app) removeContainerHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, err := a.store.GetHostContainerByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	target := "/containers/" + id
	if ref := r.Referer(); ref != "" {
		if u, err := url.Parse(ref); err == nil && u.Path == "/containers" {
			target = "/containers"
		}
	}

	if c.StackID != "" {
		if _, err := a.store.GetStack(c.StackID); err == nil {
			redirectWithError(w, r, target, "this container belongs to a stack Wharf manages — undeploy the stack instead of removing one of its containers directly")
			return
		}
	}
	if c.State == "running" {
		redirectWithError(w, r, target, "stop the container before removing it")
		return
	}

	tc, ok := a.tunnels.get(c.HostID)
	if !ok {
		redirectWithError(w, r, target, "agent for this host is not currently connected")
		return
	}

	result, err := tc.sendCommand(r.Context(), "remove", c.ContainerID)
	if err != nil {
		redirectWithError(w, r, target, err.Error())
		return
	}
	if !result.OK {
		redirectWithError(w, r, target, result.Output)
		return
	}

	// Unlike restart/stop, the container this page was ever about no
	// longer exists -- always land back on the list rather than a detail
	// page whose subject is now gone.
	a.audit(r, "container.remove", c.Name, "host "+c.HostID)
	redirectWithSavedMessage(w, r, "/containers", "Container removed")
}

func (a *app) runContainerAction(w http.ResponseWriter, r *http.Request, action string) {
	id := r.PathValue("id")
	c, err := a.store.GetHostContainerByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Both the containers list and this container's own detail page have
	// a Restart/Stop button posting here, and only the detail page should
	// always land back on the detail page -- a click from the list stays
	// on the list instead of being dragged into a detail page nobody
	// asked for. Restricted to our own /containers path (never the raw
	// Referer) so this can't become an open redirect off a spoofed header.
	target := "/containers/" + id
	if ref := r.Referer(); ref != "" {
		if u, err := url.Parse(ref); err == nil && u.Path == "/containers" {
			target = "/containers"
		}
	}

	tc, ok := a.tunnels.get(c.HostID)
	if !ok {
		redirectWithError(w, r, target, "agent for this host is not currently connected")
		return
	}

	result, err := tc.sendCommand(r.Context(), action, c.ContainerID)
	if err != nil {
		redirectWithError(w, r, target, err.Error())
		return
	}
	if !result.OK {
		redirectWithError(w, r, target, result.Output)
		return
	}

	// sendCommand already blocked until the agent's "docker restart/stop"
	// finished -- by the time this redirect lands, there's no "in
	// progress" state left to show, only a toast confirming it happened
	// (the container's own state badge on this page may already read the
	// same as before the click, e.g. "running" -> "running" again).
	msg := "Container " + action + "ed"
	if action == "stop" {
		msg = "Container stopped"
	}
	a.audit(r, "container."+action, c.Name, "host "+c.HostID)
	redirectWithSavedMessage(w, r, target, msg)
}
