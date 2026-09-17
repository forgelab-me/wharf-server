// Restart/Stop container actions — the controller->agent direction of
// the tunnel (cf. tunnel.go's tunnelConn/tunnelRegistry). Not a GitOps
// deployment, so nothing here touches the deployments table: the result
// of a restart/stop is already visible for free through the next
// docker-events-triggered state push, same as any other container
// change.
package main

import "net/http"

func (a *app) restartContainerHandler(w http.ResponseWriter, r *http.Request) {
	a.runContainerAction(w, r, "restart")
}

func (a *app) stopContainerHandler(w http.ResponseWriter, r *http.Request) {
	a.runContainerAction(w, r, "stop")
}

func (a *app) runContainerAction(w http.ResponseWriter, r *http.Request, action string) {
	id := r.PathValue("id")
	c, err := a.store.GetHostContainerByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	tc, ok := a.tunnels.get(c.HostID)
	if !ok {
		redirectWithError(w, r, "/containers/"+id, "agent for this host is not currently connected")
		return
	}

	result, err := tc.sendCommand(r.Context(), action, c.ContainerID)
	if err != nil {
		redirectWithError(w, r, "/containers/"+id, err.Error())
		return
	}
	if !result.OK {
		redirectWithError(w, r, "/containers/"+id, result.Output)
		return
	}

	http.Redirect(w, r, "/containers/"+id, http.StatusSeeOther)
}
