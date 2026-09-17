// Real network listing — replaces the original mocked networks.html
// data. Same source pattern as containers.go/images.go/volumes.go:
// host_networks, kept in sync by each agent's tunnel (cf. tunnel.go).
// "Containers" is computed here by matching a container's reported
// network attachments against each network's name, scoped to the same
// host — same approach as images.go/volumes.go's UsedBy, not a stored
// column.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

type Network struct {
	Name, HostID, Host, Driver, Scope, Containers string
}

// deleteNetworksHandler serves POST /networks/delete -- same bulk
// "hostID|name" pattern as deleteImagesHandler/deleteVolumesHandler.
// Docker's own predefined networks (bridge/host/none) and any network
// still attached to a container are refused by the daemon itself
// ("is a pre-defined network and cannot be removed" / "has active
// endpoints") -- surfaced as a normal per-item failure rather than
// special-cased here, since the daemon already enforces it correctly.
func (a *app) deleteNetworksHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		redirectWithError(w, r, "/networks", err.Error())
		return
	}
	refs := r.Form["names"]
	if len(refs) == 0 {
		redirectWithError(w, r, "/networks", "No networks selected.")
		return
	}
	var failed []string
	for _, ref := range refs {
		hostID, name, ok := strings.Cut(ref, "|")
		if !ok {
			continue
		}
		tc, connected := a.tunnels.get(hostID)
		if !connected {
			failed = append(failed, name+" (host not connected)")
			continue
		}
		result, err := tc.sendCommand(r.Context(), "network_remove", name)
		switch {
		case err != nil:
			failed = append(failed, name+" ("+err.Error()+")")
		case !result.OK:
			failed = append(failed, name+" ("+strings.TrimSpace(result.Output)+")")
		}
	}
	if len(failed) > 0 {
		redirectWithError(w, r, "/networks", fmt.Sprintf("%d of %d network(s) could not be removed: %s", len(failed), len(refs), strings.Join(failed, "; ")))
		return
	}
	// ?refreshing=1 -- same reasoning as deleteImagesHandler: the delete
	// already happened on the real daemon, but host_networks only catches
	// up once the agent's next debounced snapshot arrives, which this
	// redirect routinely beats. cf. layout.html's poll-and-replace script.
	http.Redirect(w, r, "/networks?refreshing=1", http.StatusSeeOther)
}

func (a *app) networksHandler(w http.ResponseWriter, r *http.Request) {
	networkRows, err := a.store.ListHostNetworks()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	containerRows, err := a.store.ListHostContainers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hosts, err := a.store.ListHosts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	networks := make([]Network, 0, len(networkRows))
	for _, n := range networkRows {
		var containers string
		for _, c := range containerRows {
			if c.HostID != n.HostID || c.Networks == "" {
				continue
			}
			for _, net := range strings.Split(c.Networks, ",") {
				if net == n.Name {
					if containers != "" {
						containers += ", "
					}
					containers += c.Name
					break
				}
			}
		}
		networks = append(networks, Network{
			Name:       n.Name,
			HostID:     n.HostID,
			Host:       n.HostName,
			Driver:     n.Driver,
			Scope:      n.Scope,
			Containers: containers,
		})
	}

	data := map[string]any{
		"Title":    "Networks",
		"Nav":      "networks",
		"Networks": networks,
		"Hosts":    hosts,
	}
	render(w, r, "layout", "networks.html", data)
}

// networkDetailInfo is the "Network details" card's view model, straight
// from `docker network inspect`.
type networkDetailInfo struct {
	Name, Driver, Scope, Subnet, Gateway string
	Internal, Attachable                 bool
	Labels                               []kvPair
}

type networkContainer struct {
	Name, IPv4Address string
}

type dockerNetworkInspectRaw struct {
	Name       string `json:"Name"`
	Driver     string `json:"Driver"`
	Scope      string `json:"Scope"`
	Internal   bool   `json:"Internal"`
	Attachable bool   `json:"Attachable"`
	IPAM       struct {
		Config []struct {
			Subnet  string `json:"Subnet"`
			Gateway string `json:"Gateway"`
		} `json:"Config"`
	} `json:"IPAM"`
	Containers map[string]struct {
		Name        string `json:"Name"`
		IPv4Address string `json:"IPv4Address"`
	} `json:"Containers"`
	Labels map[string]string `json:"Labels"`
}

func parseNetworkInspect(raw string) (networkDetailInfo, []networkContainer) {
	var arr []dockerNetworkInspectRaw
	if err := json.Unmarshal([]byte(raw), &arr); err != nil || len(arr) == 0 {
		return networkDetailInfo{}, nil
	}
	info := arr[0]
	detail := networkDetailInfo{
		Name:       info.Name,
		Driver:     info.Driver,
		Scope:      info.Scope,
		Internal:   info.Internal,
		Attachable: info.Attachable,
		Labels:     sortedKVPairs(info.Labels),
	}
	if len(info.IPAM.Config) > 0 {
		detail.Subnet = info.IPAM.Config[0].Subnet
		detail.Gateway = info.IPAM.Config[0].Gateway
	}
	names := make([]string, 0, len(info.Containers))
	byName := make(map[string]string, len(info.Containers))
	for _, c := range info.Containers {
		names = append(names, c.Name)
		byName[c.Name] = c.IPv4Address
	}
	sort.Strings(names)
	containers := make([]networkContainer, 0, len(names))
	for _, name := range names {
		containers = append(containers, networkContainer{Name: name, IPv4Address: byName[name]})
	}
	return detail, containers
}

// networkDetailHandler serves GET /networks/{hostID}/{name} -- hostID
// picks which agent's tunnel to ask, same reasoning as image/volume
// detail handlers: a network name is only unique within one host.
func (a *app) networkDetailHandler(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("hostID")
	name := r.PathValue("name")

	var detail networkDetailInfo
	var containers []networkContainer
	if tc, ok := a.tunnels.get(hostID); ok {
		if result, err := tc.sendCommand(r.Context(), "network_inspect", name); err == nil && result.OK {
			detail, containers = parseNetworkInspect(result.Output)
		}
	}

	data := map[string]any{
		"Title":       name,
		"Nav":         "networks",
		"NetworkName": name,
		"HostID":      hostID,
		"Detail":      detail,
		"Containers":  containers,
	}
	render(w, r, "layout", "network_detail.html", data)
}
