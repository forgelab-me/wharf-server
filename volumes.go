// Real volume listing — replaces the original mocked volumes.html data.
// Same source pattern as containers.go/images.go: host_volumes, kept in
// sync by each agent's tunnel (cf. tunnel.go). "UsedBy" is computed here
// by matching a container's reported named-volume mounts against each
// volume's name, scoped to the same host — same approach as images.go's
// UsedBy, not a stored column.
//
// Real file browsing (list/rename/delete/upload/edit inside a volume)
// lives in volumebrowse.go, a separate concern from just listing
// volumes here.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/forgelab-me/wharf-server/internal/store"
)

type Volume struct {
	Name, HostID, Host, Driver, Size, UsedBy string
}

// deleteVolumesHandler serves POST /volumes/delete -- same bulk
// "hostID|name" pattern and same independent-per-item error handling as
// deleteImagesHandler. A volume actually mounted by a container is
// refused by Docker itself ("volume is in use"), surfaced here rather
// than pre-checked, since UsedBy is only ever as fresh as the last
// snapshot.
func (a *app) deleteVolumesHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		redirectWithError(w, r, "/volumes", err.Error())
		return
	}
	refs := r.Form["names"]
	if len(refs) == 0 {
		redirectWithError(w, r, "/volumes", "No volumes selected.")
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
		result, err := tc.sendCommand(r.Context(), "volume_remove", name)
		switch {
		case err != nil:
			failed = append(failed, name+" ("+err.Error()+")")
		case !result.OK:
			failed = append(failed, name+" ("+strings.TrimSpace(result.Output)+")")
		}
	}
	if len(failed) > 0 {
		redirectWithError(w, r, "/volumes", fmt.Sprintf("%d of %d volume(s) could not be removed: %s", len(failed), len(refs), strings.Join(failed, "; ")))
		return
	}
	// ?refreshing=1 -- same reasoning as deleteImagesHandler: the delete
	// already happened on the real daemon, but host_volumes only catches
	// up once the agent's next debounced snapshot arrives, which this
	// redirect routinely beats. cf. layout.html's poll-and-replace script.
	http.Redirect(w, r, "/volumes?refreshing=1", http.StatusSeeOther)
}

func (a *app) volumesHandler(w http.ResponseWriter, r *http.Request) {
	volumeRows, err := a.store.ListHostVolumes()
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

	// Size is deliberately never computed here: `docker system df -v`
	// walks every volume's directory tree, and doing that for every
	// connected host inline in this page's own render made /volumes
	// noticeably slow to load -- found in practice, not anticipated.
	// volumes.html fetches GET /volumes/sizes itself, after the page's
	// already up, and fills each row in once that resolves.
	volumes := make([]Volume, 0, len(volumeRows))
	for _, v := range volumeRows {
		var usedBy string
		for _, c := range containerRows {
			if c.HostID != v.HostID || c.Mounts == "" {
				continue
			}
			for _, mount := range strings.Split(c.Mounts, ",") {
				if mount == v.Name {
					if usedBy != "" {
						usedBy += ", "
					}
					usedBy += c.Name
					break
				}
			}
		}
		volumes = append(volumes, Volume{
			Name:   v.Name,
			HostID: v.HostID,
			Host:   v.HostName,
			Driver: v.Driver,
			Size:   "…",
			UsedBy: usedBy,
		})
	}

	data := map[string]any{
		"Title":   "Volumes",
		"Nav":     "volumes",
		"Volumes": volumes,
		"Hosts":   hosts,
	}
	render(w, r, "layout", "volumes.html", data)
}

// volumeSizesHandler serves GET /volumes/sizes -- the async counterpart
// to the Size column volumesHandler no longer computes inline. Returns
// every connected host's real per-volume sizes in one response, keyed
// "hostID|volumeName" (matching each row's own data-vol-key) so the
// page's own script can do a single fetch and a flat map lookup instead
// of one request per host.
func (a *app) volumeSizesHandler(w http.ResponseWriter, r *http.Request) {
	volumeRows, err := a.store.ListHostVolumes()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sizesByHost := volumeSizesByHost(a, r, volumeRows)

	out := make(map[string]string, len(volumeRows))
	for _, v := range volumeRows {
		if s, ok := sizesByHost[v.HostID][v.Name]; ok {
			out[v.HostID+"|"+v.Name] = s
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// dockerDFVerbose is the shape of `docker system df -v --format
// '{{json .}}'` -- one JSON object per call (not one per volume),
// confirmed against a real Docker install rather than assumed from -v's
// plain-table behavior. Only the Volumes list is used here; Images/
// Containers/BuildCache are ignored.
type dockerDFVerbose struct {
	Volumes []struct {
		Name string `json:"Name"`
		Size string `json:"Size"`
	} `json:"Volumes"`
}

// volumeSizesByHost fetches real per-volume disk usage from every
// distinct host referenced in volumeRows that's currently connected,
// concurrently (cf. containerDetailHandler's same pattern) so N hosts
// cost one round trip's worth of wall-clock time, not N. A
// disconnected host, a timeout, or a malformed reply all degrade to
// "no sizes for this host" -- the caller already renders "—" for
// anything missing here, same as it did before this existed.
//
// Deliberately on-demand, once per /volumes page load, rather than
// folded into the tunnel's continuous background snapshot: `docker
// system df -v` walks every volume's directory tree to compute its
// size, real work worth paying for when an admin actually wants to see
// it, not on every few-second heartbeat for volumes nobody's looking at.
func volumeSizesByHost(a *app, r *http.Request, volumeRows []store.HostVolume) map[string]map[string]string {
	hostIDs := map[string]bool{}
	for _, v := range volumeRows {
		hostIDs[v.HostID] = true
	}

	var mu sync.Mutex
	out := map[string]map[string]string{}
	var wg sync.WaitGroup
	for hostID := range hostIDs {
		tc, ok := a.tunnels.get(hostID)
		if !ok {
			continue
		}
		wg.Add(1)
		go func(hostID string, tc *tunnelConn) {
			defer wg.Done()
			result, err := tc.sendCommand(r.Context(), "volume_sizes", "")
			if err != nil || !result.OK {
				return
			}
			var parsed dockerDFVerbose
			if err := json.Unmarshal([]byte(result.Output), &parsed); err != nil {
				return
			}
			sizes := make(map[string]string, len(parsed.Volumes))
			for _, v := range parsed.Volumes {
				sizes[v.Name] = v.Size
			}
			mu.Lock()
			out[hostID] = sizes
			mu.Unlock()
		}(hostID, tc)
	}
	wg.Wait()
	return out
}

// volumeDetailInfo is the "Volume details" card's view model, straight
// from `docker volume inspect`.
type volumeDetailInfo struct {
	Name, Driver, Mountpoint, Scope, CreatedAt string
	Options, Labels                            []kvPair
}

type dockerVolumeInspectRaw struct {
	Name       string            `json:"Name"`
	Driver     string            `json:"Driver"`
	Mountpoint string            `json:"Mountpoint"`
	Scope      string            `json:"Scope"`
	CreatedAt  string            `json:"CreatedAt"`
	Options    map[string]string `json:"Options"`
	Labels     map[string]string `json:"Labels"`
}

func sortedKVPairs(m map[string]string) []kvPair {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]kvPair, 0, len(keys))
	for _, k := range keys {
		out = append(out, kvPair{Key: k, Value: m[k]})
	}
	return out
}

func parseVolumeInspect(raw string) volumeDetailInfo {
	var arr []dockerVolumeInspectRaw
	if err := json.Unmarshal([]byte(raw), &arr); err != nil || len(arr) == 0 {
		return volumeDetailInfo{}
	}
	info := arr[0]
	return volumeDetailInfo{
		Name:       info.Name,
		Driver:     info.Driver,
		Mountpoint: info.Mountpoint,
		Scope:      info.Scope,
		CreatedAt:  trimCreatedAt(info.CreatedAt),
		Options:    sortedKVPairs(info.Options),
		Labels:     sortedKVPairs(info.Labels),
	}
}

// volumeDetailHandler serves GET /volumes/{hostID}/{name} -- hostID
// picks which agent's tunnel to ask, same reasoning as
// imageDetailHandler: a volume name is only unique within one host, not
// across the fleet.
func (a *app) volumeDetailHandler(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("hostID")
	name := r.PathValue("name")

	var detail volumeDetailInfo
	if tc, ok := a.tunnels.get(hostID); ok {
		if result, err := tc.sendCommand(r.Context(), "volume_inspect", name); err == nil && result.OK {
			detail = parseVolumeInspect(result.Output)
		}
	}

	containerRows, err := a.store.ListHostContainers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var usedBy []string
	for _, c := range containerRows {
		if c.HostID != hostID || c.Mounts == "" {
			continue
		}
		for _, mount := range strings.Split(c.Mounts, ",") {
			if mount == name {
				usedBy = append(usedBy, c.Name)
				break
			}
		}
	}

	data := map[string]any{
		"Title":      name,
		"Nav":        "volumes",
		"VolumeName": name,
		"HostID":     hostID,
		"Detail":     detail,
		"UsedBy":     usedBy,
	}
	render(w, r, "layout", "volume_detail.html", data)
}
