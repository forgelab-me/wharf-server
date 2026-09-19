// Real image listing — replaces the original mocked images.html data.
// Same source as containers.go: host_images, kept in sync by each
// agent's tunnel (cf. tunnel.go). "UsedBy" isn't stored anywhere — it's
// computed here by matching a container's reported image string against
// each image's repository:tag, scoped to the same host (an image can
// only ever be used by a container running on its own host).
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

type DockerImage struct {
	Repo, Tag, ID, HostID, Host, Size, UsedBy string
}

// deleteImagesHandler serves POST /images/delete -- bulk "ids" form
// values shaped "hostID|imageID" (cf. images.html's checkboxes, and the
// "Clean up unused images" button that just checks every currently
// unused row before submitting the same form). Each id is removed
// independently so one failure -- an image still in use by a stopped
// container Docker itself refuses to drop, a host that's gone offline
// mid-selection -- doesn't block the rest; failures are collected and
// reported together via redirectWithError rather than the whole
// request failing on the first one.
func (a *app) deleteImagesHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		redirectWithError(w, r, "/images", err.Error())
		return
	}
	refs := r.Form["ids"]
	if len(refs) == 0 {
		redirectWithError(w, r, "/images", "No images selected.")
		return
	}
	var failed []string
	for _, ref := range refs {
		hostID, imageID, ok := strings.Cut(ref, "|")
		if !ok {
			continue
		}
		tc, connected := a.tunnels.get(hostID)
		if !connected {
			failed = append(failed, imageID+" (host not connected)")
			continue
		}
		result, err := tc.sendCommand(r.Context(), "image_remove", imageID)
		switch {
		case err != nil:
			failed = append(failed, imageID+" ("+err.Error()+")")
		case !result.OK:
			failed = append(failed, imageID+" ("+strings.TrimSpace(result.Output)+")")
		}
	}
	if len(failed) > 0 {
		redirectWithError(w, r, "/images", fmt.Sprintf("%d of %d image(s) could not be removed: %s", len(failed), len(refs), strings.Join(failed, "; ")))
		return
	}
	// ?refreshing=1, not a plain redirect: docker rmi succeeding here
	// only means the daemon did it -- host_images itself only catches up
	// once the agent's docker events watcher notices and pushes a fresh
	// snapshot over the tunnel (debounced ~300ms, cf. tunnel.go), which
	// routinely loses the race against this redirect landing. Without
	// it the just-deleted image still shows until a manual reload. cf.
	// layout.html's poll-and-replace script. The toast fires immediately
	// regardless -- the deletion itself already succeeded above, only the
	// table's own refresh is what's still catching up.
	http.Redirect(w, r, appendSavedMessage("/images?refreshing=1", fmt.Sprintf("%d image(s) deleted", len(refs))), http.StatusSeeOther)
}

func (a *app) imagesHandler(w http.ResponseWriter, r *http.Request) {
	imageRows, err := a.store.ListHostImages()
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

	images := make([]DockerImage, 0, len(imageRows))
	for _, img := range imageRows {
		ref := img.Repository + ":" + img.Tag
		var usedBy string
		for _, c := range containerRows {
			if c.HostID == img.HostID && c.Image == ref {
				if usedBy != "" {
					usedBy += ", "
				}
				usedBy += c.Name
			}
		}
		images = append(images, DockerImage{
			Repo:   img.Repository,
			Tag:    img.Tag,
			ID:     img.ImageID,
			HostID: img.HostID,
			Host:   img.HostName,
			Size:   img.Size,
			UsedBy: usedBy,
		})
	}

	data := map[string]any{
		"Title":  "Images",
		"Nav":    "images",
		"Images": images,
		"Hosts":  hosts,
	}
	render(w, r, "layout", "images.html", data)
}

// imageDetailInfo is the "Image details"/"Dockerfile details" cards'
// view model, straight from `docker inspect` on the image -- no masking
// needed, an image's baked-in Cmd/Entrypoint/Env are the same thing
// anyone pulling the image publicly can already read, unlike a running
// container's resolved secrets.
type imageDetailInfo struct {
	ID, Size, Created, Architecture, Os, DockerVersion string
	Cmd, Entrypoint                                    string
	Env                                                []EnvVar
	Labels                                             []kvPair
}

type imageLayer struct {
	Order     int
	Size      string
	CreatedBy string
}

// dockerImageInspectRaw matches the fields this package reads out of
// `docker image inspect` -- a real Dockerfile is never available (an
// image only ever carries the config it was baked with, never its
// source), so "Dockerfile details" below means exactly that config:
// what CMD/ENTRYPOINT/ENV the image would run with, not its recipe.
type dockerImageInspectRaw struct {
	Id            string `json:"Id"`
	Size          int64  `json:"Size"`
	Created       string `json:"Created"`
	Architecture  string `json:"Architecture"`
	Os            string `json:"Os"`
	DockerVersion string `json:"DockerVersion"`
	Config        struct {
		Cmd        []string          `json:"Cmd"`
		Entrypoint []string          `json:"Entrypoint"`
		Env        []string          `json:"Env"`
		Labels     map[string]string `json:"Labels"`
	} `json:"Config"`
}

func parseImageInspect(raw string) imageDetailInfo {
	var arr []dockerImageInspectRaw
	if err := json.Unmarshal([]byte(raw), &arr); err != nil || len(arr) == 0 {
		return imageDetailInfo{}
	}
	info := arr[0]
	detail := imageDetailInfo{
		ID:            info.Id,
		Size:          humanSize(info.Size),
		Created:       trimCreatedAt(info.Created),
		Architecture:  info.Architecture,
		Os:            info.Os,
		DockerVersion: info.DockerVersion,
		Cmd:           strings.Join(info.Config.Cmd, " "),
		Entrypoint:    strings.Join(info.Config.Entrypoint, " "),
	}
	for _, kv := range info.Config.Env {
		k, v, _ := strings.Cut(kv, "=")
		detail.Env = append(detail.Env, EnvVar{Key: k, Value: v})
	}
	detail.Labels = sortedKVPairs(info.Config.Labels)
	return detail
}

// humanSize formats a raw byte count the same order of magnitude
// `docker images`'s own Size column already uses elsewhere on this
// page, so the detail page doesn't show a number in a different style
// than the list it was reached from.
func humanSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// parseImageHistory parses `docker history --no-trunc --format {{json
// .}}` -- one JSON object per layer, newest first (docker's own order,
// left as-is rather than reversed: "Order" numbers the list as shown,
// it doesn't claim to be a build step index).
func parseImageHistory(raw string) []imageLayer {
	var out []imageLayer
	order := 1
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var l struct {
			CreatedBy string `json:"CreatedBy"`
			Size      string `json:"Size"`
		}
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			continue
		}
		out = append(out, imageLayer{Order: order, Size: l.Size, CreatedBy: l.CreatedBy})
		order++
	}
	return out
}

// imageDetailHandler serves GET /images/{hostID}/{id} -- hostID picks
// which agent's tunnel to ask, since the same content-addressed image
// id could in principle exist on more than one host but `docker
// inspect`/`history` need one specific connection to run against.
func (a *app) imageDetailHandler(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("hostID")
	id := r.PathValue("id")

	var detail imageDetailInfo
	var layers []imageLayer

	if tc, ok := a.tunnels.get(hostID); ok {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			if result, err := tc.sendCommand(r.Context(), "image_inspect", id); err == nil && result.OK {
				detail = parseImageInspect(result.Output)
			}
		}()
		go func() {
			defer wg.Done()
			if result, err := tc.sendCommand(r.Context(), "image_history", id); err == nil && result.OK {
				layers = parseImageHistory(result.Output)
			}
		}()
		wg.Wait()
	}

	data := map[string]any{
		"Title":   id,
		"Nav":     "images",
		"ImageID": id,
		"HostID":  hostID,
		"Detail":  detail,
		"Layers":  layers,
	}
	render(w, r, "layout", "image_detail.html", data)
}
