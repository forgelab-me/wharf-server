// Real volume browsing — list, navigate, rename, delete, upload, and
// edit a small text file, all inside a Docker volume, admin-only. Runs
// entirely through short-lived helper containers the agent spins up
// per operation (cf. agent/tunnel.go's handleVolumeCommand) — the
// controller itself never touches a volume's bytes directly, only ever
// relays a base64 payload to/from whichever agent owns the host.
//
// Every user-supplied path goes through volumeContainerPath before it's
// ever sent to an agent: prefixing with "/" and running path.Clean
// mathematically can't produce anything above that root (Go's Clean
// collapses a leading ".." at the root to nothing), so a traversal
// attempt just gets clamped rather than needing to be specially
// detected and rejected.
package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// maxVolumeEditSize caps how large a file this will fetch into a
// browser textarea -- config files are the realistic use case here,
// not bulk data. Enforced after decoding (the read already happened by
// then), so this is about the edit UI staying usable, not a hard
// resource limit on the read itself.
const maxVolumeEditSize = 512 * 1024 // 512 KiB

// maxVolumeUploadSize caps an uploaded file -- it travels as base64
// over one JSON tunnel message, so this stays well under whatever
// message-size ceiling the websocket library itself enforces.
const maxVolumeUploadSize = 10 * 1024 * 1024 // 10 MiB

// volumeContainerPath turns a user-supplied relative path (a query or
// form value, therefore untrusted) into the full path under the
// helper container's /vol mount. See the package comment above for why
// this is safe against ".." traversal by construction, not by
// pattern-matching for it.
func volumeContainerPath(relPath string) string {
	clean := path.Clean("/" + relPath)
	if clean == "/" {
		return "/vol"
	}
	return "/vol" + clean
}

// volumeEntry is one row in the browse listing.
type volumeEntry struct {
	Name       string
	IsDir      bool
	Size       string
	Modified   string
	RelPath    string // for building this entry's own links
	ParentPath string // for the enclosing directory's own links (rename/delete targets need it, not the entry name alone)
}

// parseVolumeListing turns handleVolumeCommand's tab-separated
// "type\tsize\tmtime\tname" lines into sorted rows -- directories
// first, then files, alphabetically within each group.
func parseVolumeListing(output, dirRelPath string) []volumeEntry {
	var dirs, files []volumeEntry
	for _, line := range strings.Split(strings.TrimRight(output, "\n"), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 4)
		if len(parts) != 4 {
			continue
		}
		isDir := parts[0] == "d"
		sizeBytes, _ := strconv.ParseInt(parts[1], 10, 64)
		mtime, _ := strconv.ParseInt(parts[2], 10, 64)
		name := parts[3]
		size := "—"
		if !isDir {
			size = humanSize(sizeBytes)
		}
		modified := "—"
		if mtime > 0 {
			modified = time.Unix(mtime, 0).Format("2006-01-02 15:04:05")
		}
		entry := volumeEntry{
			Name:       name,
			IsDir:      isDir,
			Size:       size,
			Modified:   modified,
			RelPath:    path.Join(dirRelPath, name),
			ParentPath: dirRelPath,
		}
		if isDir {
			dirs = append(dirs, entry)
		} else {
			files = append(files, entry)
		}
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Name < dirs[j].Name })
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return append(dirs, files...)
}

// volumeExists reports whether name is a real, currently-known volume
// on hostID -- the one gate standing between Browse and what Docker's
// own `-v` flag does with whatever string it's given: a source
// starting with "/" is parsed as a host bind mount, not a named
// volume. Without this check, a request for
// /volumes/{hostID}/%2Fetc/browse reaches this handler with name =
// "/etc" (Go's ServeMux decodes %2F into a literal "/" before matching
// {name}, verified directly against the router), and the agent would
// bind-mount the host's real /etc -- or any absolute path, including
// "/" itself -- into a throwaway container and list/read/write/rename/
// delete it exactly as if it were a Wharf-managed volume. Checked
// against the same store data /volumes itself renders from, so only a
// volume actually known to exist on that host can ever be browsed.
func (a *app) volumeExists(hostID, name string) bool {
	volumes, err := a.store.ListHostVolumes()
	if err != nil {
		return false
	}
	for _, v := range volumes {
		if v.HostID == hostID && v.Name == name {
			return true
		}
	}
	return false
}

// volumeBrowseHandler serves GET /volumes/{hostID}/{name}/browse.
func (a *app) volumeBrowseHandler(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("hostID")
	name := r.PathValue("name")
	if !a.volumeExists(hostID, name) {
		http.NotFound(w, r)
		return
	}
	relPath := path.Clean("/" + r.URL.Query().Get("path"))
	if relPath == "/" {
		relPath = ""
	} else {
		relPath = strings.TrimPrefix(relPath, "/")
	}

	tc, ok := a.tunnels.get(hostID)
	if !ok {
		redirectWithError(w, r, "/volumes", "this host is not currently connected")
		return
	}
	result, err := tc.sendVolumeCommand(r.Context(), "volume_list", name, volumeContainerPath(relPath), "", "")
	if err != nil {
		redirectWithError(w, r, "/volumes", "could not list volume: "+err.Error())
		return
	}
	if !result.OK {
		redirectWithError(w, r, fmt.Sprintf("/volumes/%s/%s/browse", hostID, name), "could not list this directory: "+strings.TrimSpace(result.Output))
		return
	}

	var parentPath string
	if relPath != "" {
		parentPath = path.Dir(relPath)
		if parentPath == "." {
			parentPath = ""
		}
	}

	data := map[string]any{
		"Title":      "Browse · " + name,
		"Nav":        "volumes",
		"HostID":     hostID,
		"VolumeName": name,
		"Path":       relPath,
		"HasParent":  relPath != "",
		"ParentPath": parentPath,
		"Entries":    parseVolumeListing(result.Output, relPath),
	}
	render(w, r, "layout", "volume_browse.html", data)
}

// volumeBrowseRenameHandler serves POST
// /volumes/{hostID}/{name}/browse/rename.
func (a *app) volumeBrowseRenameHandler(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("hostID")
	name := r.PathValue("name")
	if !a.volumeExists(hostID, name) {
		http.NotFound(w, r)
		return
	}
	relPath := r.FormValue("path")
	newName := strings.TrimSpace(r.FormValue("new_name"))
	backTo := fmt.Sprintf("/volumes/%s/%s/browse?path=%s", hostID, name, url.QueryEscape(path.Dir("/"+relPath)))

	if newName == "" || strings.ContainsAny(newName, "/\\") {
		redirectWithError(w, r, backTo, "invalid new name")
		return
	}
	tc, ok := a.tunnels.get(hostID)
	if !ok {
		redirectWithError(w, r, backTo, "this host is not currently connected")
		return
	}
	newRelPath := path.Join(path.Dir(relPath), newName)
	result, err := tc.sendVolumeCommand(r.Context(), "volume_rename", name, volumeContainerPath(relPath), volumeContainerPath(newRelPath), "")
	if err != nil || !result.OK {
		msg := errString(err, result.Output)
		redirectWithError(w, r, backTo, "rename failed: "+msg)
		return
	}
	http.Redirect(w, r, backTo, http.StatusSeeOther)
}

// volumeBrowseDeleteHandler serves POST
// /volumes/{hostID}/{name}/browse/delete. Recursive for a directory --
// cf. the confirmation copy in volume_browse.html, which says so
// explicitly before this ever runs.
func (a *app) volumeBrowseDeleteHandler(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("hostID")
	name := r.PathValue("name")
	if !a.volumeExists(hostID, name) {
		http.NotFound(w, r)
		return
	}
	relPath := r.FormValue("path")
	backTo := fmt.Sprintf("/volumes/%s/%s/browse?path=%s", hostID, name, url.QueryEscape(path.Dir("/"+relPath)))

	if relPath == "" {
		redirectWithError(w, r, backTo, "can't delete the volume's root")
		return
	}
	tc, ok := a.tunnels.get(hostID)
	if !ok {
		redirectWithError(w, r, backTo, "this host is not currently connected")
		return
	}
	result, err := tc.sendVolumeCommand(r.Context(), "volume_delete", name, volumeContainerPath(relPath), "", "")
	if err != nil || !result.OK {
		msg := errString(err, result.Output)
		redirectWithError(w, r, backTo, "delete failed: "+msg)
		return
	}
	http.Redirect(w, r, backTo, http.StatusSeeOther)
}

// volumeBrowseUploadHandler serves POST
// /volumes/{hostID}/{name}/browse/upload.
func (a *app) volumeBrowseUploadHandler(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("hostID")
	name := r.PathValue("name")
	if !a.volumeExists(hostID, name) {
		http.NotFound(w, r)
		return
	}
	dirPath := r.URL.Query().Get("path")
	backTo := fmt.Sprintf("/volumes/%s/%s/browse?path=%s", hostID, name, url.QueryEscape(dirPath))

	r.Body = http.MaxBytesReader(w, r.Body, maxVolumeUploadSize+1<<20) // +1MiB of multipart overhead headroom
	if err := r.ParseMultipartForm(maxVolumeUploadSize); err != nil {
		redirectWithError(w, r, backTo, "upload too large or invalid (max 10 MiB)")
		return
	}
	// requireAuth's own CSRF check (cf. auth.go) skips every
	// multipart/form-data request on purpose -- calling r.ParseForm()
	// there would be a documented no-op against this exact content type,
	// but reading the token via r.FormValue would trigger a second,
	// unbounded ParseMultipartForm ahead of the size-capped one above.
	// So this route verifies its own token, after its own bounded parse.
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || !verifyCSRF(cookie.Value, r.FormValue("csrf_token")) {
		redirectWithError(w, r, backTo, "Your session or this form is stale — please reload the page and try again.")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		redirectWithError(w, r, backTo, "no file selected")
		return
	}
	defer file.Close()

	content, err := io.ReadAll(io.LimitReader(file, maxVolumeUploadSize+1))
	if err != nil {
		redirectWithError(w, r, backTo, "could not read upload: "+err.Error())
		return
	}
	if len(content) > maxVolumeUploadSize {
		redirectWithError(w, r, backTo, "file too large (max 10 MiB)")
		return
	}

	tc, ok := a.tunnels.get(hostID)
	if !ok {
		redirectWithError(w, r, backTo, "this host is not currently connected")
		return
	}
	destRelPath := path.Join(dirPath, header.Filename)
	result, err := tc.sendVolumeCommand(r.Context(), "volume_write", name, volumeContainerPath(destRelPath), "", base64.StdEncoding.EncodeToString(content))
	if err != nil || !result.OK {
		msg := errString(err, result.Output)
		redirectWithError(w, r, backTo, "upload failed: "+msg)
		return
	}
	http.Redirect(w, r, backTo, http.StatusSeeOther)
}

// volumeBrowseEditHandler serves GET
// /volumes/{hostID}/{name}/browse/edit -- fetches a file's content for
// the edit form. Refuses anything over maxVolumeEditSize or that
// doesn't look like text (a NUL byte or invalid UTF-8 in the first
// chunk) rather than handing a browser textarea a wall of binary junk.
func (a *app) volumeBrowseEditHandler(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("hostID")
	name := r.PathValue("name")
	if !a.volumeExists(hostID, name) {
		http.NotFound(w, r)
		return
	}
	relPath := r.URL.Query().Get("path")
	backTo := fmt.Sprintf("/volumes/%s/%s/browse?path=%s", hostID, name, url.QueryEscape(path.Dir("/"+relPath)))

	tc, ok := a.tunnels.get(hostID)
	if !ok {
		redirectWithError(w, r, backTo, "this host is not currently connected")
		return
	}
	result, err := tc.sendVolumeCommand(r.Context(), "volume_read", name, volumeContainerPath(relPath), "", "")
	if err != nil || !result.OK {
		msg := errString(err, result.Output)
		redirectWithError(w, r, backTo, "could not read file: "+msg)
		return
	}
	content, err := base64.StdEncoding.DecodeString(strings.TrimSpace(result.Output))
	if err != nil {
		redirectWithError(w, r, backTo, "could not decode file content")
		return
	}
	if len(content) > maxVolumeEditSize {
		redirectWithError(w, r, backTo, fmt.Sprintf("file too large to edit here (%s, max %s)", humanSize(int64(len(content))), humanSize(maxVolumeEditSize)))
		return
	}
	if !utf8.Valid(content) || strings.ContainsRune(string(content), 0) {
		redirectWithError(w, r, backTo, "this doesn't look like a text file — editing isn't offered for it")
		return
	}

	parentPath := path.Dir(relPath)
	if parentPath == "." {
		parentPath = ""
	}
	data := map[string]any{
		"Title":      "Edit · " + path.Base(relPath),
		"Nav":        "volumes",
		"HostID":     hostID,
		"VolumeName": name,
		"Path":       relPath,
		"ParentPath": parentPath,
		"Content":    string(content),
	}
	render(w, r, "layout", "volume_edit.html", data)
}

// volumeBrowseSaveHandler serves POST
// /volumes/{hostID}/{name}/browse/edit -- writes the edited content
// straight back over the same path.
func (a *app) volumeBrowseSaveHandler(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("hostID")
	name := r.PathValue("name")
	if !a.volumeExists(hostID, name) {
		http.NotFound(w, r)
		return
	}
	relPath := r.FormValue("path")
	content := r.FormValue("content")
	backTo := fmt.Sprintf("/volumes/%s/%s/browse?path=%s", hostID, name, url.QueryEscape(path.Dir("/"+relPath)))

	if len(content) > maxVolumeEditSize {
		redirectWithError(w, r, backTo, "content too large to save here")
		return
	}
	tc, ok := a.tunnels.get(hostID)
	if !ok {
		redirectWithError(w, r, backTo, "this host is not currently connected")
		return
	}
	result, err := tc.sendVolumeCommand(r.Context(), "volume_write", name, volumeContainerPath(relPath), "", base64.StdEncoding.EncodeToString([]byte(content)))
	if err != nil || !result.OK {
		msg := errString(err, result.Output)
		redirectWithError(w, r, backTo, "save failed: "+msg)
		return
	}
	http.Redirect(w, r, backTo, http.StatusSeeOther)
}

// volumeBrowseDownloadHandler serves GET
// /volumes/{hostID}/{name}/browse/download -- streams a file's raw
// bytes rather than rendering a page. No size cap of its own beyond
// what already applies to any tunnel command's reply; a very large file
// realistically times out on the agent round trip before this handler
// would need to reject it separately.
func (a *app) volumeBrowseDownloadHandler(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("hostID")
	name := r.PathValue("name")
	if !a.volumeExists(hostID, name) {
		http.NotFound(w, r)
		return
	}
	relPath := r.URL.Query().Get("path")

	tc, ok := a.tunnels.get(hostID)
	if !ok {
		http.Error(w, "this host is not currently connected", http.StatusServiceUnavailable)
		return
	}
	result, err := tc.sendVolumeCommand(r.Context(), "volume_read", name, volumeContainerPath(relPath), "", "")
	if err != nil || !result.OK {
		http.Error(w, "could not read file: "+errString(err, result.Output), http.StatusInternalServerError)
		return
	}
	content, err := base64.StdEncoding.DecodeString(strings.TrimSpace(result.Output))
	if err != nil {
		http.Error(w, "could not decode file content", http.StatusInternalServerError)
		return
	}
	filename := path.Base(relPath)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filename}))
	w.Write(content)
}

// errString picks the most useful message between a Go error (e.g. a
// tunnel timeout) and a failed command's own stderr/stdout -- whichever
// actually has something to say.
func errString(err error, output string) string {
	if err != nil {
		return err.Error()
	}
	return strings.TrimSpace(output)
}
