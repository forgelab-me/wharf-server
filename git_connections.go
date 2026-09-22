// Shared Git credentials (/git-connections) -- an SSH key or HTTP
// username/password several stacks can point at instead of each stack
// generating (and needing its Deploy Key re-pasted for) its own. Cf.
// ARCHITECTURE.md, "Credentials Git (accès aux repos)".
package main

import (
	"net/http"
	"strings"
)

func (a *app) gitConnectionsHandler(w http.ResponseWriter, r *http.Request) {
	connections, err := a.store.ListGitConnections()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Title":       "Git connections",
		"Nav":         "git-connections",
		"Connections": connections,
	}
	render(w, r, "layout", "git_connections.html", data)
}

func (a *app) gitConnectionViewHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	conn, err := a.store.GetGitConnection(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := map[string]any{
		"Title":      conn.Name,
		"Nav":        "git-connections",
		"Connection": conn,
	}
	if conn.AuthKind == "ssh_key" {
		pub, err := a.keys.ConnectionSSHPublicKey(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		data["PublicKey"] = pub
	} else {
		// Username isn't secret (unlike the password, never re-fetched
		// here) -- shown so the "replace credential" form can pre-fill it
		// instead of asking the user to remember and retype it.
		username, _, err := a.keys.ConnectionHTTPCredential(id)
		if err == nil {
			data["HTTPUsername"] = username
		}
	}
	inUse, err := a.store.GitConnectionInUse(id)
	if err == nil {
		data["InUse"] = inUse
	}
	render(w, r, "layout", "git_connection_view.html", data)
}

// regenerateGitConnectionKeyHandler serves POST
// /git-connections/{id}/regenerate-key -- the fix for a key that was
// generated in the wrong format (cf. ARCHITECTURE.md: Azure DevOps
// rejects the ed25519 keys Wharf used to generate) or is suspected
// compromised. Always regenerates fresh (RSA-4096, cf.
// GenerateConnectionSSHKeypair) rather than restoring an import -- a
// connection that started as an imported key becomes a generated one
// after this, same as if it were being set up for the first time. The
// old public key stops working the instant this returns; every Git
// host that had it as a Deploy Key needs the new one pasted in too,
// which is why this redirects back to the page that displays it rather
// than anywhere else.
func (a *app) regenerateGitConnectionKeyHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	conn, err := a.store.GetGitConnection(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if conn.AuthKind != "ssh_key" {
		http.Error(w, "this connection does not use an SSH key", http.StatusBadRequest)
		return
	}
	if _, err := a.keys.GenerateConnectionSSHKeypair(id); err != nil {
		http.Error(w, "could not regenerate key: "+err.Error(), http.StatusInternalServerError)
		return
	}
	a.audit(r, "git_connection.regenerate_key", conn.Name, "")
	redirectWithSavedMessage(w, r, "/git-connections/"+id, "SSH key regenerated")
}

// renameGitConnectionHandler serves POST /git-connections/{id}/rename.
func (a *app) renameGitConnectionHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		redirectWithError(w, r, "/git-connections/"+id, "name can't be empty")
		return
	}
	if err := a.store.RenameGitConnection(id, name); err != nil {
		redirectWithError(w, r, "/git-connections/"+id, err.Error())
		return
	}
	a.audit(r, "git_connection.rename", id, name)
	redirectWithSaved(w, r, "/git-connections/"+id)
}

// updateGitConnectionCredentialHandler serves POST
// /git-connections/{id}/credential -- replaces an http_password
// connection's username/password. Blank password keeps the existing
// one, same "re-typing the username shouldn't force re-typing an
// unchanged secret" pattern as the registry credential edit form.
func (a *app) updateGitConnectionCredentialHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	conn, err := a.store.GetGitConnection(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if conn.AuthKind != "http_password" {
		redirectWithError(w, r, "/git-connections/"+id, "this connection does not use a username/password credential")
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if username == "" {
		redirectWithError(w, r, "/git-connections/"+id, "username can't be empty")
		return
	}
	if password == "" {
		_, existing, err := a.keys.ConnectionHTTPCredential(id)
		if err != nil {
			redirectWithError(w, r, "/git-connections/"+id, "could not load the existing credential: "+err.Error())
			return
		}
		password = existing
	}
	if err := a.keys.ImportConnectionHTTPCredential(id, username, password); err != nil {
		redirectWithError(w, r, "/git-connections/"+id, "could not store credential: "+err.Error())
		return
	}
	a.audit(r, "git_connection.update_credential", conn.Name, "username "+username)
	redirectWithSaved(w, r, "/git-connections/"+id)
}

// deleteGitConnectionHandler serves POST /git-connections/{id}/delete --
// guarded by GitConnectionInUse the same way deleteStackHandler guards
// against deleting a still-deployed stack, so a connection several
// stacks share can't be pulled out from under them by mistake.
func (a *app) deleteGitConnectionHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	conn, err := a.store.GetGitConnection(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	inUse, err := a.store.GitConnectionInUse(id)
	if err != nil {
		redirectWithError(w, r, "/git-connections/"+id, err.Error())
		return
	}
	if inUse {
		redirectWithError(w, r, "/git-connections/"+id, "one or more stacks still use this connection — repoint them first")
		return
	}
	if err := a.keys.DeleteConnectionKeys(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.store.DeleteGitConnection(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.audit(r, "git_connection.delete", conn.Name, "")
	redirectWithSavedMessage(w, r, "/git-connections", "Git connection deleted")
}

func (a *app) newGitConnectionFormHandler(w http.ResponseWriter, r *http.Request) {
	render(w, r, "layout", "git_connection_form.html", map[string]any{
		"Title": "New Git connection",
		"Nav":   "git-connections",
	})
}

// createGitConnectionHandler covers all three credential-creation paths
// for a shared connection: generate an SSH key, import an existing SSH
// key, or import an HTTP username/password. Cf. ARCHITECTURE.md,
// "Séparation des rôles" — meant to be admin-only, but there is no real
// session/auth system yet to actually enforce that; stated here rather
// than pretended.
func (a *app) createGitConnectionHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	id := slugify(name)
	if id == "" {
		http.Error(w, "missing or invalid connection name", http.StatusBadRequest)
		return
	}

	authKind := r.FormValue("auth_kind")
	if authKind != "http_password" {
		authKind = "ssh_key"
	}

	if err := a.store.CreateGitConnection(id, name, authKind); err != nil {
		http.Error(w, "could not create connection (name already taken?): "+err.Error(), http.StatusConflict)
		return
	}

	switch authKind {
	case "http_password":
		username := r.FormValue("username")
		password := r.FormValue("password")
		if username == "" || password == "" {
			http.Error(w, "username and password are required", http.StatusBadRequest)
			return
		}
		if err := a.keys.ImportConnectionHTTPCredential(id, username, password); err != nil {
			http.Error(w, "could not store credential: "+err.Error(), http.StatusInternalServerError)
			return
		}
	default:
		if r.FormValue("key_source") == "import" {
			if _, err := a.keys.ImportConnectionSSHKey(id, r.FormValue("private_key")); err != nil {
				http.Error(w, "could not import key: "+err.Error(), http.StatusBadRequest)
				return
			}
		} else if _, err := a.keys.GenerateConnectionSSHKeypair(id); err != nil {
			http.Error(w, "could not generate key: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	a.audit(r, "git_connection.create", name, authKind)
	http.Redirect(w, r, "/git-connections/"+id, http.StatusSeeOther)
}
