// User management — admin-only (cf. ARCHITECTURE.md, "Séparation des
// rôles"). Every handler in this file is wrapped with requireAdmin at
// registration (main.go), not re-checked here — the same pattern
// git-connections/settings.go now follow.
package main

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"strings"
)

func (a *app) usersHandler(w http.ResponseWriter, r *http.Request) {
	users, err := a.store.ListUsers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Title": "Users",
		"Nav":   "users",
		"Users": users,
	}
	render(w, r, "layout", "users.html", data)
}

func (a *app) newUserFormHandler(w http.ResponseWriter, r *http.Request) {
	render(w, r, "layout", "user_form.html", map[string]any{
		"Title": "New user",
		"Nav":   "users",
	})
}

// createUserHandler serves POST /users. The initial password is chosen
// by the admin, same as WHARF_ADMIN_PASSWORD at first bootstrap --
// CreateUser always forces a change on next login, so this one only
// ever has to be good enough to type to the new user once.
func (a *app) createUserHandler(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	role := r.FormValue("role")
	if username == "" || password == "" {
		http.Error(w, "username and password are required", http.StatusBadRequest)
		return
	}
	if len(password) < 8 {
		http.Error(w, "password must be at least 8 characters", http.StatusBadRequest)
		return
	}
	if role != "admin" && role != "operator" {
		http.Error(w, "invalid role", http.StatusBadRequest)
		return
	}
	if err := a.store.CreateUser(username, password, role); err != nil {
		http.Error(w, "could not create user (username already taken?): "+err.Error(), http.StatusConflict)
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (a *app) setUserRoleHandler(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	role := r.FormValue("role")
	if role != "admin" && role != "operator" {
		http.Error(w, "invalid role", http.StatusBadRequest)
		return
	}
	if err := a.store.SetUserRole(username, role); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (a *app) deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	if err := a.store.DeleteUser(username); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// resetUserPasswordHandler serves POST /users/{username}/reset-password.
// Generates the new password itself (crypto/rand, not admin-typed) --
// unlike account creation, there's no reason to trust an admin's own
// judgment for a value that only needs to survive being read aloud or
// pasted once before the owner is forced to replace it. Rendered
// directly rather than redirected: a redirect would have to carry the
// password in a query string or a flash cookie, both worse than just
// answering the POST with the one page that shows it.
//
// SSO-linked accounts are refused here, not just steered away from in
// users.html -- a local-password fallback for an SSO account used to be
// offered on purpose ("Set local password"), but that's gone now; an
// OIDC account signs in through the provider only.
func (a *app) resetUserPasswordHandler(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")

	if u, err := a.store.GetUserByUsername(username); err == nil && u.OIDCIssuer != "" {
		redirectWithError(w, r, "/users", "this account signs in via SSO — there's no local password to reset")
		return
	}

	b := make([]byte, 9)
	if _, err := rand.Read(b); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	newPassword := fmt.Sprintf("%x", b) // 18 hex chars -- typeable, forced to change on next login anyway

	if err := a.store.AdminResetUserPassword(username, newPassword); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	render(w, r, "layout", "user_password_reset.html", map[string]any{
		"Title":       "Password reset",
		"Nav":         "users",
		"Username":    username,
		"NewPassword": newPassword,
	})
}
