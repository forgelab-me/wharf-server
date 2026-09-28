// Manual encrypt helper for a Git stack's secrets.enc.yaml (age or SOPS),
// admin-only. Paste or upload plaintext, pick a public key, get back
// ciphertext to copy or download. Stateless: nothing here is ever
// written to the store.
package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/forgelab-me/wharf-server/internal/keys"
)

// maxSecretsToolInputSize caps the plaintext this ever handles -- a
// secrets file is a handful of env vars, never a real upload.
const maxSecretsToolInputSize = 1 * 1024 * 1024 // 1 MiB

// secretsToolFormHandler serves GET /tools/secrets. ?stack=<id>
// pre-selects that stack in the picker and fills in its public key.
func (a *app) secretsToolFormHandler(w http.ResponseWriter, r *http.Request) {
	stacks, err := a.store.ListStacks()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Title":  "Encrypt secrets",
		"Nav":    "secrets-tool",
		"Stacks": stacks,
	}
	if stackID := r.URL.Query().Get("stack"); stackID != "" {
		if st, err := a.store.GetStack(stackID); err == nil {
			data["SelectedStackID"] = st.ID
			data["PublicKey"] = st.PublicKey
		}
	}
	render(w, r, "layout", "secrets_tool.html", data)
}

// encryptSecretsToolHandler serves POST /tools/secrets/encrypt. Renders
// the form back with an Error banner or a Result section rather than
// redirecting, so a validation error doesn't lose the pasted textarea.
func (a *app) encryptSecretsToolHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxSecretsToolInputSize+1<<20) // +1MiB of multipart overhead headroom
	if err := r.ParseMultipartForm(maxSecretsToolInputSize); err != nil {
		a.renderSecretsTool(w, r, "", "", "input too large or invalid (max 1 MiB)")
		return
	}
	// Multipart requests skip requireAuth's CSRF check; verified here
	// instead, same pattern as volumeBrowseUploadHandler.
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || !verifyCSRF(cookie.Value, r.FormValue("csrf_token")) {
		a.renderSecretsTool(w, r, "", "", "Your session or this form is stale — please reload the page and try again.")
		return
	}

	publicKey := strings.TrimSpace(r.FormValue("public_key"))
	format := r.FormValue("format")
	if format != "sops" {
		format = "age"
	}

	plaintext, pastedContent, err := secretsToolInput(r)
	if err != nil {
		a.renderSecretsTool(w, r, pastedContent, publicKey, err.Error())
		return
	}
	if len(plaintext) == 0 {
		a.renderSecretsTool(w, r, pastedContent, publicKey, "paste some content or choose a file first")
		return
	}
	if publicKey == "" {
		a.renderSecretsTool(w, r, pastedContent, publicKey, "a public key is required — pick a stack or paste one")
		return
	}

	var ciphertext []byte
	if format == "sops" {
		ciphertext, err = keys.EncryptSOPS(plaintext, publicKey)
	} else {
		ciphertext, err = keys.EncryptToRecipient(plaintext, publicKey)
	}
	if err != nil {
		a.renderSecretsTool(w, r, pastedContent, publicKey, "encryption failed: "+err.Error())
		return
	}

	// Never the plaintext or the ciphertext -- only that the action happened.
	a.audit(r, "secrets.encrypt_helper", "", format)

	stacks, listErr := a.store.ListStacks()
	if listErr != nil {
		http.Error(w, listErr.Error(), http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Title":     "Encrypt secrets",
		"Nav":       "secrets-tool",
		"Stacks":    stacks,
		"Content":   pastedContent,
		"PublicKey": publicKey,
		"Format":    format,
		"Result":    string(ciphertext),
	}
	render(w, r, "layout", "secrets_tool.html", data)
}

// secretsToolInput reads the uploaded file if present, otherwise the
// pasted textarea. pastedContent is returned separately so the textarea
// can be re-populated on a validation error (never done for a file).
func secretsToolInput(r *http.Request) (plaintext []byte, pastedContent string, err error) {
	if file, _, ferr := r.FormFile("file"); ferr == nil {
		defer file.Close()
		content, readErr := io.ReadAll(io.LimitReader(file, maxSecretsToolInputSize+1))
		if readErr != nil {
			return nil, "", readErr
		}
		if len(content) > maxSecretsToolInputSize {
			return nil, "", fmt.Errorf("file too large (max 1 MiB)")
		}
		return content, "", nil
	}
	content := r.FormValue("content")
	return []byte(content), content, nil
}

func (a *app) renderSecretsTool(w http.ResponseWriter, r *http.Request, content, publicKey, errMsg string) {
	stacks, err := a.store.ListStacks()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Title":     "Encrypt secrets",
		"Nav":       "secrets-tool",
		"Stacks":    stacks,
		"Content":   content,
		"PublicKey": publicKey,
		"Error":     errMsg,
	}
	render(w, r, "layout", "secrets_tool.html", data)
}
