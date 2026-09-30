package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/forgelab-me/wharf-server/internal/secrets"
	"github.com/forgelab-me/wharf-server/internal/store"
)

const (
	maxResolveRequestSize = 4 << 20
	maxEncFileSize        = 1 << 20
	// resolveDeadline stays under the agent's 30s HTTP client timeout.
	resolveDeadline = 25 * time.Second
)

// resolveHandler serves POST /agent/resolve: a Git-stack agent relays the
// secrets.refs.yaml (and secrets.enc.yaml, when present) it found in the
// clone, and gets back exactly the environment those references resolve to.
// Like decryptHandler it is scoped by deployment_id, and only while that
// deployment is running.
func (a *app) resolveHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxResolveRequestSize)
	var req struct {
		DeploymentID string `json:"deployment_id"`
		RefsBase64   string `json:"refs_base64"`
		EncBase64    string `json:"enc_base64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	dep, err := a.store.GetDeployment(req.DeploymentID)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "unknown deployment id", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := verifyCaller(r, a.store, dep.HostID); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if dep.Status != "running" {
		http.Error(w, "deployment is not running", http.StatusConflict)
		return
	}

	refsFile, err := base64.StdEncoding.DecodeString(req.RefsBase64)
	if err != nil {
		http.Error(w, "invalid base64 refs file: "+err.Error(), http.StatusBadRequest)
		return
	}
	encFile, err := base64.StdEncoding.DecodeString(req.EncBase64)
	if err != nil || len(encFile) > maxEncFileSize {
		http.Error(w, "invalid or oversized secrets.enc.yaml", http.StatusBadRequest)
		return
	}

	entries, err := secrets.ParseFile(refsFile)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), resolveDeadline)
	defer cancel()
	job := &secrets.Job{
		StackID:    dep.StackID,
		EncFile:    encFile,
		DecryptEnc: a.decryptEnvFile,
		Binding:    a.stackBinding(dep.StackID),
	}
	res, err := a.resolver.Resolve(ctx, job, entries)
	if err != nil {
		a.auditResolve(dep, "secrets.resolve_failed", failedKeys(err), nil)
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	a.auditResolve(dep, "secrets.resolve", entryKeys(entries), res.Sources)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Env   map[string]string `json:"env"`
		Notes []string          `json:"notes,omitempty"`
	}{Env: res.Env, Notes: res.Notes})
}

// decryptEnvFile decrypts a stack's secrets.enc.yaml into KEY -> value.
func (a *app) decryptEnvFile(stackID string, ciphertext []byte) (map[string]string, error) {
	plaintext, err := a.keys.Decrypt(stackID, ciphertext)
	if err != nil {
		return nil, err
	}
	return parseEnvLines(string(plaintext)), nil
}

// auditResolve records which keys were resolved for a deployment, and
// through which connections, never their values. Agent calls carry no
// signed-in user.
func (a *app) auditResolve(dep store.Deployment, action string, keys, sources []string) {
	detail := fmt.Sprintf("deployment %s: %s", dep.ID, strings.Join(keys, ", "))
	if len(sources) > 0 {
		detail += " (" + strings.Join(sources, "; ") + ")"
	}
	if err := a.store.RecordAudit("agent", action, dep.StackID, detail); err != nil {
		log.Println("audit:", err)
	}
}

func entryKeys(entries []secrets.Entry) []string {
	keys := make([]string, len(entries))
	for i, e := range entries {
		keys[i] = e.Key
	}
	sort.Strings(keys)
	return keys
}

func failedKeys(err error) []string {
	var rerr *secrets.ResolveError
	if !errors.As(err, &rerr) {
		return nil
	}
	keys := make([]string, len(rerr.Failures))
	for i, f := range rerr.Failures {
		keys[i] = f.Key
	}
	sort.Strings(keys)
	return keys
}
