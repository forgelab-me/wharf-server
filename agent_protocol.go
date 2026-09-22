// The agent-facing side of the mTLS channel (:8443) -- enrollment and
// everything an already-enrolled agent calls to claim and report on a
// deployment. Distinct from hosts.go (the admin-facing /hosts UI) and
// stacks.go (the admin-facing /stacks UI): the caller here is never a
// logged-in browser session, always a client certificate Wharf itself
// pinned during enrollment, verified by verifyCaller before any of this
// trusts what the request claims about itself.
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/forgelab-me/wharf-server/internal/identity"
	"github.com/forgelab-me/wharf-server/internal/keys"
	"github.com/forgelab-me/wharf-server/internal/store"
)

type enrollRequest struct {
	Hostname string `json:"hostname"`
}

type enrollResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// callerFingerprint reads the certificate that actually backed this TLS
// connection — never a client-supplied field — and returns its
// fingerprint. Security fix vs. the initial enrollment chunk: that first
// pass trusted a `cert_pem` JSON field with no cryptographic link to the
// connection at all.
func callerFingerprint(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", fmt.Errorf("no client certificate presented")
	}
	return identity.Fingerprint(r.TLS.PeerCertificates[0].Raw), nil
}

// verifyCaller checks that the certificate backing this connection
// belongs to hostID — used by every :8443 handler after enrollment so an
// agent can only ever poll/report for itself.
func verifyCaller(r *http.Request, st *store.Store, hostID string) error {
	fp, err := callerFingerprint(r)
	if err != nil {
		return err
	}
	h, err := st.GetHost(hostID)
	if err != nil {
		return err
	}
	if h.CertFingerprint != fp {
		return fmt.Errorf("certificate does not match host %q", hostID)
	}
	return nil
}

// enrollCreateHandler serves POST /agent/enrollments on the agent channel
// (:8443) — never gated by an accepted client certificate since the agent
// has no accepted identity yet at this point. Cf. ARCHITECTURE.md,
// "connect-first, approve-later". The fingerprint comes from the TLS
// connection itself (see callerFingerprint), not from anything the client
// claims in the body.
func (a *app) enrollCreateHandler(w http.ResponseWriter, r *http.Request) {
	fp, err := callerFingerprint(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var req enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	hostname := strings.TrimSpace(req.Hostname)
	if hostname == "" {
		hostname = "agent"
	}

	h, created, err := a.store.UpsertHostByFingerprint(hostname, fp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if created {
		w.WriteHeader(http.StatusCreated)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	json.NewEncoder(w).Encode(enrollResponse{ID: h.ID, Status: h.Status})
}

// enrollStatusHandler serves GET /agent/enrollments/{id} — the agent calls
// this in a loop once enrolled; it doubles as a lightweight heartbeat
// (last_seen_at). 404 if the id is unknown (e.g. the database was reset),
// an explicit signal for the agent to re-enroll instead of polling
// forever; 403 if the caller's certificate doesn't match this host.
// enrollStatusHandler serves GET /agent/enrollments/{id}. Existence is
// checked before the certificate match: if the id itself is unknown
// (e.g. the controller's DB was reset or the host was removed), the
// agent needs a real 404 to trigger its own re-enrollment (cf.
// pollLoop's re-enroll-on-404 logic) — checking the cert first, as a
// prior version did, turned an unknown id into a 403 instead, and an
// agent stuck in that state could never self-heal. Neither id existence
// nor status is sensitive: both already appear in the plaintext
// docker-run snippet the UI hands out.
func (a *app) enrollStatusHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := a.store.GetHost(id); errors.Is(err, store.ErrNotFound) {
		http.Error(w, "unknown enrollment id", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := verifyCaller(r, a.store, id); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	h, err := a.store.TouchHost(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(enrollResponse{ID: h.ID, Status: h.Status})
}

// commandsHandler serves GET /agent/commands — the calling agent (verified
// by TLS client certificate) claims its next queued deployment, if any.
// Local stacks get their secrets decrypted right here, server-side (the
// controller already holds the ciphertext from creation); Git stacks get
// a deploy key and clone parameters instead — the agent discovers and
// relays secrets.enc.yaml itself via /agent/decrypt after cloning.
func (a *app) commandsHandler(w http.ResponseWriter, r *http.Request) {
	fp, err := callerFingerprint(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	host, err := a.store.GetHostByFingerprint(fp)
	if err != nil {
		http.Error(w, "unknown caller", http.StatusForbidden)
		return
	}

	dep, ok, err := a.store.ClaimNextDeployment(host.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	st, err := a.store.GetStack(dep.StackID)
	if err != nil {
		_ = a.store.CompleteDeployment(dep.ID, "failed", "stack no longer exists: "+err.Error())
		a.notifyDeploymentFailed(dep.StackID, "stack no longer exists: "+err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := struct {
		DeploymentID   string                       `json:"deployment_id"`
		StackID        string                       `json:"stack_id"`
		SourceType     string                       `json:"source_type"`
		Action         string                       `json:"action"`
		ComposeContent string                       `json:"compose_content,omitempty"`
		Env            map[string]string            `json:"env,omitempty"`
		RepoURL        string                       `json:"repo_url,omitempty"`
		Branch         string                       `json:"branch,omitempty"`
		ComposePath    string                       `json:"compose_path,omitempty"`
		AuthKind       string                       `json:"auth_kind,omitempty"`
		SSHPrivateKey  string                       `json:"ssh_private_key,omitempty"`
		HTTPUsername   string                       `json:"http_username,omitempty"`
		HTTPPassword   string                       `json:"http_password,omitempty"`
		RegistryAuths  map[string]keys.RegistryAuth `json:"registry_auths,omitempty"`
	}{
		DeploymentID: dep.ID,
		StackID:      st.ID,
		SourceType:   st.SourceType,
		Action:       dep.Action,
	}

	// Every configured registry credential rides along on every deploy
	// that isn't a teardown -- not just the ones a compose file happens
	// to reference. For a local stack Wharf could in principle parse
	// resp.ComposeContent and filter, but a Git stack's compose isn't
	// known here at all (the agent hasn't cloned yet, cf. the RepoURL
	// branch above) -- there's no way to filter precisely for one source
	// type without the other silently getting everything anyway, so
	// both get everything, same as a real Docker host's persistent
	// `~/.docker/config.json` logins aren't scoped per compose file
	// either.
	if dep.Action != "down" {
		auths, err := a.keys.AllRegistryCredentials()
		if err != nil {
			_ = a.store.CompleteDeployment(dep.ID, "failed", "could not load registry credentials: "+err.Error())
			a.notifyDeploymentFailed(st.Name, "could not load registry credentials: "+err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(auths) > 0 {
			resp.RegistryAuths = auths
		}
	}

	if st.SourceType == "git" {
		resp.RepoURL = st.Repo
		resp.Branch = st.Branch
		resp.ComposePath = st.ComposePath

		// Teardown never clones -- no credential fetched or sent, so a
		// revoked deploy key/connection never blocks an undeploy. cf. the
		// plan for this chunk.
		if dep.Action != "down" {
			authKind, sshPriv, httpUser, httpPass, err := a.resolveGitAuth(st)
			if err != nil {
				_ = a.store.CompleteDeployment(dep.ID, "failed", "could not load git credential: "+err.Error())
				a.notifyDeploymentFailed(st.Name, "could not load git credential: "+err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			resp.AuthKind = authKind
			resp.SSHPrivateKey = sshPriv
			resp.HTTPUsername = httpUser
			resp.HTTPPassword = httpPass
		}
	} else {
		// Local stack: sent even for a "down" (cheap, and covers the case
		// where the on-disk copy was somehow lost) but never re-decrypted
		// -- teardown doesn't need secret values.
		resp.ComposeContent = st.ComposeContent
		if dep.Action != "down" {
			env := map[string]string{}
			if len(st.EncryptedSecret) > 0 {
				plaintext, err := a.keys.Decrypt(st.ID, st.EncryptedSecret)
				if err != nil {
					_ = a.store.CompleteDeployment(dep.ID, "failed", "could not decrypt secrets: "+err.Error())
					a.notifyDeploymentFailed(st.Name, "could not decrypt secrets: "+err.Error())
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				env = parseEnvLines(string(plaintext))
			}
			resp.Env = env
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// resolveGitAuth resolves the actual credential to hand the agent for a
// Git stack: a shared connection if the stack references one, otherwise
// the stack's own dedicated SSH key (the only path that existed before
// shared connections — unchanged for every stack created before this).
func (a *app) resolveGitAuth(st store.Stack) (authKind, sshPrivateKey, httpUsername, httpPassword string, err error) {
	if st.GitConnectionID == "" {
		priv, err := a.keys.SSHPrivateKey(st.ID)
		if err != nil {
			return "", "", "", "", err
		}
		return "ssh_key", priv, "", "", nil
	}

	conn, err := a.store.GetGitConnection(st.GitConnectionID)
	if err != nil {
		return "", "", "", "", fmt.Errorf("load git connection: %w", err)
	}

	switch conn.AuthKind {
	case "http_password":
		user, pass, err := a.keys.ConnectionHTTPCredential(conn.ID)
		if err != nil {
			return "", "", "", "", err
		}
		return "http_password", "", user, pass, nil
	default:
		priv, err := a.keys.ConnectionSSHPrivateKey(conn.ID)
		if err != nil {
			return "", "", "", "", err
		}
		return "ssh_key", priv, "", "", nil
	}
}

// parseEnvLines parses "KEY=value" lines (blank lines and #-comments
// skipped) as produced by decrypting a stack's secrets — shared between
// the local-stack path here and the Git path in the agent itself.
func parseEnvLines(s string) map[string]string {
	env := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			env[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return env
}

// deploymentResultHandler serves POST /agent/deployments/{id}/result.
func (a *app) deploymentResultHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	dep, err := a.store.GetDeployment(id)
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

	var req struct {
		Status         string `json:"status"`
		Output         string `json:"output"`
		ComposeContent string `json:"compose_content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := a.store.CompleteDeployment(id, req.Status, req.Output); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if req.Status == "failed" {
		stackName := dep.StackID
		if st, err := a.store.GetStack(dep.StackID); err == nil {
			stackName = st.Name
		}
		a.notifyDeploymentFailed(stackName, req.Output)
	}

	// Fire-and-forget: image policy discovery/digest resync is bookkeeping
	// for the auto-update feature, not part of the deployment itself — a
	// registry hiccup here must never make an already-succeeded deployment
	// look like it failed to the agent waiting on this response.
	if req.Status == "succeeded" && req.ComposeContent != "" {
		go syncImagePolicies(a, dep.StackID, req.ComposeContent)

		// Refreshed on every successful deploy so a compose edit that adds
		// or removes a ${...} reference is reflected the very next time
		// this stack's container detail page renders -- cf. containers.go's
		// buildEnvVars, the only reader of SubstitutedEnvKeys.
		if keys, err := substitutedEnvKeys(req.ComposeContent); err == nil {
			if err := a.store.SetSubstitutedEnvKeys(dep.StackID, keys); err != nil {
				log.Println("deployment result:", dep.StackID, "set substituted env keys:", err)
			}
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// decryptHandler serves POST /agent/decrypt — the DecryptRequest/
// DecryptResponse round trip from ARCHITECTURE.md, used by Git-sourced
// deployments where the agent discovers secrets.enc.yaml itself after
// cloning (a local stack's secrets are decrypted proactively by
// commandsHandler instead, since the controller already holds the
// ciphertext there).
//
// Scoped by deployment_id, not a bare stack_id: the caller is verified
// against the deployment's own host_id, the same anchor used by
// deploymentResultHandler and the claim in commandsHandler. A bare
// stack_id would let any enrolled agent request decryption for any
// stack regardless of which host it's actually assigned to.
func (a *app) decryptHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeploymentID     string `json:"deployment_id"`
		CiphertextBase64 string `json:"ciphertext_base64"`
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

	ciphertext, err := base64.StdEncoding.DecodeString(req.CiphertextBase64)
	if err != nil {
		http.Error(w, "invalid base64 ciphertext: "+err.Error(), http.StatusBadRequest)
		return
	}

	plaintext, err := a.keys.Decrypt(dep.StackID, ciphertext)
	if err != nil {
		http.Error(w, "decrypt failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		PlaintextBase64 string `json:"plaintext_base64"`
	}{PlaintextBase64: base64.StdEncoding.EncodeToString(plaintext)})
}
