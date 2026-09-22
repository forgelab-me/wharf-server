// UI-facing stack management (/stacks) -- create/edit/deploy/undeploy/
// delete, trigger mode (manual/webhook/polling), revision history for a
// local stack's compose file, and the webhook receiver a Git host calls
// into. The admin-facing counterpart to agent_protocol.go's :8443
// commandsHandler, which is what actually hands a queued deployment to
// an agent.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/forgelab-me/wharf-server/internal/store"
)

// stackRow is the stacks-list view model — deployment history doesn't
// exist yet (no agent), so status/sha are always the "never deployed"
// placeholder for now.
type stackRow struct {
	ID, Name, Host, Trigger, LastStatusClass, LastStatusLabel, LastSha string
}

func (a *app) stacksHandler(w http.ResponseWriter, r *http.Request) {
	stacks, err := a.store.ListStacks()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows := make([]stackRow, 0, len(stacks))
	for _, s := range stacks {
		row := stackRow{
			ID: s.ID, Name: s.Name, Host: a.hostLabel(s.Host), Trigger: s.Trigger,
			LastStatusClass: "never", LastStatusLabel: "never deployed", LastSha: "—",
		}
		if dep, ok, err := a.store.LatestDeploymentForStack(s.ID); err == nil && ok {
			row.LastStatusClass = dep.Status
			row.LastStatusLabel = dep.Status
		}
		// Only ever populated for a polling-mode stack -- the last commit
		// its own poll loop saw (cf. poller.go's RecordPoll), not
		// necessarily what's actually running if a deploy since then
		// failed. Manual/webhook-triggered git stacks have no commit
		// tracked anywhere yet (the agent never reports one back), so
		// they correctly stay "—" rather than showing something stale or
		// guessed.
		if s.LastPolledSHA != "" {
			row.LastSha = shortDigest(s.LastPolledSHA)
		}
		rows = append(rows, row)
	}
	data := map[string]any{
		"Title":  "Stacks",
		"Nav":    "stacks",
		"Stacks": rows,
	}
	render(w, r, "layout", "stacks.html", data)
}

func (a *app) newStackFormHandler(w http.ResponseWriter, r *http.Request) {
	all, err := a.store.ListHosts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var connected []store.Host
	for _, h := range all {
		if h.Status == "connected" {
			connected = append(connected, h)
		}
	}
	connections, err := a.store.ListGitConnections()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Title":       "New stack",
		"Nav":         "stacks",
		"Hosts":       connected,
		"Connections": connections,
	}
	render(w, r, "layout", "stack_form.html", data)
}

// editStackFormHandler serves GET /stacks/{id}/edit — local stacks only.
// A Git stack's compose file lives in its repo; editing it through the
// UI would undermine the whole point of GitOps for that stack, so this
// form doesn't offer that path at all.
func (a *app) editStackFormHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, err := a.store.GetStack(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if st.SourceType != "local" {
		http.Error(w, "only local stacks can be edited here — a Git stack's compose file lives in its repo", http.StatusBadRequest)
		return
	}
	data := map[string]any{
		"Title": "Edit " + st.Name,
		"Nav":   "stacks",
		"Stack": st,
	}
	render(w, r, "layout", "stack_edit.html", data)
}

// updateStackHandler serves POST /stacks/{id}/edit. Only ever changes
// compose_content — not secrets, not trigger, not host — keeping this
// chunk to exactly what was asked for. The prior content is always
// recorded as a revision first, even if the new content turns out to be
// identical, so "how many times has this been edited" stays honest.
func (a *app) updateStackHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, err := a.store.GetStack(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if st.SourceType != "local" {
		http.Error(w, "only local stacks can be edited here", http.StatusBadRequest)
		return
	}
	newContent := r.FormValue("compose_content")

	if err := a.store.RecordStackRevision(id, st.ComposeContent); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.store.UpdateStackCompose(id, newContent); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.audit(r, "stack.compose_update", st.Name, "")
	redirectWithSavedMessage(w, r, "/stacks/"+id, "Compose file saved")
}

// updateStackSecretHandler serves POST /stacks/{id}/secrets — local
// stacks only, same scoping reason as compose editing. Two distinct
// actions on purpose, not one form that treats blank-and-submit as
// "clear everything": the textarea is never pre-filled with existing
// values (cf. "aucun endpoint ne renvoie jamais la valeur d'un secret
// après stockage", ARCHITECTURE.md), so a blank submit is far more
// likely an accidental click than a deliberate wipe. action=clear is
// the only way to actually remove all secrets; action=save with an
// empty textarea is rejected instead of silently doing that.
func (a *app) updateStackSecretHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, err := a.store.GetStack(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if st.SourceType != "local" {
		http.Error(w, "only local stacks can have secrets managed here", http.StatusBadRequest)
		return
	}

	if r.FormValue("action") == "clear" {
		if err := a.store.UpdateStackSecret(id, nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		a.audit(r, "stack.secrets_clear", st.Name, "")
		redirectWithSaved(w, r, "/stacks/"+id)
		return
	}

	secrets := r.FormValue("secrets")
	if strings.TrimSpace(secrets) == "" {
		http.Error(w, "no secrets entered — use \"Remove all secrets\" if that's what you meant", http.StatusBadRequest)
		return
	}
	ciphertext, err := a.keys.Encrypt(id, []byte(secrets))
	if err != nil {
		http.Error(w, "could not encrypt secrets: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.store.UpdateStackSecret(id, ciphertext); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Never the values themselves -- only that a save happened, same
	// boundary the rest of this app already holds (cf. ARCHITECTURE.md,
	// "aucun endpoint ne renvoie jamais la valeur d'un secret").
	a.audit(r, "stack.secrets_update", st.Name, "")
	redirectWithSaved(w, r, "/stacks/"+id)
}

// restoreStackRevisionHandler serves POST
// /stacks/{id}/revisions/{revisionID}/restore. Restoring is itself
// undoable: the current content is recorded as a new revision before
// being overwritten, so restoring never destroys anything, it just adds
// to the history.
func (a *app) restoreStackRevisionHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	revID, err := strconv.ParseInt(r.PathValue("revisionID"), 10, 64)
	if err != nil {
		http.Error(w, "invalid revision id", http.StatusBadRequest)
		return
	}
	st, err := a.store.GetStack(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if st.SourceType != "local" {
		http.Error(w, "only local stacks have revision history", http.StatusBadRequest)
		return
	}
	rev, err := a.store.GetStackRevision(id, revID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if err := a.store.RecordStackRevision(id, st.ComposeContent); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.store.UpdateStackCompose(id, rev.ComposeContent); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.audit(r, "stack.revision_restore", st.Name, fmt.Sprintf("revision %d", revID))
	redirectWithSavedMessage(w, r, "/stacks/"+id, "Revision restored")
}

func (a *app) createStackHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	id := slugify(name)
	if id == "" {
		http.Error(w, "missing or invalid stack name", http.StatusBadRequest)
		return
	}

	sourceType := r.FormValue("source")
	if sourceType != "local" {
		sourceType = "git" // default/fallback
	}

	trigger := r.FormValue("trigger")
	if trigger != "webhook" && trigger != "polling" {
		trigger = "manual"
	}

	var pollSchedule string
	if trigger == "polling" {
		pollSchedule = strings.TrimSpace(r.FormValue("poll_schedule"))
		if _, err := cronParser.Parse(pollSchedule); err != nil {
			http.Error(w, "invalid cron schedule: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	st := store.Stack{
		ID:           id,
		Name:         name,
		SourceType:   sourceType,
		Host:         r.FormValue("host"),
		Trigger:      trigger,
		ComposePath:  r.FormValue("compose_path"),
		Repo:         r.FormValue("repo"),
		Branch:       r.FormValue("branch"),
		PollSchedule: pollSchedule,
	}

	if sourceType == "git" {
		secret, err := randomHex(32)
		if err != nil {
			http.Error(w, "could not generate webhook secret: "+err.Error(), http.StatusInternalServerError)
			return
		}
		st.WebhookSecret = secret
	}

	if sourceType == "local" {
		st.ComposeContent = r.FormValue("compose_content")
	}

	pub, err := a.keys.GenerateKeypair(id)
	if err != nil {
		http.Error(w, "could not generate key: "+err.Error(), http.StatusInternalServerError)
		return
	}
	st.PublicKey = pub

	if sourceType == "local" {
		if secrets := r.FormValue("secrets"); secrets != "" {
			ciphertext, err := a.keys.Encrypt(id, []byte(secrets))
			if err != nil {
				http.Error(w, "could not encrypt secrets: "+err.Error(), http.StatusInternalServerError)
				return
			}
			st.EncryptedSecret = ciphertext
			// Le clair (variable `secrets`) n'est jamais écrit nulle part
			// à partir d'ici — seul `ciphertext` rejoint le store.
		}
	} else if connID := r.FormValue("git_connection_id"); connID != "" {
		if _, err := a.store.GetGitConnection(connID); err != nil {
			http.Error(w, "unknown git connection: "+err.Error(), http.StatusBadRequest)
			return
		}
		st.GitConnectionID = connID
	} else {
		sshPub, err := a.keys.GenerateSSHKeypair(id)
		if err != nil {
			http.Error(w, "could not generate deploy key: "+err.Error(), http.StatusInternalServerError)
			return
		}
		st.SSHPublicKey = sshPub
	}

	if err := a.store.CreateStack(st); err != nil {
		http.Error(w, "could not create stack (name already taken?): "+err.Error(), http.StatusConflict)
		return
	}

	if trigger == "polling" {
		// Live immediately, no controller restart needed — AddFunc is
		// safe to call on an already-running scheduler.
		if err := registerPolling(a, st); err != nil {
			log.Println("register polling for new stack", st.ID, "failed:", err)
		}
	}

	a.audit(r, "stack.create", name, sourceType+" stack, trigger "+trigger)
	http.Redirect(w, r, "/stacks/"+id, http.StatusSeeOther)
}

func (a *app) stackViewHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, err := a.store.GetStack(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := map[string]any{
		"Title":     st.Name,
		"Nav":       "stacks",
		"Stack":     st,
		"HostLabel": a.hostLabel(st.Host),
	}
	if dep, ok, err := a.store.LatestDeploymentForStack(id); err == nil && ok {
		data["Deployment"] = dep
	}
	if rows, err := imagePolicyViewRows(a, id); err == nil {
		data["ImagePolicies"] = rows
	}
	if rows, err := stackContainerRows(a, id); err == nil {
		data["Containers"] = rows
	}
	if st.SourceType == "git" && st.GitConnectionID != "" {
		// A stack on a shared connection never has its own SSHPublicKey
		// (cf. createStackHandler) -- the template shows the connection's
		// own key instead of an always-empty stack-specific one.
		if conn, err := a.store.GetGitConnection(st.GitConnectionID); err == nil {
			data["GitConnection"] = conn
			if conn.AuthKind == "ssh_key" {
				if pub, err := a.keys.ConnectionSSHPublicKey(conn.ID); err == nil {
					data["ConnectionPublicKey"] = pub
				}
			}
		}
	}
	if st.SourceType == "local" {
		if revs, err := a.store.ListStackRevisions(id); err == nil {
			data["Revisions"] = revs
		}
		// Key names only, never values -- same stackSecrets used to mask
		// env vars by value on the container detail page
		// (server/containers.go). maskAll is meaningless for a local
		// stack (only ever true for git stacks), so it's discarded here.
		if secrets, _ := stackSecrets(a, id); len(secrets) > 0 {
			names := make([]string, 0, len(secrets))
			for k := range secrets {
				names = append(names, k)
			}
			sort.Strings(names)
			data["SecretKeys"] = names
		}
	}
	if st.Trigger == "webhook" {
		// Same derivation heuristic as hostsHandler's agent-channel
		// address: best-effort from the request's own Host, pointed at
		// :9443 since a real internet-facing webhook needs HTTPS.
		host, _, splitErr := net.SplitHostPort(r.Host)
		if splitErr != nil {
			host = r.Host
		}
		data["WebhookURL"] = fmt.Sprintf("https://%s:9443/hooks/%s", host, st.ID)
	}
	render(w, r, "layout", "stack_view.html", data)
}

// deploymentStatusHandler serves GET /stacks/{id}/deployment-status --
// a tiny JSON poll target for the stack page's own script, so it can
// notice a deploy/undeploy finishing (queued/running -> succeeded/
// failed) without the user having to reload the page themselves to
// find out. Not meant for anything but that one script; no auth
// concerns beyond the same session check every other UI route already
// gets from requireAuth.
func (a *app) deploymentStatusHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dep, ok, err := a.store.LatestDeploymentForStack(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if !ok {
		json.NewEncoder(w).Encode(struct {
			Status string `json:"status"`
		}{Status: ""})
		return
	}
	json.NewEncoder(w).Encode(struct {
		Status string `json:"status"`
		Action string `json:"action"`
	}{Status: dep.Status, Action: dep.Action})
}

// setPollScheduleHandler serves POST /stacks/{id}/poll-schedule -- there
// was no way to change a polling-mode stack's cron expression after
// creation until now. Validated with the same parser createStackHandler
// already uses, then re-registered on the live scheduler immediately
// (registerPolling replaces the stack's existing cron entry rather than
// adding a second one, cf. poller.go) -- no controller restart needed,
// same as a brand new polling stack.
func (a *app) setPollScheduleHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, err := a.store.GetStack(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if st.Trigger != "polling" {
		http.Error(w, "this stack is not in polling mode", http.StatusBadRequest)
		return
	}
	schedule := strings.TrimSpace(r.FormValue("poll_schedule"))
	if _, err := cronParser.Parse(schedule); err != nil {
		http.Error(w, "invalid cron schedule: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := a.store.SetPollSchedule(id, schedule); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	st.PollSchedule = schedule
	if err := registerPolling(a, st); err != nil {
		http.Error(w, "schedule saved but could not be applied: "+err.Error(), http.StatusInternalServerError)
		return
	}
	a.audit(r, "stack.poll_schedule_change", st.Name, schedule)
	redirectWithSaved(w, r, "/stacks/"+id)
}

// setStackTriggerHandler serves POST /stacks/{id}/trigger -- there was no
// way to change a stack's trigger mode after creation until now, only
// its schedule/secret once already in that mode (cf. setPollScheduleHandler
// above, hooksHandler below). Git stacks only: manual/webhook/polling all
// key off having a repository to check or receive a hook for, which a
// local stack doesn't have (cf. createStackHandler's own webhook-secret
// generation, git-only for the same reason).
func (a *app) setStackTriggerHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, err := a.store.GetStack(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if st.SourceType != "git" {
		redirectWithError(w, r, "/stacks/"+id, "only Git stacks can use a webhook or polling trigger")
		return
	}
	trigger := r.FormValue("trigger")
	if trigger != "manual" && trigger != "webhook" && trigger != "polling" {
		redirectWithError(w, r, "/stacks/"+id, "invalid trigger")
		return
	}

	// Preserve whatever this stack already had -- toggling back to a mode
	// it was in before (e.g. webhook -> manual -> webhook) shouldn't force
	// re-pasting a new secret into the Git host, or re-picking a schedule
	// that was already fine. Only generate/default when there's nothing
	// to preserve.
	pollSchedule := st.PollSchedule
	webhookSecret := st.WebhookSecret
	switch trigger {
	case "polling":
		if pollSchedule == "" {
			pollSchedule = "*/15 * * * *" // same cadence as the image-poller; edit right after via the schedule form below
		}
	case "webhook":
		if webhookSecret == "" {
			secret, err := randomHex(32)
			if err != nil {
				http.Error(w, "could not generate webhook secret: "+err.Error(), http.StatusInternalServerError)
				return
			}
			webhookSecret = secret
		}
	}

	if err := a.store.UpdateStackTrigger(id, trigger, pollSchedule, webhookSecret); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if trigger == "polling" {
		st.Trigger, st.PollSchedule = trigger, pollSchedule
		if err := registerPolling(a, st); err != nil {
			http.Error(w, "trigger saved but could not be scheduled: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		unregisterPolling(a, id)
	}
	a.audit(r, "stack.trigger_change", st.Name, trigger)
	redirectWithSaved(w, r, "/stacks/"+id)
}

// renameStackHandler serves POST /stacks/{id}/rename.
func (a *app) renameStackHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		redirectWithError(w, r, "/stacks/"+id, "name can't be empty")
		return
	}
	if err := a.store.RenameStack(id, name); err != nil {
		redirectWithError(w, r, "/stacks/"+id, err.Error())
		return
	}
	a.audit(r, "stack.rename", id, name)
	redirectWithSaved(w, r, "/stacks/"+id)
}

// forcePollHandler serves POST /stacks/{id}/poll-now -- runs the exact
// same check the cron schedule would (pollStack), synchronously, so an
// admin doesn't have to wait for or fiddle with the schedule just to see
// "did it move?" right now. Enqueues a deploy exactly like a real
// scheduled tick would if the remote HEAD moved since the last check --
// this is not a preview/dry-run, it's the real poll running early.
func (a *app) forcePollHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, err := a.store.GetStack(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if st.Trigger != "polling" {
		http.Error(w, "this stack is not in polling mode", http.StatusBadRequest)
		return
	}
	pollStack(a, id)
	a.audit(r, "stack.poll_now", st.Name, "")
	redirectWithSavedMessage(w, r, "/stacks/"+id, "Poll triggered")
}

// hooksHandler serves POST /hooks/{id} — the webhook receiver, on the UI
// ports rather than the agent mTLS channel: the caller is GitHub/GitLab's
// own servers, not an enrolled agent, so authentication is a shared
// secret rather than a pinned client certificate. Accepts whichever of
// three schemes the caller sends: GitHub's HMAC-SHA256 signature,
// GitLab's plain token header, or a generic shared-secret header for
// anything else. Cf. ARCHITECTURE.md, "Déclenchement du déploiement".
func (a *app) hooksHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, err := a.store.GetStack(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if st.Trigger != "webhook" || st.WebhookSecret == "" {
		http.Error(w, "webhook not enabled for this stack", http.StatusNotFound)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "could not read body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if !verifyWebhookAuth(r, body, st.WebhookSecret) {
		http.Error(w, "invalid or missing signature", http.StatusUnauthorized)
		return
	}

	if st.Host == "" {
		http.Error(w, "this stack has no target host assigned", http.StatusBadRequest)
		return
	}
	if _, err := a.store.EnqueueDeployment(st.ID, st.Host, "webhook", "up"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Not a.audit(r, ...): this request never went through requireAuth, so
	// there's no session username in context to attribute it to -- logged
	// under a fixed "webhook" actor instead of a blank one.
	if err := a.store.RecordAudit("webhook", "stack.deploy_webhook", st.Name, ""); err != nil {
		log.Println("audit:", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// verifyWebhookAuth checks whichever of the three provider schemes is
// present against secret, blind to which provider actually sent the
// request. Blind trigger: the payload itself is never parsed — a stack
// has exactly one configured branch, so any authenticated call just
// re-enqueues that stack's deploy (cf. the plan for this chunk).
func verifyWebhookAuth(r *http.Request, body []byte, secret string) bool {
	if sig := r.Header.Get("X-Hub-Signature-256"); sig != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		return subtle.ConstantTimeCompare([]byte(sig), []byte(want)) == 1
	}
	if tok := r.Header.Get("X-Gitlab-Token"); tok != "" {
		return subtle.ConstantTimeCompare([]byte(tok), []byte(secret)) == 1
	}
	if tok := r.Header.Get("X-Webhook-Secret"); tok != "" {
		return subtle.ConstantTimeCompare([]byte(tok), []byte(secret)) == 1
	}
	return false
}

// deployStackHandler serves POST /stacks/{id}/deploy — the "Deploy now"
// button.
func (a *app) deployStackHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, err := a.store.GetStack(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if st.Host == "" {
		http.Error(w, "this stack has no target host assigned", http.StatusBadRequest)
		return
	}
	if _, err := a.store.EnqueueDeployment(st.ID, st.Host, "manual", "up"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.audit(r, "stack.deploy", st.Name, "")
	redirectWithSavedMessage(w, r, "/stacks/"+id, "Deployment queued")
}

// undeployStackHandler serves POST /stacks/{id}/undeploy — the "Undeploy"
// button. Reuses the same command channel as deploy (action="down"
// instead of "up"); the agent tears down whatever is already on disk
// from the last deploy rather than re-cloning, so a revoked Git
// credential never blocks tearing a stack down. Cf. the plan for this
// chunk in ARCHITECTURE.md's history.
func (a *app) undeployStackHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, err := a.store.GetStack(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if st.Host == "" {
		redirectWithError(w, r, "/stacks/"+id, "this stack has no target host assigned")
		return
	}
	if _, err := a.store.EnqueueDeployment(st.ID, st.Host, "manual", "down"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.audit(r, "stack.undeploy", st.Name, "")
	redirectWithSavedMessage(w, r, "/stacks/"+id, "Undeploy queued")
}

// deleteStackHandler serves POST /stacks/{id}/delete. Refuses to delete
// a stack whose latest known deployment looks like it might still be
// running (action "up", status "succeeded") — Undeploy first is the
// required path, rather than this handler trying to orchestrate an
// implicit async teardown-then-delete. Also refuses while a deployment
// is merely queued/running, whatever its action: DeleteStack cascades
// into the deployments table, and deleting a just-enqueued "down" before
// the agent ever claims it would silently wipe the only record of that
// teardown, orphaning a running container with no stack left to undeploy
// it from (caught by testing — Undeploy then an immediate Delete raced
// the agent's own poll tick). A stack that was never successfully
// deployed (failed, or already undeployed) deletes clean.
func (a *app) deleteStackHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, err := a.store.GetStack(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if dep, ok, err := a.store.LatestDeploymentForStack(id); err == nil && ok {
		switch {
		case dep.Status == "queued" || dep.Status == "running":
			redirectWithError(w, r, "/stacks/"+id, "a deployment is in progress for this stack — wait for it to finish before deleting")
			return
		case dep.Action == "up" && dep.Status == "succeeded":
			redirectWithError(w, r, "/stacks/"+id, "undeploy this stack before deleting it")
			return
		}
	}
	if err := a.keys.DeleteStackKeys(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.store.DeleteStack(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.audit(r, "stack.delete", st.Name, "")
	redirectWithSavedMessage(w, r, "/stacks", "Stack deleted")
}
