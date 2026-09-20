// Notifications — a single configured webhook target (Slack, Discord,
// ntfy, or a generic JSON receiver) that gets a message on the handful
// of events worth knowing about without staring at the UI: a deployment
// failing, an enrolled agent going dark, an agent or the controller
// itself falling behind on updates. Cf. internal/keys.NotificationTarget
// for where the target itself is stored (the custodian, not the main
// store -- a webhook URL grants "post as this bot" to whoever holds it,
// closer to a credential than to ordinary settings).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// notificationCheckInterval covers the two periodic events (host
// disconnected, agent/server outdated) -- five minutes comfortably
// debounces a routine restart's brief reconnect gap without being slow
// to notice a real outage. Deployment failures are event-driven, not on
// this ticker at all (cf. the CompleteDeployment call sites in main.go).
const notificationCheckInterval = "*/5 * * * *"

// notifyState is this process's in-memory "have we already said this"
// tracker -- every event here is level-triggered (a host is down, an
// agent is outdated), and without this a still-down host would get a
// fresh notification on every single tick forever instead of once when
// it first goes down. Reset when the condition clears, so a *future*
// occurrence notifies again. Lost on restart, which is fine: a fresh
// process re-derives "is anything currently wrong" the first tick, it
// just doesn't remember whether it already said so before the restart.
type notifyState struct {
	mu                   sync.Mutex
	hostDown             map[string]bool
	agentOutdated        map[string]bool
	serverUpdateNotified bool
}

func newNotifyState() *notifyState {
	return &notifyState{hostDown: map[string]bool{}, agentOutdated: map[string]bool{}}
}

// registerNotificationChecks schedules the periodic check -- no
// immediate run at startup (unlike registerVersionChecking): right
// after a controller restart, every agent's tunnel is momentarily down
// simply because it hasn't reconnected yet, which would otherwise fire
// a false "disconnected" notification for the whole fleet on every
// single restart. Waiting for the first real tick gives agents time to
// reconnect first.
func registerNotificationChecks(a *app) error {
	_, err := a.cron.AddFunc(notificationCheckInterval, func() { checkNotifiableEvents(a) })
	return err
}

// checkNotifiableEvents is the host-disconnect and outdated-version
// half of notifications; the deployment-failed half lives at each
// CompleteDeployment(..., "failed", ...) call site instead, since that
// event has an exact moment it happens rather than a state to poll.
func checkNotifiableEvents(a *app) {
	hosts, err := a.store.ListHosts()
	if err != nil {
		log.Println("notify: list hosts:", err)
		return
	}
	latestServer, latestAgent := latest.get()

	a.notifyState.mu.Lock()
	defer a.notifyState.mu.Unlock()

	for _, h := range hosts {
		if h.Status != "connected" {
			continue // never approved (still pending) or rejected -- not something that "should" be up
		}
		_, live := a.tunnels.get(h.ID)
		wasDown := a.notifyState.hostDown[h.ID]
		switch {
		case !live && !wasDown:
			a.notifyState.hostDown[h.ID] = true
			a.notify(fmt.Sprintf("Wharf: agent %q is disconnected", h.Name))
		case live && wasDown:
			delete(a.notifyState.hostDown, h.ID)
		}

		outdated := h.AgentVersion != "" && latestAgent != "" && semverLess(h.AgentVersion, latestAgent)
		wasOutdated := a.notifyState.agentOutdated[h.ID]
		switch {
		case outdated && !wasOutdated:
			a.notifyState.agentOutdated[h.ID] = true
			a.notify(fmt.Sprintf("Wharf: agent %q is outdated (%s, latest is %s)", h.Name, h.AgentVersion, latestAgent))
		case !outdated && wasOutdated:
			delete(a.notifyState.agentOutdated, h.ID)
		}
	}

	// The running build's own version never changes without a restart, so
	// unlike the two checks above this never needs to reset -- once true,
	// it stays true for the rest of this process's life.
	if !a.notifyState.serverUpdateNotified && latestServer != "" && semverLess(version, latestServer) {
		a.notifyState.serverUpdateNotified = true
		a.notify(fmt.Sprintf("Wharf: controller update available (%s -> %s)", version, latestServer))
	}
}

// notifyDeploymentFailed is called right next to every
// CompleteDeployment(id, "failed", ...) in main.go.
func (a *app) notifyDeploymentFailed(stackName, output string) {
	a.notify(fmt.Sprintf("Wharf: stack %q failed to deploy — %s", stackName, truncateForNotify(output)))
}

func truncateForNotify(s string) string {
	const max = 300
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// notify fires message at the configured target, if any, in the
// background. Every call site here is on a path something else already
// depends on finishing promptly -- an agent waiting on its deploy-result
// response, a cron tick that has other stacks/hosts still to check --
// so a slow or unreachable webhook must never add latency there, only
// ever log its own failure.
func (a *app) notify(message string) {
	target, ok, err := a.keys.GetNotificationTarget()
	if err != nil {
		log.Println("notify: load target:", err)
		return
	}
	if !ok {
		return
	}
	go func() {
		if err := sendNotification(target.Kind, target.URL, message); err != nil {
			log.Println("notify: send failed:", err)
		}
	}()
}

// sendNotification does the actual HTTP call -- shared by the
// background a.notify path and testNotificationHandler's synchronous
// one, so "test" exercises exactly the same code a real event would.
func sendNotification(kind, url, message string) error {
	var body []byte
	contentType := "application/json"
	switch kind {
	case "slack":
		b, err := json.Marshal(map[string]string{"text": message})
		if err != nil {
			return err
		}
		body = b
	case "discord":
		b, err := json.Marshal(map[string]string{"content": message})
		if err != nil {
			return err
		}
		body = b
	case "ntfy":
		contentType = "text/plain; charset=utf-8"
		body = []byte(message)
	default: // "generic"
		b, err := json.Marshal(map[string]string{"text": message})
		if err != nil {
			return err
		}
		body = b
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	if kind == "ntfy" {
		req.Header.Set("Title", "Wharf")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("notification target responded %s", resp.Status)
	}
	return nil
}

func (a *app) settingsNotificationsHandler(w http.ResponseWriter, r *http.Request) {
	target, configured, err := a.keys.GetNotificationTarget()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Title":      "Notifications",
		"Nav":        "notifications",
		"Target":     target,
		"Configured": configured,
	}
	render(w, r, "layout", "settings_notifications.html", data)
}

// setNotificationTargetHandler serves POST /settings/notifications. A
// blank URL on a replace keeps the existing one, same "don't force
// re-pasting a credential just to change something else" pattern as the
// registry credential and OIDC forms -- there's nothing else to change
// here yet, but the convention stays consistent for when there is.
func (a *app) setNotificationTargetHandler(w http.ResponseWriter, r *http.Request) {
	kind := r.FormValue("kind")
	if kind != "slack" && kind != "discord" && kind != "ntfy" && kind != "generic" {
		http.Error(w, "invalid kind", http.StatusBadRequest)
		return
	}
	url := strings.TrimSpace(r.FormValue("url"))
	if url == "" {
		existing, ok, err := a.keys.GetNotificationTarget()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "a URL is required to configure a target for the first time", http.StatusBadRequest)
			return
		}
		url = existing.URL
	}
	if err := a.keys.SetNotificationTarget(kind, url); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Never the URL -- it's the credential-shaped half of this, same
	// boundary as every other secret this app logs around, not through.
	a.audit(r, "notifications.configure", kind, "")
	redirectWithSaved(w, r, "/settings/notifications")
}

func (a *app) deleteNotificationTargetHandler(w http.ResponseWriter, r *http.Request) {
	if err := a.keys.DeleteNotificationTarget(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.audit(r, "notifications.remove", "", "")
	redirectWithSavedMessage(w, r, "/settings/notifications", "Notification target removed")
}

// testNotificationHandler serves POST /settings/notifications/test --
// synchronous, unlike a.notify's fire-and-forget: an admin clicking
// "Send test" wants to know right away whether it actually worked, not
// have a failure quietly logged server-side.
func (a *app) testNotificationHandler(w http.ResponseWriter, r *http.Request) {
	target, ok, err := a.keys.GetNotificationTarget()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		redirectWithError(w, r, "/settings/notifications", "configure a target first")
		return
	}
	if err := sendNotification(target.Kind, target.URL, "Wharf: test notification — if you can see this, it works."); err != nil {
		redirectWithError(w, r, "/settings/notifications", "test failed: "+err.Error())
		return
	}
	redirectWithSavedMessage(w, r, "/settings/notifications", "Test notification sent")
}
