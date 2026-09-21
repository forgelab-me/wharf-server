// Audit trail — append-only record of who did what, cf.
// internal/store's AuditEntry/RecordAudit/ListAudit. Not a security
// control (nothing here is tamper-evident, signed, or shipped off the
// box) -- just accountability, worth having the moment more than one
// admin/operator can touch the same instance.
package main

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// auditCategory is one prunable slice of the audit log -- the part of
// an action before its first "." (cf. every a.audit(r, "category.verb",
// ...) call site). Retention is configured per category rather than
// per exact action: a stack's whole lifecycle or a volume's whole file
// browser is one "how long do I care about this" decision in practice,
// not a dozen separate ones.
type auditCategory struct {
	Key   string
	Label string
}

var auditCategories = []auditCategory{
	{"auth", "Sign-in / sign-out"},
	{"container", "Containers (restart/stop)"},
	{"stack", "Stacks (deploy, secrets, lifecycle)"},
	{"host", "Hosts (approve, rename, address)"},
	{"user", "Users"},
	{"git_connection", "Git connections"},
	{"registry", "Registry credentials"},
	{"oidc", "SSO (OIDC)"},
	{"image", "Images (delete)"},
	{"volume", "Volumes (delete, file browser)"},
	{"network", "Networks (delete)"},
	{"notifications", "Notifications"},
	{"backup", "Backup & restore"},
}

// auditRetentionCheckInterval: once a day is plenty of precision for a
// setting expressed in days -- no reason to check more often. Not run
// immediately at startup (same reasoning as notifications' periodic
// checks): pruning is destructive, and a controller that gets restarted
// often during normal use (an update, a config change) shouldn't have a
// chance of sweeping the log on every single one of those before an
// admin has even looked at what's configured.
const auditRetentionCheckInterval = "0 3 * * *"

func registerAuditRetention(a *app) error {
	_, err := a.cron.AddFunc(auditRetentionCheckInterval, func() { pruneAuditLog(a) })
	return err
}

// pruneAuditLog deletes anything older than its category's configured
// retention. A category with no configured retention (or explicitly 0)
// is "forever" and skipped entirely -- the common case, since most
// installs will never touch this.
func pruneAuditLog(a *app) {
	retention, err := a.store.GetAuditRetentionAll()
	if err != nil {
		log.Println("audit retention: load config:", err)
		return
	}
	for category, days := range retention {
		if days <= 0 {
			continue
		}
		cutoff := time.Now().AddDate(0, 0, -days)
		n, err := a.store.PruneAuditOlderThan(category, cutoff)
		if err != nil {
			log.Println("audit retention: prune", category, "failed:", err)
			continue
		}
		if n > 0 {
			log.Println("audit retention: pruned", n, category, "entries older than", days, "day(s)")
		}
	}
}

// audit records one entry, best-effort: a failed write here must never
// fail (or even slow down) the action it's recording -- same "log and
// move on" treatment as registerPolling's own errors elsewhere in this
// codebase. Call this right where the action already succeeded, mirroring
// exactly where redirectWithSaved/redirectWithSavedMessage already fire.
func (a *app) audit(r *http.Request, action, target, detail string) {
	username := usernameFromContext(r.Context())
	if err := a.store.RecordAudit(username, action, target, detail); err != nil {
		log.Println("audit:", err)
	}
}

// auditLogHandler serves GET /audit-log, admin-only like the rest of
// Settings.
func (a *app) auditLogHandler(w http.ResponseWriter, r *http.Request) {
	entries, err := a.store.ListAudit(500)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	retention, err := a.store.GetAuditRetentionAll()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Title":      "Audit log",
		"Nav":        "audit-log",
		"Entries":    entries,
		"Categories": auditCategories,
		"Retention":  retention,
	}
	render(w, r, "layout", "audit_log.html", data)
}

// setAuditRetentionHandler serves POST /audit-log/retention -- one form,
// every category saved together rather than a separate endpoint per
// row, since changing retention policy is inherently a "here's the
// whole table as I want it" action, not a series of independent edits.
func (a *app) setAuditRetentionHandler(w http.ResponseWriter, r *http.Request) {
	parsed := make(map[string]int, len(auditCategories))
	for _, c := range auditCategories {
		raw := strings.TrimSpace(r.FormValue("retain_" + c.Key))
		if raw == "" {
			raw = "0"
		}
		days, err := strconv.Atoi(raw)
		if err != nil || days < 0 {
			redirectWithError(w, r, "/audit-log", "invalid retention value for "+c.Label+" — enter a whole number of days, or 0 for forever")
			return
		}
		parsed[c.Key] = days
	}
	for category, days := range parsed {
		if err := a.store.SetAuditRetention(category, days); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	a.audit(r, "audit.retention_change", "", "")
	redirectWithSaved(w, r, "/audit-log")
}
