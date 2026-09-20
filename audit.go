// Audit trail — append-only record of who did what, cf.
// internal/store's AuditEntry/RecordAudit/ListAudit. Not a security
// control (nothing here is tamper-evident, signed, or shipped off the
// box) -- just accountability, worth having the moment more than one
// admin/operator can touch the same instance.
package main

import (
	"log"
	"net/http"
)

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
	data := map[string]any{
		"Title":   "Audit log",
		"Nav":     "audit-log",
		"Entries": entries,
	}
	render(w, r, "layout", "audit_log.html", data)
}
