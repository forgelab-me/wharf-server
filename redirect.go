// Shared redirect helpers -- every handler that redirects back to a page
// with a one-shot error banner or "saved" toast goes through one of
// these, so the query-string composition (cf. appendQuery) only has to
// be correct in one place.
package main

import (
	"net/http"
	"net/url"
	"strings"
)

// appendQuery joins a query fragment ("k=v" or "k1=v1&k2=v2") onto path
// with "?" or "&" as appropriate -- several redirect targets in this
// codebase already carry their own query string (a volume browser's
// backTo's "?path=...", a bulk delete's "?refreshing=1"), and a second
// bare "?" there doesn't start a new parameter, it gets appended onto
// the *value* of whatever came before it (found precisely this way:
// redirectWithError against a volumebrowse.go backTo was producing
// ".../browse?path=foo?error=bar", one query value instead of two
// params -- both the error message and the path navigation broke).
func appendQuery(path, query string) string {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + query
}

// redirectWithError sends the user back to path with message shown as a
// banner on arrival (cf. render's Error auto-injection) instead of
// http.Error's bare-text response replacing the whole page -- for a
// refused action the user can act on right there (e.g. "undeploy this
// stack before deleting it," where the undeploy button is one click
// away on the very page this redirects back to), not an actual server
// failure.
func redirectWithError(w http.ResponseWriter, r *http.Request, path, message string) {
	http.Redirect(w, r, appendQuery(path, "error="+url.QueryEscape(message)), http.StatusSeeOther)
}

// redirectWithSaved is redirectWithError's success counterpart, for a
// save whose result isn't otherwise obvious from the reloaded page (an
// address, a name, a schedule, a credential -- as opposed to e.g.
// deploying a stack, which already gets its own status badge and
// toast). render's Saved auto-injection turns the query flag into a
// one-shot showToast('Saved', 'success') on arrival, same one-reload
// lifetime as Error.
func redirectWithSaved(w http.ResponseWriter, r *http.Request, path string) {
	http.Redirect(w, r, appendQuery(path, "saved=1"), http.StatusSeeOther)
}

// redirectWithSavedMessage is redirectWithSaved with a specific toast
// instead of the generic "Saved" -- for a redirect where "Saved" would
// be the wrong word (nothing was saved, an action ran) but the same
// one-shot "this succeeded" feedback is still needed.
func redirectWithSavedMessage(w http.ResponseWriter, r *http.Request, path, message string) {
	http.Redirect(w, r, appendSavedMessage(path, message), http.StatusSeeOther)
}

// appendSavedMessage is redirectWithSavedMessage's query-building half,
// exposed directly for a caller whose redirect target already carries
// its own query string.
func appendSavedMessage(path, message string) string {
	return appendQuery(path, "saved=1&saved_msg="+url.QueryEscape(message))
}
