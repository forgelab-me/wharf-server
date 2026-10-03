package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/forgelab-me/wharf-server/internal/keys"
	"github.com/forgelab-me/wharf-server/internal/store"
)

func healthApp(t *testing.T) *app {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "wharf.db"))
	if err != nil {
		t.Fatal(err)
	}
	kc, err := keys.Open(filepath.Join(dir, "keys.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close(); kc.Close() })
	return &app{store: st, keys: kc}
}

// serveHealthz sends the request through requireAuth, as the real listener does.
func serveHealthz(a *app) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.healthzHandler)
	w := httptest.NewRecorder()
	a.requireAuth(mux).ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
	return w
}

func TestHealthzAnswersWithoutASession(t *testing.T) {
	w := serveHealthz(healthApp(t))
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != "ok" {
		t.Fatalf("a healthy controller answers 200 ok without logging in: %d %q", w.Code, w.Body.String())
	}
	if !publicPath("/healthz") {
		t.Error("/healthz must stay out of the session check")
	}
}

func TestHealthzReportsEachDatabaseDown(t *testing.T) {
	a := healthApp(t)
	a.keys.Close()
	if w := serveHealthz(a); w.Code != 503 || strings.TrimSpace(w.Body.String()) != "unhealthy" {
		t.Errorf("the secrets store is down: %d %q", w.Code, w.Body.String())
	}

	b := healthApp(t)
	b.store.Close()
	w := serveHealthz(b)
	if w.Code != 503 {
		t.Errorf("the main database is down: %d", w.Code)
	}
	// nothing is revealed to an unauthenticated caller
	for _, leak := range []string{"database", "secrets", "sqlite", "closed", "version"} {
		if strings.Contains(strings.ToLower(w.Body.String()), leak) {
			t.Errorf("the body of an unauthenticated route must not mention %q: %q", leak, w.Body.String())
		}
	}
}
