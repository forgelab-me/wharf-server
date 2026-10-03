package main

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"
)

// healthTimeout bounds the whole check: a probe that waits longer than its own
// timeout would report the wrong thing.
const healthTimeout = 3 * time.Second

// healthzHandler serves GET /healthz for monitoring and the image's
// HEALTHCHECK: 200 when both databases answer, 503 when one does not. It is
// reachable without a session, so it says nothing but ok or unhealthy: no
// version, no name of what failed (that goes to the log).
func (a *app) healthzHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), healthTimeout)
	defer cancel()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := a.healthy(ctx); err != nil {
		logHealthFailure(err)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("unhealthy\n"))
		return
	}
	_, _ = w.Write([]byte("ok\n"))
}

// healthy checks what the controller cannot work without: its main database
// and the secrets custodian's.
func (a *app) healthy(ctx context.Context) error {
	if err := a.store.Ping(ctx); err != nil {
		return &healthError{"main database", err}
	}
	if err := a.keys.Ping(ctx); err != nil {
		return &healthError{"secrets store", err}
	}
	return nil
}

type healthError struct {
	what string
	err  error
}

func (e *healthError) Error() string { return e.what + ": " + e.err.Error() }

// logHealthFailure logs at most once a minute: a probe every few seconds
// against a broken database would otherwise fill the log with the same line.
var lastHealthLog struct {
	sync.Mutex
	at time.Time
}

func logHealthFailure(err error) {
	lastHealthLog.Lock()
	defer lastHealthLog.Unlock()
	if time.Since(lastHealthLog.at) < time.Minute {
		return
	}
	lastHealthLog.at = time.Now()
	log.Println("healthz: unhealthy:", err)
}
