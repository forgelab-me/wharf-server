package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openEnrollTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestEnrollmentTokenSingleUseAndExpiry(t *testing.T) {
	s := openEnrollTest(t)
	tok, err := s.CreateEnrollmentToken("admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeEnrollmentToken(tok, "h"); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if err := s.ConsumeEnrollmentToken(tok, "h"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("second consume = %v, want ErrInvalidToken", err)
	}

	expired, _ := s.CreateEnrollmentToken("admin", -time.Minute)
	if err := s.ConsumeEnrollmentToken(expired, "h"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expired consume = %v, want ErrInvalidToken", err)
	}
	if err := s.ConsumeEnrollmentToken("wet_unknown", "h"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("unknown consume = %v, want ErrInvalidToken", err)
	}
}

func TestPurgeStalePendingOnlyTouchesOldPendingRows(t *testing.T) {
	s := openEnrollTest(t)
	old, _, _ := s.UpsertHostByFingerprint("old-pending", "sha256:01")
	approved, _, _ := s.UpsertHostByFingerprint("old-approved", "sha256:02")
	fresh, _, _ := s.UpsertHostByFingerprint("fresh-pending", "sha256:03")
	if err := s.ApproveHost(approved.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE hosts SET created_at = datetime('now', '-2 days') WHERE id IN (?, ?)`, old.ID, approved.ID); err != nil {
		t.Fatal(err)
	}

	n, err := s.PurgeStalePending(24 * time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("purged %d (err %v), want 1", n, err)
	}
	if _, err := s.GetHost(old.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale pending host must be gone: %v", err)
	}
	for _, id := range []string{approved.ID, fresh.ID} {
		if _, err := s.GetHost(id); err != nil {
			t.Fatalf("host %s must survive: %v", id, err)
		}
	}
	if c, _ := s.CountPendingHosts(); c != 1 {
		t.Fatalf("pending count = %d, want 1", c)
	}
}

func TestFingerprintRotation(t *testing.T) {
	s := openEnrollTest(t)
	a, _, _ := s.UpsertHostByFingerprint("a", "sha256:AA")
	b, _, _ := s.UpsertHostByFingerprint("b", "sha256:BB")

	if err := s.SetNextFingerprint(a.ID, "sha256:AA"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("same fingerprint = %v, want ErrNotFound", err)
	}
	if err := s.SetNextFingerprint(a.ID, "sha256:BB"); !errors.Is(err, ErrFingerprintInUse) {
		t.Fatalf("foreign fingerprint = %v, want ErrFingerprintInUse", err)
	}
	if err := s.SetNextFingerprint(a.ID, "sha256:A2"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNextFingerprint(a.ID, "sha256:A2"); err != nil {
		t.Fatalf("idempotent re-announce: %v", err)
	}
	if err := s.SetNextFingerprint(b.ID, "sha256:A2"); !errors.Is(err, ErrFingerprintInUse) {
		t.Fatalf("another host's pending next = %v, want ErrFingerprintInUse", err)
	}

	for _, fp := range []string{"sha256:AA", "sha256:A2"} {
		if h, err := s.GetHostByFingerprint(fp); err != nil || h.ID != a.ID {
			t.Fatalf("lookup %s = %v, %v", fp, h.ID, err)
		}
	}
	if err := s.PromoteFingerprint(a.ID, "sha256:A2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetHostByFingerprint("sha256:AA"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old fingerprint after promotion = %v, want ErrNotFound", err)
	}
	if next, _ := s.NextFingerprint(a.ID); next != "" {
		t.Fatalf("next = %q after promotion, want empty", next)
	}
}
