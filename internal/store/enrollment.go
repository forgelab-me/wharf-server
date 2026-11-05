package store

// Enrollment hardening, cf. ARCHITECTURE.md "Enrôlement d'un nouvel agent":
//   - single-use enrollment tokens (an optional "initial access token" in
//     RFC 7591 terms: presenting a valid one is equivalent to an admin
//     approval, since only an authenticated admin can mint one),
//   - a TTL and a cap on pending rows (RFC 8628 style expiry),
//   - two-phase certificate rotation (the new fingerprint is accepted next
//     to the current one until the agent actually uses it).

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// ErrInvalidToken is returned for an unknown, expired or already used
// enrollment token -- deliberately not distinguished, so a caller can't
// probe which tokens exist.
var ErrInvalidToken = errors.New("invalid or expired enrollment token")

// ErrFingerprintInUse is returned when a rotation targets a certificate
// already pinned to some host.
var ErrFingerprintInUse = errors.New("certificate fingerprint already in use")

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func seconds(d time.Duration) string {
	return fmt.Sprintf("%+d seconds", int64(d/time.Second))
}

// CreateEnrollmentToken mints a single-use token valid for ttl. Only its
// SHA-256 is stored: the clear value is returned once and never again.
func (s *Store) CreateEnrollmentToken(createdBy string, ttl time.Duration) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	token := "wet_" + base64.RawURLEncoding.EncodeToString(raw)
	_, err := s.db.Exec(
		`INSERT INTO enrollment_tokens (id, token_hash, created_by, expires_at) VALUES (?, ?, ?, datetime('now', ?))`,
		randSuffix()+randSuffix(), hashToken(token), createdBy, seconds(ttl),
	)
	if err != nil {
		return "", fmt.Errorf("create enrollment token: %w", err)
	}
	return token, nil
}

// ConsumeEnrollmentToken atomically marks a valid token as used. The
// UPDATE itself carries the validity conditions, so two concurrent
// enrollments can never both win the same token.
func (s *Store) ConsumeEnrollmentToken(token, hostID string) error {
	res, err := s.db.Exec(
		`UPDATE enrollment_tokens SET used_at = datetime('now'), used_by_host = ?
		 WHERE token_hash = ? AND used_at IS NULL AND expires_at > datetime('now')`,
		hostID, hashToken(token),
	)
	if err != nil {
		return fmt.Errorf("consume enrollment token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("consume enrollment token: %w", err)
	}
	if n == 0 {
		return ErrInvalidToken
	}
	return nil
}

// SetEnrollmentTokenHost records which host a consumed token produced.
func (s *Store) SetEnrollmentTokenHost(token, hostID string) error {
	_, err := s.db.Exec(`UPDATE enrollment_tokens SET used_by_host = ? WHERE token_hash = ?`, hostID, hashToken(token))
	return err
}

// PurgeEnrollmentTokens drops tokens that expired (or were used) more than
// a week ago -- kept that long only as a short audit trail.
func (s *Store) PurgeEnrollmentTokens() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM enrollment_tokens WHERE expires_at < datetime('now', '-7 days')`)
	if err != nil {
		return 0, fmt.Errorf("purge enrollment tokens: %w", err)
	}
	return res.RowsAffected()
}

// CountPendingHosts is what the enrollment endpoint checks against its cap.
func (s *Store) CountPendingHosts() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM hosts WHERE status = 'pending'`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count pending hosts: %w", err)
	}
	return n, nil
}

// PurgeStalePending deletes pending hosts older than ttl. Only 'pending'
// rows are ever touched: an approved host carries real tracked state. An
// agent that is still running simply gets a 404 on its next status poll and
// re-enrolls, which restarts its clock.
func (s *Store) PurgeStalePending(ttl time.Duration) (int64, error) {
	res, err := s.db.Exec(
		`DELETE FROM hosts WHERE status = 'pending' AND created_at < datetime('now', ?)`, seconds(-ttl),
	)
	if err != nil {
		return 0, fmt.Errorf("purge stale pending hosts: %w", err)
	}
	return res.RowsAffected()
}

// NextFingerprint returns the fingerprint a host is rotating to ("" if no
// rotation is in flight).
func (s *Store) NextFingerprint(hostID string) (string, error) {
	var fp string
	err := s.db.QueryRow(`SELECT next_cert_fingerprint FROM hosts WHERE id = ?`, hostID).Scan(&fp)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("get next fingerprint: %w", err)
	}
	return fp, nil
}

// SetNextFingerprint registers the certificate a host wants to rotate to.
// Idempotent for the same value, so an agent that crashed between asking
// and committing can simply ask again.
func (s *Store) SetNextFingerprint(hostID, fp string) error {
	var other string
	err := s.db.QueryRow(
		`SELECT id FROM hosts WHERE id != ?2 AND (cert_fingerprint = ?1 OR next_cert_fingerprint = ?1)`, fp, hostID,
	).Scan(&other)
	if err == nil {
		return ErrFingerprintInUse
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check fingerprint: %w", err)
	}
	res, err := s.db.Exec(`UPDATE hosts SET next_cert_fingerprint = ? WHERE id = ? AND cert_fingerprint != ?`, fp, hostID, fp)
	if err != nil {
		return fmt.Errorf("set next fingerprint: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// PromoteFingerprint completes a rotation the first time the new
// certificate is actually presented: it becomes the pinned one and the old
// one stops being accepted. A no-op unless fp is the pending next value.
func (s *Store) PromoteFingerprint(hostID, fp string) error {
	_, err := s.db.Exec(
		`UPDATE hosts SET cert_fingerprint = ?1, next_cert_fingerprint = '' WHERE id = ?2 AND next_cert_fingerprint = ?1 AND ?1 != ''`,
		fp, hostID,
	)
	if err != nil {
		return fmt.Errorf("promote fingerprint: %w", err)
	}
	return nil
}
