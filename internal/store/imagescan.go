package store

import (
	"database/sql"
	"errors"
	"fmt"
)

// ImageScan is one vulnerability scan of an image, keyed by the scanner
// that produced it and the image's registry digest and platform: the same
// digest is the same content wherever it is pulled from.
type ImageScan struct {
	Scanner    string
	Repository string
	Digest     string
	Platform   string
	Status     string // "ok" | "error"
	Error      string
	Notice     string // qualifies an empty result, cf. scanner.Report.Notice
	ScannedAt  string
	DBBuiltAt  string

	Critical, High, Medium, Low, Unknown int
	FixableCritical, FixableHigh         int

	// Findings is the scanner's normalized result as JSON, opaque here; left
	// out of ListImageScans, which only feeds counters.
	Findings string
}

type ScanKey struct{ Scanner, Digest, Platform string }

const imageScanCounters = `scanner, repository, digest, platform, status, error, notice, scanned_at, db_built_at,
	critical, high, medium, low, unknown, fixable_critical, fixable_high`

func scanImageScanCounters(row rowScanner, s *ImageScan) error {
	return row.Scan(&s.Scanner, &s.Repository, &s.Digest, &s.Platform, &s.Status, &s.Error, &s.Notice, &s.ScannedAt, &s.DBBuiltAt,
		&s.Critical, &s.High, &s.Medium, &s.Low, &s.Unknown, &s.FixableCritical, &s.FixableHigh)
}

// UpsertImageScan stores a scan, replacing the previous one for the same key.
func (s *Store) UpsertImageScan(sc ImageScan) error {
	if sc.Findings == "" {
		sc.Findings = "[]"
	}
	_, err := s.db.Exec(
		`INSERT INTO image_scans (`+imageScanCounters+`, findings)
		 VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (scanner, digest, platform) DO UPDATE SET
			repository = excluded.repository, status = excluded.status, error = excluded.error, notice = excluded.notice,
			scanned_at = excluded.scanned_at, db_built_at = excluded.db_built_at,
			critical = excluded.critical, high = excluded.high, medium = excluded.medium, low = excluded.low,
			unknown = excluded.unknown, fixable_critical = excluded.fixable_critical, fixable_high = excluded.fixable_high,
			findings = excluded.findings`,
		sc.Scanner, sc.Repository, sc.Digest, sc.Platform, sc.Status, sc.Error, sc.Notice, sc.DBBuiltAt,
		sc.Critical, sc.High, sc.Medium, sc.Low, sc.Unknown, sc.FixableCritical, sc.FixableHigh, sc.Findings,
	)
	if err != nil {
		return fmt.Errorf("upsert image scan %q: %w", sc.Digest, err)
	}
	return nil
}

// GetImageScan returns one scan with its findings; ok is false when none exists.
func (s *Store) GetImageScan(scanner, digest, platform string) (sc ImageScan, ok bool, err error) {
	row := s.db.QueryRow(`SELECT `+imageScanCounters+`, findings FROM image_scans WHERE scanner = ? AND digest = ? AND platform = ?`,
		scanner, digest, platform)
	err = row.Scan(&sc.Scanner, &sc.Repository, &sc.Digest, &sc.Platform, &sc.Status, &sc.Error, &sc.Notice, &sc.ScannedAt, &sc.DBBuiltAt,
		&sc.Critical, &sc.High, &sc.Medium, &sc.Low, &sc.Unknown, &sc.FixableCritical, &sc.FixableHigh, &sc.Findings)
	if errors.Is(err, sql.ErrNoRows) {
		return ImageScan{}, false, nil
	}
	if err != nil {
		return ImageScan{}, false, fmt.Errorf("get image scan %q: %w", digest, err)
	}
	return sc, true, nil
}

// ListImageScans returns every scan of one scanner, without findings.
func (s *Store) ListImageScans(scanner string) ([]ImageScan, error) {
	rows, err := s.db.Query(`SELECT `+imageScanCounters+` FROM image_scans WHERE scanner = ?`, scanner)
	if err != nil {
		return nil, fmt.Errorf("list image scans: %w", err)
	}
	defer rows.Close()
	var out []ImageScan
	for rows.Next() {
		var sc ImageScan
		if err := scanImageScanCounters(rows, &sc); err != nil {
			return nil, fmt.Errorf("scan image scan: %w", err)
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// PruneImageScans deletes every scan whose key is not in keep, returning how many went.
func (s *Store) PruneImageScans(keep map[ScanKey]bool) (int, error) {
	rows, err := s.db.Query(`SELECT scanner, digest, platform FROM image_scans`)
	if err != nil {
		return 0, fmt.Errorf("prune image scans: %w", err)
	}
	var stale []ScanKey
	for rows.Next() {
		var k ScanKey
		if err := rows.Scan(&k.Scanner, &k.Digest, &k.Platform); err != nil {
			rows.Close()
			return 0, fmt.Errorf("prune image scans: %w", err)
		}
		if !keep[k] {
			stale = append(stale, k)
		}
	}
	rows.Close()
	for _, k := range stale {
		if _, err := s.db.Exec(`DELETE FROM image_scans WHERE scanner = ? AND digest = ? AND platform = ?`, k.Scanner, k.Digest, k.Platform); err != nil {
			return 0, fmt.Errorf("prune image scans: %w", err)
		}
	}
	return len(stale), nil
}

// DeleteImageScans removes every scan of one scanner (all of them when empty).
func (s *Store) DeleteImageScans(scanner string) error {
	var err error
	if scanner == "" {
		_, err = s.db.Exec(`DELETE FROM image_scans`)
	} else {
		_, err = s.db.Exec(`DELETE FROM image_scans WHERE scanner = ?`, scanner)
	}
	if err != nil {
		return fmt.Errorf("delete image scans: %w", err)
	}
	return nil
}

// VulnSettings is the install-wide vulnerability scanning configuration.
type VulnSettings struct {
	Enabled     bool
	Scanner     string
	LastPassAt  string
	LastPassMsg string
}

// GetVulnSettings returns the settings; the zero value (disabled) when never saved.
func (s *Store) GetVulnSettings() (VulnSettings, error) {
	var v VulnSettings
	var enabled int
	err := s.db.QueryRow(`SELECT enabled, scanner, last_pass_at, last_pass_msg FROM vuln_settings WHERE id = 1`).
		Scan(&enabled, &v.Scanner, &v.LastPassAt, &v.LastPassMsg)
	if errors.Is(err, sql.ErrNoRows) {
		return VulnSettings{}, nil
	}
	if err != nil {
		return VulnSettings{}, fmt.Errorf("get vuln settings: %w", err)
	}
	v.Enabled = enabled != 0
	return v, nil
}

// SetVulnSettingsChoice saves whether scanning is on and which scanner, leaving the last-pass report alone.
func (s *Store) SetVulnSettingsChoice(enabled bool, scanner string) error {
	flag := 0
	if enabled {
		flag = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO vuln_settings (id, enabled, scanner) VALUES (1, ?, ?)
		 ON CONFLICT (id) DO UPDATE SET enabled = excluded.enabled, scanner = excluded.scanner`, flag, scanner)
	if err != nil {
		return fmt.Errorf("set vuln settings: %w", err)
	}
	return nil
}

// SetVulnLastPass records the outcome of the latest scan pass.
func (s *Store) SetVulnLastPass(msg string) error {
	_, err := s.db.Exec(
		`INSERT INTO vuln_settings (id, last_pass_at, last_pass_msg) VALUES (1, datetime('now'), ?)
		 ON CONFLICT (id) DO UPDATE SET last_pass_at = excluded.last_pass_at, last_pass_msg = excluded.last_pass_msg`, msg)
	if err != nil {
		return fmt.Errorf("set vuln last pass: %w", err)
	}
	return nil
}
