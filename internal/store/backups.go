package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Volume backups: where they go (a destination), what and when (a job), and what
// happened (a run). Cf. ARCHITECTURE.md, "Sauvegardes de volumes". The passwords
// of a destination are not here: they live in the keys custodian.

// BackupDestination is a place backups are written to. Config holds the
// non-secret fields of its type (for "smb": server, share, subdir, version,
// username, domain).
type BackupDestination struct {
	ID        string
	Name      string
	Type      string
	Config    map[string]string
	CreatedAt string
}

// BackupRetention is how many snapshots of each volume to keep. All zero keeps everything.
type BackupRetention struct {
	KeepLast    int `json:"keep_last,omitempty"`
	KeepDaily   int `json:"keep_daily,omitempty"`
	KeepWeekly  int `json:"keep_weekly,omitempty"`
	KeepMonthly int `json:"keep_monthly,omitempty"`
}

func (r BackupRetention) None() bool {
	return r.KeepLast <= 0 && r.KeepDaily <= 0 && r.KeepWeekly <= 0 && r.KeepMonthly <= 0
}

// BackupJob is which named volumes of one host go to which destination, and when.
type BackupJob struct {
	ID            string
	Name          string
	HostID        string
	DestinationID string
	Volumes       []string // ticked one by one: a fixed list
	Stacks        []string // every volume of these compose projects, now and later
	LabelRules    []string // "key" or "key=value": every volume with one of these labels
	Excluded      []string // left out of this job, whatever else takes them
	Schedule      string   // 5-field cron, empty for manual only
	Mode          string   // "live" | "stop"
	Retention     BackupRetention
	Enabled       bool
	CreatedAt     string
}

// BackupVolumeResult is the outcome for one volume of a run.
type BackupVolumeResult struct {
	Volume          string `json:"volume"`
	Status          string `json:"status"`
	SnapshotID      string `json:"snapshot_id,omitempty"`
	FilesNew        int    `json:"files_new,omitempty"`
	FilesChanged    int    `json:"files_changed,omitempty"`
	FilesUnmodified int    `json:"files_unmodified,omitempty"`
	DataAdded       int64  `json:"data_added,omitempty"`
	TotalBytes      int64  `json:"total_bytes,omitempty"`
	Message         string `json:"message,omitempty"`
	Retention       string `json:"retention,omitempty"`
}

// BackupRun is one execution of a job (or one restore).
type BackupRun struct {
	ID         string
	JobID      string
	Kind       string // "backup" | "restore"
	Trigger    string // "manual" | "schedule"
	Actor      string
	Status     string // "running" | "success" | "warning" | "error"
	Code       string
	Message    string
	Results    []BackupVolumeResult
	Restored   string // the new volume of a restore
	StartedAt  string
	FinishedAt string
}

func (r BackupRun) Finished() bool { return r.Status != "running" }

// ---- destinations

func decodeConfig(raw string) map[string]string {
	cfg := map[string]string{}
	_ = json.Unmarshal([]byte(raw), &cfg)
	return cfg
}

func (s *Store) CreateBackupDestination(d BackupDestination) error {
	cfg, err := json.Marshal(d.Config)
	if err != nil || string(cfg) == "null" {
		cfg = []byte("{}")
	}
	if _, err := s.db.Exec(`INSERT INTO backup_destinations (id, name, type, config) VALUES (?, ?, ?, ?)`, d.ID, d.Name, d.Type, string(cfg)); err != nil {
		return fmt.Errorf("create backup destination: %w", err)
	}
	return nil
}

func (s *Store) UpdateBackupDestination(id, name string, config map[string]string) error {
	cfg, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	res, err := s.db.Exec(`UPDATE backup_destinations SET name = ?, config = ? WHERE id = ?`, name, string(cfg), id)
	if err != nil {
		return fmt.Errorf("update backup destination: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanDestination(row interface{ Scan(...any) error }) (BackupDestination, error) {
	var d BackupDestination
	var cfg string
	if err := row.Scan(&d.ID, &d.Name, &d.Type, &cfg, &d.CreatedAt); err != nil {
		return d, err
	}
	d.Config = decodeConfig(cfg)
	return d, nil
}

func (s *Store) GetBackupDestination(id string) (BackupDestination, error) {
	d, err := scanDestination(s.db.QueryRow(`SELECT id, name, type, config, created_at FROM backup_destinations WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	if err != nil {
		return d, fmt.Errorf("get backup destination: %w", err)
	}
	return d, nil
}

func (s *Store) ListBackupDestinations() ([]BackupDestination, error) {
	rows, err := s.db.Query(`SELECT id, name, type, config, created_at FROM backup_destinations ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list backup destinations: %w", err)
	}
	defer rows.Close()
	var out []BackupDestination
	for rows.Next() {
		d, err := scanDestination(rows)
		if err != nil {
			return nil, fmt.Errorf("scan backup destination: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeleteBackupDestination refuses while a job still writes to it.
func (s *Store) DeleteBackupDestination(id string) error {
	jobs, err := s.ListBackupJobs()
	if err != nil {
		return err
	}
	var users []string
	for _, j := range jobs {
		if j.DestinationID == id {
			users = append(users, j.Name)
		}
	}
	if len(users) > 0 {
		return fmt.Errorf("still used by: %s", strings.Join(users, ", "))
	}
	if _, err := s.db.Exec(`DELETE FROM backup_destinations WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete backup destination: %w", err)
	}
	return s.ClearBackupRepoStates(id)
}

// ---- jobs

func decodeList(raw string, into *[]string) {
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), into)
	}
}

func jsonList(l []string) string {
	if len(l) == 0 {
		return "[]"
	}
	raw, _ := json.Marshal(l)
	return string(raw)
}

func (s *Store) CreateBackupJob(j BackupJob) error {
	ret, _ := json.Marshal(j.Retention)
	if _, err := s.db.Exec(
		`INSERT INTO backup_jobs (id, name, host_id, destination_id, volumes, stacks, label_rules, excluded, schedule, mode, retention, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		j.ID, j.Name, j.HostID, j.DestinationID, jsonList(j.Volumes), jsonList(j.Stacks), jsonList(j.LabelRules), jsonList(j.Excluded), j.Schedule, j.Mode, string(ret), boolInt(j.Enabled),
	); err != nil {
		return fmt.Errorf("create backup job: %w", err)
	}
	return nil
}

func (s *Store) UpdateBackupJob(j BackupJob) error {
	ret, _ := json.Marshal(j.Retention)
	res, err := s.db.Exec(
		`UPDATE backup_jobs SET name = ?, host_id = ?, destination_id = ?, volumes = ?, stacks = ?, label_rules = ?, excluded = ?, schedule = ?, mode = ?, retention = ?, enabled = ? WHERE id = ?`,
		j.Name, j.HostID, j.DestinationID, jsonList(j.Volumes), jsonList(j.Stacks), jsonList(j.LabelRules), jsonList(j.Excluded), j.Schedule, j.Mode, string(ret), boolInt(j.Enabled), j.ID,
	)
	if err != nil {
		return fmt.Errorf("update backup job: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func scanJob(row interface{ Scan(...any) error }) (BackupJob, error) {
	var j BackupJob
	var vols, stacks, rules, excluded, ret string
	var enabled int
	if err := row.Scan(&j.ID, &j.Name, &j.HostID, &j.DestinationID, &vols, &stacks, &rules, &excluded, &j.Schedule, &j.Mode, &ret, &enabled, &j.CreatedAt); err != nil {
		return j, err
	}
	_ = json.Unmarshal([]byte(vols), &j.Volumes)
	// older rows have '' for the columns added later
	decodeList(stacks, &j.Stacks)
	decodeList(rules, &j.LabelRules)
	decodeList(excluded, &j.Excluded)
	_ = json.Unmarshal([]byte(ret), &j.Retention)
	j.Enabled = enabled != 0
	return j, nil
}

const jobColumns = `id, name, host_id, destination_id, volumes, stacks, label_rules, excluded, schedule, mode, retention, enabled, created_at`

func (s *Store) GetBackupJob(id string) (BackupJob, error) {
	j, err := scanJob(s.db.QueryRow(`SELECT `+jobColumns+` FROM backup_jobs WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return j, ErrNotFound
	}
	if err != nil {
		return j, fmt.Errorf("get backup job: %w", err)
	}
	return j, nil
}

func (s *Store) ListBackupJobs() ([]BackupJob, error) {
	rows, err := s.db.Query(`SELECT ` + jobColumns + ` FROM backup_jobs ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list backup jobs: %w", err)
	}
	defer rows.Close()
	var out []BackupJob
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, fmt.Errorf("scan backup job: %w", err)
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// DeleteBackupJob removes a job and its history. The snapshots stay on the destination.
func (s *Store) DeleteBackupJob(id string) error {
	if _, err := s.db.Exec(`DELETE FROM backup_runs WHERE job_id = ?`, id); err != nil {
		return fmt.Errorf("delete backup runs: %w", err)
	}
	if _, err := s.db.Exec(`DELETE FROM backup_jobs WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete backup job: %w", err)
	}
	return nil
}

// ---- runs

const runColumns = `id, job_id, kind, triggered_by, actor, status, code, message, results, restored, started_at, COALESCE(finished_at, '')`

func (s *Store) CreateBackupRun(r BackupRun) error {
	if _, err := s.db.Exec(
		`INSERT INTO backup_runs (id, job_id, kind, triggered_by, actor, status, code, message, restored) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.JobID, r.Kind, r.Trigger, r.Actor, r.Status, r.Code, r.Message, r.Restored,
	); err != nil {
		return fmt.Errorf("create backup run: %w", err)
	}
	return nil
}

// FinishBackupRun records the outcome of a run that was still running. It does
// nothing, and says so, when the run was already finished (a late duplicate report).
func (s *Store) FinishBackupRun(id, status, code, message, restored string, results []BackupVolumeResult) (bool, error) {
	raw, _ := json.Marshal(results)
	if results == nil {
		raw = []byte("[]")
	}
	res, err := s.db.Exec(
		`UPDATE backup_runs SET status = ?, code = ?, message = ?, restored = ?, results = ?, finished_at = datetime('now') WHERE id = ? AND status = 'running'`,
		status, code, message, restored, string(raw), id,
	)
	if err != nil {
		return false, fmt.Errorf("finish backup run: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func scanRun(row interface{ Scan(...any) error }) (BackupRun, error) {
	var r BackupRun
	var results string
	if err := row.Scan(&r.ID, &r.JobID, &r.Kind, &r.Trigger, &r.Actor, &r.Status, &r.Code, &r.Message, &results, &r.Restored, &r.StartedAt, &r.FinishedAt); err != nil {
		return r, err
	}
	_ = json.Unmarshal([]byte(results), &r.Results)
	return r, nil
}

func (s *Store) GetBackupRun(id string) (BackupRun, error) {
	r, err := scanRun(s.db.QueryRow(`SELECT `+runColumns+` FROM backup_runs WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, fmt.Errorf("get backup run: %w", err)
	}
	return r, nil
}

// ListBackupRuns returns the newest runs first, of one job when jobID is set, else of all.
func (s *Store) ListBackupRuns(jobID string, limit int) ([]BackupRun, error) {
	q, args := `SELECT `+runColumns+` FROM backup_runs`, []any{}
	if jobID != "" {
		q += ` WHERE job_id = ?`
		args = append(args, jobID)
	}
	q += ` ORDER BY started_at DESC, rowid DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("list backup runs: %w", err)
	}
	defer rows.Close()
	var out []BackupRun
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, fmt.Errorf("scan backup run: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RunningBackupRuns are the runs that have not reported yet.
func (s *Store) RunningBackupRuns() ([]BackupRun, error) {
	rows, err := s.db.Query(`SELECT ` + runColumns + ` FROM backup_runs WHERE status = 'running'`)
	if err != nil {
		return nil, fmt.Errorf("list running backup runs: %w", err)
	}
	defer rows.Close()
	var out []BackupRun
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, fmt.Errorf("scan backup run: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// FailStaleBackupRuns marks runs that have been running since before cutoff
// (a "YYYY-MM-DD HH:MM:SS" UTC string) as lost. It returns how many.
func (s *Store) FailStaleBackupRuns(cutoff, message string) (int64, error) {
	res, err := s.db.Exec(
		`UPDATE backup_runs SET status = 'error', code = 'LOST', message = ?, finished_at = datetime('now') WHERE status = 'running' AND started_at < ?`,
		message, cutoff,
	)
	if err != nil {
		return 0, fmt.Errorf("fail stale backup runs: %w", err)
	}
	return res.RowsAffected()
}

// ---- the state of a repository, as last seen

// SetBackupRepoState records whether a host's repository on a destination exists:
// the answer of the last action that could tell (a test, an initialization, a run).
func (s *Store) SetBackupRepoState(destID, hostID string, initialized bool) error {
	if _, err := s.db.Exec(
		`INSERT INTO backup_repos (destination_id, host_id, initialized) VALUES (?, ?, ?)
		 ON CONFLICT(destination_id, host_id) DO UPDATE SET initialized = excluded.initialized, checked_at = datetime('now')`,
		destID, hostID, boolInt(initialized),
	); err != nil {
		return fmt.Errorf("record repository state: %w", err)
	}
	return nil
}

// BackupRepoState says whether the repository was last seen as initialized. known
// is false when nothing has told yet.
func (s *Store) BackupRepoState(destID, hostID string) (initialized, known bool, checkedAt string, err error) {
	var n int
	err = s.db.QueryRow(`SELECT initialized, checked_at FROM backup_repos WHERE destination_id = ? AND host_id = ?`, destID, hostID).Scan(&n, &checkedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, "", nil
	}
	if err != nil {
		return false, false, "", fmt.Errorf("get repository state: %w", err)
	}
	return n != 0, true, checkedAt, nil
}

// ClearBackupRepoStates forgets what was known of a destination's repositories,
// when the destination changed (the repositories may now be somewhere else) or went away.
func (s *Store) ClearBackupRepoStates(destID string) error {
	if _, err := s.db.Exec(`DELETE FROM backup_repos WHERE destination_id = ?`, destID); err != nil {
		return fmt.Errorf("clear repository states: %w", err)
	}
	return nil
}
