// Package store is the controller's main application database — schema
// per ARCHITECTURE.md's "Modèle de données". Deliberately does not import
// the keys package and never sees a private key; only public keys and
// ciphertexts pass through here.
package store

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("not found")

type Stack struct {
	ID              string
	Name            string
	SourceType      string // "git" | "local"
	Repo            string
	Branch          string
	ComposePath     string
	ComposeContent  string
	EncryptedSecret []byte
	Host            string
	Trigger         string
	PublicKey       string
	SSHPublicKey    string // dedicated deploy key, git stacks only
	GitConnectionID string // nullable: shared connection instead of a dedicated key
	WebhookSecret   string // active only when Trigger == "webhook"
	PollSchedule    string // cron expression, active only when Trigger == "polling"
	LastPolledSHA   string
	LastPolledAt    string
	// SubstitutedEnvKeys is a comma-joined list of environment variable
	// names that the last successfully deployed compose file set via
	// ${...}/$VAR substitution in at least one service -- cf.
	// containers.go's buildEnvVars, which is the only reader. Only ever
	// consulted for a Git-sourced stack: a local stack's own secret
	// values are already known centrally and masked by matching value
	// instead (a strictly more precise check), so this stays empty and
	// unused there.
	SubstitutedEnvKeys string
}

type GitConnection struct {
	ID       string
	Name     string
	AuthKind string // "ssh_key" | "http_password"
}

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	// WAL + busy_timeout: with the container/image tunnel (one goroutine
	// per connected agent, writing every few seconds) added on top of the
	// existing HTTP handlers and background pollers, plain rollback-journal
	// SQLite started throwing SQLITE_BUSY under real concurrent writes
	// (caught by testing, not theoretical) -- WAL lets readers and a
	// writer proceed together, busy_timeout makes a second writer wait
	// instead of failing immediately.
	//
	// A prior version of this fix also called SetMaxOpenConns(1), to
	// force every access through one connection. That turned out to be
	// an overcorrection with a real cost: on a host with genuine ongoing
	// container activity (not the clean throwaway containers used while
	// developing this), the tunnel pushes frequent snapshots, and with
	// only one connection allowed, database/sql queues *every* other
	// query -- reads included -- behind whichever one currently holds
	// it. A user hit this for real: their agent's simple status check
	// (GetHost/TouchHost, normally near-instant) queued long enough
	// behind tunnel snapshot writes to blow through its 30s client
	// timeout, making the controller look unreachable even though the
	// network was fine. WAL + busy_timeout alone already give SQLite's
	// own concurrency model (many readers, one writer, waiting instead
	// of failing) -- forcing everything through a single Go-level
	// connection on top of that wasn't needed to fix the original bug,
	// only to make a different one. A capped pool avoids unbounded
	// connection growth without reintroducing that bottleneck.
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	db.SetMaxOpenConns(10)
	const schema = `
	CREATE TABLE IF NOT EXISTS stacks (
		id               TEXT PRIMARY KEY,
		name             TEXT NOT NULL,
		source_type      TEXT NOT NULL,
		repo             TEXT NOT NULL DEFAULT '',
		branch           TEXT NOT NULL DEFAULT '',
		compose_path     TEXT NOT NULL DEFAULT '',
		compose_content  TEXT NOT NULL DEFAULT '',
		encrypted_secret BLOB,
		host             TEXT NOT NULL DEFAULT '',
		trigger_mode     TEXT NOT NULL DEFAULT 'manual',
		public_key       TEXT NOT NULL DEFAULT '',
		ssh_public_key   TEXT NOT NULL DEFAULT '',
		git_connection_id TEXT,
		webhook_secret   TEXT NOT NULL DEFAULT '',
		poll_schedule    TEXT NOT NULL DEFAULT '',
		last_polled_sha  TEXT NOT NULL DEFAULT '',
		last_polled_at   TEXT,
		substituted_env_keys TEXT NOT NULL DEFAULT '',
		created_at       TEXT NOT NULL DEFAULT (datetime('now'))
	);
	CREATE TABLE IF NOT EXISTS git_connections (
		id         TEXT PRIMARY KEY,
		name       TEXT NOT NULL,
		auth_kind  TEXT NOT NULL,
		created_at TEXT NOT NULL DEFAULT (datetime('now'))
	);
	CREATE TABLE IF NOT EXISTS hosts (
		id               TEXT PRIMARY KEY,
		name             TEXT NOT NULL,
		status           TEXT NOT NULL DEFAULT 'pending',
		cert_fingerprint TEXT NOT NULL UNIQUE,
		approved_by      TEXT NOT NULL DEFAULT '',
		approved_at      TEXT,
		last_seen_at     TEXT NOT NULL DEFAULT (datetime('now')),
		created_at       TEXT NOT NULL DEFAULT (datetime('now')),
		address          TEXT NOT NULL DEFAULT '',
		agent_version    TEXT NOT NULL DEFAULT ''
	);
	CREATE TABLE IF NOT EXISTS deployments (
		id           TEXT PRIMARY KEY,
		stack_id     TEXT NOT NULL,
		host_id      TEXT NOT NULL,
		action       TEXT NOT NULL DEFAULT 'up',
		trigger_mode TEXT NOT NULL DEFAULT 'manual',
		status       TEXT NOT NULL DEFAULT 'queued',
		output       TEXT NOT NULL DEFAULT '',
		started_at   TEXT,
		finished_at  TEXT,
		created_at   TEXT NOT NULL DEFAULT (datetime('now'))
	);
	CREATE TABLE IF NOT EXISTS image_policies (
		stack_id       TEXT NOT NULL,
		service_name   TEXT NOT NULL,
		image_ref      TEXT NOT NULL DEFAULT '',
		policy         TEXT NOT NULL DEFAULT 'pinned',
		applied_digest TEXT NOT NULL DEFAULT '',
		updated_at     TEXT NOT NULL DEFAULT (datetime('now')),
		PRIMARY KEY (stack_id, service_name)
	);
	CREATE TABLE IF NOT EXISTS image_digest_cache (
		image_ref  TEXT PRIMARY KEY,
		digest     TEXT NOT NULL DEFAULT '',
		checked_at TEXT,
		last_error TEXT NOT NULL DEFAULT ''
	);
	CREATE TABLE IF NOT EXISTS host_containers (
		host_id      TEXT NOT NULL,
		container_id TEXT NOT NULL,
		name         TEXT NOT NULL,
		image        TEXT NOT NULL DEFAULT '',
		state        TEXT NOT NULL DEFAULT '',
		status       TEXT NOT NULL DEFAULT '',
		ports        TEXT NOT NULL DEFAULT '',
		created      TEXT NOT NULL DEFAULT '',
		stack_id     TEXT NOT NULL DEFAULT '',
		service_name TEXT NOT NULL DEFAULT '',
		mounts       TEXT NOT NULL DEFAULT '',
		networks     TEXT NOT NULL DEFAULT '',
		updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
		PRIMARY KEY (host_id, container_id)
	);
	CREATE TABLE IF NOT EXISTS host_images (
		host_id    TEXT NOT NULL,
		image_id   TEXT NOT NULL,
		repository TEXT NOT NULL DEFAULT '',
		tag        TEXT NOT NULL DEFAULT '',
		size       TEXT NOT NULL DEFAULT '',
		updated_at TEXT NOT NULL DEFAULT (datetime('now')),
		PRIMARY KEY (host_id, image_id, repository, tag)
	);
	CREATE TABLE IF NOT EXISTS host_volumes (
		host_id    TEXT NOT NULL,
		name       TEXT NOT NULL,
		driver     TEXT NOT NULL DEFAULT '',
		updated_at TEXT NOT NULL DEFAULT (datetime('now')),
		PRIMARY KEY (host_id, name)
	);
	CREATE TABLE IF NOT EXISTS host_networks (
		host_id    TEXT NOT NULL,
		name       TEXT NOT NULL,
		driver     TEXT NOT NULL DEFAULT '',
		scope      TEXT NOT NULL DEFAULT '',
		updated_at TEXT NOT NULL DEFAULT (datetime('now')),
		PRIMARY KEY (host_id, name)
	);
	CREATE TABLE IF NOT EXISTS stack_revisions (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		stack_id        TEXT NOT NULL,
		compose_content TEXT NOT NULL,
		created_at      TEXT NOT NULL DEFAULT (datetime('now'))
	);
	CREATE TABLE IF NOT EXISTS admin_user (
		id                   INTEGER PRIMARY KEY CHECK (id = 1),
		username             TEXT NOT NULL,
		password_hash        TEXT NOT NULL,
		must_change_password INTEGER NOT NULL DEFAULT 0,
		updated_at           TEXT NOT NULL DEFAULT (datetime('now'))
	);
	CREATE TABLE IF NOT EXISTS users (
		username             TEXT PRIMARY KEY,
		password_hash        TEXT NOT NULL DEFAULT '',
		role                 TEXT NOT NULL DEFAULT 'operator',
		must_change_password INTEGER NOT NULL DEFAULT 0,
		oidc_subject         TEXT,
		oidc_issuer          TEXT,
		created_at           TEXT NOT NULL DEFAULT (datetime('now')),
		last_login_at        TEXT
	);
	CREATE TABLE IF NOT EXISTS sessions (
		token      TEXT PRIMARY KEY,
		username   TEXT NOT NULL,
		created_at TEXT NOT NULL DEFAULT (datetime('now')),
		expires_at TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS audit_log (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		username   TEXT NOT NULL,
		action     TEXT NOT NULL,
		target     TEXT NOT NULL DEFAULT '',
		detail     TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL DEFAULT (datetime('now'))
	);`
	// Migration: host_images' primary key used to be (host_id,
	// repository, tag) -- itself an earlier fix for a multi-tag image's
	// second row colliding on (host_id, image_id), cf. ARCHITECTURE.md.
	// That key breaks the moment two dangling images exist on the same
	// host: Docker allows any number of distinct image ids to share
	// repository=tag="<none>", so the second such INSERT inside
	// ReplaceHostImages' transaction hit the primary key and rolled
	// back the *entire* snapshot silently -- which is why dangling
	// images never showed up in the UI at all, not just the colliding
	// one. The real invariant is the full (host_id, image_id,
	// repository, tag) triple. host_images is pure derived cache data,
	// entirely replaced on every agent snapshot (cf. ReplaceHostImages)
	// -- nothing to preserve, so a table still shaped the old way is
	// just dropped; CREATE TABLE IF NOT EXISTS below recreates it
	// correctly and the agent's next snapshot refills it within
	// seconds.
	var existingImagesPK string
	_ = db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'host_images'`).Scan(&existingImagesPK)
	if existingImagesPK != "" && !strings.Contains(existingImagesPK, "host_id, image_id, repository, tag") {
		if _, err := db.Exec(`DROP TABLE host_images`); err != nil {
			db.Close()
			return nil, fmt.Errorf("migrate host_images primary key: %w", err)
		}
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	// CREATE TABLE IF NOT EXISTS above only covers a brand-new database --
	// a column added after this project's first release needs an
	// idempotent ALTER TABLE too, run on every startup, for a database
	// that already existed before this column did.
	if _, err := db.Exec(`ALTER TABLE stacks ADD COLUMN substituted_env_keys TEXT NOT NULL DEFAULT ''`); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		db.Close()
		return nil, fmt.Errorf("migrate stacks.substituted_env_keys: %w", err)
	}
	if _, err := db.Exec(`ALTER TABLE hosts ADD COLUMN agent_version TEXT NOT NULL DEFAULT ''`); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		db.Close()
		return nil, fmt.Errorf("migrate hosts.agent_version: %w", err)
	}
	// The file is guaranteed to exist by now (the schema exec above forced
	// the driver to create it) -- tightened to owner-only every startup,
	// not just at creation, so an existing deployment upgrading onto this
	// picks it up too, not just a fresh install. Best-effort: a platform
	// where chmod isn't meaningful (Windows) just leaves it alone rather
	// than failing startup over it.
	_ = os.Chmod(path, 0o600)
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) CreateStack(st Stack) error {
	var connID any
	if st.GitConnectionID != "" {
		connID = st.GitConnectionID
	}
	_, err := s.db.Exec(
		`INSERT INTO stacks (id, name, source_type, repo, branch, compose_path, compose_content, encrypted_secret, host, trigger_mode, public_key, ssh_public_key, git_connection_id, webhook_secret, poll_schedule)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		st.ID, st.Name, st.SourceType, st.Repo, st.Branch, st.ComposePath, st.ComposeContent, st.EncryptedSecret, st.Host, st.Trigger, st.PublicKey, st.SSHPublicKey, connID, st.WebhookSecret, st.PollSchedule,
	)
	if err != nil {
		return fmt.Errorf("insert stack: %w", err)
	}
	return nil
}

func (s *Store) ListStacks() ([]Stack, error) {
	rows, err := s.db.Query(`SELECT id, name, source_type, repo, branch, compose_path, host, trigger_mode, public_key, poll_schedule, last_polled_sha FROM stacks ORDER BY rowid DESC`)
	if err != nil {
		return nil, fmt.Errorf("list stacks: %w", err)
	}
	defer rows.Close()

	var out []Stack
	for rows.Next() {
		var st Stack
		if err := rows.Scan(&st.ID, &st.Name, &st.SourceType, &st.Repo, &st.Branch, &st.ComposePath, &st.Host, &st.Trigger, &st.PublicKey, &st.PollSchedule, &st.LastPolledSHA); err != nil {
			return nil, fmt.Errorf("scan stack: %w", err)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *Store) GetStack(id string) (Stack, error) {
	var st Stack
	var connID sql.NullString
	var lastPolledAt sql.NullString
	err := s.db.QueryRow(
		`SELECT id, name, source_type, repo, branch, compose_path, compose_content, encrypted_secret, host, trigger_mode, public_key, ssh_public_key, git_connection_id, webhook_secret, poll_schedule, last_polled_sha, last_polled_at, substituted_env_keys FROM stacks WHERE id = ?`, id,
	).Scan(&st.ID, &st.Name, &st.SourceType, &st.Repo, &st.Branch, &st.ComposePath, &st.ComposeContent, &st.EncryptedSecret, &st.Host, &st.Trigger, &st.PublicKey, &st.SSHPublicKey, &connID, &st.WebhookSecret, &st.PollSchedule, &st.LastPolledSHA, &lastPolledAt, &st.SubstitutedEnvKeys)
	if err != nil {
		return Stack{}, fmt.Errorf("get stack %q: %w", id, err)
	}
	st.GitConnectionID = connID.String
	st.LastPolledAt = lastPolledAt.String
	return st, nil
}

// RecordPoll updates a stack's last-seen remote sha and poll timestamp —
// called on every scheduled check, whether or not the sha changed.
func (s *Store) RecordPoll(stackID, sha string) error {
	_, err := s.db.Exec(
		`UPDATE stacks SET last_polled_sha = ?, last_polled_at = datetime('now') WHERE id = ?`,
		sha, stackID,
	)
	if err != nil {
		return fmt.Errorf("record poll for stack %q: %w", stackID, err)
	}
	return nil
}

// SetSubstitutedEnvKeys records which environment variable names the
// last successfully deployed compose file set via ${...}/$VAR
// substitution -- cf. containers.go's buildEnvVars, the only reader.
// Called after every successful deployment (main.go's
// deploymentResultHandler), git and local alike, though only a
// Git-sourced stack's rendering actually consults it.
func (s *Store) SetSubstitutedEnvKeys(stackID string, keys []string) error {
	_, err := s.db.Exec(`UPDATE stacks SET substituted_env_keys = ? WHERE id = ?`, strings.Join(keys, ","), stackID)
	if err != nil {
		return fmt.Errorf("set substituted env keys for stack %q: %w", stackID, err)
	}
	return nil
}

// SetPollSchedule updates a polling-mode stack's cron expression. Does
// not touch last_polled_sha/last_polled_at -- the next check under the
// new schedule compares against whatever was last seen under the old
// one, exactly as if the schedule had always been this one.
func (s *Store) SetPollSchedule(stackID, schedule string) error {
	_, err := s.db.Exec(`UPDATE stacks SET poll_schedule = ? WHERE id = ?`, schedule, stackID)
	if err != nil {
		return fmt.Errorf("set poll schedule for stack %q: %w", stackID, err)
	}
	return nil
}

// UpdateStackTrigger switches a stack's trigger mode. pollSchedule and
// webhookSecret are whatever the caller decided the stack should end up
// with (a default schedule if newly-polling, a freshly generated secret
// if newly-webhook, or just the previous value preserved either way) --
// one write for all three columns, so a trigger switch is atomic rather
// than a mode change followed by a separate schedule/secret write that
// could land only half-applied.
func (s *Store) UpdateStackTrigger(stackID, trigger, pollSchedule, webhookSecret string) error {
	_, err := s.db.Exec(
		`UPDATE stacks SET trigger_mode = ?, poll_schedule = ?, webhook_secret = ? WHERE id = ?`,
		trigger, pollSchedule, webhookSecret, stackID,
	)
	if err != nil {
		return fmt.Errorf("update trigger for stack %q: %w", stackID, err)
	}
	return nil
}

// RenameStack changes a stack's display name -- like a host's name
// (cf. SetHostName), the id is what deployments/image policies/secrets
// actually key on, so this has no effect on anything already running.
func (s *Store) RenameStack(id, name string) error {
	_, err := s.db.Exec(`UPDATE stacks SET name = ? WHERE id = ?`, name, id)
	if err != nil {
		return fmt.Errorf("rename stack %q: %w", id, err)
	}
	return nil
}

// DeleteStack removes a stack and everything scoped to it in the main
// store — deployment history and image policies. It does not touch
// host_containers (nothing to do: a stack this is safe to delete has
// nothing running, cf. the "already undeployed" check callers are
// expected to make first) nor the custodian's keys (a separate store —
// callers must also call keys.Custodian.DeleteStackKeys).
func (s *Store) DeleteStack(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("delete stack %q: %w", id, err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM deployments WHERE stack_id = ?`, id); err != nil {
		return fmt.Errorf("delete stack %q: deployments: %w", id, err)
	}
	if _, err := tx.Exec(`DELETE FROM image_policies WHERE stack_id = ?`, id); err != nil {
		return fmt.Errorf("delete stack %q: image policies: %w", id, err)
	}
	res, err := tx.Exec(`DELETE FROM stacks WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete stack %q: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete stack %q: %w", id, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

type Host struct {
	ID              string
	Name            string
	Status          string // "pending" | "connected"
	CertFingerprint string
	ApprovedBy      string
	LastSeenAt      string
	Address         string // reachable network address, admin-set, empty until configured — cf. ARCHITECTURE.md, port links
	AgentVersion    string // this host's agent build, reported on every "state" push — empty until the agent's first connection after this column existed, cf. versioncheck.go
}

var hostSlugRe = regexp.MustCompile(`[^a-z0-9-]+`)

func hostSlug(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = strings.ReplaceAll(s, " ", "-")
	s = hostSlugRe.ReplaceAllString(s, "")
	s = strings.Trim(s, "-")
	if s == "" {
		s = "host"
	}
	return s
}

func randSuffix() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// UpsertHostByFingerprint is what the enrollment endpoint calls on every
// request: the certificate fingerprint is the true identity, hostname is
// just a display label. A known fingerprint is a reconnect (last_seen_at
// bumped, status untouched, created=false); an unknown one is a brand new
// pending host (created=true).
func (s *Store) UpsertHostByFingerprint(name, fingerprint string) (host Host, created bool, err error) {
	existing, err := s.GetHostByFingerprint(fingerprint)
	if err == nil {
		if _, err := s.db.Exec(`UPDATE hosts SET last_seen_at = datetime('now') WHERE id = ?`, existing.ID); err != nil {
			return Host{}, false, fmt.Errorf("touch host: %w", err)
		}
		return existing, false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return Host{}, false, err
	}

	id := hostSlug(name)
	for attempt := 0; attempt < 5; attempt++ {
		candidate := id
		if attempt > 0 {
			candidate = id + "-" + randSuffix()
		}
		_, err := s.db.Exec(
			`INSERT INTO hosts (id, name, status, cert_fingerprint) VALUES (?, ?, 'pending', ?)`,
			candidate, name, fingerprint,
		)
		if err == nil {
			h, err := s.GetHost(candidate)
			return h, true, err
		}
		if !strings.Contains(err.Error(), "UNIQUE constraint failed: hosts.id") {
			return Host{}, false, fmt.Errorf("insert host: %w", err)
		}
	}
	return Host{}, false, fmt.Errorf("insert host: could not allocate a unique id for %q", name)
}

// GetHostByFingerprint is how the agent channel resolves "which host is
// calling" from its TLS client certificate.
func (s *Store) GetHostByFingerprint(fingerprint string) (Host, error) {
	var h Host
	err := s.db.QueryRow(
		`SELECT id, name, status, cert_fingerprint, approved_by, last_seen_at, address, agent_version FROM hosts WHERE cert_fingerprint = ?`, fingerprint,
	).Scan(&h.ID, &h.Name, &h.Status, &h.CertFingerprint, &h.ApprovedBy, &h.LastSeenAt, &h.Address, &h.AgentVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return Host{}, ErrNotFound
	}
	if err != nil {
		return Host{}, fmt.Errorf("get host by fingerprint: %w", err)
	}
	return h, nil
}

func (s *Store) GetHost(id string) (Host, error) {
	var h Host
	err := s.db.QueryRow(
		`SELECT id, name, status, cert_fingerprint, approved_by, last_seen_at, address, agent_version FROM hosts WHERE id = ?`, id,
	).Scan(&h.ID, &h.Name, &h.Status, &h.CertFingerprint, &h.ApprovedBy, &h.LastSeenAt, &h.Address, &h.AgentVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return Host{}, ErrNotFound
	}
	if err != nil {
		return Host{}, fmt.Errorf("get host %q: %w", id, err)
	}
	return h, nil
}

func (s *Store) ListHosts() ([]Host, error) {
	rows, err := s.db.Query(`SELECT id, name, status, cert_fingerprint, approved_by, last_seen_at, address, agent_version FROM hosts ORDER BY rowid DESC`)
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}
	defer rows.Close()

	var out []Host
	for rows.Next() {
		var h Host
		if err := rows.Scan(&h.ID, &h.Name, &h.Status, &h.CertFingerprint, &h.ApprovedBy, &h.LastSeenAt, &h.Address, &h.AgentVersion); err != nil {
			return nil, fmt.Errorf("scan host: %w", err)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// SetHostAddress records a host's reachable network address (e.g. an IP
// or LAN hostname), used only to build clickable published-port links --
// never guessed from a request's own Host header, which would be wrong
// the moment controller and agent live on different machines.
func (s *Store) SetHostAddress(id, address string) error {
	res, err := s.db.Exec(`UPDATE hosts SET address = ? WHERE id = ?`, address, id)
	if err != nil {
		return fmt.Errorf("set host address %q: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("set host address %q: %w", id, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetHostAgentVersion records the version an agent reported on its most
// recent "state" push (cf. tunnel.go) -- purely informational, compared
// against the latest published release by versioncheck.go to flag an
// outdated agent in the Hosts UI. Overwritten on every state push rather
// than only on change, same as the container/image/volume/network
// snapshots it arrives alongside.
func (s *Store) SetHostAgentVersion(id, version string) error {
	_, err := s.db.Exec(`UPDATE hosts SET agent_version = ? WHERE id = ?`, version, id)
	if err != nil {
		return fmt.Errorf("set host agent version %q: %w", id, err)
	}
	return nil
}

// SetHostName renames a host -- purely a display label (the id, not the
// name, is what every foreign key and the agent's own identity actually
// reference), so renaming has no effect on stacks/containers/tunnels
// already pointing at this host by id.
func (s *Store) SetHostName(id, name string) error {
	res, err := s.db.Exec(`UPDATE hosts SET name = ? WHERE id = ?`, name, id)
	if err != nil {
		return fmt.Errorf("set host name %q: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("set host name %q: %w", id, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ApproveHost is the only thing that ever moves a host out of "pending".
func (s *Store) ApproveHost(id, approvedBy string) error {
	res, err := s.db.Exec(
		`UPDATE hosts SET status = 'connected', approved_by = ?, approved_at = datetime('now') WHERE id = ?`,
		approvedBy, id,
	)
	if err != nil {
		return fmt.Errorf("approve host: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("approve host: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// RejectPendingHost removes a still-pending enrollment. Scoped to
// status = 'pending' in the query itself, not just by the UI only
// showing this button there -- an approved/connected host has real
// tracked data (containers, images, stacks that may target it) a
// rejection was never meant to touch, so the same request against
// anything else is simply a no-op (ErrNotFound) rather than a
// destructive surprise. A rejected agent that retries enrollment just
// shows up again as a fresh pending row -- nothing to remember about
// having said no once.
func (s *Store) RejectPendingHost(id string) error {
	res, err := s.db.Exec(`DELETE FROM hosts WHERE id = ? AND status = 'pending'`, id)
	if err != nil {
		return fmt.Errorf("reject pending host: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("reject pending host: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchHost updates last_seen_at — called on every GET
// /agent/enrollments/{id} poll, doubling as a lightweight heartbeat.
func (s *Store) TouchHost(id string) (Host, error) {
	res, err := s.db.Exec(`UPDATE hosts SET last_seen_at = datetime('now') WHERE id = ?`, id)
	if err != nil {
		return Host{}, fmt.Errorf("touch host: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Host{}, fmt.Errorf("touch host: %w", err)
	}
	if n == 0 {
		return Host{}, ErrNotFound
	}
	return s.GetHost(id)
}

type Deployment struct {
	ID      string
	StackID string
	HostID  string
	Action  string // "up" | "down"
	Trigger string
	Status  string // "queued" | "running" | "succeeded" | "failed"
	Output  string
}

func newDeploymentID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func (s *Store) EnqueueDeployment(stackID, hostID, trigger, action string) (Deployment, error) {
	id := newDeploymentID()
	_, err := s.db.Exec(
		`INSERT INTO deployments (id, stack_id, host_id, trigger_mode, action, status) VALUES (?, ?, ?, ?, ?, 'queued')`,
		id, stackID, hostID, trigger, action,
	)
	if err != nil {
		return Deployment{}, fmt.Errorf("enqueue deployment: %w", err)
	}
	return s.GetDeployment(id)
}

func (s *Store) GetDeployment(id string) (Deployment, error) {
	var d Deployment
	err := s.db.QueryRow(
		`SELECT id, stack_id, host_id, action, trigger_mode, status, output FROM deployments WHERE id = ?`, id,
	).Scan(&d.ID, &d.StackID, &d.HostID, &d.Action, &d.Trigger, &d.Status, &d.Output)
	if errors.Is(err, sql.ErrNoRows) {
		return Deployment{}, ErrNotFound
	}
	if err != nil {
		return Deployment{}, fmt.Errorf("get deployment %q: %w", id, err)
	}
	return d, nil
}

// ClaimNextDeployment atomically flips the oldest queued deployment for
// hostID to "running" and returns it. ok is false if there is none.
func (s *Store) ClaimNextDeployment(hostID string) (dep Deployment, ok bool, err error) {
	var id string
	err = s.db.QueryRow(
		`SELECT id FROM deployments WHERE host_id = ? AND status = 'queued' ORDER BY rowid ASC LIMIT 1`, hostID,
	).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return Deployment{}, false, nil
	}
	if err != nil {
		return Deployment{}, false, fmt.Errorf("find queued deployment: %w", err)
	}

	res, err := s.db.Exec(
		`UPDATE deployments SET status = 'running', started_at = datetime('now') WHERE id = ? AND status = 'queued'`, id,
	)
	if err != nil {
		return Deployment{}, false, fmt.Errorf("claim deployment: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Deployment{}, false, fmt.Errorf("claim deployment: %w", err)
	}
	if n == 0 {
		// Lost a race between the SELECT and the UPDATE -- fine, there is
		// only ever one agent per host polling in practice.
		return Deployment{}, false, nil
	}

	d, err := s.GetDeployment(id)
	return d, true, err
}

func (s *Store) CompleteDeployment(id, status, output string) error {
	res, err := s.db.Exec(
		`UPDATE deployments SET status = ?, output = ?, finished_at = datetime('now') WHERE id = ?`,
		status, output, id,
	)
	if err != nil {
		return fmt.Errorf("complete deployment: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("complete deployment: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// LatestDeploymentForStack returns the most recent deployment row for a
// stack; ok is false if it has never been deployed.
func (s *Store) LatestDeploymentForStack(stackID string) (dep Deployment, ok bool, err error) {
	var id string
	err = s.db.QueryRow(
		`SELECT id FROM deployments WHERE stack_id = ? ORDER BY rowid DESC LIMIT 1`, stackID,
	).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return Deployment{}, false, nil
	}
	if err != nil {
		return Deployment{}, false, fmt.Errorf("latest deployment for stack %q: %w", stackID, err)
	}
	d, err := s.GetDeployment(id)
	return d, true, err
}

// RecentDeployment is one row of the dashboard's activity feed -- a flat,
// already-joined view (stack/host names resolved), unlike Deployment
// which only holds ids and is meant for the deploy/poll machinery.
type RecentDeployment struct {
	StackID   string
	StackName string
	HostName  string
	Action    string
	Trigger   string
	Status    string
	CreatedAt string
}

// ListRecentDeployments returns the most recent deployments across every
// stack, newest first -- the dashboard's activity feed. Unlike
// LatestDeploymentForStack (one per stack, for the stack list/detail
// pages), this is a single global feed that can show a stack more than
// once. INNER JOIN on stacks is safe: DeleteStack cascades into
// deployments, so a row here always has a live stack; hosts have no
// delete path today, but LEFT JOIN costs nothing and stays correct if
// that ever changes.
func (s *Store) ListRecentDeployments(limit int) ([]RecentDeployment, error) {
	rows, err := s.db.Query(
		`SELECT d.stack_id, s.name, COALESCE(h.name, d.host_id), d.action, d.trigger_mode, d.status, d.created_at
		 FROM deployments d
		 JOIN stacks s ON s.id = d.stack_id
		 LEFT JOIN hosts h ON h.id = d.host_id
		 ORDER BY d.rowid DESC
		 LIMIT ?`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list recent deployments: %w", err)
	}
	defer rows.Close()

	var out []RecentDeployment
	for rows.Next() {
		var d RecentDeployment
		if err := rows.Scan(&d.StackID, &d.StackName, &d.HostName, &d.Action, &d.Trigger, &d.Status, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan recent deployment: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// CountDeploymentsSince24h counts deployments queued in the last 24h --
// the dashboard's "Deployments (24h)" stat.
func (s *Store) CountDeploymentsSince24h() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM deployments WHERE created_at >= datetime('now', '-1 day')`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count deployments in last 24h: %w", err)
	}
	return n, nil
}

// CreateGitConnection stores metadata only — no secret material. Credential
// values live exclusively in the isolated secrets-service store (cf.
// internal/keys), keyed by the same id.
func (s *Store) CreateGitConnection(id, name, authKind string) error {
	_, err := s.db.Exec(
		`INSERT INTO git_connections (id, name, auth_kind) VALUES (?, ?, ?)`,
		id, name, authKind,
	)
	if err != nil {
		return fmt.Errorf("insert git connection: %w", err)
	}
	return nil
}

func (s *Store) GetGitConnection(id string) (GitConnection, error) {
	var c GitConnection
	err := s.db.QueryRow(`SELECT id, name, auth_kind FROM git_connections WHERE id = ?`, id).Scan(&c.ID, &c.Name, &c.AuthKind)
	if errors.Is(err, sql.ErrNoRows) {
		return GitConnection{}, ErrNotFound
	}
	if err != nil {
		return GitConnection{}, fmt.Errorf("get git connection %q: %w", id, err)
	}
	return c, nil
}

// RenameGitConnection changes a shared connection's display name.
func (s *Store) RenameGitConnection(id, name string) error {
	_, err := s.db.Exec(`UPDATE git_connections SET name = ? WHERE id = ?`, name, id)
	if err != nil {
		return fmt.Errorf("rename git connection %q: %w", id, err)
	}
	return nil
}

// GitConnectionInUse reports whether any stack currently references
// this connection -- the guard deleteGitConnectionHandler checks before
// ever calling DeleteGitConnection, so a connection several stacks
// share can't be pulled out from under them by mistake.
func (s *Store) GitConnectionInUse(id string) (bool, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM stacks WHERE git_connection_id = ?`, id).Scan(&n); err != nil {
		return false, fmt.Errorf("check git connection usage %q: %w", id, err)
	}
	return n > 0, nil
}

// DeleteGitConnection removes a connection's metadata row. Callers must
// also call keys.Custodian.DeleteConnectionKeys — same split as
// DeleteStack/DeleteStackKeys, main store vs. the isolated secrets
// store.
func (s *Store) DeleteGitConnection(id string) error {
	_, err := s.db.Exec(`DELETE FROM git_connections WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete git connection %q: %w", id, err)
	}
	return nil
}

func (s *Store) ListGitConnections() ([]GitConnection, error) {
	rows, err := s.db.Query(`SELECT id, name, auth_kind FROM git_connections ORDER BY rowid DESC`)
	if err != nil {
		return nil, fmt.Errorf("list git connections: %w", err)
	}
	defer rows.Close()

	var out []GitConnection
	for rows.Next() {
		var c GitConnection
		if err := rows.Scan(&c.ID, &c.Name, &c.AuthKind); err != nil {
			return nil, fmt.Errorf("scan git connection: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ImagePolicy tracks one service's image inside one stack, discovered from
// the compose file actually deployed (cf. syncImagePolicies in
// server/images.go) — never guessed ahead of a real deployment.
type ImagePolicy struct {
	StackID       string
	ServiceName   string
	ImageRef      string
	Policy        string // "pinned" | "auto" | "propose"
	AppliedDigest string
}

// UpsertImagePolicy records a service discovered in a stack's compose
// file. A new (stack, service) pair starts "pinned" (never polled until an
// operator opts in — no surprise registry traffic). An existing row keeps
// its policy; if the image reference itself changed (e.g. a version bump
// in the compose file), applied_digest is reset since the old digest no
// longer describes what's tracked.
func (s *Store) UpsertImagePolicy(stackID, serviceName, imageRef string) error {
	_, err := s.db.Exec(
		`INSERT INTO image_policies (stack_id, service_name, image_ref, updated_at) VALUES (?, ?, ?, datetime('now'))
		 ON CONFLICT (stack_id, service_name) DO UPDATE SET
		   image_ref = excluded.image_ref,
		   applied_digest = CASE WHEN image_policies.image_ref = excluded.image_ref THEN image_policies.applied_digest ELSE '' END,
		   updated_at = datetime('now')`,
		stackID, serviceName, imageRef,
	)
	if err != nil {
		return fmt.Errorf("upsert image policy %q/%q: %w", stackID, serviceName, err)
	}
	return nil
}

// PruneImagePolicies removes rows for services no longer present in the
// stack's compose file — the image-tracking equivalent of --remove-orphans.
func (s *Store) PruneImagePolicies(stackID string, keepServices []string) error {
	keep := make(map[string]bool, len(keepServices))
	for _, svc := range keepServices {
		keep[svc] = true
	}
	rows, err := s.db.Query(`SELECT service_name FROM image_policies WHERE stack_id = ?`, stackID)
	if err != nil {
		return fmt.Errorf("list image policies for prune %q: %w", stackID, err)
	}
	var stale []string
	for rows.Next() {
		var svc string
		if err := rows.Scan(&svc); err != nil {
			rows.Close()
			return fmt.Errorf("scan image policy service: %w", err)
		}
		if !keep[svc] {
			stale = append(stale, svc)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, svc := range stale {
		if _, err := s.db.Exec(`DELETE FROM image_policies WHERE stack_id = ? AND service_name = ?`, stackID, svc); err != nil {
			return fmt.Errorf("prune image policy %q/%q: %w", stackID, svc, err)
		}
	}
	return nil
}

func (s *Store) SetImagePolicy(stackID, serviceName, policy string) error {
	res, err := s.db.Exec(
		`UPDATE image_policies SET policy = ?, updated_at = datetime('now') WHERE stack_id = ? AND service_name = ?`,
		policy, stackID, serviceName,
	)
	if err != nil {
		return fmt.Errorf("set image policy %q/%q: %w", stackID, serviceName, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("set image policy %q/%q: %w", stackID, serviceName, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) SetAppliedDigest(stackID, serviceName, digest string) error {
	_, err := s.db.Exec(
		`UPDATE image_policies SET applied_digest = ?, updated_at = datetime('now') WHERE stack_id = ? AND service_name = ?`,
		digest, stackID, serviceName,
	)
	if err != nil {
		return fmt.Errorf("set applied digest %q/%q: %w", stackID, serviceName, err)
	}
	return nil
}

// ListImagePolicies returns every tracked (stack, service) across the
// whole controller — used by the registry poller to decide what's due a
// check, regardless of which stack it belongs to.
func (s *Store) ListImagePolicies() ([]ImagePolicy, error) {
	rows, err := s.db.Query(`SELECT stack_id, service_name, image_ref, policy, applied_digest FROM image_policies`)
	if err != nil {
		return nil, fmt.Errorf("list image policies: %w", err)
	}
	defer rows.Close()

	var out []ImagePolicy
	for rows.Next() {
		var p ImagePolicy
		if err := rows.Scan(&p.StackID, &p.ServiceName, &p.ImageRef, &p.Policy, &p.AppliedDigest); err != nil {
			return nil, fmt.Errorf("scan image policy: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) ListImagePoliciesForStack(stackID string) ([]ImagePolicy, error) {
	rows, err := s.db.Query(`SELECT stack_id, service_name, image_ref, policy, applied_digest FROM image_policies WHERE stack_id = ? ORDER BY service_name`, stackID)
	if err != nil {
		return nil, fmt.Errorf("list image policies for stack %q: %w", stackID, err)
	}
	defer rows.Close()

	var out []ImagePolicy
	for rows.Next() {
		var p ImagePolicy
		if err := rows.Scan(&p.StackID, &p.ServiceName, &p.ImageRef, &p.Policy, &p.AppliedDigest); err != nil {
			return nil, fmt.Errorf("scan image policy: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetImageDigestCache reads the last known digest for a canonical image
// reference (registry_host/repository:tag) — shared across every stack
// and service that happen to reference the same image, which is the
// whole point: N stacks on "mysql:latest" share one cache row instead of
// each tracking their own copy of a fact that's true for all of them.
func (s *Store) GetImageDigestCache(canonicalRef string) (digest string, ok bool, err error) {
	err = s.db.QueryRow(`SELECT digest FROM image_digest_cache WHERE image_ref = ?`, canonicalRef).Scan(&digest)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("get image digest cache %q: %w", canonicalRef, err)
	}
	if digest == "" {
		return "", false, nil
	}
	return digest, true, nil
}

func (s *Store) SetImageDigestCache(canonicalRef, digest string) error {
	_, err := s.db.Exec(
		`INSERT INTO image_digest_cache (image_ref, digest, checked_at, last_error) VALUES (?, ?, datetime('now'), '')
		 ON CONFLICT (image_ref) DO UPDATE SET digest = excluded.digest, checked_at = excluded.checked_at, last_error = ''`,
		canonicalRef, digest,
	)
	if err != nil {
		return fmt.Errorf("set image digest cache %q: %w", canonicalRef, err)
	}
	return nil
}

// SetImageDigestCacheError records a failed check without touching the
// last known-good digest — a registry hiccup shouldn't erase what was
// previously confirmed, and the error is kept only for operator visibility.
func (s *Store) SetImageDigestCacheError(canonicalRef, errMsg string) error {
	_, err := s.db.Exec(
		`INSERT INTO image_digest_cache (image_ref, digest, checked_at, last_error) VALUES (?, '', datetime('now'), ?)
		 ON CONFLICT (image_ref) DO UPDATE SET checked_at = excluded.checked_at, last_error = excluded.last_error`,
		canonicalRef, errMsg,
	)
	if err != nil {
		return fmt.Errorf("set image digest cache error %q: %w", canonicalRef, err)
	}
	return nil
}

// HostContainer is one row of `docker ps -a` as last reported by a host's
// agent over the container tunnel (cf. server/tunnel.go). StackID/
// ServiceName come from the compose labels the agent's own deployments
// already attach (com.docker.compose.project/.service) — empty for a
// container Wharf didn't deploy.
type HostContainer struct {
	HostID      string
	ContainerID string
	Name        string
	Image       string
	State       string
	Status      string
	Ports       string
	Created     string
	StackID     string
	ServiceName string
	Mounts      string // comma-separated named volumes, cf. store.Volume "used by"
	Networks    string // comma-separated network names, cf. store.Network "containers"
	HostName    string // joined in from hosts, only set by ListHostContainers
}

// ReplaceHostContainers swaps in a host's full container snapshot —
// delete-then-insert in one transaction, same "current truth replaces
// whatever was there" approach as PruneImagePolicies. A container that's
// gone (stopped and removed) simply isn't in the next snapshot; there's
// no separate removal-detection logic to get wrong.
func (s *Store) ReplaceHostContainers(hostID string, rows []HostContainer) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("replace host containers %q: %w", hostID, err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM host_containers WHERE host_id = ?`, hostID); err != nil {
		return fmt.Errorf("replace host containers %q: clear old: %w", hostID, err)
	}
	for _, c := range rows {
		_, err := tx.Exec(
			`INSERT INTO host_containers (host_id, container_id, name, image, state, status, ports, created, stack_id, service_name, mounts, networks, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
			hostID, c.ContainerID, c.Name, c.Image, c.State, c.Status, c.Ports, c.Created, c.StackID, c.ServiceName, c.Mounts, c.Networks,
		)
		if err != nil {
			return fmt.Errorf("replace host containers %q: insert %q: %w", hostID, c.ContainerID, err)
		}
	}
	return tx.Commit()
}

func (s *Store) ListHostContainers() ([]HostContainer, error) {
	rows, err := s.db.Query(
		`SELECT hc.host_id, hc.container_id, hc.name, hc.image, hc.state, hc.status, hc.ports, hc.created, hc.stack_id, hc.service_name, hc.mounts, hc.networks, h.name
		 FROM host_containers hc JOIN hosts h ON h.id = hc.host_id
		 ORDER BY hc.name`,
	)
	if err != nil {
		return nil, fmt.Errorf("list host containers: %w", err)
	}
	defer rows.Close()

	var out []HostContainer
	for rows.Next() {
		var c HostContainer
		if err := rows.Scan(&c.HostID, &c.ContainerID, &c.Name, &c.Image, &c.State, &c.Status, &c.Ports, &c.Created, &c.StackID, &c.ServiceName, &c.Mounts, &c.Networks, &c.HostName); err != nil {
			return nil, fmt.Errorf("scan host container: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListHostContainersByStack is ListHostContainers scoped to one stack —
// what the stack detail page shows, rather than the fleet-wide list.
func (s *Store) ListHostContainersByStack(stackID string) ([]HostContainer, error) {
	rows, err := s.db.Query(
		`SELECT hc.host_id, hc.container_id, hc.name, hc.image, hc.state, hc.status, hc.ports, hc.created, hc.stack_id, hc.service_name, hc.mounts, hc.networks, h.name
		 FROM host_containers hc JOIN hosts h ON h.id = hc.host_id
		 WHERE hc.stack_id = ?
		 ORDER BY hc.service_name, hc.name`, stackID,
	)
	if err != nil {
		return nil, fmt.Errorf("list host containers for stack %q: %w", stackID, err)
	}
	defer rows.Close()

	var out []HostContainer
	for rows.Next() {
		var c HostContainer
		if err := rows.Scan(&c.HostID, &c.ContainerID, &c.Name, &c.Image, &c.State, &c.Status, &c.Ports, &c.Created, &c.StackID, &c.ServiceName, &c.Mounts, &c.Networks, &c.HostName); err != nil {
			return nil, fmt.Errorf("scan host container: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetHostContainerByID(containerID string) (HostContainer, error) {
	var c HostContainer
	err := s.db.QueryRow(
		`SELECT hc.host_id, hc.container_id, hc.name, hc.image, hc.state, hc.status, hc.ports, hc.created, hc.stack_id, hc.service_name, hc.mounts, hc.networks, h.name
		 FROM host_containers hc JOIN hosts h ON h.id = hc.host_id
		 WHERE hc.container_id = ?`, containerID,
	).Scan(&c.HostID, &c.ContainerID, &c.Name, &c.Image, &c.State, &c.Status, &c.Ports, &c.Created, &c.StackID, &c.ServiceName, &c.Mounts, &c.Networks, &c.HostName)
	if errors.Is(err, sql.ErrNoRows) {
		return HostContainer{}, ErrNotFound
	}
	if err != nil {
		return HostContainer{}, fmt.Errorf("get host container %q: %w", containerID, err)
	}
	return c, nil
}

// HostImage is one row of `docker images` as last reported by a host's
// agent over the same tunnel as HostContainer (cf. server/tunnel.go).
// Keyed by (host_id, image_id, repository, tag), the full triple: a
// single image can carry several tags (several rows sharing one
// image_id, caught by testing when (host_id, image_id) alone made a
// multi-tagged image's second row fail), and separately, any number of
// distinct dangling images can share repository=tag="<none>" on the
// same host (caught the same way, the other side of the same bug --
// (host_id, repository, tag) alone made the *second* dangling image on
// a host collide, silently rolling back the whole snapshot and hiding
// every dangling image from the UI, not just the one that collided).
type HostImage struct {
	HostID     string
	ImageID    string
	Repository string
	Tag        string
	Size       string
	HostName   string // joined in from hosts, only set by ListHostImages
}

// ReplaceHostImages swaps in a host's full image snapshot -- same
// delete-then-insert approach as ReplaceHostContainers, for the same
// reason: an image that's gone (removed) just isn't in the next
// snapshot, no separate removal detection to write.
func (s *Store) ReplaceHostImages(hostID string, rows []HostImage) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("replace host images %q: %w", hostID, err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM host_images WHERE host_id = ?`, hostID); err != nil {
		return fmt.Errorf("replace host images %q: clear old: %w", hostID, err)
	}
	for _, img := range rows {
		_, err := tx.Exec(
			`INSERT INTO host_images (host_id, image_id, repository, tag, size, updated_at)
			 VALUES (?, ?, ?, ?, ?, datetime('now'))`,
			hostID, img.ImageID, img.Repository, img.Tag, img.Size,
		)
		if err != nil {
			return fmt.Errorf("replace host images %q: insert %q: %w", hostID, img.ImageID, err)
		}
	}
	return tx.Commit()
}

func (s *Store) ListHostImages() ([]HostImage, error) {
	rows, err := s.db.Query(
		`SELECT hi.host_id, hi.image_id, hi.repository, hi.tag, hi.size, h.name
		 FROM host_images hi JOIN hosts h ON h.id = hi.host_id
		 ORDER BY hi.repository, hi.tag`,
	)
	if err != nil {
		return nil, fmt.Errorf("list host images: %w", err)
	}
	defer rows.Close()

	var out []HostImage
	for rows.Next() {
		var img HostImage
		if err := rows.Scan(&img.HostID, &img.ImageID, &img.Repository, &img.Tag, &img.Size, &img.HostName); err != nil {
			return nil, fmt.Errorf("scan host image: %w", err)
		}
		out = append(out, img)
	}
	return out, rows.Err()
}

// HostVolume is one row of `docker volume ls` as last reported by a
// host's agent over the same tunnel as HostContainer/HostImage (cf.
// server/tunnel.go). Deliberately has no Size: real per-volume disk
// usage needs `docker system df -v`, which walks each volume's files
// and is too slow to run on every docker events line (cf.
// ARCHITECTURE.md) -- left for a later, separate chunk.
type HostVolume struct {
	HostID   string
	Name     string
	Driver   string
	HostName string // joined in from hosts, only set by ListHostVolumes
}

// ReplaceHostVolumes swaps in a host's full volume snapshot -- same
// delete-then-insert approach as ReplaceHostContainers/ReplaceHostImages.
func (s *Store) ReplaceHostVolumes(hostID string, rows []HostVolume) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("replace host volumes %q: %w", hostID, err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM host_volumes WHERE host_id = ?`, hostID); err != nil {
		return fmt.Errorf("replace host volumes %q: clear old: %w", hostID, err)
	}
	for _, v := range rows {
		_, err := tx.Exec(
			`INSERT INTO host_volumes (host_id, name, driver, updated_at) VALUES (?, ?, ?, datetime('now'))`,
			hostID, v.Name, v.Driver,
		)
		if err != nil {
			return fmt.Errorf("replace host volumes %q: insert %q: %w", hostID, v.Name, err)
		}
	}
	return tx.Commit()
}

func (s *Store) ListHostVolumes() ([]HostVolume, error) {
	rows, err := s.db.Query(
		`SELECT hv.host_id, hv.name, hv.driver, h.name
		 FROM host_volumes hv JOIN hosts h ON h.id = hv.host_id
		 ORDER BY hv.name`,
	)
	if err != nil {
		return nil, fmt.Errorf("list host volumes: %w", err)
	}
	defer rows.Close()

	var out []HostVolume
	for rows.Next() {
		var v HostVolume
		if err := rows.Scan(&v.HostID, &v.Name, &v.Driver, &v.HostName); err != nil {
			return nil, fmt.Errorf("scan host volume: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// HostNetwork is one row of `docker network ls` as last reported by a
// host's agent over the same tunnel as HostContainer/HostImage/
// HostVolume (cf. server/tunnel.go). "Which containers use this
// network" isn't stored here: derived from HostContainer.Networks at
// display time, same pattern as HostVolume's "used by".
type HostNetwork struct {
	HostID   string
	Name     string
	Driver   string
	Scope    string
	HostName string // joined in from hosts, only set by ListHostNetworks
}

// ReplaceHostNetworks swaps in a host's full network snapshot -- same
// delete-then-insert approach as the other three host_* tables.
func (s *Store) ReplaceHostNetworks(hostID string, rows []HostNetwork) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("replace host networks %q: %w", hostID, err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM host_networks WHERE host_id = ?`, hostID); err != nil {
		return fmt.Errorf("replace host networks %q: clear old: %w", hostID, err)
	}
	for _, n := range rows {
		_, err := tx.Exec(
			`INSERT INTO host_networks (host_id, name, driver, scope, updated_at) VALUES (?, ?, ?, ?, datetime('now'))`,
			hostID, n.Name, n.Driver, n.Scope,
		)
		if err != nil {
			return fmt.Errorf("replace host networks %q: insert %q: %w", hostID, n.Name, err)
		}
	}
	return tx.Commit()
}

func (s *Store) ListHostNetworks() ([]HostNetwork, error) {
	rows, err := s.db.Query(
		`SELECT hn.host_id, hn.name, hn.driver, hn.scope, h.name
		 FROM host_networks hn JOIN hosts h ON h.id = hn.host_id
		 ORDER BY hn.name`,
	)
	if err != nil {
		return nil, fmt.Errorf("list host networks: %w", err)
	}
	defer rows.Close()

	var out []HostNetwork
	for rows.Next() {
		var n HostNetwork
		if err := rows.Scan(&n.HostID, &n.Name, &n.Driver, &n.Scope, &n.HostName); err != nil {
			return nil, fmt.Errorf("scan host network: %w", err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// StackRevision is a lightweight version history entry for a local
// stack's compose file — the closest equivalent a local (no-Git) stack
// has to commit history. Recorded on every edit, capturing what the
// compose content *was* right before it changed.
type StackRevision struct {
	ID             int64
	StackID        string
	ComposeContent string
	CreatedAt      string
}

// RecordStackRevision snapshots a stack's current compose content before
// it's about to change — called by both editing and restoring, so
// restoring an old revision is itself undoable (it becomes a new
// revision on top, nothing is ever overwritten in place).
func (s *Store) RecordStackRevision(stackID, composeContent string) error {
	_, err := s.db.Exec(
		`INSERT INTO stack_revisions (stack_id, compose_content) VALUES (?, ?)`,
		stackID, composeContent,
	)
	if err != nil {
		return fmt.Errorf("record stack revision for %q: %w", stackID, err)
	}
	return nil
}

func (s *Store) ListStackRevisions(stackID string) ([]StackRevision, error) {
	rows, err := s.db.Query(
		`SELECT id, stack_id, compose_content, created_at FROM stack_revisions WHERE stack_id = ? ORDER BY id DESC`, stackID,
	)
	if err != nil {
		return nil, fmt.Errorf("list stack revisions for %q: %w", stackID, err)
	}
	defer rows.Close()

	var out []StackRevision
	for rows.Next() {
		var rev StackRevision
		if err := rows.Scan(&rev.ID, &rev.StackID, &rev.ComposeContent, &rev.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan stack revision: %w", err)
		}
		out = append(out, rev)
	}
	return out, rows.Err()
}

// GetStackRevision scopes the lookup to stackID too, not just the
// revision id — a URL parameter alone shouldn't be able to pull another
// stack's compose content into this one via restore.
func (s *Store) GetStackRevision(stackID string, id int64) (StackRevision, error) {
	var rev StackRevision
	err := s.db.QueryRow(
		`SELECT id, stack_id, compose_content, created_at FROM stack_revisions WHERE id = ? AND stack_id = ?`, id, stackID,
	).Scan(&rev.ID, &rev.StackID, &rev.ComposeContent, &rev.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return StackRevision{}, ErrNotFound
	}
	if err != nil {
		return StackRevision{}, fmt.Errorf("get stack revision %d for %q: %w", id, stackID, err)
	}
	return rev, nil
}

// UpdateStackCompose overwrites a local stack's compose content. Callers
// are expected to RecordStackRevision the old content first — this
// function doesn't do it itself so a future caller with a different
// reason to change compose_content isn't forced into the history model.
func (s *Store) UpdateStackCompose(stackID, composeContent string) error {
	res, err := s.db.Exec(`UPDATE stacks SET compose_content = ? WHERE id = ?`, composeContent, stackID)
	if err != nil {
		return fmt.Errorf("update compose content for %q: %w", stackID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update compose content for %q: %w", stackID, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateStackSecret overwrites a local stack's whole encrypted secret
// block -- ciphertext nil/empty clears it entirely, same "whatever you
// submit becomes the full content" semantics as UpdateStackCompose,
// never a merge with what was there. No revision history here (unlike
// compose content): a secret's old value is meant to become
// unrecoverable, not preserved.
func (s *Store) UpdateStackSecret(stackID string, ciphertext []byte) error {
	res, err := s.db.Exec(`UPDATE stacks SET encrypted_secret = ? WHERE id = ?`, ciphertext, stackID)
	if err != nil {
		return fmt.Errorf("update secret for %q: %w", stackID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update secret for %q: %w", stackID, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// User is a local or OIDC account (ARCHITECTURE.md, "Modèle de
// données" -- OIDCSubject/OIDCIssuer are populated once OIDC login
// itself is wired; both nullable columns already exist so that isn't a
// second migration later). Never carries PasswordHash -- nothing above
// the store package needs it, only VerifyUserCredentials compares it
// internally.
type User struct {
	Username           string
	Role               string // "admin" | "operator"
	MustChangePassword bool
	OIDCSubject        string
	OIDCIssuer         string
	CreatedAt          string
	LastLoginAt        string
}

// EnsureFirstUser bootstraps the very first account (role "admin") when
// no user exists yet -- either from WHARF_ADMIN_USER/WHARF_ADMIN_PASSWORD
// on a genuinely fresh controller, or migrated from the pre-multi-user
// admin_user singleton on one upgrading from that model. The migration
// path matters: an operator who already went through the forced
// first-login password change once must never be sent through it again
// just because this feature landed -- their existing hash and
// must_change_password state move over as-is, the env vars are ignored
// entirely in that case.
func (s *Store) EnsureFirstUser(username, password string) error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return fmt.Errorf("count users: %w", err)
	}
	if n > 0 {
		return nil
	}

	var legacyUsername, legacyHash string
	var legacyMustChange bool
	err := s.db.QueryRow(`SELECT username, password_hash, must_change_password FROM admin_user WHERE id = 1`).
		Scan(&legacyUsername, &legacyHash, &legacyMustChange)
	switch {
	case err == nil:
		_, err = s.db.Exec(
			`INSERT INTO users (username, password_hash, role, must_change_password) VALUES (?, ?, 'admin', ?)`,
			legacyUsername, legacyHash, legacyMustChange,
		)
		if err != nil {
			return fmt.Errorf("migrate legacy admin user: %w", err)
		}
		return nil
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("check legacy admin user: %w", err)
	}

	hash, herr := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if herr != nil {
		return fmt.Errorf("hash admin password: %w", herr)
	}
	if _, err := s.db.Exec(`INSERT INTO users (username, password_hash, role, must_change_password) VALUES (?, ?, 'admin', 1)`, username, string(hash)); err != nil {
		return fmt.Errorf("create first user: %w", err)
	}
	return nil
}

// VerifyUserCredentials reports whether username/password match a local
// account. A wrong username, an unknown user, or an OIDC-only account
// (empty password_hash) all still run a bcrypt compare against a fixed
// dummy hash so none of those cases is observably faster than a wrong
// password on a real account.
var dummyHashForTiming, _ = bcrypt.GenerateFromPassword([]byte("wharf-timing-decoy"), bcrypt.DefaultCost)

func (s *Store) VerifyUserCredentials(username, password string) (bool, error) {
	var hash string
	err := s.db.QueryRow(`SELECT password_hash FROM users WHERE username = ?`, username).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && hash == "") {
		bcrypt.CompareHashAndPassword(dummyHashForTiming, []byte(password))
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("load user %q: %w", username, err)
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil, nil
}

// GetUserByUsername is requireAuth's per-request lookup (cf.
// server/auth.go) -- role and must_change_password are never cached in
// the session itself, so a role change or a forced password reset takes
// effect on this user's very next request, not after their session
// expires.
func (s *Store) GetUserByUsername(username string) (User, error) {
	var u User
	var mustChange int
	var oidcSubject, oidcIssuer, lastLogin sql.NullString
	err := s.db.QueryRow(
		`SELECT username, role, must_change_password, oidc_subject, oidc_issuer, created_at, last_login_at FROM users WHERE username = ?`, username,
	).Scan(&u.Username, &u.Role, &mustChange, &oidcSubject, &oidcIssuer, &u.CreatedAt, &lastLogin)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("get user %q: %w", username, err)
	}
	u.MustChangePassword = mustChange != 0
	u.OIDCSubject = oidcSubject.String
	u.OIDCIssuer = oidcIssuer.String
	u.LastLoginAt = lastLogin.String
	return u, nil
}

// ListUsers returns every account, sorted by username -- the /users
// admin page.
func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query(`SELECT username, role, must_change_password, oidc_subject, oidc_issuer, created_at, last_login_at FROM users ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		var u User
		var mustChange int
		var oidcSubject, oidcIssuer, lastLogin sql.NullString
		if err := rows.Scan(&u.Username, &u.Role, &mustChange, &oidcSubject, &oidcIssuer, &u.CreatedAt, &lastLogin); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		u.MustChangePassword = mustChange != 0
		u.OIDCSubject = oidcSubject.String
		u.OIDCIssuer = oidcIssuer.String
		u.LastLoginAt = lastLogin.String
		out = append(out, u)
	}
	return out, rows.Err()
}

// TouchUserLogin stamps last_login_at on a successful sign-in --
// best-effort, called after VerifyUserCredentials already confirmed the
// password, so a failure here shouldn't block the login itself.
func (s *Store) TouchUserLogin(username string) error {
	_, err := s.db.Exec(`UPDATE users SET last_login_at = datetime('now') WHERE username = ?`, username)
	if err != nil {
		return fmt.Errorf("touch login for %q: %w", username, err)
	}
	return nil
}

// GetUserByOIDCSubject looks up an account already linked to this exact
// (issuer, subject) pair -- the stable identity OIDC actually promises,
// unlike a username/email a provider could let change. ok is false on
// a first-ever login from this identity, not an error: the caller
// provisions a new account in that case (cf. oidc.go).
func (s *Store) GetUserByOIDCSubject(issuer, subject string) (User, bool, error) {
	var u User
	var mustChange int
	var oidcSubject, oidcIssuer, lastLogin sql.NullString
	err := s.db.QueryRow(
		`SELECT username, role, must_change_password, oidc_subject, oidc_issuer, created_at, last_login_at
		 FROM users WHERE oidc_issuer = ? AND oidc_subject = ?`, issuer, subject,
	).Scan(&u.Username, &u.Role, &mustChange, &oidcSubject, &oidcIssuer, &u.CreatedAt, &lastLogin)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, fmt.Errorf("get user by oidc subject: %w", err)
	}
	u.MustChangePassword = mustChange != 0
	u.OIDCSubject = oidcSubject.String
	u.OIDCIssuer = oidcIssuer.String
	u.LastLoginAt = lastLogin.String
	return u, true, nil
}

// CreateOIDCUser provisions a brand-new account on a first successful
// OIDC login -- no password_hash (empty, cf. VerifyUserCredentials
// already treating that as "can't log in with a password"), no forced
// change screen (there's no local password to change). role is normally
// "operator" -- an identity provider knowing who someone is says nothing
// about what they should be allowed to manage in Wharf -- unless the
// caller has matched an admin-group claim (cf. server/oidc.go's optional
// AdminGroup setting), in which case the account is provisioned as
// "admin" directly rather than created as operator and promoted a
// heartbeat later. Returns ErrNotFound-shaped conflict error if username
// is already taken by a different account (local, or a different OIDC
// identity) -- caller must not silently link an OIDC login to an
// unrelated existing user just because the name matches.
func (s *Store) CreateOIDCUser(username, issuer, subject, role string) error {
	if role != "admin" && role != "operator" {
		role = "operator"
	}
	_, err := s.db.Exec(
		`INSERT INTO users (username, password_hash, role, must_change_password, oidc_subject, oidc_issuer) VALUES (?, '', ?, 0, ?, ?)`,
		username, role, subject, issuer,
	)
	if err != nil {
		return fmt.Errorf("create oidc user %q: %w", username, err)
	}
	return nil
}

// CreateUser is the admin-only path (server/users.go) -- always forces a
// change on first login, same as EnsureFirstUser's own bootstrap,
// because the admin creating this account necessarily knows the initial
// password too.
func (s *Store) CreateUser(username, password, role string) error {
	if role != "admin" && role != "operator" {
		return fmt.Errorf("invalid role %q", role)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	_, err = s.db.Exec(`INSERT INTO users (username, password_hash, role, must_change_password) VALUES (?, ?, ?, 1)`, username, string(hash), role)
	if err != nil {
		return fmt.Errorf("create user %q: %w", username, err)
	}
	return nil
}

// SetUserPassword is the self-service path (the logged-in user changing
// their own password after verifying their current one) -- clears
// must_change_password, since they chose this one themselves.
func (s *Store) SetUserPassword(username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	res, err := s.db.Exec(`UPDATE users SET password_hash = ?, must_change_password = 0 WHERE username = ?`, string(hash), username)
	if err != nil {
		return fmt.Errorf("set password for %q: %w", username, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AdminResetUserPassword is the admin-initiated path (server/users.go,
// "Reset password" on another account) -- unlike SetUserPassword, this
// sets must_change_password back to true: the admin now also knows this
// temporary password, so the account isn't really secured again until
// its owner picks their own.
func (s *Store) AdminResetUserPassword(username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	res, err := s.db.Exec(`UPDATE users SET password_hash = ?, must_change_password = 1 WHERE username = ?`, string(hash), username)
	if err != nil {
		return fmt.Errorf("reset password for %q: %w", username, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ErrLastAdmin is returned by SetUserRole/DeleteUser when the requested
// change would leave zero admin accounts -- a controller with no admin
// left can never manage git connections, registry credentials, or users
// again, so this is refused outright rather than left as a foot-gun.
// Exported so callers like the OIDC group-sync path (server/oidc.go) can
// treat it as an expected, non-fatal outcome rather than a login error.
var ErrLastAdmin = errors.New("cannot remove the last admin account")

// SetUserRole changes a user's role, guarded in the same transaction
// against demoting the last remaining admin.
func (s *Store) SetUserRole(username, role string) error {
	if role != "admin" && role != "operator" {
		return fmt.Errorf("invalid role %q", role)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("set role for %q: %w", username, err)
	}
	defer tx.Rollback()

	var currentRole string
	if err := tx.QueryRow(`SELECT role FROM users WHERE username = ?`, username).Scan(&currentRole); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("load user %q: %w", username, err)
	}
	if currentRole == "admin" && role != "admin" {
		var adminCount int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin'`).Scan(&adminCount); err != nil {
			return fmt.Errorf("count admins: %w", err)
		}
		if adminCount <= 1 {
			return ErrLastAdmin
		}
	}
	if _, err := tx.Exec(`UPDATE users SET role = ? WHERE username = ?`, role, username); err != nil {
		return fmt.Errorf("set role for %q: %w", username, err)
	}
	return tx.Commit()
}

// DeleteUser removes an account and every one of its live sessions in
// the same transaction -- without that second delete, a just-removed
// user's existing cookie would keep authenticating them for up to
// SessionTTL. Guarded like SetUserRole against deleting the last admin.
func (s *Store) DeleteUser(username string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("delete user %q: %w", username, err)
	}
	defer tx.Rollback()

	var role string
	if err := tx.QueryRow(`SELECT role FROM users WHERE username = ?`, username).Scan(&role); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("load user %q: %w", username, err)
	}
	if role == "admin" {
		var adminCount int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin'`).Scan(&adminCount); err != nil {
			return fmt.Errorf("count admins: %w", err)
		}
		if adminCount <= 1 {
			return ErrLastAdmin
		}
	}
	if _, err := tx.Exec(`DELETE FROM users WHERE username = ?`, username); err != nil {
		return fmt.Errorf("delete user %q: %w", username, err)
	}
	if _, err := tx.Exec(`DELETE FROM sessions WHERE username = ?`, username); err != nil {
		return fmt.Errorf("delete sessions for %q: %w", username, err)
	}
	return tx.Commit()
}

// SessionTTL is how long a session cookie stays valid after login. The
// UI's cookie MaxAge (cf. server/auth.go) is derived from this constant
// rather than repeating the value, so the two can't drift apart.
const SessionTTL = 7 * 24 * time.Hour

// CreateSession issues a new random session token for username, valid for
// SessionTTL, and opportunistically sweeps expired rows so the table
// doesn't grow unbounded on a single-admin system with no other cleanup
// job.
func (s *Store) CreateSession(username string) (string, error) {
	if _, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < datetime('now')`); err != nil {
		return "", fmt.Errorf("sweep expired sessions: %w", err)
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	token := fmt.Sprintf("%x", b)
	expiresAt := time.Now().Add(SessionTTL).UTC().Format("2006-01-02 15:04:05")
	if _, err := s.db.Exec(`INSERT INTO sessions (token, username, expires_at) VALUES (?, ?, ?)`, token, username, expiresAt); err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}
	return token, nil
}

// GetSessionUsername returns the username for a live (unexpired) session
// token, or ok=false if the token is unknown or has expired.
func (s *Store) GetSessionUsername(token string) (username string, ok bool, err error) {
	err = s.db.QueryRow(`SELECT username FROM sessions WHERE token = ? AND expires_at > datetime('now')`, token).Scan(&username)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("get session: %w", err)
	}
	return username, true, nil
}

// DeleteSession removes a session token (logout). Deleting an
// already-gone token is not an error -- logout is idempotent.
func (s *Store) DeleteSession(token string) error {
	if _, err := s.db.Exec(`DELETE FROM sessions WHERE token = ?`, token); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// AuditEntry is one row of the admin-facing audit trail (cf.
// server/audit.go) -- who did what, to which resource, and when. Not a
// security control (nothing here is tamper-evident or exported off the
// box) -- just accountability once more than one admin/operator can
// touch the same instance.
type AuditEntry struct {
	ID        int64
	Username  string
	Action    string
	Target    string
	Detail    string
	CreatedAt string
}

// RecordAudit appends one row -- always append-only, no update/delete
// path, since editing your own audit trail after the fact defeats the
// point of having one.
func (s *Store) RecordAudit(username, action, target, detail string) error {
	_, err := s.db.Exec(
		`INSERT INTO audit_log (username, action, target, detail) VALUES (?, ?, ?, ?)`,
		username, action, target, detail,
	)
	if err != nil {
		return fmt.Errorf("record audit entry: %w", err)
	}
	return nil
}

// ListAudit returns the most recent entries, newest first, capped at
// limit -- no pagination yet (cf. the /audit-log page), same "build what
// today's scale actually needs" call as image polling's fixed interval;
// revisit if a real instance's history ever makes 500 too few to find
// something in.
func (s *Store) ListAudit(limit int) ([]AuditEntry, error) {
	rows, err := s.db.Query(`SELECT id, username, action, target, detail, created_at FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit entries: %w", err)
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.Username, &e.Action, &e.Target, &e.Detail, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan audit entry: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
