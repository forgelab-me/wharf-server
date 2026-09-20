// Package keys is the secrets custodian described in ARCHITECTURE.md
// ("Garde des clés : tout sur le contrôleur, jamais sur les agents") — the
// only code in the controller that ever holds an age private key. It has
// its own SQLite file, physically separate from the main application
// database; nothing outside this package ever sees a private key.
package keys

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
	_ "modernc.org/sqlite"
)

type Custodian struct {
	db *sql.DB
}

func Open(path string) (*Custodian, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open key store: %w", err)
	}
	const schema = `
	CREATE TABLE IF NOT EXISTS age_keys (
		stack_id    TEXT PRIMARY KEY,
		public_key  TEXT NOT NULL,
		private_key TEXT NOT NULL,
		source      TEXT NOT NULL DEFAULT 'generated',
		created_at  TEXT NOT NULL DEFAULT (datetime('now'))
	);
	CREATE TABLE IF NOT EXISTS ssh_keys (
		stack_id    TEXT PRIMARY KEY,
		public_key  TEXT NOT NULL,
		private_key TEXT NOT NULL,
		source      TEXT NOT NULL DEFAULT 'generated',
		created_at  TEXT NOT NULL DEFAULT (datetime('now'))
	);
	CREATE TABLE IF NOT EXISTS connection_ssh_keys (
		connection_id TEXT PRIMARY KEY,
		public_key    TEXT NOT NULL,
		private_key   TEXT NOT NULL,
		source        TEXT NOT NULL DEFAULT 'generated',
		created_at    TEXT NOT NULL DEFAULT (datetime('now'))
	);
	CREATE TABLE IF NOT EXISTS connection_http_credentials (
		connection_id TEXT PRIMARY KEY,
		username      TEXT NOT NULL,
		password      TEXT NOT NULL,
		created_at    TEXT NOT NULL DEFAULT (datetime('now'))
	);
	CREATE TABLE IF NOT EXISTS registry_credentials (
		host       TEXT PRIMARY KEY,
		name       TEXT NOT NULL DEFAULT '',
		type       TEXT NOT NULL DEFAULT 'custom',
		username   TEXT NOT NULL,
		password   TEXT NOT NULL,
		created_at TEXT NOT NULL DEFAULT (datetime('now'))
	);
	CREATE TABLE IF NOT EXISTS oidc_config (
		id            INTEGER PRIMARY KEY CHECK (id = 1),
		issuer_url    TEXT NOT NULL,
		client_id     TEXT NOT NULL,
		client_secret TEXT NOT NULL,
		display_name    TEXT NOT NULL DEFAULT 'SSO',
		admin_group     TEXT NOT NULL DEFAULT '',
		operator_group  TEXT NOT NULL DEFAULT '',
		disable_local_auth INTEGER NOT NULL DEFAULT 0,
		updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
	);`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init key store schema: %w", err)
	}
	if _, err := db.Exec(`ALTER TABLE registry_credentials ADD COLUMN name TEXT NOT NULL DEFAULT ''`); err != nil && !isDuplicateColumn(err) {
		db.Close()
		return nil, fmt.Errorf("migrate registry_credentials.name: %w", err)
	}
	if _, err := db.Exec(`ALTER TABLE registry_credentials ADD COLUMN type TEXT NOT NULL DEFAULT 'custom'`); err != nil && !isDuplicateColumn(err) {
		db.Close()
		return nil, fmt.Errorf("migrate registry_credentials.type: %w", err)
	}
	if _, err := db.Exec(`ALTER TABLE oidc_config ADD COLUMN admin_group TEXT NOT NULL DEFAULT ''`); err != nil && !isDuplicateColumn(err) {
		db.Close()
		return nil, fmt.Errorf("migrate oidc_config.admin_group: %w", err)
	}
	if _, err := db.Exec(`ALTER TABLE oidc_config ADD COLUMN operator_group TEXT NOT NULL DEFAULT ''`); err != nil && !isDuplicateColumn(err) {
		db.Close()
		return nil, fmt.Errorf("migrate oidc_config.operator_group: %w", err)
	}
	if _, err := db.Exec(`ALTER TABLE oidc_config ADD COLUMN disable_local_auth INTEGER NOT NULL DEFAULT 0`); err != nil && !isDuplicateColumn(err) {
		db.Close()
		return nil, fmt.Errorf("migrate oidc_config.disable_local_auth: %w", err)
	}
	// Owner-only, every startup, not just at creation -- this is the one
	// file in the whole controller that ever holds a private key, cf. the
	// package comment. Best-effort: a platform where chmod isn't
	// meaningful (Windows) just leaves it alone rather than failing
	// startup over it.
	_ = os.Chmod(path, 0o600)
	return &Custodian{db: db}, nil
}

// isDuplicateColumn recognizes SQLite's "duplicate column name" error from
// an ALTER TABLE ADD COLUMN that's already been applied by a previous
// startup -- CREATE TABLE IF NOT EXISTS above only handles a brand-new
// database; an existing one from before these columns existed needs this
// migration path instead, run idempotently on every startup.
func isDuplicateColumn(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate column name")
}

func (c *Custodian) Close() error { return c.db.Close() }

// GenerateKeypair creates a fresh age keypair for stackID and returns only
// the public key. The private key is written straight to the isolated
// store and never returned to any caller — by construction, not by
// convention.
func (c *Custodian) GenerateKeypair(stackID string) (publicKey string, err error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", fmt.Errorf("generate age identity: %w", err)
	}
	_, err = c.db.Exec(
		`INSERT INTO age_keys (stack_id, public_key, private_key, source) VALUES (?, ?, ?, 'generated')`,
		stackID, id.Recipient().String(), id.String(),
	)
	if err != nil {
		return "", fmt.Errorf("store generated key: %w", err)
	}
	return id.Recipient().String(), nil
}

// PublicKey returns the (non-secret) public key for a stack, for display.
func (c *Custodian) PublicKey(stackID string) (string, error) {
	var pub string
	err := c.db.QueryRow(`SELECT public_key FROM age_keys WHERE stack_id = ?`, stackID).Scan(&pub)
	if err != nil {
		return "", fmt.Errorf("lookup public key: %w", err)
	}
	return pub, nil
}

// Encrypt encrypts plaintext to stackID's current public key. Used for
// UI-authored (local) stacks: the caller must discard the plaintext right
// after this call and persist only the returned ciphertext (cf.
// ARCHITECTURE.md, "Création sans Git").
func (c *Custodian) Encrypt(stackID string, plaintext []byte) ([]byte, error) {
	pub, err := c.PublicKey(stackID)
	if err != nil {
		return nil, err
	}
	recipient, err := age.ParseX25519Recipient(pub)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	var buf bytes.Buffer
	wc, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, fmt.Errorf("start encryption: %w", err)
	}
	if _, err := wc.Write(plaintext); err != nil {
		return nil, fmt.Errorf("write plaintext: %w", err)
	}
	if err := wc.Close(); err != nil {
		return nil, fmt.Errorf("finalize encryption: %w", err)
	}
	return buf.Bytes(), nil
}

// Decrypt is the one operation that ever touches a private key — cf.
// ARCHITECTURE.md's Decrypt(stack_id, ciphertext) -> plaintext.
func (c *Custodian) Decrypt(stackID string, ciphertext []byte) ([]byte, error) {
	var priv string
	err := c.db.QueryRow(`SELECT private_key FROM age_keys WHERE stack_id = ?`, stackID).Scan(&priv)
	if err != nil {
		return nil, fmt.Errorf("lookup private key: %w", err)
	}
	id, err := age.ParseX25519Identity(priv)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	// A stack's secrets.enc.yaml can be either format: Wharf's own
	// plain-age whole-file encryption, or real SOPS output (age used as
	// SOPS' KMS backend) from an existing external workflow -- cf.
	// sops.go. Detected by shape, not by a file extension or a setting,
	// so nothing about how a stack is configured needs to say which one
	// it used.
	if looksLikeSOPS(ciphertext) {
		return decryptSOPS(ciphertext, id)
	}

	r, err := age.Decrypt(bytes.NewReader(ciphertext), id)
	if err != nil {
		if looksCRLFMangled(ciphertext) {
			// A real age file's header is pure ASCII with bare LF line
			// endings per spec -- a \r this early can only mean something
			// rewrote line endings after age produced the file (Git's
			// autocrlf checking it out as "text" with no .gitattributes
			// override, a Windows shell's text-mode redirection, an
			// editor's own save). Deliberately not auto-corrected: if the
			// mangling touched the binary payload too (any stray 0x0A byte
			// in the ciphertext would have picked up the same extra 0x0D),
			// blindly stripping \r could silently reconstruct the wrong
			// plaintext instead of failing loudly -- a re-encrypt is the
			// only reliably correct fix, cf. ARCHITECTURE.md.
			return nil, fmt.Errorf("decrypt: ciphertext has Windows-style line endings (CRLF), which corrupts age's binary format -- mark this file as binary (e.g. a .gitattributes line like \"secrets.enc.yaml -text\") and re-encrypt/re-commit it; original error: %w", err)
		}
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return nil, fmt.Errorf("read plaintext: %w", err)
	}
	return buf.Bytes(), nil
}

// looksCRLFMangled checks for a \r within age's own plaintext header
// (comfortably longer than "age-encryption.org/v1" plus a couple of
// recipient stanza lines) -- real age output never contains one there,
// so finding one is a reliable, low-false-positive signal of this
// specific corruption rather than a garden-variety wrong-key/corrupt-
// ciphertext failure.
func looksCRLFMangled(ciphertext []byte) bool {
	n := len(ciphertext)
	if n > 256 {
		n = 256
	}
	return bytes.Contains(ciphertext[:n], []byte("\r"))
}

// DeleteStackKeys removes a stack's private key material — its age
// keypair and, if it has one, its dedicated SSH deploy key (a stack
// using a shared git_connection instead has no row here, so this is a
// harmless no-op for that half). Called when a stack itself is deleted:
// its keys must never outlive the stack that owned them.
func (c *Custodian) DeleteStackKeys(stackID string) error {
	if _, err := c.db.Exec(`DELETE FROM age_keys WHERE stack_id = ?`, stackID); err != nil {
		return fmt.Errorf("delete age key for stack %q: %w", stackID, err)
	}
	if _, err := c.db.Exec(`DELETE FROM ssh_keys WHERE stack_id = ?`, stackID); err != nil {
		return fmt.Errorf("delete ssh key for stack %q: %w", stackID, err)
	}
	return nil
}

// DeleteConnectionKeys removes a shared git connection's key material --
// its SSH keypair or HTTP credential, whichever it has (the other DELETE
// is a harmless no-op). Called when a connection itself is deleted;
// mirrors DeleteStackKeys for the connection-scoped tables.
func (c *Custodian) DeleteConnectionKeys(connectionID string) error {
	if _, err := c.db.Exec(`DELETE FROM connection_ssh_keys WHERE connection_id = ?`, connectionID); err != nil {
		return fmt.Errorf("delete ssh key for connection %q: %w", connectionID, err)
	}
	if _, err := c.db.Exec(`DELETE FROM connection_http_credentials WHERE connection_id = ?`, connectionID); err != nil {
		return fmt.Errorf("delete http credential for connection %q: %w", connectionID, err)
	}
	return nil
}

// GenerateSSHKeypair creates a fresh RSA-4096 SSH deploy key for stackID
// and returns only the public key, in OpenSSH authorized_keys format
// (paste into a Git host's read-only Deploy Key settings). RSA, not
// ed25519: Azure DevOps' SSH public key field rejects anything else
// outright ("Invalid key: Valid keys will start with 'ssh-rsa'"),
// confirmed by a real add-deploy-key attempt against it — RSA-4096 is
// still accepted everywhere ed25519 would have been (GitHub, GitLab,
// Bitbucket), so it's the one type that works across every host rather
// than picking per-vendor. Same custody discipline as GenerateKeypair:
// the private key is written straight to this isolated store and never
// returned to any caller.
func (c *Custodian) GenerateSSHKeypair(stackID string) (publicKey string, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", fmt.Errorf("generate rsa key: %w", err)
	}

	sshPub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		return "", fmt.Errorf("convert public key: %w", err)
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))

	block, err := ssh.MarshalPrivateKey(priv, "wharf deploy key")
	if err != nil {
		return "", fmt.Errorf("marshal private key: %w", err)
	}
	privPEM := string(pem.EncodeToMemory(block))

	_, err = c.db.Exec(
		`INSERT INTO ssh_keys (stack_id, public_key, private_key) VALUES (?, ?, ?)`,
		stackID, pubLine, privPEM,
	)
	if err != nil {
		return "", fmt.Errorf("store generated ssh key: %w", err)
	}
	return pubLine, nil
}

// SSHPrivateKey returns the private deploy key for a stack, in OpenSSH PEM
// format. Used only by the controller's command-response builder to hand
// the agent what it needs for one clone — cf. ARCHITECTURE.md, "Credentials
// Git" (the v1 tradeoff: the key transits to the agent transiently, rather
// than a hardened short-lived token). Never exposed through any other
// handler or template.
func (c *Custodian) SSHPrivateKey(stackID string) (string, error) {
	var priv string
	err := c.db.QueryRow(`SELECT private_key FROM ssh_keys WHERE stack_id = ?`, stackID).Scan(&priv)
	if err != nil {
		return "", fmt.Errorf("lookup ssh private key: %w", err)
	}
	return priv, nil
}

// GenerateConnectionSSHKeypair is GenerateSSHKeypair's counterpart for a
// shared connection (reused across stacks) rather than a single stack.
// RSA-4096, same reasoning as GenerateSSHKeypair (Azure DevOps rejects
// ed25519 outright). Also doubles as "regenerate": called again on a
// connection that already has a key (cf. git_connection_view.html's
// "Regenerate key" action -- needed the moment a key already handed to
// a host turns out to be the wrong type/compromised/whatever), the
// ON CONFLICT replaces the old row outright rather than erroring on the
// connection_id primary key. The old public key stops being valid the
// instant this returns; the admin still has to remove/replace it on
// whichever Git host(s) had it as a Deploy Key.
func (c *Custodian) GenerateConnectionSSHKeypair(connectionID string) (publicKey string, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", fmt.Errorf("generate rsa key: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		return "", fmt.Errorf("convert public key: %w", err)
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))

	block, err := ssh.MarshalPrivateKey(priv, "wharf connection key")
	if err != nil {
		return "", fmt.Errorf("marshal private key: %w", err)
	}
	privPEM := string(pem.EncodeToMemory(block))

	_, err = c.db.Exec(
		`INSERT INTO connection_ssh_keys (connection_id, public_key, private_key, source) VALUES (?, ?, ?, 'generated')
		 ON CONFLICT(connection_id) DO UPDATE SET public_key = excluded.public_key, private_key = excluded.private_key, source = 'generated', created_at = datetime('now')`,
		connectionID, pubLine, privPEM,
	)
	if err != nil {
		return "", fmt.Errorf("store generated connection ssh key: %w", err)
	}
	return pubLine, nil
}

// ImportConnectionSSHKey stores an already-existing private key for a
// shared connection, deriving and returning only its public half. This is
// the one point in the system where a private key genuinely passes
// through the browser/API — same discipline as importing an age key:
// never rejoined/returned after this call. Same replace-on-conflict as
// GenerateConnectionSSHKeypair: importing again onto a connection that
// already has a key swaps it out rather than erroring.
func (c *Custodian) ImportConnectionSSHKey(connectionID, privateKeyPEM string) (publicKey string, err error) {
	raw, err := ssh.ParseRawPrivateKey([]byte(privateKeyPEM))
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return "", fmt.Errorf("derive public key: %w", err)
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	_, err = c.db.Exec(
		`INSERT INTO connection_ssh_keys (connection_id, public_key, private_key, source) VALUES (?, ?, ?, 'imported')
		 ON CONFLICT(connection_id) DO UPDATE SET public_key = excluded.public_key, private_key = excluded.private_key, source = 'imported', created_at = datetime('now')`,
		connectionID, pubLine, privateKeyPEM,
	)
	if err != nil {
		return "", fmt.Errorf("store imported connection ssh key: %w", err)
	}
	return pubLine, nil
}

// ImportConnectionHTTPCredential stores a username/password (or
// username/token) credential for a shared connection. Always an import —
// Wharf has no way to mint a PAT or Deploy Token itself, only the Git
// host does. INSERT OR REPLACE so this doubles as the update path
// (cf. updateGitConnectionCredentialHandler) without a near-duplicate
// method: connection_id is the table's primary key, so a second call
// for the same connection just replaces the row instead of conflicting.
func (c *Custodian) ImportConnectionHTTPCredential(connectionID, username, password string) error {
	_, err := c.db.Exec(
		`INSERT OR REPLACE INTO connection_http_credentials (connection_id, username, password) VALUES (?, ?, ?)`,
		connectionID, username, password,
	)
	if err != nil {
		return fmt.Errorf("store connection http credential: %w", err)
	}
	return nil
}

// ConnectionSSHPublicKey returns a shared connection's public key, for
// display — e.g. to paste into a Git host's Deploy Key settings after
// creation. Not a secret, safe to fetch any time (unlike the private
// half, which only ConnectionSSHPrivateKey below can retrieve).
func (c *Custodian) ConnectionSSHPublicKey(connectionID string) (string, error) {
	var pub string
	err := c.db.QueryRow(`SELECT public_key FROM connection_ssh_keys WHERE connection_id = ?`, connectionID).Scan(&pub)
	if err != nil {
		return "", fmt.Errorf("lookup connection public key: %w", err)
	}
	return pub, nil
}

// ConnectionSSHPrivateKey mirrors SSHPrivateKey for a shared connection.
func (c *Custodian) ConnectionSSHPrivateKey(connectionID string) (string, error) {
	var priv string
	err := c.db.QueryRow(`SELECT private_key FROM connection_ssh_keys WHERE connection_id = ?`, connectionID).Scan(&priv)
	if err != nil {
		return "", fmt.Errorf("lookup connection ssh private key: %w", err)
	}
	return priv, nil
}

// ConnectionHTTPCredential returns a shared connection's HTTP credential.
// Used only by the controller's command-response builder, same discipline
// as SSHPrivateKey/ConnectionSSHPrivateKey.
func (c *Custodian) ConnectionHTTPCredential(connectionID string) (username, password string, err error) {
	err = c.db.QueryRow(
		`SELECT username, password FROM connection_http_credentials WHERE connection_id = ?`, connectionID,
	).Scan(&username, &password)
	if err != nil {
		return "", "", fmt.Errorf("lookup connection http credential: %w", err)
	}
	return username, password, nil
}

// CountImportedKeys sums age/SSH keys whose source is 'imported' rather
// than 'generated' -- the dashboard's "Imported keys not rotated" stat,
// a hygiene reminder: a key Wharf generated itself never left its
// boundary, but an imported one's private half was seen elsewhere first.
// HTTP credentials aren't counted -- there's no "generate a password"
// path for those, so every row is trivially "imported" and the count
// would just equal "how many Git connections use a password," not a
// useful signal.
func (c *Custodian) CountImportedKeys() (int, error) {
	var n int
	err := c.db.QueryRow(`
		SELECT
			(SELECT COUNT(*) FROM age_keys WHERE source = 'imported') +
			(SELECT COUNT(*) FROM ssh_keys WHERE source = 'imported') +
			(SELECT COUNT(*) FROM connection_ssh_keys WHERE source = 'imported')
	`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count imported keys: %w", err)
	}
	return n, nil
}

// SetRegistryCredential stores (or replaces) the username/password used
// to authenticate to a private registry at host (e.g. "docker.io",
// "ghcr.io", "myregistry.example.com") — same plaintext-in-the-isolated-
// custodian-DB pattern as connection_http_credentials, not a new trust
// model. name and regType are display-only (a friendly label and a
// vendor hint for the settings UI, cf. server/registries.go's
// registryTypes) — resolution by server/internal/registry and by the
// agent's docker-login-at-deploy-time path is always by host, same as
// Docker's own ~/.docker/config.json keys credentials by registry
// hostname. One credential per host: a private Docker Hub repo and a
// private GHCR package need different accounts anyway, never the same
// pull secret reused across hosts.
func (c *Custodian) SetRegistryCredential(name, host, regType, username, password string) error {
	_, err := c.db.Exec(
		`INSERT INTO registry_credentials (host, name, type, username, password) VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(host) DO UPDATE SET name = excluded.name, type = excluded.type, username = excluded.username, password = excluded.password, created_at = datetime('now')`,
		host, name, regType, username, password,
	)
	if err != nil {
		return fmt.Errorf("set registry credential for %q: %w", host, err)
	}
	return nil
}

// RegistryCredential looks up a stored credential for host; ok is false
// if none is configured, in which case the caller should fall back to
// an anonymous/public request rather than treating it as an error --
// most images really are public.
func (c *Custodian) RegistryCredential(host string) (username, password string, ok bool, err error) {
	err = c.db.QueryRow(`SELECT username, password FROM registry_credentials WHERE host = ?`, host).Scan(&username, &password)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, fmt.Errorf("lookup registry credential for %q: %w", host, err)
	}
	return username, password, true, nil
}

// ListRegistries returns every configured registry credential, sorted --
// for the settings page, which shows name/type/host/username, never the
// password back.
type RegistryCredentialInfo struct {
	Name, Host, Type, Username string
}

func (c *Custodian) ListRegistries() ([]RegistryCredentialInfo, error) {
	rows, err := c.db.Query(`SELECT name, host, type, username FROM registry_credentials ORDER BY name, host`)
	if err != nil {
		return nil, fmt.Errorf("list registry credentials: %w", err)
	}
	defer rows.Close()

	var out []RegistryCredentialInfo
	for rows.Next() {
		var info RegistryCredentialInfo
		if err := rows.Scan(&info.Name, &info.Host, &info.Type, &info.Username); err != nil {
			return nil, fmt.Errorf("scan registry credential: %w", err)
		}
		out = append(out, info)
	}
	return out, rows.Err()
}

// AllRegistryCredentials returns every configured registry credential
// keyed by host, for the deploy-time docker-login path (cf.
// server/main.go's commandsHandler and ARCHITECTURE.md's "Identifiants
// de registre envoyés à chaque déploiement"). Unlike RegistryCredential,
// which answers "is there a credential for this one host" for the
// digest-check path, this hands the agent everything at once because a
// Git stack's compose file — and therefore which images/registries it
// actually references — isn't known to the controller until the agent
// has cloned it.
type RegistryAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (c *Custodian) AllRegistryCredentials() (map[string]RegistryAuth, error) {
	rows, err := c.db.Query(`SELECT host, username, password FROM registry_credentials`)
	if err != nil {
		return nil, fmt.Errorf("list all registry credentials: %w", err)
	}
	defer rows.Close()

	out := map[string]RegistryAuth{}
	for rows.Next() {
		var host string
		var auth RegistryAuth
		if err := rows.Scan(&host, &auth.Username, &auth.Password); err != nil {
			return nil, fmt.Errorf("scan registry credential: %w", err)
		}
		out[host] = auth
	}
	return out, rows.Err()
}

// DeleteRegistryCredential removes a host's stored credential -- future
// digest checks against that host fall back to anonymous access, same
// as if it had never been configured.
func (c *Custodian) DeleteRegistryCredential(host string) error {
	if _, err := c.db.Exec(`DELETE FROM registry_credentials WHERE host = ?`, host); err != nil {
		return fmt.Errorf("delete registry credential for %q: %w", host, err)
	}
	return nil
}

// OIDCConfig is Wharf's single configured SSO provider -- one at a
// time, matching how admin_user/registry_credentials are each a small
// fixed set of rows rather than an open-ended list; nothing about OIDC
// login needs more than one provider to be useful here.
type OIDCConfig struct {
	IssuerURL, ClientID, ClientSecret, DisplayName string
	// AdminGroup, when set, is a group name Wharf looks for in the
	// provider's "groups" claim on every OIDC login (not just first
	// provisioning) -- cf. server/oidc.go. A match provisions/keeps the
	// account as "admin"; cf. OperatorGroup for the "operator" half and
	// for what either field set at all does to who can sign in.
	AdminGroup string
	// OperatorGroup, when set, is the "operator" counterpart to
	// AdminGroup -- but the two aren't symmetric in effect. With EITHER
	// field non-empty, sign-in itself becomes gated: only a member of
	// AdminGroup or OperatorGroup may sign in at all, everyone else is
	// refused outright (cf. oidcCallbackHandler). With both empty
	// (the default), any successfully authenticated user is allowed in
	// as "operator" -- unchanged from before this field existed. This
	// asymmetry exists because AdminGroup alone was never meant to
	// double as an access allowlist by accident; a real allowlist needs
	// an explicit, separate opt-in.
	OperatorGroup string
	// DisableLocalAuth, when true, makes /login refuse every
	// username/password attempt outright, regardless of credentials --
	// SSO becomes the only way in. Real lockout risk if the provider
	// ever becomes unreachable or misconfigured after this is turned on
	// (cf. settings_authentication.html's own warning copy, shown right
	// next to the checkbox); there is no built-in bypass, recovering
	// requires direct access to the controller's database, the same as
	// any other admin-only escape hatch this app doesn't pretend to
	// protect against.
	DisableLocalAuth bool
}

// SetOIDCConfig stores (or replaces) the provider Wharf authenticates
// against. ClientSecret lives here, in the isolated custodian DB, same
// physical boundary as every other credential in this package -- never
// in the main application database.
func (c *Custodian) SetOIDCConfig(issuerURL, clientID, clientSecret, displayName, adminGroup, operatorGroup string, disableLocalAuth bool) error {
	if displayName == "" {
		displayName = "SSO"
	}
	disableLocalAuthInt := 0
	if disableLocalAuth {
		disableLocalAuthInt = 1
	}
	_, err := c.db.Exec(
		`INSERT INTO oidc_config (id, issuer_url, client_id, client_secret, display_name, admin_group, operator_group, disable_local_auth) VALUES (1, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET issuer_url = excluded.issuer_url, client_id = excluded.client_id, client_secret = excluded.client_secret, display_name = excluded.display_name, admin_group = excluded.admin_group, operator_group = excluded.operator_group, disable_local_auth = excluded.disable_local_auth, updated_at = datetime('now')`,
		issuerURL, clientID, clientSecret, displayName, adminGroup, operatorGroup, disableLocalAuthInt,
	)
	if err != nil {
		return fmt.Errorf("set oidc config: %w", err)
	}
	return nil
}

// GetOIDCConfig returns the configured provider; ok is false if none is
// set, in which case the caller should hide SSO login entirely rather
// than attempt a request with empty credentials.
func (c *Custodian) GetOIDCConfig() (cfg OIDCConfig, ok bool, err error) {
	var disableLocalAuthInt int
	err = c.db.QueryRow(`SELECT issuer_url, client_id, client_secret, display_name, admin_group, operator_group, disable_local_auth FROM oidc_config WHERE id = 1`).
		Scan(&cfg.IssuerURL, &cfg.ClientID, &cfg.ClientSecret, &cfg.DisplayName, &cfg.AdminGroup, &cfg.OperatorGroup, &disableLocalAuthInt)
	if errors.Is(err, sql.ErrNoRows) {
		return OIDCConfig{}, false, nil
	}
	if err != nil {
		return OIDCConfig{}, false, fmt.Errorf("get oidc config: %w", err)
	}
	cfg.DisableLocalAuth = disableLocalAuthInt != 0
	return cfg, true, nil
}

// DeleteOIDCConfig removes the configured provider -- SSO login
// disappears from /login immediately, existing local accounts (and any
// account already linked to this provider via oidc_subject/oidc_issuer)
// are untouched.
func (c *Custodian) DeleteOIDCConfig() error {
	if _, err := c.db.Exec(`DELETE FROM oidc_config WHERE id = 1`); err != nil {
		return fmt.Errorf("delete oidc config: %w", err)
	}
	return nil
}

// BackupTo writes a consistent snapshot to path (which must not already
// exist), same VACUUM INTO approach as internal/store.Store.BackupTo --
// this custodian isn't opened in WAL mode, but VACUUM INTO is still the
// right primitive: a single self-contained file, safe to read back
// without racing whatever write this process might be doing at the
// same moment.
func (c *Custodian) BackupTo(path string) error {
	if _, err := c.db.Exec(`VACUUM INTO ?`, path); err != nil {
		return fmt.Errorf("backup keys: %w", err)
	}
	return nil
}
