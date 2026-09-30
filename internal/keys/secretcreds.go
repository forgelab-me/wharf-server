package keys

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// SetSecretCredentials stores (or replaces) the credential fields of a
// secret connection. An empty map removes them.
func (c *Custodian) SetSecretCredentials(connectionID string, creds map[string]string) error {
	if len(creds) == 0 {
		return c.DeleteSecretCredentials(connectionID)
	}
	raw, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("encode credentials: %w", err)
	}
	_, err = c.db.Exec(
		`INSERT INTO secret_connection_credentials (connection_id, data) VALUES (?, ?)
		 ON CONFLICT(connection_id) DO UPDATE SET data = excluded.data, updated_at = datetime('now')`,
		connectionID, string(raw),
	)
	if err != nil {
		return fmt.Errorf("store secret connection credentials: %w", err)
	}
	return nil
}

// SecretCredentials returns a connection's credential fields, nil when none are stored.
func (c *Custodian) SecretCredentials(connectionID string) (map[string]string, error) {
	var raw string
	err := c.db.QueryRow(`SELECT data FROM secret_connection_credentials WHERE connection_id = ?`, connectionID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load secret connection credentials: %w", err)
	}
	var creds map[string]string
	if err := json.Unmarshal([]byte(raw), &creds); err != nil {
		return nil, fmt.Errorf("decode secret connection credentials: %w", err)
	}
	return creds, nil
}

// SecretCredentialFields names the credential fields that are set, without their values.
func (c *Custodian) SecretCredentialFields(connectionID string) ([]string, error) {
	creds, err := c.SecretCredentials(connectionID)
	if err != nil {
		return nil, err
	}
	var names []string
	for name, v := range creds {
		if v != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func (c *Custodian) DeleteSecretCredentials(connectionID string) error {
	if _, err := c.db.Exec(`DELETE FROM secret_connection_credentials WHERE connection_id = ?`, connectionID); err != nil {
		return fmt.Errorf("delete secret connection credentials: %w", err)
	}
	return nil
}
