package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// SecretConnection is a configured secret backend. A global connection
// (StackID empty) is shared; a local one belongs to one stack and either
// inherits its config from a global parent (ParentID) or stands alone.
// Credentials live in the custodian, never here.
type SecretConnection struct {
	ID        string
	Name      string
	Type      string
	StackID   string
	ParentID  string
	Config    map[string]string
	CreatedAt string
}

// SecretBinding attaches one connection to a stack for a provider type,
// limited to the given path prefixes.
type SecretBinding struct {
	StackID      string
	Type         string
	ConnectionID string
	Prefixes     []string
}

const secretConnectionColumns = `id, name, type, stack_id, parent_id, config, created_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanSecretConnection(row rowScanner) (SecretConnection, error) {
	var c SecretConnection
	var config string
	if err := row.Scan(&c.ID, &c.Name, &c.Type, &c.StackID, &c.ParentID, &config, &c.CreatedAt); err != nil {
		return SecretConnection{}, err
	}
	if err := json.Unmarshal([]byte(config), &c.Config); err != nil {
		return SecretConnection{}, fmt.Errorf("decode config of secret connection %q: %w", c.ID, err)
	}
	if c.Config == nil {
		c.Config = map[string]string{}
	}
	return c, nil
}

func (s *Store) CreateSecretConnection(c SecretConnection) error {
	config, err := json.Marshal(c.Config)
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	if string(config) == "null" {
		config = []byte("{}")
	}
	if _, err := s.db.Exec(
		`INSERT INTO secret_connections (id, name, type, stack_id, parent_id, config) VALUES (?, ?, ?, ?, ?, ?)`,
		c.ID, c.Name, c.Type, c.StackID, c.ParentID, string(config),
	); err != nil {
		return fmt.Errorf("create secret connection: %w", err)
	}
	return nil
}

// UpdateSecretConnection replaces a connection's name and config.
func (s *Store) UpdateSecretConnection(id, name string, config map[string]string) error {
	raw, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	if string(raw) == "null" {
		raw = []byte("{}")
	}
	res, err := s.db.Exec(`UPDATE secret_connections SET name = ?, config = ? WHERE id = ?`, name, string(raw), id)
	if err != nil {
		return fmt.Errorf("update secret connection %q: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) GetSecretConnection(id string) (SecretConnection, error) {
	c, err := scanSecretConnection(s.db.QueryRow(`SELECT `+secretConnectionColumns+` FROM secret_connections WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return SecretConnection{}, ErrNotFound
	}
	if err != nil {
		return SecretConnection{}, fmt.Errorf("get secret connection %q: %w", id, err)
	}
	return c, nil
}

func (s *Store) queryConnections(query string, args ...any) ([]SecretConnection, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list secret connections: %w", err)
	}
	defer rows.Close()
	var out []SecretConnection
	for rows.Next() {
		c, err := scanSecretConnection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListGlobalSecretConnections returns the shared connections, by name.
func (s *Store) ListGlobalSecretConnections() ([]SecretConnection, error) {
	return s.queryConnections(`SELECT ` + secretConnectionColumns + ` FROM secret_connections WHERE stack_id = '' ORDER BY name`)
}

// SecretConnectionChildren returns the local connections inheriting from a global one.
func (s *Store) SecretConnectionChildren(parentID string) ([]SecretConnection, error) {
	return s.queryConnections(`SELECT `+secretConnectionColumns+` FROM secret_connections WHERE parent_id = ? ORDER BY stack_id`, parentID)
}

// SecretConnectionsForStack returns the connections private to a stack.
func (s *Store) SecretConnectionsForStack(stackID string) ([]SecretConnection, error) {
	return s.queryConnections(`SELECT `+secretConnectionColumns+` FROM secret_connections WHERE stack_id = ?`, stackID)
}

func (s *Store) DeleteSecretConnection(id string) error {
	if _, err := s.db.Exec(`DELETE FROM secret_connections WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete secret connection %q: %w", id, err)
	}
	return nil
}

// SecretConnectionUsers names the stacks bound to a global connection,
// directly (shared credentials) or through a local connection inheriting it.
func (s *Store) SecretConnectionUsers(globalID string) (shared, own []string, err error) {
	rows, err := s.db.Query(`
		SELECT b.stack_id, b.connection_id = ? AS is_shared
		FROM stack_secret_bindings b
		LEFT JOIN secret_connections c ON c.id = b.connection_id
		WHERE b.connection_id = ? OR c.parent_id = ?
		ORDER BY b.stack_id`, globalID, globalID, globalID)
	if err != nil {
		return nil, nil, fmt.Errorf("secret connection users: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var stackID string
		var isShared bool
		if err := rows.Scan(&stackID, &isShared); err != nil {
			return nil, nil, err
		}
		if isShared {
			shared = append(shared, stackID)
		} else {
			own = append(own, stackID)
		}
	}
	return shared, own, rows.Err()
}

// SetSecretBinding creates or replaces the stack's binding for a type.
func (s *Store) SetSecretBinding(b SecretBinding) error {
	prefixes, err := json.Marshal(b.Prefixes)
	if err != nil {
		return fmt.Errorf("encode prefixes: %w", err)
	}
	if _, err := s.db.Exec(
		`INSERT INTO stack_secret_bindings (stack_id, type, connection_id, prefixes) VALUES (?, ?, ?, ?)
		 ON CONFLICT(stack_id, type) DO UPDATE SET connection_id = excluded.connection_id, prefixes = excluded.prefixes`,
		b.StackID, b.Type, b.ConnectionID, string(prefixes),
	); err != nil {
		return fmt.Errorf("set secret binding: %w", err)
	}
	return nil
}

func scanSecretBinding(row rowScanner) (SecretBinding, error) {
	var b SecretBinding
	var prefixes string
	if err := row.Scan(&b.StackID, &b.Type, &b.ConnectionID, &prefixes); err != nil {
		return SecretBinding{}, err
	}
	if err := json.Unmarshal([]byte(prefixes), &b.Prefixes); err != nil {
		return SecretBinding{}, fmt.Errorf("decode prefixes of secret binding %q/%q: %w", b.StackID, b.Type, err)
	}
	return b, nil
}

func (s *Store) GetSecretBinding(stackID, typ string) (SecretBinding, error) {
	b, err := scanSecretBinding(s.db.QueryRow(
		`SELECT stack_id, type, connection_id, prefixes FROM stack_secret_bindings WHERE stack_id = ? AND type = ?`, stackID, typ))
	if errors.Is(err, sql.ErrNoRows) {
		return SecretBinding{}, ErrNotFound
	}
	if err != nil {
		return SecretBinding{}, fmt.Errorf("get secret binding: %w", err)
	}
	return b, nil
}

func (s *Store) ListSecretBindings(stackID string) ([]SecretBinding, error) {
	rows, err := s.db.Query(`SELECT stack_id, type, connection_id, prefixes FROM stack_secret_bindings WHERE stack_id = ? ORDER BY type`, stackID)
	if err != nil {
		return nil, fmt.Errorf("list secret bindings: %w", err)
	}
	defer rows.Close()
	var out []SecretBinding
	for rows.Next() {
		b, err := scanSecretBinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) DeleteSecretBinding(stackID, typ string) error {
	if _, err := s.db.Exec(`DELETE FROM stack_secret_bindings WHERE stack_id = ? AND type = ?`, stackID, typ); err != nil {
		return fmt.Errorf("delete secret binding: %w", err)
	}
	return nil
}
