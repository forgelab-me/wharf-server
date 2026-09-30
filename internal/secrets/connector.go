package secrets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Field describes one input of a provider's connection form. Config fields
// are shared and visible; credential fields are write-only, and a stack can
// replace the whole credential group.
type Field struct {
	Name        string
	Label       string
	Help        string
	Placeholder string
	Default     string
	Credential  bool
	Required    bool
	Input       string // "text" (default), "textarea" or "select"
	Options     []string
}

// Connector is a provider that reads from an external service through a
// connection (sops, which uses the stack's own key, is not one).
type Connector interface {
	Provider
	Label() string
	Fields() []Field
	ValidateConfig(config map[string]string) error
	ValidateCredentials(credentials map[string]string) error
	// Check proves the connection works (login only, no secret read).
	Check(ctx context.Context, eff *Effective) error
}

// Effective is a stack's resolved connection for one scheme: the shared
// config, the credentials that apply, and the paths the stack may read.
type Effective struct {
	Type        string
	Config      map[string]string
	Credentials map[string]string
	Prefixes    []string
	// Source says where the credentials come from, for errors and audit.
	Source string
	// Identity changes whenever the config or credentials do, and differs
	// between two stacks that authenticate differently: it keys the token cache.
	Identity string
}

// NewEffective fills in Identity.
func NewEffective(typ string, config, credentials map[string]string, prefixes []string, source string) *Effective {
	raw, _ := json.Marshal(struct {
		Type   string
		Config map[string]string
		Creds  map[string]string
	}{typ, config, credentials})
	sum := sha256.Sum256(raw)
	return &Effective{
		Type:        typ,
		Config:      config,
		Credentials: credentials,
		Prefixes:    prefixes,
		Source:      source,
		Identity:    hex.EncodeToString(sum[:]),
	}
}

// NoBindingError means the stack has no connection for a scheme.
type NoBindingError struct{ Scheme string }

func (e *NoBindingError) Error() string {
	return fmt.Sprintf("this stack has no %s connection", e.Scheme)
}

// IsNoBinding reports whether err is a NoBindingError.
func IsNoBinding(err error) bool {
	var nb *NoBindingError
	return errors.As(err, &nb)
}

// NormalizePrefixes parses the allowed-prefix input: one path per line (or
// comma-separated), each covering itself and everything below it. A lone
// "*" allows every path.
func NormalizePrefixes(input string) ([]string, error) {
	fields := strings.FieldsFunc(input, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' })
	var out []string
	seen := map[string]bool{}
	for _, f := range fields {
		p := strings.TrimSpace(f)
		if p == "" {
			continue
		}
		if p != "*" {
			p = strings.TrimSuffix(strings.TrimSuffix(p, "*"), "/")
			if err := checkPath(p); err != nil {
				return nil, fmt.Errorf("prefix %q: %w", f, err)
			}
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("at least one allowed path prefix is required (use * to allow everything)")
	}
	return out, nil
}

// PathAllowed reports whether path is covered by one of the prefixes,
// compared by whole segments.
func PathAllowed(prefixes []string, path string) bool {
	for _, p := range prefixes {
		if p == "*" || path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}
