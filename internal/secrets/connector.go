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
	// HelpURL, when set, is shown as a "Read more" link after the help text.
	HelpURL string
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
	// Rules are the connection's path rules with {stack} already replaced;
	// HasRules says the connection has some at all, even when none applies.
	Rules    []string
	HasRules bool
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

// ApplyPathRules reads the connection's rules from its config and puts a
// stack's id in them. A stack id that cannot be put in a rule gets nothing.
func (e *Effective) ApplyPathRules(stackID string) error {
	rules, err := ParseRules(e.Config[PathRulesKey])
	if err != nil {
		return fmt.Errorf("the connection's path rules are invalid: %w", err)
	}
	e.HasRules = len(rules) > 0
	e.Rules = ExpandRules(rules, stackID)
	return nil
}

// PathAllowed reports whether the stack may read a path: it is covered by one
// of its own allowed paths or by a path rule of the connection. When the
// connection has rules, a "*" allowed path no longer counts: rules limit what
// a stack can be given, they are not a default to override.
func (e *Effective) PathAllowed(path string) bool {
	prefixes := e.Prefixes
	if e.HasRules {
		prefixes = nil
		for _, p := range e.Prefixes {
			if p != "*" {
				prefixes = append(prefixes, p)
			}
		}
	}
	return PathAllowed(prefixes, path) || RuleAllowed(e.Rules, path)
}

// AllowedSummary lists what a stack may read, for error messages.
func (e *Effective) AllowedSummary() string {
	var parts []string
	parts = append(parts, e.Prefixes...)
	for _, r := range e.Rules {
		parts = append(parts, "rule "+r)
	}
	if len(parts) == 0 {
		return "nothing: no allowed path and no path rule"
	}
	return strings.Join(parts, ", ")
}

// NormalizePrefixes parses the allowed-prefix input like ParsePrefixes, and
// requires at least one.
func NormalizePrefixes(input string) ([]string, error) {
	out, err := ParsePrefixes(input)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("at least one allowed path prefix is required (use * to allow everything)")
	}
	return out, nil
}

// ParsePrefixes parses the allowed-prefix input: one path per line (or
// comma-separated), each covering itself and everything below it. A lone
// "*" allows every path. It may be empty.
func ParsePrefixes(input string) ([]string, error) {
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
