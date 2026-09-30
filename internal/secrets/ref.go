// Package secrets parses secrets.refs.yaml and resolves the references in
// it (ref+<scheme>://<path>#/<field>) into environment variables, cf.
// ARCHITECTURE.md, "Secrets externes".
package secrets

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/token"
)

// RefsFileName is the file a Git stack may keep next to its compose file.
const RefsFileName = "secrets.refs.yaml"

// MaxRefsFileSize bounds what the controller will parse.
const MaxRefsFileSize = 64 << 10

var (
	envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	schemeRe = regexp.MustCompile(`^[a-z][a-z0-9]*$`)
)

// Ref is one parsed ref+<scheme>://<path>#/<field>.
type Ref struct {
	Scheme string
	Path   string // normalized: no empty, "." or ".." segment
	Field  string
}

func (r Ref) String() string {
	return "ref+" + r.Scheme + "://" + r.Path + "#/" + r.Field
}

// Entry is one line of secrets.refs.yaml.
type Entry struct {
	Key string
	Ref Ref
}

// ParseRef parses and validates a single reference. Query parameters are
// rejected: a reference says what to read, the connection says where.
func ParseRef(s string) (Ref, error) {
	rest, ok := strings.CutPrefix(s, "ref+")
	if !ok {
		return Ref{}, errors.New("not a reference (must start with ref+)")
	}
	scheme, rest, ok := strings.Cut(rest, "://")
	if !ok || !schemeRe.MatchString(scheme) {
		return Ref{}, errors.New("expected ref+<scheme>://<path>#/<field>")
	}
	path, field, ok := strings.Cut(rest, "#/")
	if !ok {
		return Ref{}, errors.New("missing #/<field>")
	}
	if strings.Contains(path, "?") || strings.Contains(field, "?") {
		return Ref{}, errors.New("query parameters are not allowed in a reference")
	}
	if err := checkPath(path); err != nil {
		return Ref{}, fmt.Errorf("path: %w", err)
	}
	if field == "" || strings.Contains(field, "/") {
		return Ref{}, errors.New("field must be a single non-empty name")
	}
	if err := checkChars(field); err != nil {
		return Ref{}, fmt.Errorf("field: %w", err)
	}
	return Ref{Scheme: scheme, Path: path, Field: field}, nil
}

func checkPath(path string) error {
	if path == "" {
		return errors.New("empty")
	}
	if err := checkChars(path); err != nil {
		return err
	}
	for _, seg := range strings.Split(path, "/") {
		switch seg {
		case "":
			return errors.New("empty segment")
		case ".", "..":
			return errors.New(`"." and ".." segments are not allowed`)
		}
	}
	return nil
}

func checkChars(s string) error {
	for _, r := range s {
		switch {
		case r == '%':
			return errors.New("percent-encoding is not allowed")
		case r == '#':
			return errors.New("# is not allowed")
		case r == '\\':
			return errors.New("backslash is not allowed")
		case r <= ' ' || r == 0x7f:
			return errors.New("whitespace and control characters are not allowed")
		}
	}
	return nil
}

// ParseFile parses secrets.refs.yaml: a flat KEY: ref+... map. Every error
// names a key or a line, never echoes file content.
func ParseFile(data []byte) ([]Entry, error) {
	if len(data) > MaxRefsFileSize {
		return nil, fmt.Errorf("%s is larger than %d KiB", RefsFileName, MaxRefsFileSize>>10)
	}

	var doc yaml.MapSlice
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s is not a valid flat KEY: ref+... map%s", RefsFileName, errorLine(err))
	}

	var problems []string
	seen := map[string]bool{}
	entries := make([]Entry, 0, len(doc))
	for i, item := range doc {
		key, ok := item.Key.(string)
		if !ok || !envKeyRe.MatchString(key) {
			problems = append(problems, fmt.Sprintf("entry %d: key is not a valid environment variable name", i+1))
			continue
		}
		if seen[key] {
			problems = append(problems, key+": defined more than once")
			continue
		}
		seen[key] = true

		raw, ok := item.Value.(string)
		if !ok {
			problems = append(problems, key+": value must be a ref+<scheme>://... string")
			continue
		}
		ref, err := ParseRef(raw)
		if err != nil {
			if !strings.HasPrefix(raw, "ref+") {
				problems = append(problems, key+": literal values are not allowed, keep non-secret settings in the stack's environment variables")
			} else {
				problems = append(problems, key+": "+err.Error())
			}
			continue
		}
		entries = append(entries, Entry{Key: key, Ref: ref})
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, fmt.Errorf("invalid %s:\n  %s", RefsFileName, strings.Join(problems, "\n  "))
	}
	return entries, nil
}

// errorLine returns " (line N)" when the YAML error carries a position,
// without the source excerpt goccy puts in its message.
func errorLine(err error) string {
	var te interface{ GetToken() *token.Token }
	if errors.As(err, &te) {
		if tok := te.GetToken(); tok != nil && tok.Position != nil {
			return fmt.Sprintf(" (line %d)", tok.Position.Line)
		}
	}
	return ""
}
