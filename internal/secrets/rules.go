package secrets

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// PathRulesKey is the connection config key that holds its path rules.
const PathRulesKey = "path_rules"

const stackPlaceholder = "{stack}"

// stackIDRe is what a stack id looks like (cf. slugify): nothing that needs
// escaping, and no "_" or "/", which is what makes "{stack}_" unambiguous.
var stackIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// PathRulesDocsURL is the documentation of path rules, with worked examples.
const PathRulesDocsURL = "https://wharf.forgelab.me/guide/path-rules"

// PathRulesField is the connection form input every connector offers.
var PathRulesField = Field{
	Name:  PathRulesKey,
	Label: "Path rules",
	Input: "textarea",
	Help: "Optional, one rule per line. Limits every stack on this connection to its own secrets, so no path has to be typed stack by stack. " +
		"{stack} is the stack's id and * stands for any characters inside one segment. " +
		"Examples: secret/{stack} (a folder per stack), {stack} (a project per stack), homelab/{stack}_* (secrets named after the stack, in a shared project).",
	HelpURL: PathRulesDocsURL,
}

// ParseRules reads a connection's path rules, one per line, and checks each.
func ParseRules(input string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.FieldsFunc(input, func(r rune) bool { return r == '\n' || r == '\r' }) {
		rule := strings.TrimSpace(line)
		if rule == "" {
			continue
		}
		if err := checkRule(rule); err != nil {
			return nil, fmt.Errorf("rule %q: %w", rule, err)
		}
		if !seen[rule] {
			seen[rule] = true
			out = append(out, rule)
		}
	}
	return out, nil
}

// ValidatePathRules checks the rules held in a connection's config.
func ValidatePathRules(config map[string]string) error {
	_, err := ParseRules(config[PathRulesKey])
	return err
}

// checkRule refuses what could make a rule wider than it looks.
func checkRule(rule string) error {
	segments := strings.Split(rule, "/")
	allWild := true
	for _, seg := range segments {
		switch seg {
		case "":
			return errors.New("empty segment")
		case ".", "..":
			return errors.New(`"." and ".." segments are not allowed`)
		}
		if seg != "*" {
			allWild = false
		}
		if strings.Contains(seg, "**") {
			return errors.New("use a single * to stand for any characters")
		}
		rest := seg
		for {
			i := strings.Index(rest, stackPlaceholder)
			if i < 0 {
				break
			}
			after := rest[i+len(stackPlaceholder):]
			// the stack id is cut off by what follows it: only a character a
			// stack id cannot contain keeps "blog" from reading "blog-staging"
			if after != "" && after[0] != '_' {
				return fmt.Errorf("%s must be followed by _, / or the end of the rule, not %q", stackPlaceholder, after[:1])
			}
			rest = rest[:i] + "x" + after
		}
		if strings.ContainsAny(rest, "{}") {
			return fmt.Errorf("only %s is allowed between braces", stackPlaceholder)
		}
		if err := checkChars(strings.ReplaceAll(rest, "*", "x")); err != nil {
			return err
		}
	}
	if allWild {
		return errors.New("a rule made only of * allows every path")
	}
	return nil
}

// ExpandRules puts a stack's id in place of {stack}. A stack id that does not
// look like one gets no rule at all: nothing is allowed.
func ExpandRules(rules []string, stackID string) []string {
	if !stackIDRe.MatchString(stackID) {
		return nil
	}
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = strings.ReplaceAll(r, stackPlaceholder, stackID)
	}
	return out
}

// RuleAllowed reports whether path starts with segments matching one of the
// (expanded) rules: a rule covers what it names and everything below it.
func RuleAllowed(rules []string, path string) bool {
	segs := strings.Split(path, "/")
	for _, rule := range rules {
		want := strings.Split(rule, "/")
		if len(segs) < len(want) {
			continue
		}
		ok := true
		for i, w := range want {
			if !globSegment(w, segs[i]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// globSegment matches one path segment against a pattern in which * stands for
// any run of characters, case-sensitively.
func globSegment(pattern, s string) bool {
	px, sx := 0, 0
	star, mark := -1, 0
	for sx < len(s) {
		switch {
		case px < len(pattern) && pattern[px] == '*':
			star, mark = px, sx
			px++
		case px < len(pattern) && pattern[px] == s[sx]:
			px++
			sx++
		case star >= 0:
			px = star + 1
			mark++
			sx = mark
		default:
			return false
		}
	}
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}
