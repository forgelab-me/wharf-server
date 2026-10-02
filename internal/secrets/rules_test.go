package secrets

import (
	"strings"
	"testing"
)

func TestParseRulesAcceptsTheDocumentedForms(t *testing.T) {
	got, err := ParseRules("  {stack}  \nhomelab/{stack}_*\r\n\nshared_*\n{stack}\n*/{stack}_*\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"{stack}", "homelab/{stack}_*", "shared_*", "*/{stack}_*"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("rules = %q, want %q (trimmed, blank lines dropped, duplicates merged)", got, want)
	}
	if got, err := ParseRules(""); err != nil || len(got) != 0 {
		t.Errorf("no rule is not an error: %v %v", got, err)
	}
}

func TestParseRulesRefusesWhatWouldWidenARule(t *testing.T) {
	for rule, why := range map[string]string{
		"{stack}-*":       "'-' can be inside a stack id: blog would read blog-staging",
		"{stack}*":        "a * right after the id is the same trap",
		"{stack}x":        "any letter after the id",
		"{stack}{stack}":  "two ids glued together",
		"*":               "everything",
		"*/*":             "everything, spelled out",
		"homelab/*":       "", // fine: a project, any secret
		"../{stack}":      "going up",
		"a//b":            "an empty segment",
		"/{stack}":        "a leading slash",
		"{stack}/":        "a trailing slash",
		"{name}_*":        "only {stack} is a placeholder",
		"{stack":          "a stray brace",
		"a**b":            "** is not a thing",
		"{stack}%2f":      "percent-encoding",
		"homelab/{stack}": "", // fine
	} {
		_, err := ParseRules(rule)
		if why == "" {
			if err != nil {
				t.Errorf("%q must be accepted: %v", rule, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%q must be refused (%s)", rule, why)
		}
	}
}

func TestExpandRules(t *testing.T) {
	got := ExpandRules([]string{"{stack}", "homelab/{stack}_*", "shared_*"}, "blog")
	if strings.Join(got, "|") != "blog|homelab/blog_*|shared_*" {
		t.Errorf("expanded = %q", got)
	}
	for _, bad := range []string{"", "Blog", "blog_x", "../x", "a/b", "-a", "blog*"} {
		if got := ExpandRules([]string{"{stack}"}, bad); got != nil {
			t.Errorf("a stack id like %q gets no rule at all, got %q", bad, got)
		}
	}
}

func TestRuleAllowed(t *testing.T) {
	type c struct {
		rule, stack, path string
		want              bool
	}
	for _, tc := range []c{
		// one project per stack
		{"{stack}", "blog", "blog/db_password", true},
		{"{stack}", "blog", "blog", true},
		{"{stack}", "blog", "shop/db_password", false},
		{"{stack}", "blog", "blogger/db_password", false},
		{"{stack}", "blog", "blog-staging/db_password", false},
		// a shared project, secrets named after the stack
		{"homelab/{stack}_*", "blog", "homelab/blog_db", true},
		{"homelab/{stack}_*", "blog", "homelab/blog_", true},
		{"homelab/{stack}_*", "blog", "homelab/shop_db", false},
		{"homelab/{stack}_*", "blog", "homelab/blogger_db", false},
		{"homelab/{stack}_*", "blog", "homelab/blog-staging_db", false},
		{"homelab/{stack}_*", "blog", "homelab/blog", false},
		{"homelab/{stack}_*", "blog", "other/blog_db", false},
		{"homelab/{stack}_*", "blog", "homelab", false},
		{"homelab/{stack}_*", "blog-staging", "homelab/blog-staging_db", true},
		{"homelab/{stack}_*", "blog-staging", "homelab/blog_db", false},
		// below what the rule names
		{"homelab/{stack}_*", "blog", "homelab/blog_db/extra", true},
		// a wildcard segment, case, shared names
		{"*/{stack}_*", "blog", "Perso/blog_db", true},
		{"*/{stack}_*", "blog", "Perso/Blog_db", false},
		{"shared_*", "blog", "shared_smtp", true},
		{"shared_*", "blog", "sharedsmtp", false},
		// * stays inside its segment
		{"homelab/{stack}_*", "blog", "homelab/blog_a/b", true},
		{"{stack}_*", "blog", "blog_a", true},
		{"{stack}_*", "blog", "blog/a", false},
	} {
		rules, err := ParseRules(tc.rule)
		if err != nil {
			t.Fatalf("%q: %v", tc.rule, err)
		}
		if got := RuleAllowed(ExpandRules(rules, tc.stack), tc.path); got != tc.want {
			t.Errorf("rule %q for stack %q, path %q: allowed = %v, want %v", tc.rule, tc.stack, tc.path, got, tc.want)
		}
	}
	if RuleAllowed(nil, "anything") {
		t.Error("no rule allows nothing")
	}
}

func TestEveryRuleOfAStackIsDisjointFromAnotherStack(t *testing.T) {
	// two stacks whose ids start the same way: neither may read the other's secrets
	rules, _ := ParseRules("homelab/{stack}_*\n{stack}")
	ids := []string{"blog", "blog-staging", "b", "blog-staging-2"}
	for _, a := range ids {
		for _, b := range ids {
			if a == b {
				continue
			}
			for _, path := range []string{"homelab/" + b + "_db", b + "/db"} {
				if RuleAllowed(ExpandRules(rules, a), path) {
					t.Errorf("stack %q must not read %q", a, path)
				}
			}
		}
	}
}

func TestGlobSegment(t *testing.T) {
	for _, tc := range []struct {
		pattern, s string
		want       bool
	}{
		{"*", "", true}, {"*", "abc", true}, {"a*", "a", true}, {"a*", "ab", true}, {"a*", "b", false},
		{"*c", "abc", true}, {"*c", "abd", false}, {"a*c", "abbbc", true}, {"a*c", "ac", true}, {"a*c", "abbbd", false},
		{"a*b*c", "aXbYc", true}, {"a*b*c", "aXcYb", false}, {"abc", "abc", true}, {"abc", "abcd", false}, {"", "", true}, {"", "a", false},
	} {
		if got := globSegment(tc.pattern, tc.s); got != tc.want {
			t.Errorf("globSegment(%q, %q) = %v, want %v", tc.pattern, tc.s, got, tc.want)
		}
	}
}

// The examples of site/docs/guide/path-rules.md, one row per row of its tables.
// If an example there changes, change it here, and the other way round.
func TestPathRulesDocumentationExamples(t *testing.T) {
	type ex struct {
		rules, stack, path string
		want               bool
	}
	for _, e := range []ex{
		// OpenBao or Vault: a folder per stack
		{"secret/{stack}", "blog", "secret/blog/db", true},
		{"secret/{stack}", "blog", "secret/blog", true},
		{"secret/{stack}", "blog", "secret/shop/db", false},
		{"secret/{stack}", "blog", "secret/blogger/db", false},
		{"secret/{stack}", "blog", "secret/blog-staging/db", false},
		// ... and one shared folder
		{"secret/{stack}\nsecret/shared", "blog", "secret/shared/smtp", true},
		{"secret/{stack}\nsecret/shared", "shop", "secret/shared/smtp", true},
		{"secret/{stack}\nsecret/shared", "shop", "secret/blog/db", false},
		// Bitwarden: a project per stack
		{"{stack}", "blog", "blog/db_password", true},
		{"{stack}", "shop", "blog/db_password", false},
		// Bitwarden: a shared project, secrets named after the stack
		{"homelab/{stack}_*", "blog", "homelab/blog_db_password", true},
		{"homelab/{stack}_*", "blog", "homelab/blog_smtp", true},
		{"homelab/{stack}_*", "blog", "homelab/shop_smtp", false},
		{"homelab/{stack}_*", "blog", "homelab/blogger_db", false},
		{"homelab/{stack}_*", "blog", "homelab/blog-staging_db", false},
		{"homelab/{stack}_*", "blog-staging", "homelab/blog-staging_db", true},
		{"homelab/{stack}_*", "blog-staging", "homelab/blog_db", false},
		// a shared secret on top of a stack's own
		{"homelab/{stack}_*\nhomelab/shared_*", "blog", "homelab/shared_smtp", true},
		{"homelab/{stack}_*\nhomelab/shared_*", "blog", "homelab/blog_db", true},
		{"homelab/{stack}_*\nhomelab/shared_*", "blog", "homelab/shop_db", false},
		// a wildcard first segment
		{"*/{stack}_*", "blog", "Perso/blog_db", true},
		{"*/{stack}_*", "blog", "Work/blog_db", true},
		{"*/{stack}_*", "blog", "Perso/shop_db", false},
		// a common path as a second rule
		{"homelab/{stack}_*\nkv/common", "blog", "kv/common/smtp", true},
		{"homelab/{stack}_*\nkv/common", "blog", "kv/other", false},
	} {
		rules, err := ParseRules(e.rules)
		if err != nil {
			t.Fatalf("%q: %v", e.rules, err)
		}
		if got := RuleAllowed(ExpandRules(rules, e.stack), e.path); got != e.want {
			t.Errorf("rules %q, stack %q, path %q: allowed = %v, the documentation says %v", e.rules, e.stack, e.path, got, e.want)
		}
	}
}

// The refused rules of the documentation's table.
func TestPathRulesDocumentationRefusedRules(t *testing.T) {
	for _, rule := range []string{"{stack}-*", "{stack}x", "{stack}*", "*", "*/*", "a**b", "../{stack}", "a//b", "/{stack}", "{stack}/", "{name}_*"} {
		if _, err := ParseRules(rule); err == nil {
			t.Errorf("the documentation says %q is refused", rule)
		}
	}
	for _, rule := range []string{"{stack}_*", "{stack}/*", "{stack}_", "{stack}", "kv/common"} {
		if _, err := ParseRules(rule); err != nil {
			t.Errorf("the documentation says %q is accepted: %v", rule, err)
		}
	}
}

func TestPathRulesDocsURL(t *testing.T) {
	if PathRulesField.HelpURL != PathRulesDocsURL || !strings.HasPrefix(PathRulesDocsURL, "https://") || !strings.HasSuffix(PathRulesDocsURL, "/guide/path-rules") {
		t.Errorf("the field links to the documentation page: %q", PathRulesField.HelpURL)
	}
	if strings.Contains(PathRulesField.Help, "What follows {stack}") {
		t.Error("the long rules live in the documentation, not in the form")
	}
}
