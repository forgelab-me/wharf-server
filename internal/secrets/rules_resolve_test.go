package secrets

import (
	"context"
	"strings"
	"testing"
)

func effectiveWith(t *testing.T, rules, stackID string, prefixes []string) *Effective {
	t.Helper()
	config := map[string]string{"address": "https://bao.example.lan:8200", PathRulesKey: rules}
	eff := NewEffective("vault", config, map[string]string{"token": "t"}, prefixes, "test")
	if err := eff.ApplyPathRules(stackID); err != nil {
		t.Fatal(err)
	}
	return eff
}

func TestEffectivePathAllowedWithoutRulesIsWhatItAlwaysWas(t *testing.T) {
	eff := effectiveWith(t, "", "blog", []string{"secret/blog"})
	if eff.HasRules || len(eff.Rules) != 0 {
		t.Fatalf("no rule on the connection: %+v", eff)
	}
	for path, want := range map[string]bool{"secret/blog": true, "secret/blog/db": true, "secret/blogger": false, "secret/prod": false} {
		if got := eff.PathAllowed(path); got != want {
			t.Errorf("%q = %v, want %v", path, got, want)
		}
	}
	if !effectiveWith(t, "", "blog", []string{"*"}).PathAllowed("anything/at/all") {
		t.Error("without rules a * still allows everything")
	}
}

func TestEffectivePathAllowedWithRules(t *testing.T) {
	eff := effectiveWith(t, "secret/{stack}\nshared_*", "blog", nil)
	if !eff.HasRules {
		t.Fatal("the connection has rules")
	}
	for path, want := range map[string]bool{
		"secret/blog": true, "secret/blog/db": true, "shared_smtp": true,
		"secret/shop/db": false, "secret/blogger": false, "secret/blog-staging/db": false, "other": false,
	} {
		if got := eff.PathAllowed(path); got != want {
			t.Errorf("%q = %v, want %v", path, got, want)
		}
	}

	// the administrator can add paths on top of the rules
	extra := effectiveWith(t, "secret/{stack}", "blog", []string{"kv/common"})
	if !extra.PathAllowed("kv/common/smtp") || !extra.PathAllowed("secret/blog/db") || extra.PathAllowed("kv/other") {
		t.Error("extra paths add to the rules, nothing more")
	}
}

func TestRulesLimitWhatAStarAllowedPathCouldGive(t *testing.T) {
	// a binding saved before the connection got rules still holds a *
	eff := effectiveWith(t, "secret/{stack}", "blog", []string{"*"})
	if eff.PathAllowed("secret/shop/db") {
		t.Error("a * allowed path must not widen a connection that has rules")
	}
	if !eff.PathAllowed("secret/blog/db") {
		t.Error("the rule itself still applies")
	}
}

func TestAStackIdThatCannotBeInARuleGetsNothing(t *testing.T) {
	eff := effectiveWith(t, "secret/{stack}", "../etc", []string{"*"})
	if !eff.HasRules || len(eff.Rules) != 0 {
		t.Fatalf("rules = %q, has = %v: the rule is there, it just allows nothing", eff.Rules, eff.HasRules)
	}
	if eff.PathAllowed("secret/anything") || eff.PathAllowed("secret/../etc") {
		t.Error("an unusable stack id must not fall back to the * of its binding")
	}
}

func TestApplyPathRulesRefusesStoredGarbage(t *testing.T) {
	eff := NewEffective("vault", map[string]string{PathRulesKey: "{stack}-*"}, nil, nil, "test")
	if err := eff.ApplyPathRules("blog"); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Errorf("rules that could not have been saved are an error, not silently ignored: %v", err)
	}
}

func TestAllowedSummary(t *testing.T) {
	if got := effectiveWith(t, "", "blog", nil).AllowedSummary(); !strings.Contains(got, "nothing") {
		t.Errorf("summary = %q", got)
	}
	if got := effectiveWith(t, "secret/{stack}", "blog", []string{"kv/common"}).AllowedSummary(); got != "kv/common, rule secret/blog" {
		t.Errorf("summary = %q", got)
	}
}

func TestResolverEnforcesPathRules(t *testing.T) {
	f := newFakeVault(t)
	config := map[string]string{"address": f.srv.URL, "kv_version": "2", PathRulesKey: "secret/{stack}"}
	eff := NewEffective("vault", config, map[string]string{"token": testStatic}, nil, "test connection")
	if err := eff.ApplyPathRules("blog"); err != nil {
		t.Fatal(err)
	}
	r := NewResolver(SOPSProvider(), VaultProvider())

	res, err := r.Resolve(context.Background(), jobFor(eff), []Entry{{"DB_PASSWORD", Ref{"vault", "secret/blog/db", "password"}}})
	if err != nil || res.Env["DB_PASSWORD"] != "p4ss" {
		t.Fatalf("a path under the rule is read: %+v, %v", res, err)
	}

	before := f.reads.Load()
	_, err = r.Resolve(context.Background(), jobFor(eff), []Entry{
		{"OTHER_STACK", Ref{"vault", "secret/shop/db", "password"}},
		{"SIBLING", Ref{"vault", "secret/blogger/db", "password"}},
	})
	var rerr *ResolveError
	if !asResolveError(err, &rerr) || len(rerr.Failures) != 2 {
		t.Fatalf("err = %v, want two failures", err)
	}
	if !strings.Contains(err.Error(), "rule secret/blog") {
		t.Errorf("the message names the rule that applied: %v", err)
	}
	if f.reads.Load() != before {
		t.Error("a path outside the rule must never reach the server")
	}
}

func TestParsePrefixesMayBeEmptyAndNormalizeMayNot(t *testing.T) {
	if got, err := ParsePrefixes("  \n"); err != nil || len(got) != 0 {
		t.Errorf("ParsePrefixes(blank) = %v, %v", got, err)
	}
	if _, err := NormalizePrefixes(""); err == nil {
		t.Error("NormalizePrefixes still requires one")
	}
	if got, err := ParsePrefixes("secret/blog/*, kv/app"); err != nil || strings.Join(got, "|") != "secret/blog|kv/app" {
		t.Errorf("ParsePrefixes = %v, %v", got, err)
	}
}

func TestVaultRefusesWrongRulesInItsConfig(t *testing.T) {
	p := VaultProvider()
	config := map[string]string{"address": "https://bao.example.lan:8200", PathRulesKey: "secret/{stack}-*"}
	if err := p.ValidateConfig(config); err == nil {
		t.Error("a rule that would let one stack read another's secrets must be refused")
	}
	config[PathRulesKey] = "secret/{stack}"
	if err := p.ValidateConfig(config); err != nil {
		t.Errorf("a good rule is accepted: %v", err)
	}
	found := false
	for _, f := range p.Fields() {
		if f.Name == PathRulesKey && f.Input == "textarea" && !f.Credential {
			found = true
		}
	}
	if !found {
		t.Error("the connection form offers the rules field")
	}
}

// ---- {stack} in a reference's path

// recordingConnector is a connection-based provider that returns the path it was asked for.
type recordingConnector struct{}

func (recordingConnector) Scheme() string                              { return "vault" }
func (recordingConnector) Label() string                               { return "recording" }
func (recordingConnector) Fields() []Field                             { return nil }
func (recordingConnector) ValidateConfig(map[string]string) error      { return nil }
func (recordingConnector) ValidateCredentials(map[string]string) error { return nil }
func (recordingConnector) Check(context.Context, *Effective) error     { return nil }
func (recordingConnector) Resolve(_ context.Context, _ *Job, ref Ref) (string, error) {
	return "read:" + ref.Path + "#" + ref.Field, nil
}

func stackJob(t *testing.T, stackID, rules string) *Job {
	t.Helper()
	return &Job{StackID: stackID, Binding: func(string) (*Effective, error) { return effectiveWith(t, rules, stackID, nil), nil }}
}

func resolveRefs(t *testing.T, job *Job, refs ...string) (Result, error) {
	t.Helper()
	var entries []Entry
	for i, s := range refs {
		ref, err := ParseRef(s)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		entries = append(entries, Entry{Key: "K" + string(rune('A'+i)), Ref: ref})
	}
	return NewResolver(recordingConnector{}).Resolve(context.Background(), job, entries)
}

func TestStackPlaceholderGivesEachStackItsOwnSecretsFromOneFile(t *testing.T) {
	const ref = "ref+vault://homelab/{stack}_PIHOLE#/value"
	for _, stack := range []string{"dnsweaver-1", "dnsweaver-2"} {
		res, err := resolveRefs(t, stackJob(t, stack, "homelab/{stack}_*"), ref)
		if err != nil {
			t.Fatalf("%s: %v", stack, err)
		}
		if got, want := res.Env["KA"], "read:homelab/"+stack+"_PIHOLE#value"; got != want {
			t.Errorf("%s read %q, want %q", stack, got, want)
		}
	}
}

func TestStackPlaceholderStillGoesThroughThePathRules(t *testing.T) {
	// the expansion cannot reach another stack's secrets: the rule sees the real path
	_, err := resolveRefs(t, stackJob(t, "dnsweaver-2", "homelab/{stack}_*"), "ref+vault://homelab/dnsweaver-1_PIHOLE#/value")
	if err == nil || !strings.Contains(err.Error(), `path "homelab/dnsweaver-1_PIHOLE" is outside`) {
		t.Fatalf("a literal path of another stack is refused: %v", err)
	}
	// a placeholder that lands outside the rule is refused too, and the error shows the real path
	_, err = resolveRefs(t, stackJob(t, "blog", "secret/{stack}"), "ref+vault://other/{stack}/db#/value")
	if err == nil || !strings.Contains(err.Error(), `path "other/blog/db" is outside`) {
		t.Fatalf("the error names the expanded path: %v", err)
	}
}

func TestStackPlaceholderNeedsAPlainStackId(t *testing.T) {
	for _, id := range []string{"", "../x", "Blog", "a/b", "blog_x"} {
		job := &Job{StackID: id, Binding: func(string) (*Effective, error) { return effectiveWith(t, "", "blog", []string{"*"}), nil }}
		if _, err := resolveRefs(t, job, "ref+vault://secret/{stack}/db#/value"); err == nil || !strings.Contains(err.Error(), "not a plain id") {
			t.Errorf("stack id %q must make {stack} fail: %v", id, err)
		}
	}
	// a reference without the placeholder does not care about the id
	job := &Job{StackID: "", Binding: func(string) (*Effective, error) { return effectiveWith(t, "", "blog", []string{"*"}), nil }}
	if _, err := resolveRefs(t, job, "ref+vault://secret/db#/value"); err != nil {
		t.Errorf("no placeholder, nothing to expand: %v", err)
	}
}

func TestParseRefAcceptsOnlyTheStackPlaceholder(t *testing.T) {
	for s, ok := range map[string]bool{
		"ref+bws://homelab/{stack}_PIHOLE#/value": true,
		"ref+vault://secret/{stack}/{stack}#/pw":  true,
		"ref+vault://secret/{stak}/db#/pw":        false,
		"ref+vault://secret/{name}/db#/pw":        false,
		"ref+vault://secret/{stack/db#/pw":        false,
		"ref+vault://secret/stack}/db#/pw":        false,
		"ref+vault://secret/db#/{stack}":          false,
	} {
		if _, err := ParseRef(s); (err == nil) != ok {
			t.Errorf("%q: error = %v, accepted should be %v", s, err, ok)
		}
	}
}
