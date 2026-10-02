package main

import (
	"net/url"
	"strings"
	"testing"

	"github.com/forgelab-me/wharf-server/internal/secrets"
	"github.com/forgelab-me/wharf-server/internal/store"
)

// createGlobalWithRules creates a shared connection with path rules through the
// real handler.
func (f *secretsFixture) createGlobalWithRules(t *testing.T, name, rules string) (store.SecretConnection, string) {
	t.Helper()
	form := url.Values{"type": {"vault"}, "name": {name}, "cfg_address": {"https://bao.example.lan:8200"},
		"cfg_path_rules": {rules}, "cred_token": {"s.abc"}}
	code, loc := call(f.a.createSecretProviderHandler, "/settings/secret-providers", form, nil)
	if code != 303 {
		t.Fatalf("create: %d", code)
	}
	if msg := redirectParam(t, loc, "error"); msg != "" {
		return store.SecretConnection{}, msg
	}
	conns, _ := f.a.store.ListGlobalSecretConnections()
	for _, c := range conns {
		if c.Name == name {
			return c, ""
		}
	}
	t.Fatalf("connection %s not stored", name)
	return store.SecretConnection{}, ""
}

func TestConnectionRefusesAWrongRule(t *testing.T) {
	f := newSecretsFixture(t)
	for _, rule := range []string{"secret/{stack}-*", "*", "../{stack}", "secret/{name}"} {
		if _, msg := f.createGlobalWithRules(t, "bao", rule); msg == "" {
			t.Errorf("the rule %q must be refused when the connection is created", rule)
		}
	}
	if conn, msg := f.createGlobalWithRules(t, "bao", "secret/{stack}\nshared_*"); msg != "" || conn.Config[secrets.PathRulesKey] != "secret/{stack}\nshared_*" {
		t.Errorf("a good rule is kept as written: %q %v", msg, conn.Config)
	}
}

func TestBindingOnAConnectionWithRulesNeedsNoPaths(t *testing.T) {
	f := newSecretsFixture(t)
	conn, _ := f.createGlobalWithRules(t, "bao", "secret/{stack}")

	code, msg := f.saveBinding("blog", url.Values{"mode": {"shared"}, "connection_id": {conn.ID}})
	if code != 303 || msg != "" {
		t.Fatalf("no path typed, rules apply: %d %q", code, msg)
	}
	b, err := f.a.store.GetSecretBinding("blog", "vault")
	if err != nil || len(b.Prefixes) != 0 {
		t.Fatalf("binding = %+v, %v", b, err)
	}

	eff, err := f.a.stackBinding("blog")("vault")
	if err != nil {
		t.Fatal(err)
	}
	if !eff.PathAllowed("secret/blog/db") || eff.PathAllowed("secret/wiki/db") || eff.PathAllowed("secret/blogger") {
		t.Errorf("the rule is applied to blog: %+v", eff.Rules)
	}

	// the same connection gives another stack its own namespace, with nothing typed
	if code, msg := f.saveBinding("wiki", url.Values{"mode": {"shared"}, "connection_id": {conn.ID}}); code != 303 || msg != "" {
		t.Fatalf("wiki: %d %q", code, msg)
	}
	wiki, _ := f.a.stackBinding("wiki")("vault")
	if !wiki.PathAllowed("secret/wiki/db") || wiki.PathAllowed("secret/blog/db") {
		t.Errorf("wiki gets its own: %+v", wiki.Rules)
	}
}

func TestBindingOnAConnectionWithRulesTakesExtraPathsButNotAStar(t *testing.T) {
	f := newSecretsFixture(t)
	conn, _ := f.createGlobalWithRules(t, "bao", "secret/{stack}")

	if _, msg := f.saveBinding("blog", url.Values{"mode": {"shared"}, "connection_id": {conn.ID}, "prefixes": {"*"}}); !strings.Contains(msg, "not *") {
		t.Errorf("a * would give the stack everything, rules or not: %q", msg)
	}
	if code, msg := f.saveBinding("blog", url.Values{"mode": {"shared"}, "connection_id": {conn.ID}, "prefixes": {"kv/common\nkv/smtp"}}); code != 303 || msg != "" {
		t.Fatalf("extra paths are fine: %d %q", code, msg)
	}
	eff, _ := f.a.stackBinding("blog")("vault")
	if !eff.PathAllowed("kv/common/x") || !eff.PathAllowed("secret/blog/x") || eff.PathAllowed("kv/other") {
		t.Errorf("rules and extras together: rules %v, prefixes %v", eff.Rules, eff.Prefixes)
	}
}

func TestBindingWithoutRulesStillNeedsPaths(t *testing.T) {
	f := newSecretsFixture(t)
	conn := f.createGlobal(t, "plain", map[string]string{"token": "s.abc"})
	if _, msg := f.saveBinding("blog", url.Values{"mode": {"shared"}, "connection_id": {conn.ID}}); !strings.Contains(msg, "at least one allowed path") {
		t.Errorf("without rules nothing changed: %q", msg)
	}
	if code, msg := f.saveBinding("blog", url.Values{"mode": {"shared"}, "connection_id": {conn.ID}, "prefixes": {"*"}}); code != 303 || msg != "" {
		t.Errorf("and a * is still accepted there: %d %q", code, msg)
	}
}

func TestAnOwnCredentialsBindingInheritsTheRules(t *testing.T) {
	f := newSecretsFixture(t)
	conn, _ := f.createGlobalWithRules(t, "bao", "secret/{stack}")
	code, msg := f.saveBinding("blog", url.Values{"mode": {"own"}, "connection_id": {conn.ID}, "cred_token": {"s.own"}})
	if code != 303 || msg != "" {
		t.Fatalf("own credentials: %d %q", code, msg)
	}
	eff, err := f.a.stackBinding("blog")("vault")
	if err != nil {
		t.Fatal(err)
	}
	if !eff.HasRules || !eff.PathAllowed("secret/blog/db") || eff.PathAllowed("secret/wiki/db") {
		t.Errorf("a stack with its own credentials cannot step out of the shared connection's rules: %+v", eff.Rules)
	}
}

func TestSeparateConnectionCanCarryItsOwnRules(t *testing.T) {
	f := newSecretsFixture(t)
	form := url.Values{"mode": {"separate"}, "cfg_address": {"https://bao.example.lan:8200"}, "cfg_path_rules": {"secret/{stack}"}, "cred_token": {"s.abc"}}
	if code, msg := f.saveBinding("blog", form); code != 303 || msg != "" {
		t.Fatalf("%d %q", code, msg)
	}
	eff, _ := f.a.stackBinding("blog")("vault")
	if !eff.HasRules || !eff.PathAllowed("secret/blog/x") {
		t.Errorf("%+v", eff)
	}
	form.Set("cfg_path_rules", "{stack}-*")
	if _, msg := f.saveBinding("blog", form); msg == "" {
		t.Error("a wrong rule is refused there too")
	}
}

func TestRulesAddedLaterOverrideAStarSavedBefore(t *testing.T) {
	f := newSecretsFixture(t)
	conn := f.createGlobal(t, "plain", map[string]string{"token": "s.abc"})
	if code, msg := f.saveBinding("blog", url.Values{"mode": {"shared"}, "connection_id": {conn.ID}, "prefixes": {"*"}}); code != 303 || msg != "" {
		t.Fatal(code, msg)
	}
	before, _ := f.a.stackBinding("blog")("vault")
	if !before.PathAllowed("anything/at/all") {
		t.Fatal("the * works while the connection has no rules")
	}

	config := map[string]string{"address": conn.Config["address"], secrets.PathRulesKey: "secret/{stack}"}
	if err := f.a.store.UpdateSecretConnection(conn.ID, conn.Name, config); err != nil {
		t.Fatal(err)
	}
	after, _ := f.a.stackBinding("blog")("vault")
	if after.PathAllowed("anything/at/all") || !after.PathAllowed("secret/blog/db") {
		t.Error("the day the connection gets rules, an old * stops opening everything")
	}
}

func TestStackPageShowsWhatTheRulesAllow(t *testing.T) {
	f := newSecretsFixture(t)
	conn, _ := f.createGlobalWithRules(t, "bao", "homelab/{stack}_*")
	if code, msg := f.saveBinding("blog", url.Values{"mode": {"shared"}, "connection_id": {conn.ID}, "prefixes": {"kv/common"}}); code != 303 || msg != "" {
		t.Fatal(code, msg)
	}
	rows, _ := f.a.stackSecretsView("blog")
	if len(rows) != 1 || rows[0].Rules != "homelab/blog_*" || rows[0].Prefixes != "kv/common" {
		t.Errorf("rows = %+v", rows)
	}

	body := get(f.a.stackBindingFormHandler, "/stacks/blog/secrets/bindings/vault", map[string]string{"id": "blog", "type": "vault"}).Body.String()
	if !strings.Contains(body, "homelab/blog_*") || !strings.Contains(body, `data-rules="homelab/blog_*"`) || !strings.Contains(body, "<strong>added</strong>") {
		t.Error("the binding form says what the connection's rules allow this stack")
	}
}

func TestFormsLinkToThePathRulesDocumentation(t *testing.T) {
	f := newSecretsFixture(t)
	want := `href="` + secrets.PathRulesDocsURL + `"`

	form := getAs("admin", f.a.newSecretProviderFormHandler, "/settings/secret-providers/new?type=vault")
	if !strings.Contains(form, want) || !strings.Contains(form, "Read more") || !strings.Contains(form, "Path rules") {
		t.Error("the connection form's Path rules field links to the documentation")
	}

	conn, _ := f.createGlobalWithRules(t, "bao", "secret/{stack}")
	binding := get(f.a.stackBindingFormHandler, "/stacks/blog/secrets/bindings/vault", map[string]string{"id": "blog", "type": "vault"}).Body.String()
	// the three variants of the allowed paths help, and the Path rules field of the "own connection" section
	if strings.Count(binding, want) != 4 || !strings.Contains(binding, "How path rules work") {
		t.Errorf("the binding form links from each help variant and from its own rules field: %d", strings.Count(binding, want))
	}
	if code, msg := f.saveBinding("blog", url.Values{"mode": {"shared"}, "connection_id": {conn.ID}}); code != 303 || msg != "" {
		t.Fatal(code, msg)
	}
	if body := get(f.a.stackBindingFormHandler, "/stacks/blog/secrets/bindings/vault", map[string]string{"id": "blog", "type": "vault"}).Body.String(); !strings.Contains(body, want) {
		t.Error("the link stays once the stack is attached")
	}
}

func TestProvidersListShowsRulesAndAnEditLink(t *testing.T) {
	f := newSecretsFixture(t)
	conn, _ := f.createGlobalWithRules(t, "bao", "secret/{stack}\nshared_*")
	body := getAs("admin", f.a.secretProvidersHandler, "/settings/secret-providers")
	for _, want := range []string{"<code>secret/{stack}</code>", "<code>shared_*</code>", `href="/settings/secret-providers/` + conn.ID + `" class="btn btn-ghost btn-sm">Edit`} {
		if !strings.Contains(body, want) {
			t.Errorf("the connections list lacks %q", want)
		}
	}
}

func TestProvidersListShowsTheBitwardenServer(t *testing.T) {
	p := secrets.BwsProvider(secrets.NewBwsTool(t.TempDir()))
	for config, want := range map[string]string{"": "https://vault.bitwarden.com", "eu": "https://vault.bitwarden.eu"} {
		if got := connectorSummary(p, map[string]string{"region": config}); got != want {
			t.Errorf("region %q: %q, want %q", config, got, want)
		}
	}
	if got := connectorSummary(p, map[string]string{"region": "custom", "server_url": "https://bw.example.lan/"}); got != "https://bw.example.lan" {
		t.Errorf("custom: %q", got)
	}
}
