package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// getAs is get with a signed-in role, as the session middleware would set it.
func getAs(role string, h http.HandlerFunc, target string) string {
	req := httptest.NewRequest("GET", target, nil)
	req = req.WithContext(context.WithValue(req.Context(), roleCtxKey, role))
	w := httptest.NewRecorder()
	h(w, req)
	return w.Body.String()
}

// groupOpen says whether a sidebar group is rendered open.
func groupOpen(t *testing.T, body, key string) bool {
	t.Helper()
	m := regexp.MustCompile(`<details class="nav-group" data-key="` + key + `"([^>]*)>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no %q group in the sidebar", key)
	}
	return strings.Contains(m[1], "open")
}

func TestSidebarGroupsAreClosedUnlessThePageIsInThem(t *testing.T) {
	f := newVulnFixture(t)
	f.a.tunnels = newTunnelRegistry()

	home := getAs("admin", f.a.stacksHandler, "/stacks")
	if groupOpen(t, home, "tools") || groupOpen(t, home, "settings") {
		t.Error("on a page outside them, Tools and Settings are folded")
	}

	settings := getAs("admin", f.a.settingsVulnHandler, "/settings/vulnerability-scanning")
	if !groupOpen(t, settings, "settings") || groupOpen(t, settings, "tools") {
		t.Error("on a Settings page, Settings is open and Tools is not")
	}
	if !strings.Contains(settings, `class="active">Vulnerability scanning</a>`) {
		t.Error("the current page is marked, inside the group that shows it")
	}

	tool := getAs("admin", f.a.secretsToolFormHandler, "/tools/secrets")
	if !groupOpen(t, tool, "tools") || groupOpen(t, tool, "settings") {
		t.Error("on the Tools page, Tools is open and Settings is not")
	}
}

func TestSidebarGroupsAreForAdminsOnly(t *testing.T) {
	f := newVulnFixture(t)
	body := getAs("operator", f.a.stacksHandler, "/stacks")
	for _, absent := range []string{`<details class="nav-group"`, "Encrypt secrets", "Audit log", "Backup"} {
		if strings.Contains(body, absent) {
			t.Errorf("a non-admin does not see %q in the menu", absent)
		}
	}
}

func TestSidebarGroupsStayUsableWithoutScript(t *testing.T) {
	f := newVulnFixture(t)
	body := getAs("admin", f.a.stacksHandler, "/stacks")
	if !strings.Contains(body, `<summary class="nav-section">Settings</summary>`) {
		t.Error("the header is a <summary>: a <details> opens on click without any script")
	}
}

// Every link of the Settings group must open the group on its own page: a link
// added to the menu but not to the group's condition would leave you on a page
// whose menu entry is folded away.
func TestEverySettingsLinkOpensItsGroup(t *testing.T) {
	raw, err := templatesFS.ReadFile("web/templates/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	layout := string(raw)
	start := strings.Index(layout, `data-key="settings"`)
	end := strings.Index(layout[start:], "</details>")
	group := layout[start : start+end]

	open := group[:strings.Index(group, "<summary")]
	links := regexp.MustCompile(`class="\{\{if eq \.Nav "([a-z-]+)"\}\}active`).FindAllStringSubmatch(group, -1)
	if len(links) < 9 {
		t.Fatalf("expected the nine Settings links, found %d", len(links))
	}
	for _, m := range links {
		if !strings.Contains(open, `(eq .Nav "`+m[1]+`")`) {
			t.Errorf("the %q page does not open the Settings group", m[1])
		}
	}
}
