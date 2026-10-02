package main

import (
	"regexp"
	"strings"
	"testing"

	"github.com/forgelab-me/wharf-server/internal/registry"
	"github.com/forgelab-me/wharf-server/internal/store"
)

// imagesPanelFixture is the "shop" stack with one service whose image has an
// update waiting and one that is up to date, both scanned.
func imagesPanelFixture(t *testing.T) *vulnFixture {
	t.Helper()
	f, _ := graphPagesFixture(t)
	st := f.a.store
	for _, p := range []struct{ svc, img, applied, latest string }{
		{"web", "nginx:1.27", "a", "b"},
		{"cache", "redis:7", "c", "c"},
	} {
		if err := st.UpsertImagePolicy("shop", p.svc, p.img); err != nil {
			t.Fatal(err)
		}
		ref, _ := registry.ParseRef(p.img)
		st.SetImageDigestCache(ref.Canonical(), digestOf(p.latest))
		st.SetAppliedDigest("shop", p.svc, digestOf(p.applied))
	}
	for d, s := range map[string]store.ImageScan{"a": {High: 3}, "b": {}, "c": {Medium: 1}} {
		s.Scanner, s.Digest, s.Platform, s.Status = "trivy", digestOf(d), "linux/amd64", "ok"
		st.UpsertImageScan(s)
	}
	return f
}

// imageRow returns the table row of a service of the Images panel.
func imageRow(t *testing.T, body, service string) string {
	t.Helper()
	re := regexp.MustCompile(`(?s)<tr[^>]*>\s*<td>` + service + `</td>.*?</tr>`)
	row := re.FindString(body)
	if row == "" {
		t.Fatalf("no row for %s", service)
	}
	return row
}

func TestImagesPanelLinesUpAcrossColumns(t *testing.T) {
	f := imagesPanelFixture(t)
	body := get(f.a.stackViewHandler, "/stacks/shop", map[string]string{"id": "shop"}).Body.String()

	web := imageRow(t, body, "web")
	if !strings.Contains(web, `class="has-l2 has-btn"`) {
		t.Errorf("a row with an update and a scan has two lines, the first tall enough for the button:\n%s", web)
	}
	// Applied, Latest and the last column each put their name, or the button,
	// on the first line and their badge on the second
	if got := strings.Count(web, `class="img-l1"`); got != 3 {
		t.Errorf("first lines = %d, want 3 (Applied, Latest, button)", got)
	}
	if got := strings.Count(web, `class="img-l2"`); got != 3 {
		t.Errorf("second lines = %d, want 3", got)
	}
	last1, last2 := strings.LastIndex(web, `class="img-l1"`), strings.LastIndex(web, `class="img-l2"`)
	if !strings.Contains(web[last1:last2], `>Apply</button>`) || strings.Contains(web[last1:last2], "Update available") {
		t.Errorf("the button is alone on the first line of the last column:\n%s", web)
	}
	if !strings.Contains(web[last2:], "Update available") || strings.Contains(web[last2:], ">Apply<") {
		t.Errorf("the update badge sits under the button:\n%s", web)
	}

	cache := imageRow(t, body, "cache")
	if strings.Contains(cache, "has-btn") || !strings.Contains(cache, `class="has-l2"`) {
		t.Errorf("an up to date, scanned row has a second line but no room for a button:\n%s", cache)
	}
	if strings.Contains(cache, "Update available") || strings.Contains(cache, ">Apply<") {
		t.Errorf("nothing to apply:\n%s", cache)
	}
}

func TestImagesPanelWithoutScanningAndUpToDateIsASingleLine(t *testing.T) {
	f := imagesPanelFixture(t)
	f.a.store.SetVulnSettingsChoice(false, "trivy")
	body := get(f.a.stackViewHandler, "/stacks/shop", map[string]string{"id": "shop"}).Body.String()

	if cache := imageRow(t, body, "cache"); strings.Contains(cache, "has-l2") {
		t.Errorf("no scan and no update: nothing for a second line, the row stays low:\n%s", cache)
	}
	if web := imageRow(t, body, "web"); !strings.Contains(web, `class="has-l2 has-btn"`) {
		t.Errorf("an update waiting still needs its button line:\n%s", web)
	}
}
