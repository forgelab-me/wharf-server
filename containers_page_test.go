package main

import (
	"strings"
	"testing"

	"github.com/forgelab-me/wharf-server/internal/registry"
	"github.com/forgelab-me/wharf-server/internal/store"
)

// containersPageFixture is a host running three containers of the "shop" stack:
// one whose image is up to date, one with an update waiting, one with no image
// policy, plus a container no stack owns.
func containersPageFixture(t *testing.T) (*vulnFixture, store.Host) {
	t.Helper()
	f, h := graphPagesFixture(t)
	st := f.a.store
	st.ReplaceHostContainers(h.ID, []store.HostContainer{
		{HostID: h.ID, ContainerID: "c1", Name: "shop-web-1", ServiceName: "web", Image: "nginx:1.27", ImageID: "aaaaaaaaaaaa", State: "running", Status: "Up", StackID: "shop"},
		{HostID: h.ID, ContainerID: "c2", Name: "shop-cache-1", ServiceName: "cache", Image: "redis:7", State: "running", Status: "Up", StackID: "shop"},
		{HostID: h.ID, ContainerID: "c3", Name: "shop-db-1", ServiceName: "db", Image: "postgres:16", State: "running", Status: "Up", StackID: "shop"},
		{HostID: h.ID, ContainerID: "c4", Name: "portainer", Image: "portainer/portainer-ce", State: "running", Status: "Up"},
	})
	for service, image := range map[string]string{"web": "nginx:1.27", "cache": "redis:7"} {
		if err := st.UpsertImagePolicy("shop", service, image); err != nil {
			t.Fatal(err)
		}
		ref, _ := registry.ParseRef(image)
		if err := st.SetImageDigestCache(ref.Canonical(), digestOf("e")); err != nil {
			t.Fatal(err)
		}
	}
	st.SetAppliedDigest("shop", "web", digestOf("d")) // the registry has moved on
	st.SetAppliedDigest("shop", "cache", digestOf("e"))
	st.UpsertImageScan(store.ImageScan{Scanner: "trivy", Digest: digestOf("a"), Platform: "linux/amd64", Status: "ok", High: 2})
	return f, h
}

func rowOf(body, name string) string {
	i := strings.Index(body, ">"+name+"</a>")
	if i < 0 {
		return ""
	}
	start := strings.LastIndex(body[:i], "<tr")
	end := strings.Index(body[i:], "</tr>")
	return body[start : i+end]
}

func TestContainersPageShowsFreshnessAsADot(t *testing.T) {
	f, _ := containersPageFixture(t)
	body := get(f.a.containersHandler, "/containers", nil).Body.String()

	if row := rowOf(body, "shop-web-1"); !strings.Contains(row, `upd-dot upd-outdated`) || strings.Contains(row, "upd-current") {
		t.Errorf("an image with an update waiting has the amber dot:\n%s", row)
	}
	if row := rowOf(body, "shop-cache-1"); !strings.Contains(row, `upd-dot upd-current`) {
		t.Errorf("an up to date image has the green dot:\n%s", row)
	}
	for _, name := range []string{"shop-db-1", "portainer"} {
		row := rowOf(body, name)
		if strings.Contains(row, "upd-current") || strings.Contains(row, "upd-outdated") {
			t.Errorf("%s is not tracked by an image policy: no dot of either colour:\n%s", name, row)
		}
		if !strings.Contains(row, `<span class="upd-dot"></span>`) {
			t.Errorf("%s keeps the dot's room so that image names line up:\n%s", name, row)
		}
	}

	for _, gone := range []string{`>up to date</span>`, `>update available</span>`} {
		if strings.Contains(body, gone) {
			t.Errorf("the freshness is no longer a badge with words in each row: %s", gone)
		}
	}
	legend := body[strings.Index(body, `class="upd-legend"`):]
	for _, want := range []string{"up to date", "update available", "image policy"} {
		if !strings.Contains(legend, want) {
			t.Errorf("the legend under the table says %q", want)
		}
	}
}

func TestContainersPageVulnerabilitiesBehindASwitch(t *testing.T) {
	f, _ := containersPageFixture(t)
	body := get(f.a.containersHandler, "/containers", nil).Body.String()

	if !strings.Contains(body, `class="vuln-toggle"`) || !strings.Contains(body, "> Vulnerabilities</label>") {
		t.Error("with scanning on there is a switch for the vulnerabilities")
	}
	if !strings.Contains(body, `class="containers-table hide-vuln"`) {
		t.Error("the badges are hidden until the switch is turned on: the page was too busy")
	}
	if row := rowOf(body, "shop-web-1"); !strings.Contains(row, `class="vuln-badge"`) || !strings.Contains(row, "2 high") {
		t.Errorf("the badge is still there, in a wrapper the switch hides:\n%s", row)
	}
	if !strings.Contains(body, "wharf.containers.vulnerabilities") {
		t.Error("the choice is remembered by the browser")
	}
}

func TestContainersPageWithoutScanningHasNoSwitch(t *testing.T) {
	f, _ := containersPageFixture(t)
	f.a.store.SetVulnSettingsChoice(false, "trivy")
	body := get(f.a.containersHandler, "/containers", nil).Body.String()

	for _, absent := range []string{"vuln-toggle", "hide-vuln", "wharf.containers.vulnerabilities", "2 high"} {
		if strings.Contains(body, absent) {
			t.Errorf("with scanning off there is nothing to switch: found %q", absent)
		}
	}
	if !strings.Contains(body, "upd-outdated") || !strings.Contains(body, `class="upd-legend"`) {
		t.Error("the freshness dot and its legend do not depend on scanning")
	}
}

func TestContainersPageWithoutContainers(t *testing.T) {
	f := newVulnFixture(t)
	body := get(f.a.containersHandler, "/containers", nil).Body.String()
	if !strings.Contains(body, "No containers") || strings.Contains(body, "upd-legend") {
		t.Errorf("an empty page has no legend:\n%.300s", body)
	}
}
