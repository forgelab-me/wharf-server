package main

import (
	"strings"
	"testing"

	"github.com/forgelab-me/wharf-server/internal/store"
)

func TestStackState(t *testing.T) {
	for _, c := range []struct {
		last           string
		running, total int
		class, label   string
	}{
		{"succeeded", 3, 3, "ok", "running 3/3"},
		{"succeeded", 2, 3, "warn", "partial 2/3"},
		{"succeeded", 0, 2, "muted", "stopped 0/2"},
		{"succeeded", 0, 0, "muted", "not running"},
		{"", 0, 0, "muted", "never deployed"},
		{"failed", 0, 2, "bad", "failed · 0/2"},
		{"failed", 0, 0, "bad", "failed"},
		{"queued", 1, 2, "warn", "deploying"},
		{"running", 0, 0, "warn", "deploying"},
		{"", 2, 2, "ok", "running 2/2"},
	} {
		class, label := stackState(c.last, c.running, c.total)
		if class != c.class || label != c.label {
			t.Errorf("stackState(%q, %d, %d) = %q %q, want %q %q", c.last, c.running, c.total, class, label, c.class, c.label)
		}
	}
}

func TestBuildStackRows(t *testing.T) {
	stacks := []store.Stack{{ID: "blog", Name: "blog", Host: "h1", Trigger: "polling"}, {ID: "empty", Name: "empty", Host: "h1", Trigger: "manual"}}
	by := map[string][]store.HostContainer{"blog": {
		{HostID: "h1", ContainerID: "c2", Name: "blog-db-1", ServiceName: "db", Image: "postgres:16.4@sha256:abc", State: "running", Mounts: "blog_data,/opt/conf"},
		{HostID: "h1", ContainerID: "c1", Name: "blog-web-1", ServiceName: "web", Image: "ghcr.io/acme/web:2.4", State: "running", Ports: "0.0.0.0:8081->80/tcp", ImageID: "i1"},
		{HostID: "h1", ContainerID: "c3", Name: "blog-old-1", ServiceName: "old", Image: "old:1", State: "exited"},
	}}
	scan := func(c store.HostContainer) *scanBadge {
		switch c.ContainerID {
		case "c1":
			return &scanBadge{Level: "high", Label: "3 high", Tooltip: "t"}
		case "c2":
			return &scanBadge{Level: "clean", Label: "clean"}
		}
		return nil
	}
	rows := buildStackRows(stacks, by, map[string]string{"blog": "succeeded"},
		func(id string) string { return "label-" + id }, func(string) string { return "192.168.1.20" }, scan)

	blog := rows[0]
	if blog.Host != "label-h1" || blog.Trigger != "polling" || blog.Running != 2 || blog.Total != 3 {
		t.Errorf("blog = %+v", blog)
	}
	if blog.StateClass != "warn" || blog.StateLabel != "partial 2/3" || blog.LastStatus != "succeeded" {
		t.Errorf("state = %q %q", blog.StateClass, blog.StateLabel)
	}
	if blog.Worst == nil || blog.Worst.Level != "high" || blog.Worst.Text != "3 high" {
		t.Errorf("the stack carries its worst vulnerability: %+v", blog.Worst)
	}
	var order []string
	for _, c := range blog.Cards {
		order = append(order, c.Service)
	}
	if strings.Join(order, ",") != "db,old,web" {
		t.Errorf("cards are sorted by service: %v", order)
	}
	db, old, web := blog.Cards[0], blog.Cards[1], blog.Cards[2]
	if db.Image != "postgres:16.4" || db.ImageTip != "postgres:16.4@sha256:abc" || db.Volumes != 1 {
		t.Errorf("image keeps name and tag, bind mounts are not volumes: %+v", db)
	}
	if !web.Active || old.Active || old.Dot != "off" {
		t.Errorf("only a running container has live figures: web %v, old %v/%q", web.Active, old.Active, old.Dot)
	}
	if len(web.Ports) != 1 || web.Ports[0].URL != "http://192.168.1.20:8081" {
		t.Errorf("ports link to the host's address: %+v", web.Ports)
	}
	if web.Chip == nil || old.Chip != nil {
		t.Errorf("chips: web %+v, old %+v", web.Chip, old.Chip)
	}

	empty := rows[1]
	if empty.Total != 0 || len(empty.Cards) != 0 || empty.Worst != nil || empty.StateLabel != "never deployed" {
		t.Errorf("a stack with no container: %+v", empty)
	}
}

func TestBuildStackRowsWithoutScanning(t *testing.T) {
	rows := buildStackRows([]store.Stack{{ID: "s", Name: "s"}},
		map[string][]store.HostContainer{"s": {{ContainerID: "c1", Name: "s-1", State: "running"}}},
		nil, func(string) string { return "" }, func(string) string { return "" }, nil)
	if rows[0].Worst != nil || rows[0].Cards[0].Chip != nil {
		t.Errorf("with scanning off no chip is drawn: %+v", rows[0])
	}
}

func TestStacksPage(t *testing.T) {
	f, h := graphPagesFixture(t)
	f.a.store.ReplaceHostContainers(h.ID, []store.HostContainer{
		{HostID: h.ID, ContainerID: "c1", Name: "shop-web-1", ServiceName: "web", Image: "nginx:1.27", ImageID: "aaaaaaaaaaaa", State: "running", Status: "Up", StackID: "shop", Ports: "0.0.0.0:8080->80/tcp", Mounts: "shop_data"},
		{HostID: h.ID, ContainerID: "c2", Name: "shop-db-1", ServiceName: "db", Image: "postgres:16", State: "exited", Status: "Exited", StackID: "shop"},
		{HostID: h.ID, ContainerID: "c3", Name: "portainer", Image: "portainer/portainer-ce", State: "running", Status: "Up"},
	})
	f.a.store.UpsertImageScan(store.ImageScan{Scanner: "trivy", Digest: digestOf("a"), Platform: "linux/amd64", Status: "ok", High: 2})

	w := get(f.a.stacksHandler, "/stacks", nil)
	body := w.Body.String()
	if w.Code != 200 {
		t.Fatalf("%d\n%.500s", w.Code, body)
	}
	for _, want := range []string{
		`class="st-table"`, `data-id="shop"`, `href="/stacks/shop"`, "partial 1/2",
		`data-m="cpu"`, `data-m="mem"`, `data-m="net"`, `data-m="disk"`,
		`class="st-detail" data-for="shop" hidden`, `data-cid="c1"`, `href="/containers/c1"`,
		`class="st-card off" data-cid="c2"`, "gchip-high", `title="nginx:1.27"`,
		"/stats/stacks", `action="/stacks/shop/delete"`, `id="st-all"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(body, "portainer") {
		t.Error("a container no stack owns is not listed")
	}
	if strings.Contains(body, `class="st-card" data-cid="c2"`) {
		t.Error("a stopped container's card is greyed")
	}
}

func TestStacksPageWithoutStacks(t *testing.T) {
	f := newVulnFixture(t)
	body := get(f.a.stacksHandler, "/stacks", nil).Body.String()
	if !strings.Contains(body, "No stack yet") || strings.Contains(body, "st-table") || strings.Contains(body, "/stats/stacks") {
		t.Errorf("an empty list neither draws a table nor polls:\n%.400s", body)
	}
}
