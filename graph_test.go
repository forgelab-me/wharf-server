package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/forgelab-me/wharf-server/internal/store"
)

func overlap(a, b gNode) bool {
	return a.X < b.X+b.W && b.X < a.X+a.W && a.Y < b.Y+b.H && b.Y < a.Y+a.H
}

// checkLayout fails if two nodes overlap or one leaves the canvas.
func checkLayout(t *testing.T, g *graph) {
	t.Helper()
	for i, n := range g.Nodes {
		if n.X < 0 || n.Y < 0 || n.X+n.W > g.W || n.Y+n.H > g.H {
			t.Errorf("node %d (%s %v) leaves the %dx%d canvas: %d,%d %dx%d", i, n.Kind, n.Lines, g.W, g.H, n.X, n.Y, n.W, n.H)
		}
		for j := i + 1; j < len(g.Nodes); j++ {
			if overlap(n, g.Nodes[j]) {
				t.Errorf("nodes %d and %d overlap: %v / %v", i, j, n.Lines, g.Nodes[j].Lines)
			}
		}
	}
	for i, r := range g.Regions {
		if r.X < 0 || r.Y < 0 || r.X+r.W > g.W || r.Y+r.H > g.H {
			t.Errorf("region %d leaves the canvas", i)
		}
		for j := i + 1; j < len(g.Regions); j++ {
			o := g.Regions[j]
			if r.X < o.X+o.W && o.X < r.X+r.W && r.Y < o.Y+o.H && o.Y < r.Y+r.H {
				t.Errorf("regions %d and %d overlap", i, j)
			}
		}
	}
}

func kinds(g *graph, kind string) int {
	n := 0
	for _, node := range g.Nodes {
		if node.Kind == kind {
			n++
		}
	}
	return n
}

func edgeKinds(g *graph, kind string) int {
	n := 0
	for _, e := range g.Edges {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

func findNode(t *testing.T, g *graph, title string) gNode {
	t.Helper()
	for _, n := range g.Nodes {
		if len(n.Lines) > 0 && n.Lines[0].Text == title {
			return n
		}
	}
	t.Fatalf("no node titled %q", title)
	return gNode{}
}

func blogContainers() []store.HostContainer {
	return []store.HostContainer{
		{HostID: "h1", ContainerID: "c1", Name: "blog-web-1", ServiceName: "web", Image: "nginx:1.27", State: "running", StackID: "blog", Mounts: "uploads", Networks: "blog_default"},
		{HostID: "h1", ContainerID: "c2", Name: "blog-app-1", ServiceName: "app", Image: "ghcr.io/acme/blog:2.4", State: "running", StackID: "blog", Mounts: "uploads", Networks: "blog_default"},
		{HostID: "h1", ContainerID: "c3", Name: "blog-db-1", ServiceName: "db", Image: "postgres:16.4@sha256:abc", State: "exited", StackID: "blog", Mounts: "db-data", Networks: "blog_default,backend"},
	}
}

func TestStackGraphNothingToDrawWithoutContainers(t *testing.T) {
	if g := buildStackGraph(stackGraphInput{Stack: store.Stack{ID: "blog", Name: "blog"}}); g != nil {
		t.Errorf("a stack with no container has no graph: %+v", g)
	}
}

func TestStackGraphLayout(t *testing.T) {
	g := buildStackGraph(stackGraphInput{
		Stack: store.Stack{ID: "blog", Name: "blog"}, Host: "nas-01", Status: "deployed",
		Sources:    []gSource{{Label: "Git source", Detail: "acme/blog @ main"}, {Label: "Image policy", Detail: "3 service(s)"}},
		Containers: blogContainers(),
	})
	if g == nil {
		t.Fatal("no graph")
	}
	checkLayout(t, g)

	if got := kinds(g, "source"); got != 2 {
		t.Errorf("sources = %d", got)
	}
	if got := kinds(g, "container"); got != 3 {
		t.Errorf("containers = %d", got)
	}
	// uploads is shared by two containers: one node, two edges
	if got := kinds(g, "volume"); got != 2 {
		t.Errorf("volume nodes = %d, want uploads and db-data", got)
	}
	if got := edgeKinds(g, "volume"); got != 3 {
		t.Errorf("volume edges = %d, want 3", got)
	}
	if got := kinds(g, "network"); got != 2 {
		t.Errorf("network nodes = %d, want backend and blog_default", got)
	}
	if got := edgeKinds(g, "network"); got != 4 {
		t.Errorf("network edges = %d, want 4", got)
	}
	if got := edgeKinds(g, "flow"); got != 2+3 { // sources -> stack, stack -> containers
		t.Errorf("flow edges = %d, want 5", got)
	}

	db := findNode(t, g, "db")
	if db.Dot != "off" {
		t.Errorf("an exited container is not drawn as running: %q", db.Dot)
	}
	if !strings.Contains(db.Lines[1].Text, "postgres:16.4") || strings.Contains(db.Lines[1].Text, "sha256") {
		t.Errorf("the image line keeps name and tag, not the digest: %q", db.Lines[1].Text)
	}
	if app := findNode(t, g, "app"); app.Lines[1].Text != "blog:2.4" {
		t.Errorf("the registry and path are dropped: %q", app.Lines[1].Text)
	}
	if db.Href != "/containers/c3" {
		t.Errorf("href = %q", db.Href)
	}
	var legend []string
	for _, l := range g.Legend {
		legend = append(legend, l.Key)
	}
	if strings.Join(legend, ",") != "ef,ev,en" {
		t.Errorf("legend = %v", legend)
	}
}

func TestStackGraphWithoutVolumesOrNetworksDrawsNoResources(t *testing.T) {
	g := buildStackGraph(stackGraphInput{
		Stack:      store.Stack{ID: "x", Name: "x"},
		Sources:    []gSource{{Label: "Compose file", Detail: "local"}},
		Containers: []store.HostContainer{{HostID: "h1", ContainerID: "c1", Name: "x-1", Image: "busybox"}},
	})
	checkLayout(t, g)
	if kinds(g, "volume")+kinds(g, "network") != 0 || edgeKinds(g, "volume")+edgeKinds(g, "network") != 0 {
		t.Errorf("nothing to link: %+v", g.Edges)
	}
	if len(g.Legend) != 1 || g.Legend[0].Key != "ef" {
		t.Errorf("only the deploy arrow needs a legend: %+v", g.Legend)
	}
	if findNode(t, g, "x-1").Lines[0].Text != "x-1" {
		t.Error("a container with no service name is titled by its own name")
	}
}

func TestStackGraphBigStackStaysInsideTheCanvas(t *testing.T) {
	var cs []store.HostContainer
	for i := 0; i < 14; i++ {
		cs = append(cs, store.HostContainer{HostID: "h1", ContainerID: fmt.Sprint("c", i), Name: fmt.Sprint("svc-", i), ServiceName: fmt.Sprint("service-with-a-very-long-name-", i),
			Image: "registry.example.com/team/some-image:1.2.3", Mounts: fmt.Sprint("vol-", i%3), Networks: "shared"})
	}
	g := buildStackGraph(stackGraphInput{Stack: store.Stack{ID: "big", Name: "big"}, Sources: []gSource{{Label: "Git source", Detail: "a/b @ main"}}, Containers: cs})
	checkLayout(t, g)
	for _, n := range g.Nodes {
		for _, l := range n.Lines {
			if len([]rune(l.Text)) > 26 {
				t.Errorf("text %q is too long for its node", l.Text)
			}
		}
	}
}

func TestStackGraphChips(t *testing.T) {
	scan := func(c store.HostContainer) *scanBadge {
		switch c.ContainerID {
		case "c1":
			return &scanBadge{Level: "clean", Label: "clean", Tooltip: "no finding"}
		case "c2":
			return &scanBadge{Level: "high", Label: "3 high", Tooltip: "3 high"}
		case "c3":
			return &scanBadge{Level: "critical", Label: "1 critical · 3 high", Tooltip: "worst"}
		}
		return nil
	}
	g := buildStackGraph(stackGraphInput{Stack: store.Stack{ID: "blog", Name: "blog"}, Sources: []gSource{{Label: "Git source", Detail: "a/b"}},
		Containers: blogContainers(), Scan: scan})
	checkLayout(t, g)
	if !g.HasScan {
		t.Error("the legend must explain the chip")
	}
	if c := findNode(t, g, "web").Chip; c == nil || c.Text != "clean" {
		t.Errorf("web chip = %+v", c)
	}
	if c := findNode(t, g, "app").Chip; c == nil || c.Text != "3 high" || c.Level != "high" {
		t.Errorf("a short label keeps its count: %+v", c)
	}
	db := findNode(t, g, "db")
	if db.Chip == nil || db.Chip.Text != "crit" || db.Chip.Tooltip != "worst" {
		t.Errorf("a long label falls back to the level: %+v", db.Chip)
	}
	if db.Chip.X < db.X || db.Chip.X+db.Chip.W > db.X+db.W {
		t.Errorf("the chip must sit inside its node: %+v in %d..%d", db.Chip, db.X, db.X+db.W)
	}

	g = buildStackGraph(stackGraphInput{Stack: store.Stack{ID: "blog", Name: "blog"}, Containers: blogContainers()})
	if g.HasScan || findNode(t, g, "web").Chip != nil {
		t.Error("with scanning off no chip is drawn")
	}
}

func TestChipForNoneLevels(t *testing.T) {
	for label, want := range map[string]string{
		"local image": "local", "update agent": "agent", "not scanned yet": "queued", "scan failed": "failed", "nothing detected": "none",
	} {
		if c := chipFor(&scanBadge{Level: "none", Label: label}, false); c == nil || c.Text != want {
			t.Errorf("%q -> %+v, want %q", label, c, want)
		}
	}
	if chipFor(nil, true) != nil {
		t.Error("no badge, no chip")
	}
}

func hostFixture() hostGraphInput {
	cs := []store.HostContainer{
		{HostID: "h1", ContainerID: "c1", Name: "web", State: "running", StackID: "blog", Networks: "blog_default", Mounts: "uploads"},
		{HostID: "h1", ContainerID: "c2", Name: "app", State: "running", StackID: "blog", Networks: "bridge,blog_default"},
		{HostID: "h1", ContainerID: "c3", Name: "db", State: "running", StackID: "blog", Networks: "blog_default", Mounts: "db-data"},
		{HostID: "h1", ContainerID: "c4", Name: "prometheus", State: "running", StackID: "metrics", Networks: "metrics"},
		{HostID: "h1", ContainerID: "c5", Name: "grafana", State: "running", StackID: "metrics", Networks: "metrics"},
		{HostID: "h1", ContainerID: "c6", Name: "cadvisor", State: "running", Networks: "metrics"},
		{HostID: "h1", ContainerID: "c7", Name: "portainer", State: "running", Networks: "bridge"},
		{HostID: "h1", ContainerID: "c8", Name: "tmp-test", State: "exited"},
	}
	return hostGraphInput{
		Host:       store.Host{ID: "h1", Name: "nas-01"},
		Containers: cs,
		Volumes:    []store.HostVolume{{HostID: "h1", Name: "uploads"}, {HostID: "h1", Name: "db-data"}, {HostID: "h1", Name: "junk1"}, {HostID: "h1", Name: "junk2"}},
		StackNames: map[string]string{"blog": "Blog", "metrics": "Metrics"},
	}
}

func stackNamed(t *testing.T, topo *topology, name string) topoStack {
	t.Helper()
	for _, s := range topo.Stacks {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no stack %q in %v", name, stackNames(topo))
	return topoStack{}
}

func stackNames(topo *topology) []string {
	var out []string
	for _, s := range topo.Stacks {
		out = append(out, s.Name)
	}
	return out
}

func rowNamed(t *testing.T, s topoStack, name string) topoRow {
	t.Helper()
	for _, r := range s.Rows {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no container %q in %s", name, s.Name)
	return topoRow{}
}

func labels(pills []topoPill) string {
	var out []string
	for _, p := range pills {
		out = append(out, p.Label)
	}
	return strings.Join(out, ",")
}

func TestHostTopologyGroupsByStack(t *testing.T) {
	in := hostFixture()
	in.Containers[0].Image = "nginx:1.27"
	in.Containers[1].Image = "ghcr.io/acme/blog:2.4@sha256:abc"
	topo := buildHostTopology(in)
	if topo == nil {
		t.Fatal("no topology")
	}
	if got := strings.Join(stackNames(topo), "|"); got != "Blog|Metrics|"+unmanagedGroup {
		t.Errorf("stacks = %q: managed ones by name, the rest last", got)
	}

	blog := stackNamed(t, topo, "Blog")
	if blog.Href != "/stacks/blog" || blog.Unmanaged || blog.Running != 3 || len(blog.Rows) != 3 {
		t.Errorf("blog = %+v", blog)
	}
	var names []string
	for _, r := range blog.Rows {
		names = append(names, r.Name)
	}
	if strings.Join(names, ",") != "app,db,web" {
		t.Errorf("containers are sorted by name: %v", names)
	}

	other := stackNamed(t, topo, unmanagedGroup)
	if other.Href != "" || !other.Unmanaged || len(other.Rows) != 3 || other.Running != 2 {
		t.Errorf("what Wharf does not manage has no page and is marked: %+v", other)
	}
	if tmp := rowNamed(t, other, "tmp-test"); tmp.Dot != "off" || len(tmp.Networks) != 0 || len(tmp.Volumes) != 0 {
		t.Errorf("a stopped container with nothing attached: %+v", tmp)
	}

	web := rowNamed(t, blog, "web")
	if web.Image != "nginx:1.27" || web.ImageTip != "nginx:1.27" || web.Href != "/containers/c1" || web.Dot != "ok" {
		t.Errorf("web = %+v", web)
	}
	if app := rowNamed(t, blog, "app"); app.Image != "blog:2.4" || app.ImageTip != "ghcr.io/acme/blog:2.4@sha256:abc" {
		t.Errorf("the image shows name and tag, the tooltip the whole reference: %+v", app)
	}
}

func TestHostTopologyNetworksAndTheirColours(t *testing.T) {
	topo := buildHostTopology(hostFixture())
	blog := stackNamed(t, topo, "Blog")
	app := rowNamed(t, blog, "app")
	if labels(app.Networks) != "blog_default,bridge" {
		t.Errorf("a container lists every network it is on: %q", labels(app.Networks))
	}
	if app.Networks[0].Class != "tp-n1" || app.Networks[1].Class != "tp-ng" {
		t.Errorf("custom networks take a colour, Docker's own are grey: %+v", app.Networks)
	}
	if rowNamed(t, blog, "web").Networks[0].Class != app.Networks[0].Class {
		t.Error("one network, one colour, wherever it appears")
	}
	if prom := rowNamed(t, stackNamed(t, topo, "Metrics"), "prometheus"); prom.Networks[0].Class != "tp-n2" || prom.Networks[0].Href != "/networks/h1/metrics" {
		t.Errorf("prometheus network = %+v", prom.Networks)
	}

	var legend []string
	for _, n := range topo.Networks {
		legend = append(legend, n.Label+"="+n.Note)
	}
	want := []string{
		"blog_default=internal to Blog",
		"metrics=shared by Metrics, " + unmanagedGroup,
		"bridge=Docker's default network",
	}
	if strings.Join(legend, "|") != strings.Join(want, "|") {
		t.Errorf("legend = %q, want %q", legend, want)
	}
}

// A frontend on the proxy's network and on its stack's backend network, a
// backend on the backend network only: each container is one row, and the
// legend says which network links which stacks.
func TestHostTopologyShowsWhatLinksTwoStacks(t *testing.T) {
	topo := buildHostTopology(hostGraphInput{
		Host: store.Host{ID: "h1"},
		Containers: []store.HostContainer{
			{HostID: "h1", ContainerID: "c1", Name: "shop-frontend-1", StackID: "shop", Networks: "traefik_frontend,shop_backend", Mounts: "shop_assets"},
			{HostID: "h1", ContainerID: "c2", Name: "shop-backend-1", StackID: "shop", Networks: "shop_backend", Mounts: "shop_assets"},
			{HostID: "h1", ContainerID: "c3", Name: "traefik", StackID: "edge", Networks: "traefik_frontend"},
		},
		StackNames: map[string]string{"shop": "Shop", "edge": "Edge"},
	})
	shop := stackNamed(t, topo, "Shop")
	if len(shop.Rows) != 2 || len(stackNamed(t, topo, "Edge").Rows) != 1 {
		t.Fatalf("each container is drawn once: %+v", topo.Stacks)
	}
	front, back := rowNamed(t, shop, "shop-frontend-1"), rowNamed(t, shop, "shop-backend-1")
	if labels(front.Networks) != "shop_backend,traefik_frontend" || labels(back.Networks) != "shop_backend" {
		t.Errorf("networks: frontend %q, backend %q", labels(front.Networks), labels(back.Networks))
	}
	if front.Networks[1].Class != rowNamed(t, stackNamed(t, topo, "Edge"), "traefik").Networks[0].Class {
		t.Error("the frontend and the proxy share the colour of their common network")
	}
	var legend []string
	for _, n := range topo.Networks {
		legend = append(legend, n.Label+"="+n.Note)
	}
	if got := strings.Join(legend, "|"); got != "shop_backend=internal to Shop|traefik_frontend=shared by Edge, Shop" {
		t.Errorf("legend = %q", got)
	}
}

func TestHostTopologyVolumes(t *testing.T) {
	topo := buildHostTopology(hostFixture())
	web := rowNamed(t, stackNamed(t, topo, "Blog"), "web")
	if len(web.Volumes) != 1 || web.Volumes[0].Label != "uploads" || web.Volumes[0].Href != "/volumes/h1/uploads" ||
		!strings.Contains(web.Volumes[0].Tip, "used by web") {
		t.Errorf("a volume links to its page and says who uses it: %+v", web.Volumes)
	}
	if topo.Unused != 2 {
		t.Errorf("unused = %d, want 2", topo.Unused)
	}

	in := hostFixture()
	for i := range in.Containers {
		in.Containers[i].Mounts = ""
	}
	in.Volumes = nil
	if topo := buildHostTopology(in); topo.Unused != 0 {
		t.Errorf("no volume, nothing unused: %d", topo.Unused)
	}
}

func TestHostTopologyKeepsEveryContainerAndFullNames(t *testing.T) {
	var cs []store.HostContainer
	for i := 0; i < 40; i++ {
		cs = append(cs, store.HostContainer{HostID: "h1", ContainerID: fmt.Sprint("b", i), Name: fmt.Sprintf("container-with-a-long-name-%02d", i), State: "running", Networks: "bridge"})
	}
	topo := buildHostTopology(hostGraphInput{Host: store.Host{ID: "h1"}, Containers: cs})
	if len(topo.Stacks) != 1 || len(topo.Stacks[0].Rows) != 40 || topo.Stacks[0].Running != 40 {
		t.Fatalf("every container is drawn, none dropped: %+v", topo.Stacks)
	}
	if topo.Stacks[0].Rows[0].Name != "container-with-a-long-name-00" {
		t.Errorf("full names are kept, the browser truncates them: %q", topo.Stacks[0].Rows[0].Name)
	}
}

func TestHostTopologyAStackWharfNoLongerKnowsIsNotManaged(t *testing.T) {
	topo := buildHostTopology(hostGraphInput{
		Host:       store.Host{ID: "h1"},
		Containers: []store.HostContainer{{HostID: "h1", ContainerID: "c1", Name: "ghost", StackID: "deleted-stack", Networks: "x"}},
		StackNames: map[string]string{"blog": "Blog"},
	})
	if len(topo.Stacks) != 1 || !topo.Stacks[0].Unmanaged {
		t.Errorf("a container of a deleted stack is not managed: %+v", topo.Stacks)
	}
}

func TestHostTopologyNothingToDrawWithoutContainers(t *testing.T) {
	if topo := buildHostTopology(hostGraphInput{Host: store.Host{ID: "h1"}}); topo != nil {
		t.Errorf("an empty host has no topology: %+v", topo)
	}
}

func TestHostTopologyVulnerabilities(t *testing.T) {
	in := hostFixture()
	in.Scan = func(c store.HostContainer) *scanBadge {
		switch c.ContainerID {
		case "c1":
			return &scanBadge{Level: "clean", Label: "clean", Tooltip: "no finding"}
		case "c2":
			return &scanBadge{Level: "high", Label: "3 high", Tooltip: "3 high"}
		case "c3":
			return &scanBadge{Level: "critical", Label: "1 critical · 3 high", Tooltip: "worst"}
		case "c4":
			return &scanBadge{Level: "clean", Label: "clean"}
		case "c5":
			return &scanBadge{Level: "none", Label: "local image", Tooltip: "no digest"}
		}
		return nil
	}
	topo := buildHostTopology(in)
	blog := stackNamed(t, topo, "Blog")
	if c := rowNamed(t, blog, "app").Chip; c == nil || c.Text != "3 high" || c.Level != "high" {
		t.Errorf("a short label keeps its count: %+v", c)
	}
	if c := rowNamed(t, blog, "db").Chip; c == nil || c.Text != "crit" || c.Tooltip != "worst" {
		t.Errorf("a long label falls back to the level: %+v", c)
	}
	if blog.Worst == nil || blog.Worst.Level != "critical" {
		t.Errorf("a stack carries its worst vulnerability: %+v", blog.Worst)
	}
	metrics := stackNamed(t, topo, "Metrics")
	if metrics.Worst == nil || metrics.Worst.Text != "local" {
		t.Errorf("an image that could not be scanned must not make a stack look clean: %+v", metrics.Worst)
	}
	if other := stackNamed(t, topo, unmanagedGroup); other.Worst != nil || rowNamed(t, other, "cadvisor").Chip != nil {
		t.Error("nothing known, nothing drawn")
	}
	if !topo.HasScan {
		t.Error("the legend explains the chips")
	}

	in.Scan = nil
	if off := buildHostTopology(in); off.HasScan || stackNamed(t, off, "Blog").Worst != nil || rowNamed(t, stackNamed(t, off, "Blog"), "web").Chip != nil {
		t.Error("with scanning off no chip is drawn")
	}
}

func TestSpreadStepSqueezes(t *testing.T) {
	if spreadStep(1, 40) != 6 || spreadStep(3, 40) != 6 {
		t.Error("a few edges keep the usual gap")
	}
	if got := spreadStep(10, 40); got != 3 || spread(100, 0, 10, got)-100 < -20 {
		t.Errorf("ten edges must stay inside a 40px node: step %d", got)
	}
	if spreadStep(100, 40) < 1 {
		t.Error("the gap never reaches zero")
	}
}

func TestHelpers(t *testing.T) {
	for in, want := range map[string]string{
		"git@github.com:acme/blog.git":     "acme/blog",
		"https://github.com/acme/blog.git": "acme/blog",
		"https://git.example.com/a/b/c/d":  "c/d",
		"blog":                             "blog",
	} {
		if got := shortRepo(in); got != want {
			t.Errorf("shortRepo(%q) = %q, want %q", in, got, want)
		}
	}
	if got := truncate("abcdefghijkl", 8); got != "abcdefg…" {
		t.Errorf("truncate = %q", got)
	}
	if got := truncate("héllo", 5); got != "héllo" {
		t.Errorf("truncate must count characters, not bytes: %q", got)
	}
	if got := splitList(" b, a ,,c"); strings.Join(got, "") != "abc" {
		t.Errorf("splitList = %v", got)
	}
}

func get(h http.HandlerFunc, target string, path map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", target, nil)
	for k, v := range path {
		req.SetPathValue(k, v)
	}
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

// graphPagesFixture is a host with a local stack running two containers and an
// unmanaged one.
func graphPagesFixture(t *testing.T) (*vulnFixture, store.Host) {
	t.Helper()
	f := newVulnFixture(t)
	f.a.tunnels = newTunnelRegistry()
	st := f.a.store
	h, _, _ := st.UpsertHostByFingerprint("nas-01", "sha256:1")
	st.SetHostArch(h.ID, "amd64")
	st.SetHostAgentVersion(h.ID, "0.6.1")
	if err := st.CreateStack(store.Stack{ID: "shop", Name: "shop", SourceType: "local", Host: h.ID, Trigger: "manual", ComposeContent: "services: {}"}); err != nil {
		t.Fatal(err)
	}
	st.ReplaceHostImages(h.ID, []store.HostImage{{HostID: h.ID, ImageID: "aaaaaaaaaaaa", Repository: "nginx", Tag: "1.27", Digest: digestOf("a")}})
	st.ReplaceHostContainers(h.ID, []store.HostContainer{
		{HostID: h.ID, ContainerID: "c1", Name: "shop-web-1", ServiceName: "web", Image: "nginx:1.27", ImageID: "aaaaaaaaaaaa", State: "running", Status: "Up", StackID: "shop", Mounts: "shop_data", Networks: "shop_default"},
		{HostID: h.ID, ContainerID: "c2", Name: "shop-db-1", ServiceName: "db", Image: "postgres:16", State: "running", Status: "Up", StackID: "shop", Networks: "shop_default"},
		{HostID: h.ID, ContainerID: "c3", Name: "portainer", Image: "portainer/portainer-ce", State: "running", Status: "Up", Networks: "bridge"},
	})
	st.ReplaceHostVolumes(h.ID, []store.HostVolume{{HostID: h.ID, Name: "shop_data"}, {HostID: h.ID, Name: "old"}})
	return f, h
}

func TestStackPageDrawsItsTopology(t *testing.T) {
	f, h := graphPagesFixture(t)
	w := get(f.a.stackViewHandler, "/stacks/shop", map[string]string{"id": "shop"})
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "Topology") || !strings.Contains(body, `<svg class="graph"`) {
		t.Fatalf("stack page: %d\n%.600s", w.Code, body)
	}
	for _, want := range []string{`href="/containers/c1"`, `href="/volumes/` + h.ID + `/shop_data"`, `href="/networks/` + h.ID + `/shop_default"`, "gedge-volume", "gedge-network", "nginx:1.27"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(body, "portainer") {
		t.Error("another stack's, or an unmanaged, container is not part of this stack's graph")
	}

	// a chip appears once scanning knows the image
	f.a.store.UpsertImageScan(store.ImageScan{Scanner: "trivy", Digest: digestOf("a"), Platform: "linux/amd64", Status: "ok", High: 2})
	body = get(f.a.stackViewHandler, "/stacks/shop", map[string]string{"id": "shop"}).Body.String()
	if !strings.Contains(body, "gchip-high") || !strings.Contains(body, "Chip: worst vulnerability") {
		t.Error("the scanned image must show its chip")
	}

	// no container, no panel
	f.a.store.ReplaceHostContainers(h.ID, nil)
	if body := get(f.a.stackViewHandler, "/stacks/shop", map[string]string{"id": "shop"}).Body.String(); strings.Contains(body, "Topology") {
		t.Error("a stack that runs nothing has no topology")
	}
}

func TestHostPageDrawsItsTopology(t *testing.T) {
	f, h := graphPagesFixture(t)
	w := get(f.a.hostViewHandler, "/hosts/"+h.ID, map[string]string{"id": h.ID})
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "Topology") {
		t.Fatalf("host page: %d\n%.600s", w.Code, body)
	}
	for _, want := range []string{`href="/stacks/shop"`, "tp-table", ">shop_default</a>", ">bridge</a>", "internal to shop", "Docker&#39;s default network", "Not managed by Wharf", "1 volume(s) not used by any container", ">shop_data</a>"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}

	f.a.store.ReplaceHostContainers(h.ID, nil)
	if body := get(f.a.hostViewHandler, "/hosts/"+h.ID, map[string]string{"id": h.ID}).Body.String(); strings.Contains(body, "Topology") {
		t.Error("an empty host has no topology")
	}
}

func TestGraphEscapesWhatContainersSay(t *testing.T) {
	f, h := graphPagesFixture(t)
	f.a.store.ReplaceHostContainers(h.ID, []store.HostContainer{
		{HostID: h.ID, ContainerID: "c9", Name: `<script>alert(1)</script>`, Image: `x"onload="y`, State: "running", Networks: `evil"><script>`},
	})
	body := get(f.a.hostViewHandler, "/hosts/"+h.ID, map[string]string{"id": h.ID}).Body.String()
	if strings.Contains(body, "<script>alert(1)") || strings.Contains(body, `evil"><script>`) {
		t.Error("container data must be escaped in the SVG")
	}
}

func TestPlural(t *testing.T) {
	for n, want := range map[int]string{0: "0 services", 1: "1 service", 2: "2 services"} {
		if got := plural(n, "service"); got != want {
			t.Errorf("plural(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestBindMountsAreNotVolumes(t *testing.T) {
	mounts := `app_data,/opt/app/config,/run/desktop/mnt/host/d/Dev,be6e839d655ea0b653dd58a8180f,C:\Users\x`
	if got := volumeList(mounts); strings.Join(got, "|") != "app_data|be6e839d655ea0b653dd58a8180f" {
		t.Errorf("volumeList = %v", got)
	}

	cs := []store.HostContainer{{HostID: "h1", ContainerID: "c1", Name: "app", Mounts: mounts, Networks: "bridge"}}
	st := buildStackGraph(stackGraphInput{Stack: store.Stack{ID: "app", Name: "app"}, Sources: []gSource{{Label: "x", Detail: "y"}}, Containers: cs})
	if got := kinds(st, "volume"); got != 2 {
		t.Errorf("stack graph volumes = %d, want 2", got)
	}
	host := buildHostTopology(hostGraphInput{Host: store.Host{ID: "h1"}, Containers: cs, StackNames: map[string]string{}})
	if got := labels(host.Stacks[0].Rows[0].Volumes); got != "app_data,be6e839d655ea0b653dd58a8180f" {
		t.Errorf("host topology volumes = %q", got)
	}
}
