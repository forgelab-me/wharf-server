// Topology graphs: the stack page and the host page each draw their
// containers, volumes and networks as an SVG. The layout is computed here, in
// plain Go, so it can be tested; layout.html's "graph" template only draws
// what this file placed.
package main

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/forgelab-me/wharf-server/internal/store"
)

type graph struct {
	W, H    int
	Headers []gLine
	Regions []gRegion
	Edges   []gEdge
	Nodes   []gNode
	Legend  []gLegend
	HasScan bool // a vulnerability chip is drawn: the legend explains it
}

type gLine struct {
	Text, Class string
	X, Y        int
}

type gRegion struct {
	X, Y, W, H int
	Label      string
	Href       string
	LX, LY     int
}

type gEdge struct{ D, Kind string } // Kind: flow | volume | network

type gChip struct {
	Text, Level string
	X, Y, W, H  int
	TX, TY      int
	Tooltip     string
}

type gNode struct {
	Kind       string // source | stack | container | volume | network
	Class      string
	X, Y, W, H int
	Href, Tip  string
	Lines      []gLine
	Dot        string // ok | warn | off
	DX, DY     int
	Chip       *gChip
}

type gLegend struct{ Key, Label string }

const (
	gCanvasW = 680
	gTop     = 30

	gSrcX, gSrcW     = 0, 168
	gStackX, gStackW = 204, 110
	gCtrX, gCtrW     = 350, 160
	gResX, gResW     = 540, 140

	gSrcH, gSrcPitch = 50, 62
	gStackH          = 84
	gCtrH, gCtrPitch = 52, 66
	gResH, gResPitch = 40, 52
)

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n < 2 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

// shortImage keeps the name and tag of an image reference, dropping the
// registry, the path and any digest: "ghcr.io/acme/blog:2.4" -> "blog:2.4".
func shortImage(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		ref = ref[i+1:]
	}
	return ref
}

// shortRepo reduces a Git remote to its last two path segments.
func shortRepo(repo string) string {
	repo = strings.TrimSuffix(strings.TrimSpace(repo), ".git")
	repo = strings.ReplaceAll(repo, ":", "/")
	parts := strings.Split(strings.TrimRight(repo, "/"), "/")
	if len(parts) > 2 {
		parts = parts[len(parts)-2:]
	}
	return strings.Join(parts, "/")
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

var volumeName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

// volumeList keeps the Docker volumes of a container's mounts: docker ps also
// lists bind mounts there, as paths, and those are not volumes.
func volumeList(mounts string) []string {
	var out []string
	for _, m := range splitList(mounts) {
		if volumeName.MatchString(m) {
			out = append(out, m)
		}
	}
	return out
}

func dotFor(state string) string {
	switch state {
	case "running":
		return "ok"
	case "restarting", "paused":
		return "warn"
	}
	return "off"
}

var chipCompact = map[string]string{
	"critical": "crit", "high": "high", "medium": "med", "clean": "clean",
	"local image": "local", "update agent": "agent", "not scanned yet": "queued",
	"scan failed": "failed", "nothing detected": "none",
}

// chipFor sizes a vulnerability chip; withCount keeps the badge's own label
// ("3 high") when it is short enough.
func chipFor(b *scanBadge, withCount bool) *gChip {
	if b == nil {
		return nil
	}
	text := b.Label
	if !(withCount && len(text) <= 16 && b.Level != "none" && b.Level != "clean") {
		text = chipCompact[b.Level]
		if b.Level == "none" {
			text = chipCompact[b.Label]
		}
		if text == "" {
			text = truncate(b.Label, 10)
		}
	}
	w := len([]rune(text))*6 + 14
	if w < 36 {
		w = 36
	}
	return &gChip{Text: text, Level: b.Level, W: w, H: 16, Tooltip: b.Tooltip}
}

func (c *gChip) place(x, y int) {
	c.X, c.Y = x, y
	c.TX, c.TY = x+c.W/2, y+12
}

// spread offsets the i-th of n edges that meet at the same side of a node, so
// they do not overlap.
func spread(center, i, n, step int) int {
	return center + (2*i-(n-1))*step/2
}

// spreadStep is the gap between edges meeting at one side of a node of height
// h: 6, squeezed when there are too many to fit.
func spreadStep(n, h int) int {
	step := 6
	if n > 1 && (h-12)/(n-1) < step {
		step = (h - 12) / (n - 1)
	}
	if step < 1 {
		step = 1
	}
	return step
}

func curve(x1, y1, x2, y2 int) string {
	xm := (x1 + x2) / 2
	return fmt.Sprintf("M%d %d C%d %d %d %d %d %d", x1, y1, xm, y1, xm, y2, x2, y2)
}

func colHeight(n, h, pitch int) int {
	if n == 0 {
		return 0
	}
	return n*pitch - (pitch - h)
}

type gSource struct {
	Label, Detail, Href string
}

type stackGraphInput struct {
	Stack      store.Stack
	Host       string // label of the target host
	Status     string // "deployed", "failed"... empty when never deployed
	Sources    []gSource
	Containers []store.HostContainer
	Scan       func(store.HostContainer) *scanBadge
}

// buildStackGraph lays a stack out left to right: what feeds it, the stack,
// its containers, then the volumes and networks those containers use.
func buildStackGraph(in stackGraphInput) *graph {
	if len(in.Containers) == 0 {
		return nil
	}
	cs := append([]store.HostContainer(nil), in.Containers...)
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].ServiceName != cs[j].ServiceName {
			return cs[i].ServiceName < cs[j].ServiceName
		}
		return cs[i].Name < cs[j].Name
	})

	type resource struct{ name, kind string }
	var resources []resource
	index := map[string]int{}
	add := func(kind, name string) int {
		key := kind + "|" + name
		if i, ok := index[key]; ok {
			return i
		}
		index[key] = len(resources)
		resources = append(resources, resource{name, kind})
		return index[key]
	}
	// volumes first, then networks, each alphabetical
	var vols, nets []string
	seenV, seenN := map[string]bool{}, map[string]bool{}
	for _, c := range cs {
		for _, v := range volumeList(c.Mounts) {
			if !seenV[v] {
				seenV[v] = true
				vols = append(vols, v)
			}
		}
		for _, n := range splitList(c.Networks) {
			if !seenN[n] {
				seenN[n] = true
				nets = append(nets, n)
			}
		}
	}
	sort.Strings(vols)
	sort.Strings(nets)
	for _, v := range vols {
		add("volume", v)
	}
	for _, n := range nets {
		add("network", n)
	}

	contentH := gStackH
	for _, h := range []int{colHeight(len(cs), gCtrH, gCtrPitch), colHeight(len(resources), gResH, gResPitch), colHeight(len(in.Sources), gSrcH, gSrcPitch)} {
		if h > contentH {
			contentH = h
		}
	}
	top := func(colH int) int { return gTop + (contentH-colH)/2 }

	g := &graph{W: gCanvasW, H: gTop + contentH + 8}
	g.Headers = append(g.Headers, gLine{Text: "Stack", Class: "ghead", X: gStackX, Y: 14}, gLine{Text: "Containers", Class: "ghead", X: gCtrX, Y: 14})
	if len(in.Sources) > 0 {
		g.Headers = append(g.Headers, gLine{Text: "Sources", Class: "ghead", X: gSrcX, Y: 14})
	}
	if len(resources) > 0 {
		g.Headers = append(g.Headers, gLine{Text: "Volumes and networks", Class: "ghead", X: gResX, Y: 14})
	}

	// the stack
	stackY := gTop + (contentH-gStackH)/2
	stackCY := stackY + gStackH/2
	statusClass := "gsub gcenter"
	switch in.Status {
	case "deployed":
		statusClass += " gok"
	case "failed":
		statusClass += " gbad"
	}
	status := in.Status
	if status == "" {
		status = "not deployed"
	}
	stack := gNode{Kind: "stack", X: gStackX, Y: stackY, W: gStackW, H: gStackH,
		Tip: in.Stack.Name + " on " + in.Host,
		Lines: []gLine{
			{Text: truncate(in.Stack.Name, 14), Class: "gtitle gbig gcenter", X: gStackX + gStackW/2, Y: stackY + 32},
			{Text: status, Class: statusClass, X: gStackX + gStackW/2, Y: stackY + 52},
			{Text: truncate(in.Host, 16), Class: "gsub gcenter", X: gStackX + gStackW/2, Y: stackY + 70},
		}}

	// sources
	srcTop := top(colHeight(len(in.Sources), gSrcH, gSrcPitch))
	for i, s := range in.Sources {
		y := srcTop + i*gSrcPitch
		n := gNode{Kind: "source", X: gSrcX, Y: y, W: gSrcW, H: gSrcH, Href: s.Href, Tip: s.Label + ": " + s.Detail,
			Lines: []gLine{
				{Text: truncate(s.Label, 26), Class: "gsub", X: gSrcX + 12, Y: y + 20},
				{Text: truncate(s.Detail, 24), Class: "gtitle", X: gSrcX + 12, Y: y + 38},
			}}
		g.Nodes = append(g.Nodes, n)
		g.Edges = append(g.Edges, gEdge{Kind: "flow", D: curve(gSrcX+gSrcW, y+gSrcH/2, gStackX, spread(stackCY, i, len(in.Sources), spreadStep(len(in.Sources), gStackH)))})
	}
	g.Nodes = append(g.Nodes, stack)

	// containers, resources, and the links between them
	ctrTop := top(colHeight(len(cs), gCtrH, gCtrPitch))
	resTop := top(colHeight(len(resources), gResH, gResPitch))

	type link struct{ c, r int }
	var links []link
	outDeg := make([]int, len(cs))
	inDeg := make([]int, len(resources))
	for i, c := range cs {
		for _, v := range volumeList(c.Mounts) {
			links = append(links, link{i, index["volume|"+v]})
		}
		for _, n := range splitList(c.Networks) {
			links = append(links, link{i, index["network|"+n]})
		}
	}
	for _, l := range links {
		outDeg[l.c]++
		inDeg[l.r]++
	}
	stackStep := spreadStep(len(cs), gStackH)
	for i, c := range cs {
		y := ctrTop + i*gCtrPitch
		name := c.ServiceName
		if name == "" {
			name = c.Name
		}
		var chip *gChip
		if in.Scan != nil {
			chip = chipFor(in.Scan(c), true)
		}
		titleMax := 20
		if chip != nil {
			chip.place(gCtrX+gCtrW-chip.W-8, y+8)
			titleMax = 11
			g.HasScan = true
		}
		n := gNode{Kind: "container", X: gCtrX, Y: y, W: gCtrW, H: gCtrH, Href: "/containers/" + c.ContainerID,
			Tip: fmt.Sprintf("%s — %s — %s", c.Name, c.Image, c.Status),
			Lines: []gLine{
				{Text: truncate(name, titleMax), Class: "gtitle", X: gCtrX + 26, Y: y + 20},
				{Text: truncate(shortImage(c.Image), 22), Class: "gsub gmono", X: gCtrX + 14, Y: y + 40},
			},
			Dot: dotFor(c.State), DX: gCtrX + 14, DY: y + 16, Chip: chip}
		g.Nodes = append(g.Nodes, n)
		g.Edges = append(g.Edges, gEdge{Kind: "flow", D: curve(gStackX+gStackW, spread(stackCY, i, len(cs), stackStep), gCtrX, y+gCtrH/2)})
	}
	nextOut := make([]int, len(cs))
	nextIn := make([]int, len(resources))
	for _, l := range links {
		cy := ctrTop + l.c*gCtrPitch + gCtrH/2
		ry := resTop + l.r*gResPitch + gResH/2
		g.Edges = append(g.Edges, gEdge{
			Kind: resources[l.r].kind,
			D:    curve(gCtrX+gCtrW, spread(cy, nextOut[l.c], outDeg[l.c], spreadStep(outDeg[l.c], gCtrH)), gResX, spread(ry, nextIn[l.r], inDeg[l.r], spreadStep(inDeg[l.r], gResH))),
		})
		nextOut[l.c]++
		nextIn[l.r]++
	}
	hostID := cs[0].HostID
	for i, r := range resources {
		y := resTop + i*gResPitch
		shown := r.name
		if prefix := in.Stack.ID + "_"; strings.HasPrefix(shown, prefix) && len(shown) > len(prefix) {
			shown = shown[len(prefix):]
		}
		href := "/volumes/" + hostID + "/" + url.PathEscape(r.name)
		if r.kind == "network" {
			href = "/networks/" + hostID + "/" + url.PathEscape(r.name)
		}
		g.Nodes = append(g.Nodes, gNode{Kind: r.kind, X: gResX, Y: y, W: gResW, H: gResH, Href: href, Tip: r.kind + " " + r.name,
			Lines: []gLine{
				{Text: truncate(shown, 18), Class: "gtitle", X: gResX + 12, Y: y + 18},
				{Text: r.kind, Class: "gsub", X: gResX + 12, Y: y + 33},
			}})
	}

	g.Legend = append(g.Legend, gLegend{"ef", "deploys"})
	if len(vols) > 0 {
		g.Legend = append(g.Legend, gLegend{"ev", "mounts a volume"})
	}
	if len(nets) > 0 {
		g.Legend = append(g.Legend, gLegend{"en", "joins a network"})
	}
	return g
}
