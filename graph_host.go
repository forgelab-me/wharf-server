// The host page's topology: its containers grouped by stack, each with its
// image, vulnerabilities, networks and volumes. Plain HTML laid out by CSS, so
// it follows the width of the window.
package main

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/forgelab-me/wharf-server/internal/store"
)

type hostGraphInput struct {
	Host       store.Host
	Containers []store.HostContainer // this host's only
	Volumes    []store.HostVolume
	StackNames map[string]string // id -> name of the stacks Wharf knows
	Scan       func(store.HostContainer) *scanBadge
}

type topology struct {
	Stacks   []topoStack
	Networks []topoNet // what the colours of the network pills mean
	Unused   int       // volumes no container mounts
	HasScan  bool      // a vulnerability chip is drawn
}

type topoStack struct {
	Name, Href string
	Unmanaged  bool // not deployed by a stack Wharf knows
	Running    int
	Worst      *gChip // the worst vulnerability among its containers
	Rows       []topoRow
}

type topoRow struct {
	Name, Href, Tip string
	Image, ImageTip string
	Dot             string
	Chip            *gChip
	Networks        []topoPill
	Volumes         []topoPill
}

type topoPill struct {
	Label, Href, Tip, Class string
}

type topoNet struct {
	Label, Href, Class, Note string
}

const (
	unmanagedGroup = "Not managed by Wharf"
	topoNetColors  = 6
)

func builtinNetwork(name string) bool {
	return name == "bridge" || name == "host" || name == "none"
}

var builtinNote = map[string]string{
	"bridge": "Docker's default network",
	"host":   "the host's own network",
	"none":   "no network access",
}

// scanRank orders badges from the one to worry about most; a container that
// could not be scanned ranks above a clean one so that a stack never looks
// cleaner than what is known of it.
func scanRank(level string) int {
	switch level {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "none":
		return 2
	case "clean":
		return 1
	}
	return 0
}

// buildHostTopology groups a host's containers by stack, then lists, for each,
// what it runs and what it is connected to.
func buildHostTopology(in hostGraphInput) *topology {
	if len(in.Containers) == 0 {
		return nil
	}
	t := &topology{}

	// network colours: Docker's own networks are grey, the others take a colour
	// each in alphabetical order
	netClass := map[string]string{}
	var custom []string
	for _, c := range in.Containers {
		for _, n := range splitList(c.Networks) {
			if _, ok := netClass[n]; ok {
				continue
			}
			netClass[n] = "tp-ng"
			if !builtinNetwork(n) {
				custom = append(custom, n)
			}
		}
	}
	sort.Strings(custom)
	for i, n := range custom {
		netClass[n] = fmt.Sprintf("tp-n%d", i%topoNetColors+1)
	}

	usedBy := map[string][]string{} // volume -> container names
	for _, c := range in.Containers {
		for _, v := range volumeList(c.Mounts) {
			usedBy[v] = append(usedBy[v], c.Name)
		}
	}

	groups := map[string][]store.HostContainer{}
	for _, c := range in.Containers {
		group := unmanagedGroup
		if name, ok := in.StackNames[c.StackID]; ok && c.StackID != "" {
			group = name
		}
		groups[group] = append(groups[group], c)
	}
	names := make([]string, 0, len(groups))
	for g := range groups {
		names = append(names, g)
	}
	sort.Slice(names, func(i, j int) bool {
		ui, uj := names[i] == unmanagedGroup, names[j] == unmanagedGroup
		if ui != uj {
			return !ui
		}
		return names[i] < names[j]
	})
	stackIDOf := map[string]string{}
	for id, name := range in.StackNames {
		stackIDOf[name] = id
	}

	netGroups := map[string]map[string]bool{} // network -> groups on it
	for _, g := range names {
		list := groups[g]
		sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
		stack := topoStack{Name: g, Unmanaged: g == unmanagedGroup}
		if !stack.Unmanaged {
			stack.Href = "/stacks/" + stackIDOf[g]
		}
		var worst *scanBadge
		for _, c := range list {
			row := topoRow{Name: c.Name, Href: "/containers/" + c.ContainerID, Dot: dotFor(c.State),
				Image: shortImage(c.Image), ImageTip: c.Image,
				Tip: fmt.Sprintf("%s — %s — %s", c.Name, c.Image, c.Status)}
			if c.State == "running" {
				stack.Running++
			}
			if in.Scan != nil {
				if b := in.Scan(c); b != nil {
					row.Chip = chipFor(b, true)
					t.HasScan = true
					if worst == nil || scanRank(b.Level) > scanRank(worst.Level) {
						worst = b
					}
				}
			}
			for _, n := range splitList(c.Networks) {
				row.Networks = append(row.Networks, topoPill{Label: n, Class: netClass[n],
					Href: "/networks/" + in.Host.ID + "/" + url.PathEscape(n), Tip: "network " + n})
				if netGroups[n] == nil {
					netGroups[n] = map[string]bool{}
				}
				netGroups[n][g] = true
			}
			for _, v := range volumeList(c.Mounts) {
				row.Volumes = append(row.Volumes, topoPill{Label: v, Href: "/volumes/" + in.Host.ID + "/" + url.PathEscape(v),
					Tip: "volume " + v + " — used by " + strings.Join(usedBy[v], ", ")})
			}
			stack.Rows = append(stack.Rows, row)
		}
		stack.Worst = chipFor(worst, true)
		t.Stacks = append(t.Stacks, stack)
	}

	// legend: every network drawn, and who is on it
	nets := make([]string, 0, len(netGroups))
	for n := range netGroups {
		nets = append(nets, n)
	}
	sort.Slice(nets, func(i, j int) bool {
		bi, bj := builtinNetwork(nets[i]), builtinNetwork(nets[j])
		if bi != bj {
			return !bi
		}
		return nets[i] < nets[j]
	})
	for _, n := range nets {
		var who []string
		for g := range netGroups[n] {
			who = append(who, g)
		}
		sort.Strings(who)
		note := builtinNote[n]
		switch {
		case note != "":
		case len(who) > 1:
			note = "shared by " + strings.Join(who, ", ")
		case who[0] == unmanagedGroup:
			note = "only used by containers Wharf does not manage"
		default:
			note = "internal to " + who[0]
		}
		t.Networks = append(t.Networks, topoNet{Label: n, Class: netClass[n], Note: note, Href: "/networks/" + in.Host.ID + "/" + url.PathEscape(n)})
	}

	for _, v := range in.Volumes {
		if _, ok := usedBy[v.Name]; !ok {
			t.Unused++
		}
	}
	return t
}
