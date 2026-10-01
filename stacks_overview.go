package main

import (
	"fmt"
	"sort"

	"github.com/forgelab-me/wharf-server/internal/store"
)

// stackRow is one line of the stacks list, with the cards of its containers
// shown when it is unfolded. The live figures are not here: the page fetches
// them (cf. stackstats.go).
type stackRow struct {
	ID, Name, Host, Trigger string
	LastStatus              string // the last deployment's status, shown as a tooltip
	StateClass, StateLabel  string
	Running, Total          int
	Worst                   *gChip // the worst vulnerability among its containers
	Cards                   []stackCard
}

type stackCard struct {
	ID, Name, Service string
	Image, ImageTip   string
	Dot               string
	Active            bool // running: it has live figures
	Chip              *gChip
	Ports             []portLink
	Volumes           int
}

// stackState words a stack's state from its last deployment and the containers
// it has now.
func stackState(lastStatus string, running, total int) (class, label string) {
	counts := ""
	if total > 0 {
		counts = fmt.Sprintf("%d/%d", running, total)
	}
	switch {
	case lastStatus == "queued" || lastStatus == "running":
		return "warn", "deploying"
	case lastStatus == "failed":
		if counts != "" {
			return "bad", "failed · " + counts
		}
		return "bad", "failed"
	case total == 0 && lastStatus == "":
		return "muted", "never deployed"
	case total == 0:
		return "muted", "not running"
	case running == total:
		return "ok", "running " + counts
	case running == 0:
		return "muted", "stopped " + counts
	}
	return "warn", "partial " + counts
}

// buildStackRows prepares the stacks list. byStack holds each stack's
// containers (from the agents' last snapshots); scan may be nil.
func buildStackRows(stacks []store.Stack, byStack map[string][]store.HostContainer, lastStatus map[string]string,
	hostLabel func(hostID string) string, hostAddress func(hostID string) string, scan func(store.HostContainer) *scanBadge) []stackRow {
	rows := make([]stackRow, 0, len(stacks))
	for _, s := range stacks {
		row := stackRow{ID: s.ID, Name: s.Name, Host: hostLabel(s.Host), Trigger: s.Trigger, LastStatus: lastStatus[s.ID]}
		cs := append([]store.HostContainer(nil), byStack[s.ID]...)
		sort.Slice(cs, func(i, j int) bool {
			if cs[i].ServiceName != cs[j].ServiceName {
				return cs[i].ServiceName < cs[j].ServiceName
			}
			return cs[i].Name < cs[j].Name
		})
		var badges []*scanBadge
		for _, c := range cs {
			card := stackCard{ID: c.ContainerID, Name: c.Name, Service: c.ServiceName, Image: shortImage(c.Image), ImageTip: c.Image,
				Dot: dotFor(c.State), Active: c.State == "running", Ports: parsePorts(c.Ports, hostAddress(c.HostID)),
				Volumes: len(volumeList(c.Mounts))}
			if c.State == "running" {
				row.Running++
			}
			if scan != nil {
				if b := scan(c); b != nil {
					card.Chip = chipFor(b, true)
					badges = append(badges, b)
				}
			}
			row.Cards = append(row.Cards, card)
		}
		row.Total = len(cs)
		row.Worst = chipFor(worstOf(badges), true)
		row.StateClass, row.StateLabel = stackState(row.LastStatus, row.Running, row.Total)
		rows = append(rows, row)
	}
	return rows
}

// worstOf picks the badge to worry about most; nil when there is none.
func worstOf(badges []*scanBadge) *scanBadge {
	var worst *scanBadge
	for _, b := range badges {
		if worst == nil || scanRank(b.Level) > scanRank(worst.Level) {
			worst = b
		}
	}
	return worst
}

// stackRows gathers what the list needs from the store.
func (a *app) stackRows() ([]stackRow, error) {
	stacks, err := a.store.ListStacks()
	if err != nil {
		return nil, err
	}
	byStack := map[string][]store.HostContainer{}
	if all, err := a.store.ListHostContainers(); err == nil {
		for _, c := range all {
			if c.StackID != "" {
				byStack[c.StackID] = append(byStack[c.StackID], c)
			}
		}
	}
	addresses := map[string]string{}
	if hosts, err := a.store.ListHosts(); err == nil {
		for _, h := range hosts {
			addresses[h.ID] = h.Address
		}
	}
	last := map[string]string{}
	for _, s := range stacks {
		if dep, ok, err := a.store.LatestDeploymentForStack(s.ID); err == nil && ok {
			last[s.ID] = dep.Status
		}
	}
	return buildStackRows(stacks, byStack, last, a.hostLabel, func(id string) string { return addresses[id] }, a.scanChips()), nil
}
