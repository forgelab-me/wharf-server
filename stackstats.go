// Live figures for the stacks list: CPU, memory, network and disk of every
// container of every stack Wharf manages, measured with one agent command per
// host and cached for a few seconds so that however many pages are open the
// hosts are measured once. Nothing is stored: the page keeps its own rolling
// window (cf. ARCHITECTURE.md, "Aperçu en direct sur la liste des stacks").
package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/forgelab-me/wharf-server/internal/store"
)

// minAgentForStatsMany is the first agent that understands "stats_many".
const minAgentForStatsMany = "0.7.0"

const (
	statsCacheTTL    = 3 * time.Second
	statsHostTimeout = 8 * time.Second
)

// States of one stack's figures.
const (
	statsOK           = "ok"
	statsDisconnected = "disconnected"
	statsOldAgent     = "old_agent"
	statsError        = "error"
)

var errHostDisconnected = errors.New("host not connected")

// containerStat is one container's figures. Network and disk are totals since
// the container started, as docker reports them: the page turns two successive
// readings into a rate.
type containerStat struct {
	CPU        float64 `json:"cpu"` // percent of one core, docker's own figure
	MemBytes   float64 `json:"memBytes"`
	MemPercent float64 `json:"memPercent"`
	NetRx      float64 `json:"netRx"`
	NetTx      float64 `json:"netTx"`
	BlkRead    float64 `json:"blkRead"`
	BlkWrite   float64 `json:"blkWrite"`
}

func (c *containerStat) add(o containerStat) {
	c.CPU += o.CPU
	c.MemBytes += o.MemBytes
	c.NetRx += o.NetRx
	c.NetTx += o.NetTx
	c.BlkRead += o.BlkRead
	c.BlkWrite += o.BlkWrite
}

type stackStat struct {
	State      string                   `json:"state"`
	Message    string                   `json:"message,omitempty"`
	Totals     containerStat            `json:"totals"`
	Containers map[string]containerStat `json:"containers"` // by container id
}

type stackStatsResponse struct {
	At     int64                `json:"at"` // unix milliseconds of the measure
	Stacks map[string]stackStat `json:"stacks"`
}

// rawStatLine is one line of an agent's "stats_many" answer: sizes in exact
// bytes (cf. the agent's rawStat; `docker stats` rounds to three digits, which
// leaves no usable rate over a few seconds).
type rawStatLine struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	CPU      float64 `json:"cpu"` // percent of one core
	MemUsage float64 `json:"mem_usage"`
	MemLimit float64 `json:"mem_limit"`
	NetRx    float64 `json:"net_rx"`
	NetTx    float64 `json:"net_tx"`
	BlkRead  float64 `json:"blk_read"`
	BlkWrite float64 `json:"blk_write"`
}

// parseRawStats reads the answer, skipping any line that is not JSON.
func parseRawStats(raw string) []rawStatLine {
	var out []rawStatLine
	for _, line := range strings.Split(raw, "\n") {
		var l rawStatLine
		if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &l); err == nil && (l.ID != "" || l.Name != "") {
			out = append(out, l)
		}
	}
	return out
}

func statFromLine(l rawStatLine) containerStat {
	st := containerStat{CPU: l.CPU, MemBytes: l.MemUsage, NetRx: l.NetRx, NetTx: l.NetTx, BlkRead: l.BlkRead, BlkWrite: l.BlkWrite}
	if l.MemLimit > 0 {
		st.MemPercent = l.MemUsage / l.MemLimit * 100
	}
	return st
}

// hostMeasure is what one host answered.
type hostMeasure struct {
	Lines   []rawStatLine
	State   string // statsOK unless the host could not be measured
	Message string
}

// lineFor finds the line of a container. The engine answers with the full id;
// the docker CLI, which the agent falls back to, prints a short one.
func lineFor(c store.HostContainer, lines []rawStatLine) (rawStatLine, bool) {
	for _, l := range lines {
		// an empty id is a prefix of everything: it must not match
		if l.ID != "" && (strings.HasPrefix(c.ContainerID, l.ID) || strings.HasPrefix(l.ID, c.ContainerID)) {
			return l, true
		}
		if l.Name != "" && l.Name == c.Name {
			return l, true
		}
	}
	return rawStatLine{}, false
}

// buildStackStats puts each host's lines back under the stacks they belong to.
// A stack with no container is left out; a container that is not running has no
// figures and is left out of its stack's.
func buildStackStats(stacks []store.Stack, containers []store.HostContainer, measures map[string]hostMeasure) map[string]stackStat {
	managed := map[string]bool{}
	for _, s := range stacks {
		managed[s.ID] = true
	}
	out := map[string]stackStat{}
	for _, c := range containers {
		if !managed[c.StackID] {
			continue
		}
		st, ok := out[c.StackID]
		if !ok {
			st = stackStat{State: statsOK, Containers: map[string]containerStat{}}
		}
		m, measured := measures[c.HostID]
		switch {
		case !measured || m.State == "":
			// nothing was asked of this host: nothing is running there
		case m.State != statsOK:
			st.State, st.Message = m.State, m.Message
		default:
			if l, found := lineFor(c, m.Lines); found && c.State == "running" {
				cs := statFromLine(l)
				st.Containers[c.ContainerID] = cs
				st.Totals.add(cs)
			}
		}
		out[c.StackID] = st
	}
	for id, st := range out {
		if st.State != statsOK {
			st.Containers = map[string]containerStat{}
			st.Totals = containerStat{}
			out[id] = st
		}
	}
	return out
}

// agentTooOldForStats: an agent that never reported a version predates version
// reporting altogether; a non-release build ("dev") is let through.
func agentTooOldForStats(agentVersion string) bool {
	return agentVersion == "" || semverLess(agentVersion, minAgentForStatsMany)
}

// statsCollector measures the managed stacks' containers, at most once per
// statsCacheTTL however many callers there are.
type statsCollector struct {
	a     *app
	fetch func(ctx context.Context, hostID string, ids []string) (string, error)
	now   func() time.Time

	mu    sync.Mutex
	at    time.Time
	last  stackStatsResponse
	valid bool
}

func newStatsCollector(a *app) *statsCollector {
	return &statsCollector{a: a, fetch: a.fetchStats, now: time.Now}
}

// fetchStats asks one host's agent to measure containers.
func (a *app) fetchStats(ctx context.Context, hostID string, ids []string) (string, error) {
	tc, ok := a.tunnels.get(hostID)
	if !ok {
		return "", errHostDisconnected
	}
	res, err := tc.send(ctx, tunnelMessage{Action: "stats_many", ContainerIDs: ids})
	if err != nil {
		return "", err
	}
	if !res.OK {
		return "", errors.New(strings.TrimSpace(res.Output))
	}
	return res.Output, nil
}

func (a *app) statsCollector() *statsCollector {
	a.statsOnce.Do(func() {
		if a.statsC == nil {
			a.statsC = newStatsCollector(a)
		}
	})
	return a.statsC
}

// get returns the last measure if it is recent enough, else measures again.
// The lock is held while measuring, so callers that arrive meanwhile wait for
// that one measure instead of starting their own.
func (c *statsCollector) get() stackStatsResponse {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.valid && c.now().Sub(c.at) < statsCacheTTL {
		return c.last
	}
	c.last = c.collect()
	c.at = c.now()
	c.valid = true
	return c.last
}

func (c *statsCollector) collect() stackStatsResponse {
	resp := stackStatsResponse{Stacks: map[string]stackStat{}}
	resp.At = c.now().UnixMilli()
	stacks, err := c.a.store.ListStacks()
	if err != nil {
		return resp
	}
	containers, err := c.a.store.ListHostContainers()
	if err != nil {
		return resp
	}
	managed := map[string]bool{}
	for _, s := range stacks {
		managed[s.ID] = true
	}
	running := map[string][]string{} // host -> ids of the running containers of managed stacks
	hosts := map[string]bool{}
	for _, ct := range containers {
		if !managed[ct.StackID] {
			continue
		}
		hosts[ct.HostID] = true
		if ct.State == "running" {
			running[ct.HostID] = append(running[ct.HostID], ct.ContainerID)
		}
	}

	measures := map[string]hostMeasure{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for hostID := range hosts {
		hostID := hostID
		ids := running[hostID]
		sort.Strings(ids)
		if h, err := c.a.store.GetHost(hostID); err == nil && agentTooOldForStats(h.AgentVersion) {
			measures[hostID] = hostMeasure{State: statsOldAgent, Message: "update the agent to " + minAgentForStatsMany + " or later for live figures"}
			continue
		}
		if len(ids) == 0 {
			measures[hostID] = hostMeasure{State: statsOK}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), statsHostTimeout)
			defer cancel()
			m := hostMeasure{State: statsOK}
			out, err := c.fetch(ctx, hostID, ids)
			switch {
			case errors.Is(err, errHostDisconnected):
				m = hostMeasure{State: statsDisconnected, Message: "this host is not connected"}
			case err != nil:
				m = hostMeasure{State: statsError, Message: err.Error()}
			default:
				m.Lines = parseRawStats(out)
			}
			mu.Lock()
			measures[hostID] = m
			mu.Unlock()
		}()
	}
	wg.Wait()
	// stamped when the figures came back, not when they were asked for: the
	// counters are read about then, and the page divides by the time between two
	resp.At = c.now().UnixMilli()
	resp.Stacks = buildStackStats(stacks, containers, measures)
	return resp
}

// stackStatsHandler serves GET /stats/stacks, polled by the stacks list. (Not
// /stacks/stats: a stack can be named "stats".)
func (a *app) stackStatsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeStatsJSON(w, a.statsCollector().get())
}
