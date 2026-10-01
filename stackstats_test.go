package main

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/forgelab-me/wharf-server/internal/store"
)

var testUnits = map[string]float64{"": 1, "b": 1, "kb": 1e3, "mb": 1e6, "gb": 1e9, "kib": 1 << 10, "mib": 1 << 20, "gib": 1 << 30}

// testBytes reads "100MiB" or "1kB": the tests are written in the units docker
// prints, the agent now answers in exact bytes.
func testBytes(s string) float64 {
	s = strings.TrimSpace(s)
	i := strings.IndexFunc(s, func(r rune) bool { return (r < '0' || r > '9') && r != '.' })
	if i < 0 {
		i = len(s)
	}
	v, _ := strconv.ParseFloat(s[:i], 64)
	return v * testUnits[strings.ToLower(strings.TrimSpace(s[i:]))]
}

// dockerLine builds one line of a "stats_many" answer from docker's own units.
func dockerLine(id, name, cpu, mem, net, blk string) string {
	pair := func(s string) (float64, float64) {
		a, b, _ := strings.Cut(s, " / ")
		return testBytes(a), testBytes(b)
	}
	c, _ := strconv.ParseFloat(strings.TrimSuffix(cpu, "%"), 64)
	used, limit := pair(mem)
	rx, tx := pair(net)
	rd, wr := pair(blk)
	raw, _ := json.Marshal(rawStatLine{ID: id, Name: name, CPU: c, MemUsage: used, MemLimit: limit, NetRx: rx, NetTx: tx, BlkRead: rd, BlkWrite: wr})
	return string(raw)
}

func TestBuildStackStats(t *testing.T) {
	stacks := []store.Stack{{ID: "blog"}, {ID: "shop"}}
	containers := []store.HostContainer{
		{HostID: "h1", ContainerID: "aaaaaaaaaaaa1111", Name: "blog-web-1", StackID: "blog", State: "running"},
		{HostID: "h1", ContainerID: "bbbbbbbbbbbb2222", Name: "blog-db-1", StackID: "blog", State: "running"},
		{HostID: "h1", ContainerID: "cccccccccccc3333", Name: "blog-old-1", StackID: "blog", State: "exited"},
		{HostID: "h1", ContainerID: "dddddddddddd4444", Name: "portainer", StackID: "", State: "running"},
		{HostID: "h2", ContainerID: "eeeeeeeeeeee5555", Name: "shop-app-1", StackID: "shop", State: "running"},
		{HostID: "h1", ContainerID: "ffffffffffff6666", Name: "external-1", StackID: "not-managed", State: "running"},
	}
	lines := strings.Join([]string{
		dockerLine("aaaaaaaaaaaa", "blog-web-1", "1.50%", "100MiB / 8GiB", "1kB / 2kB", "0B / 1MB"),
		dockerLine("bbbbbbbbbbbb", "blog-db-1", "2.50%", "200MiB / 8GiB", "3kB / 4kB", "2MB / 3MB"),
		dockerLine("dddddddddddd", "portainer", "9.00%", "1GiB / 8GiB", "0B / 0B", "0B / 0B"),
	}, "\n")
	got := buildStackStats(stacks, containers, map[string]hostMeasure{
		"h1": {State: statsOK, Lines: parseRawStats(lines)},
		"h2": {State: statsDisconnected, Message: "this host is not connected"},
	})

	blog := got["blog"]
	if blog.State != statsOK || len(blog.Containers) != 2 {
		t.Fatalf("blog = %+v", blog)
	}
	if blog.Totals.CPU != 4 || blog.Totals.MemBytes != 300*1048576 || blog.Totals.NetRx != 4000 || blog.Totals.NetTx != 6000 ||
		blog.Totals.BlkRead != 2e6 || blog.Totals.BlkWrite != 4e6 {
		t.Errorf("a stack's figures are the sum of its containers': %+v", blog.Totals)
	}
	if _, ok := blog.Containers["cccccccccccc3333"]; ok {
		t.Error("a stopped container has no figures")
	}
	if c := blog.Containers["aaaaaaaaaaaa1111"]; c.CPU != 1.5 || c.MemBytes != 100*1048576 {
		t.Errorf("a container is matched to its line by the id docker prints: %+v", c)
	}

	if _, ok := got["not-managed"]; ok {
		t.Error("only the stacks Wharf manages are measured")
	}
	shop := got["shop"]
	if shop.State != statsDisconnected || shop.Message == "" || len(shop.Containers) != 0 || shop.Totals.CPU != 0 {
		t.Errorf("a host that could not be measured gives a state, no figures: %+v", shop)
	}
}

func TestBuildStackStatsMatchesByNameWhenTheIDIsNotThere(t *testing.T) {
	got := buildStackStats([]store.Stack{{ID: "s"}},
		[]store.HostContainer{{HostID: "h", ContainerID: "1234567890abcdef", Name: "s-web-1", StackID: "s", State: "running"}},
		map[string]hostMeasure{"h": {State: statsOK, Lines: parseRawStats(dockerLine("", "s-web-1", "3%", "1MiB / 2GiB", "0B / 0B", "0B / 0B"))}})
	if got["s"].Totals.CPU != 3 {
		t.Errorf("%+v", got["s"])
	}
}

func TestBuildStackStatsStackWithNothingRunning(t *testing.T) {
	got := buildStackStats([]store.Stack{{ID: "s"}},
		[]store.HostContainer{{HostID: "h", ContainerID: "1234567890ab", Name: "s-web-1", StackID: "s", State: "exited"}},
		map[string]hostMeasure{"h": {State: statsOK}})
	if st, ok := got["s"]; !ok || st.State != statsOK || len(st.Containers) != 0 {
		t.Errorf("a stack with nothing running is ok and empty, not an error: %+v", got)
	}
}

func TestAgentTooOldForStats(t *testing.T) {
	for v, want := range map[string]bool{"": true, "0.6.1": true, "0.6.9": true, "0.7.0": false, "0.7.1": false, "0.10.0": false, "dev": false} {
		if got := agentTooOldForStats(v); got != want {
			t.Errorf("agentTooOldForStats(%q) = %v, want %v", v, got, want)
		}
	}
}

// statsFixture is a host with a stack of two running containers and an
// unmanaged one, measured by a fake agent.
type statsFixture struct {
	f      *vulnFixture
	hostID string

	mu    sync.Mutex
	now   time.Time
	calls int
	ids   [][]string
	reply func(hostID string) (string, error)
	gate  chan struct{} // when set, a measure waits for it
}

func newStatsFixture(t *testing.T) *statsFixture {
	t.Helper()
	f := newVulnFixture(t)
	s := &statsFixture{f: f, now: time.Unix(1000, 0)}
	st := f.a.store
	h, _, _ := st.UpsertHostByFingerprint("nas", "sha256:1")
	s.hostID = h.ID
	st.SetHostAgentVersion(h.ID, "0.7.0")
	if err := st.CreateStack(store.Stack{ID: "blog", Name: "blog", SourceType: "local", Host: h.ID, Trigger: "manual", ComposeContent: "services: {}"}); err != nil {
		t.Fatal(err)
	}
	st.ReplaceHostContainers(h.ID, []store.HostContainer{
		{HostID: h.ID, ContainerID: "aaaaaaaaaaaa1111", Name: "blog-web-1", StackID: "blog", State: "running"},
		{HostID: h.ID, ContainerID: "bbbbbbbbbbbb2222", Name: "blog-db-1", StackID: "blog", State: "running"},
		{HostID: h.ID, ContainerID: "cccccccccccc3333", Name: "blog-old-1", StackID: "blog", State: "exited"},
		{HostID: h.ID, ContainerID: "dddddddddddd4444", Name: "portainer", State: "running"},
	})
	s.reply = func(string) (string, error) {
		return dockerLine("aaaaaaaaaaaa", "blog-web-1", "1%", "10MiB / 1GiB", "1kB / 1kB", "0B / 0B") + "\n" +
			dockerLine("bbbbbbbbbbbb", "blog-db-1", "2%", "20MiB / 1GiB", "1kB / 1kB", "0B / 0B"), nil
	}
	f.a.statsC = &statsCollector{
		a: f.a,
		now: func() time.Time {
			s.mu.Lock()
			defer s.mu.Unlock()
			return s.now
		},
		fetch: func(_ context.Context, hostID string, ids []string) (string, error) {
			s.mu.Lock()
			s.calls++
			s.ids = append(s.ids, ids)
			gate, reply := s.gate, s.reply
			s.mu.Unlock()
			if gate != nil {
				<-gate
			}
			return reply(hostID)
		},
	}
	return s
}

func (s *statsFixture) advance(d time.Duration) {
	s.mu.Lock()
	s.now = s.now.Add(d)
	s.mu.Unlock()
}

func (s *statsFixture) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func TestCollectorMeasuresOnlyTheRunningContainersOfManagedStacks(t *testing.T) {
	s := newStatsFixture(t)
	resp := s.f.a.statsCollector().get()

	if s.callCount() != 1 {
		t.Fatalf("one command per host, got %d", s.callCount())
	}
	if got := strings.Join(s.ids[0], ","); got != "aaaaaaaaaaaa1111,bbbbbbbbbbbb2222" {
		t.Errorf("asked for %q: neither the stopped container nor the unmanaged one", got)
	}
	blog := resp.Stacks["blog"]
	if blog.State != statsOK || blog.Totals.CPU != 3 || len(blog.Containers) != 2 {
		t.Errorf("blog = %+v", blog)
	}
	if resp.At != 1000*1000 {
		t.Errorf("at = %d", resp.At)
	}
}

func TestCollectorCachesForAFewSeconds(t *testing.T) {
	s := newStatsFixture(t)
	c := s.f.a.statsCollector()
	c.get()
	s.advance(statsCacheTTL - time.Millisecond)
	c.get()
	if s.callCount() != 1 {
		t.Fatalf("a recent measure is reused: %d commands", s.callCount())
	}
	s.advance(2 * time.Millisecond)
	c.get()
	if s.callCount() != 2 {
		t.Errorf("an old one is measured again: %d commands", s.callCount())
	}
}

func TestCollectorSharesOneMeasureBetweenSimultaneousCallers(t *testing.T) {
	s := newStatsFixture(t)
	s.gate = make(chan struct{})
	c := s.f.a.statsCollector()

	var wg sync.WaitGroup
	results := make([]stackStatsResponse, 10)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = c.get()
		}(i)
	}
	time.Sleep(50 * time.Millisecond) // everyone is waiting behind the first caller
	close(s.gate)
	wg.Wait()

	if s.callCount() != 1 {
		t.Errorf("ten pages open, one measure: %d commands", s.callCount())
	}
	for i, r := range results {
		if r.Stacks["blog"].Totals.CPU != 3 {
			t.Errorf("caller %d got %+v", i, r.Stacks["blog"])
		}
	}
}

func TestCollectorHostStates(t *testing.T) {
	s := newStatsFixture(t)
	c := s.f.a.statsCollector()

	s.reply = func(string) (string, error) { return "", errHostDisconnected }
	if st := c.get().Stacks["blog"]; st.State != statsDisconnected || len(st.Containers) != 0 {
		t.Errorf("disconnected: %+v", st)
	}

	s.advance(time.Minute)
	s.reply = func(string) (string, error) { return "", errors.New("docker said no") }
	if st := c.get().Stacks["blog"]; st.State != statsError || !strings.Contains(st.Message, "docker said no") {
		t.Errorf("error: %+v", st)
	}

	s.advance(time.Minute)
	s.reply = func(string) (string, error) {
		return dockerLine("aaaaaaaaaaaa", "blog-web-1", "1%", "1MiB / 1GiB", "0B / 0B", "0B / 0B"), nil
	}
	if st := c.get().Stacks["blog"]; st.State != statsOK || len(st.Containers) != 1 {
		t.Errorf("the next measure recovers: %+v", st)
	}

	// an agent that does not know the command is not even asked
	s.f.a.store.SetHostAgentVersion(s.hostID, "0.6.1")
	s.advance(time.Minute)
	before := s.callCount()
	if st := c.get().Stacks["blog"]; st.State != statsOldAgent || !strings.Contains(st.Message, "0.7.0") {
		t.Errorf("old agent: %+v", st)
	}
	if s.callCount() != before {
		t.Error("an old agent must not be sent a command it does not understand")
	}
}

func TestCollectorAStackWithNothingRunningCostsNoCommand(t *testing.T) {
	s := newStatsFixture(t)
	s.f.a.store.ReplaceHostContainers(s.hostID, []store.HostContainer{
		{HostID: s.hostID, ContainerID: "cccccccccccc3333", Name: "blog-old-1", StackID: "blog", State: "exited"},
	})
	resp := s.f.a.statsCollector().get()
	if s.callCount() != 0 {
		t.Errorf("nothing to measure: %d commands", s.callCount())
	}
	if st := resp.Stacks["blog"]; st.State != statsOK || len(st.Containers) != 0 {
		t.Errorf("blog = %+v", st)
	}
}

func TestStackStatsHandler(t *testing.T) {
	s := newStatsFixture(t)
	w := get(s.f.a.stackStatsHandler, "/stats/stacks", nil)
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	var body struct {
		At     int64 `json:"at"`
		Stacks map[string]struct {
			State      string                    `json:"state"`
			Totals     map[string]float64        `json:"totals"`
			Containers map[string]map[string]any `json:"containers"`
		} `json:"stacks"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	blog := body.Stacks["blog"]
	if blog.State != "ok" || blog.Totals["cpu"] != 3 || blog.Totals["memBytes"] != 30*1048576 || len(blog.Containers) != 2 {
		t.Errorf("blog = %+v", blog)
	}
	if _, ok := blog.Containers["aaaaaaaaaaaa1111"]["netRx"]; !ok {
		t.Error("each container carries its totals, keyed by its id")
	}
}

func TestLineForNeverMatchesOnAnEmptyID(t *testing.T) {
	c := store.HostContainer{ContainerID: "aaaaaaaaaaaa1111", Name: "web"}
	if _, ok := lineFor(c, []rawStatLine{{ID: "", Name: "another"}}); ok {
		t.Error("an empty id is a prefix of every id: it must not match")
	}
	if _, ok := lineFor(c, []rawStatLine{{ID: "aaaaaaaaaaaa"}}); !ok {
		t.Error("the CLI's short id matches")
	}
	if _, ok := lineFor(c, []rawStatLine{{ID: "aaaaaaaaaaaa1111ffff"}}); !ok {
		t.Error("a longer id the other way round matches too")
	}
	if _, ok := lineFor(c, []rawStatLine{{ID: "bbbbbbbbbbbb"}}); ok {
		t.Error("another container")
	}
}

func TestMeasureIsStampedWhenTheFiguresCameBack(t *testing.T) {
	s := newStatsFixture(t)
	slow := s.reply
	s.reply = func(host string) (string, error) {
		s.advance(2 * time.Second) // a slow engine: the counters are read some time after the question
		return slow(host)
	}
	if got := s.f.a.statsCollector().get().At; got != 1000*1000+2000 {
		t.Errorf("at = %d, want the time the figures came back (%d)", got, 1000*1000+2000)
	}
}
