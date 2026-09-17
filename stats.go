// CPU/RAM/disk stats -- on demand over the tunnel's existing command
// channel (cf. ARCHITECTURE.md, "Stats CPU/mémoire, enfin"), not a new
// continuously-sampled stream: a page open in a browser polls this
// endpoint itself and draws its own rolling chart client-side, with
// zero cost anywhere while nobody's looking.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// dockerStatsLine matches one line of `docker stats --format {{json .}}`.
type dockerStatsLine struct {
	Container string `json:"Container"`
	Name      string `json:"Name"`
	CPUPerc   string `json:"CPUPerc"`
	MemUsage  string `json:"MemUsage"`
	MemPerc   string `json:"MemPerc"`
	NetIO     string `json:"NetIO"`   // "rx / tx"
	BlockIO   string `json:"BlockIO"` // "read / write"
}

// dockerInfoLine matches the fields this package actually reads from
// `docker info --format {{json .}}` -- the two host-wide facts available
// without mounting /proc: total memory and CPU count, both already known
// to the daemon itself.
type dockerInfoLine struct {
	MemTotal int64 `json:"MemTotal"`
	NCPU     int   `json:"NCPU"`
}

// dockerDFLine matches one line of `docker system df --format {{json .}}`
// -- one row per resource type (Images, Containers, Local Volumes,
// Build Cache).
type dockerDFLine struct {
	Type        string `json:"Type"`
	TotalCount  string `json:"TotalCount"`
	Active      string `json:"Active"`
	Size        string `json:"Size"`
	Reclaimable string `json:"Reclaimable"`
}

var percentRe = regexp.MustCompile(`^([\d.]+)%?$`)

// parsePercent turns docker's "12.34%" into 12.34; a value it can't
// parse (never expected from docker's own output, but a stopped/
// restarting container can print "--" here) becomes 0 rather than
// failing the whole request over one cosmetic field.
func parsePercent(s string) float64 {
	m := percentRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0
	}
	return v
}

var byteSizeRe = regexp.MustCompile(`^([\d.]+)\s*([a-zA-Z]*)$`)

// parseHumanBytes turns docker's own human-readable sizes ("10.5MiB",
// "512MB", "1B", "0B") into a raw byte count. Docker's own formatter
// (go-units) is 1024-based regardless of whether it labels the unit
// "MB" or "MiB", so both spellings map to the same multiplier here --
// deliberately not trying to distinguish SI from IEC, since the source
// never actually does.
func parseHumanBytes(s string) float64 {
	m := byteSizeRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0
	}
	// "MiB" -> "M", "MB" -> "M", "B"/"" -> "" (raw bytes, default case
	// below) -- TrimSuffix only once (on "B") left "Mi"/"Gi"/"Ki"/"Ti"
	// unstripped for docker's actual IEC-style output ("14.69MiB"),
	// silently falling through to "treat as raw bytes" and undercounting
	// every non-trivial size by ~1000x. Caught by testing: a host
	// reporting gigabytes of real container memory usage summed to a
	// four-digit byte count.
	unit := strings.ToUpper(m[2])
	unit = strings.TrimSuffix(unit, "IB")
	unit = strings.TrimSuffix(unit, "B")
	switch unit {
	case "K":
		return v * 1024
	case "M":
		return v * 1024 * 1024
	case "G":
		return v * 1024 * 1024 * 1024
	case "T":
		return v * 1024 * 1024 * 1024 * 1024
	default:
		return v
	}
}

// parseDockerStatsLines parses newline-delimited `docker stats --format
// {{json .}}` output -- one JSON object per line, no enclosing array.
func parseDockerStatsLines(raw string) []dockerStatsLine {
	var out []dockerStatsLine
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var l dockerStatsLine
		if err := json.Unmarshal([]byte(line), &l); err == nil {
			out = append(out, l)
		}
	}
	return out
}

func parseDockerDFLines(raw string) []dockerDFLine {
	var out []dockerDFLine
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var l dockerDFLine
		if err := json.Unmarshal([]byte(line), &l); err == nil {
			out = append(out, l)
		}
	}
	return out
}

// parseDockerInfo parses the one-line `docker info --format {{json .}}`
// output. Zero value (rather than an error) on a parse failure: MemTotal
// display just reads "0 B" for the one field this package actually
// depends on, harmless enough not to fail the whole stats request over.
func parseDockerInfo(raw string) dockerInfoLine {
	var l dockerInfoLine
	json.Unmarshal([]byte(strings.TrimSpace(raw)), &l)
	return l
}

// parsePairSum splits docker's "X / Y" pair fields (NetIO, BlockIO) and
// sums the left and right sides separately across every line -- e.g.
// every container's own rx total, added up into one host-wide rx total.
func parsePairSum(lines []dockerStatsLine, field func(dockerStatsLine) string) (left, right float64) {
	for _, l := range lines {
		a, b, _ := strings.Cut(field(l), " / ")
		left += parseHumanBytes(a)
		right += parseHumanBytes(b)
	}
	return left, right
}

// writeStatsJSON is the shared response path for both stats endpoints --
// plain JSON, not rendered through a template, since it's polled every
// few seconds by client-side JS and never navigated to directly.
func writeStatsJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// containerStatsHandler serves GET /containers/{id}/stats -- one
// snapshot of CPU/mem for a single container, polled by the container
// detail page's live chart. Same "not available right now" fallback as
// logs/inspect if the host's agent isn't connected, just as JSON instead
// of a template placeholder.
func (a *app) containerStatsHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, err := a.store.GetHostContainerByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	tc, ok := a.tunnels.get(c.HostID)
	if !ok {
		http.Error(w, "host not connected", http.StatusServiceUnavailable)
		return
	}
	result, err := tc.sendCommand(r.Context(), "stats", c.ContainerID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusGatewayTimeout)
		return
	}
	if !result.OK {
		http.Error(w, result.Output, http.StatusInternalServerError)
		return
	}
	lines := parseDockerStatsLines(result.Output)
	if len(lines) == 0 {
		http.Error(w, "no stats returned", http.StatusInternalServerError)
		return
	}
	writeStatsJSON(w, map[string]any{
		"cpuPercent": parsePercent(lines[0].CPUPerc),
		"memPercent": parsePercent(lines[0].MemPerc),
		"memUsage":   lines[0].MemUsage,
	})
}

// hostStatsHandler serves GET /hosts/{id}/stats -- CPU/mem/network/IO
// summed across every container currently on the host (cf. package
// comment: this is "every container", not the whole machine, the agent
// has no visibility beyond docker.sock) plus Docker's own disk footprint
// from `docker system df`, plus the two real host-wide facts `docker
// info` hands out without needing /proc: total memory and CPU count --
// found missing when a real memory figure was compared side by side
// against the container page's own "used / limit" display and there was
// no "/ limit" half to compare it to at all. Polled by the host detail
// page's live charts.
func (a *app) hostStatsHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := a.store.GetHost(id); err != nil {
		http.NotFound(w, r)
		return
	}
	tc, ok := a.tunnels.get(id)
	if !ok {
		http.Error(w, "host not connected", http.StatusServiceUnavailable)
		return
	}
	result, err := tc.sendCommand(r.Context(), "host_stats", "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusGatewayTimeout)
		return
	}
	if !result.OK {
		http.Error(w, result.Output, http.StatusInternalServerError)
		return
	}
	statsPart, rest, _ := strings.Cut(result.Output, "\n---df---\n")
	dfPart, infoPart, _ := strings.Cut(rest, "\n---info---\n")

	containers := parseDockerStatsLines(statsPart)
	var cpuSum, memUsedSum float64
	for _, c := range containers {
		cpuSum += parsePercent(c.CPUPerc)
		used, _, _ := strings.Cut(c.MemUsage, " / ")
		memUsedSum += parseHumanBytes(used)
	}
	netRx, netTx := parsePairSum(containers, func(l dockerStatsLine) string { return l.NetIO })
	blockRead, blockWrite := parsePairSum(containers, func(l dockerStatsLine) string { return l.BlockIO })

	var disk []map[string]string
	for _, d := range parseDockerDFLines(dfPart) {
		disk = append(disk, map[string]string{
			"type": d.Type, "size": d.Size, "reclaimable": d.Reclaimable, "count": d.TotalCount,
		})
	}

	info := parseDockerInfo(infoPart)
	memUsedMiB := memUsedSum / 1024 / 1024
	memTotalMiB := float64(info.MemTotal) / 1024 / 1024
	var memPercentOfHost float64
	if memTotalMiB > 0 {
		memPercentOfHost = memUsedMiB / memTotalMiB * 100
	}

	writeStatsJSON(w, map[string]any{
		"cpuPercent":       cpuSum,
		"cpuCores":         info.NCPU,
		"memUsedBytes":     memUsedSum,
		"memUsedMiB":       memUsedMiB, // chart-friendly scale -- raw bytes would need its own axis formatter
		"memTotalMiB":      memTotalMiB,
		"memPercentOfHost": memPercentOfHost,
		"memUsedDisplay":   fmt.Sprintf("%.1f MiB", memUsedMiB),
		"memTotalDisplay":  fmt.Sprintf("%.1f GiB", memTotalMiB/1024),
		"netRxMiB":         netRx / 1024 / 1024,
		"netTxMiB":         netTx / 1024 / 1024,
		"blockReadMiB":     blockRead / 1024 / 1024,
		"blockWriteMiB":    blockWrite / 1024 / 1024,
		"containerCount":   len(containers),
		"disk":             disk,
	})
}
