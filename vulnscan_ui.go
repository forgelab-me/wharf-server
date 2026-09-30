package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/forgelab-me/wharf-server/internal/scanner"
	"github.com/forgelab-me/wharf-server/internal/store"
)

// minAgentForImageDigests is the first agent that reports image digests, and
// so the first whose containers can be scanned.
const minAgentForImageDigests = "0.6.0"

// scanBadge is the compact vulnerability summary shown next to an image.
type scanBadge struct {
	Level   string // critical | high | medium | clean | none
	Label   string
	Tooltip string
	Link    string // the findings page, empty when there is nothing to open
}

func badgeFromScan(sc store.ImageScan, scannerLabel string) *scanBadge {
	if sc.Status != "ok" {
		return &scanBadge{Level: "none", Label: "scan failed", Tooltip: sc.Error}
	}
	var parts []string
	add := func(n int, name string) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, name))
		}
	}
	add(sc.Critical, "critical")
	add(sc.High, "high")
	if len(parts) == 0 {
		add(sc.Medium, "medium")
		add(sc.Low, "low")
		add(sc.Unknown, "unknown")
	}
	label, level := "clean", "clean"
	if sc.Critical+sc.High+sc.Medium+sc.Low+sc.Unknown == 0 && sc.Notice != "" {
		return &scanBadge{Level: "none", Label: "nothing detected", Tooltip: sc.Notice,
			Link: "/scans/" + sc.Digest + "?platform=" + sc.Platform}
	}
	switch {
	case sc.Critical > 0:
		level = "critical"
	case sc.High > 0:
		level = "high"
	case sc.Medium+sc.Low+sc.Unknown > 0:
		level = "medium"
	}
	if len(parts) > 0 {
		label = strings.Join(parts, " · ")
	}
	tooltip := fmt.Sprintf("Critical %d (%d fixable) · High %d (%d fixable) · Medium %d · Low %d · Unknown %d — %s, scanned %s",
		sc.Critical, sc.FixableCritical, sc.High, sc.FixableHigh, sc.Medium, sc.Low, sc.Unknown, scannerLabel, sc.ScannedAt)
	if sc.DBBuiltAt != "" {
		tooltip += ", database built " + sc.DBBuiltAt
	}
	return &scanBadge{Level: level, Label: label, Tooltip: tooltip,
		Link: "/scans/" + sc.Digest + "?platform=" + sc.Platform}
}

// scanIndex answers "what did the scanner find for this image" for the pages
// that show badges; a nil index (scanning off) answers nothing.
type scanIndex struct {
	label      string
	scans      map[string]store.ImageScan // digest|platform
	digestOf   map[string]string          // host|image id -> registry digest
	inUse      map[string]bool            // host|image id run by a container
	platformOf map[string]string          // host id -> platform
	oldAgent   map[string]bool            // host id -> agent too old to report digests
}

func (a *app) newScanIndex() *scanIndex {
	sc, ok := a.vuln.activeScanner()
	if !ok {
		return nil
	}
	ix := &scanIndex{
		label: sc.Label(), scans: map[string]store.ImageScan{}, digestOf: map[string]string{},
		inUse: map[string]bool{}, platformOf: map[string]string{}, oldAgent: map[string]bool{},
	}
	scans, _ := a.store.ListImageScans(sc.Name())
	for _, s := range scans {
		ix.scans[s.Digest+"|"+s.Platform] = s
	}
	images, _ := a.store.ListHostImages()
	for _, img := range images {
		if img.Digest != "" {
			ix.digestOf[img.HostID+"|"+img.ImageID] = img.Digest
		}
	}
	containers, _ := a.store.ListHostContainers()
	for _, c := range containers {
		if c.ImageID != "" {
			ix.inUse[c.HostID+"|"+c.ImageID] = true
		}
	}
	hosts, _ := a.store.ListHosts()
	for _, h := range hosts {
		arch, _ := a.store.HostArch(h.ID)
		ix.platformOf[h.ID] = platformFor(arch)
		ix.oldAgent[h.ID] = h.AgentVersion == "" || semverLess(h.AgentVersion, minAgentForImageDigests)
	}
	return ix
}

func (ix *scanIndex) lookup(digest, hostID string) *scanBadge {
	platform := ix.platformOf[hostID]
	if platform == "" {
		platform = platformFor("")
	}
	if sc, ok := ix.scans[digest+"|"+platform]; ok {
		return badgeFromScan(sc, ix.label)
	}
	return &scanBadge{Level: "none", Label: "not scanned yet", Tooltip: "Queued for the next scan pass."}
}

// forDigest is for an image known by its registry digest (an image policy).
func (ix *scanIndex) forDigest(digest, hostID string) *scanBadge {
	if ix == nil || digest == "" {
		return nil
	}
	return ix.lookup(digest, hostID)
}

// forImage is for an image on a host, identified by the id its containers run.
func (ix *scanIndex) forImage(hostID, imageID string) *scanBadge {
	if ix == nil || imageID == "" {
		return nil
	}
	key := hostID + "|" + imageID
	digest := ix.digestOf[key]
	if digest == "" {
		switch {
		case ix.oldAgent[hostID]:
			return &scanBadge{Level: "none", Label: "update agent", Tooltip: "This host's agent predates " + minAgentForImageDigests + " and does not report image digests."}
		case ix.inUse[key]:
			return &scanBadge{Level: "none", Label: "local image", Tooltip: "Built or loaded locally: there is no registry digest to scan."}
		}
		return nil
	}
	if !ix.inUse[key] {
		if sc, ok := ix.scans[digest+"|"+ix.platformOf[hostID]]; ok {
			return badgeFromScan(sc, ix.label)
		}
		return nil
	}
	return ix.lookup(digest, hostID)
}

type scannerOption struct {
	Name, Label, Version string
	Selected, Installed  bool
	DBSize               string
}

func (a *app) settingsVulnHandler(w http.ResponseWriter, r *http.Request) {
	st, _ := a.store.GetVulnSettings()
	e := a.vuln

	var options []scannerOption
	for _, sc := range e.scanners {
		options = append(options, scannerOption{
			Name: sc.Name(), Label: sc.Label(), Version: sc.Version(),
			Selected: sc.Name() == st.Scanner, Installed: sc.Installed(e.cacheDir),
			DBSize: humanSize(dbSizeEstimate[sc.Name()]),
		})
	}
	if st.Scanner == "" && len(options) > 0 {
		options[0].Selected = true
	}

	data := map[string]any{
		"Title":       "Vulnerability scanning",
		"Nav":         "vuln-scanning",
		"Enabled":     st.Enabled,
		"Options":     options,
		"CacheDir":    e.cacheDir,
		"CacheErr":    "",
		"Status":      e.snapshot(),
		"LastPassAt":  st.LastPassAt,
		"LastPassMsg": st.LastPassMsg,
	}
	if err := e.cacheReady(); err != nil {
		data["CacheErr"] = err.Error()
	}
	if free, ok := scanner.FreeBytes(e.cacheDir); ok {
		data["Free"] = humanSize(free)
	}

	if sc, ok := e.byName(st.Scanner); ok {
		data["ScannerLabel"] = sc.Label()
		data["ScannerVersion"] = sc.Version()
		data["Installed"] = sc.Installed(e.cacheDir)
		data["DiskUsed"] = humanSize(scanner.DiskUsage(sc.DataDirs(e.cacheDir)...))
		if built, _ := sc.DBBuiltAt(r.Context(), e.cacheDir); built != "" {
			data["DBBuilt"] = built
		}
		scans, _ := a.store.ListImageScans(sc.Name())
		var ok, failed, fixableCritical int
		for _, s := range scans {
			if s.Status == "ok" {
				ok++
				fixableCritical += s.FixableCritical
			} else {
				failed++
			}
		}
		data["ScansOK"], data["ScansFailed"], data["FixableCritical"] = ok, failed, fixableCritical
	}
	render(w, r, "layout", "settings_vuln.html", data)
}

func (a *app) saveVulnHandler(w http.ResponseWriter, r *http.Request) {
	const back = "/settings/vulnerability-scanning"
	name := r.FormValue("scanner")
	sc, ok := a.vuln.byName(name)
	if !ok {
		redirectWithError(w, r, back, "choose Trivy or Grype")
		return
	}
	enabled := r.FormValue("enabled") != ""
	prev, _ := a.store.GetVulnSettings()

	if enabled {
		if err := a.vuln.cacheReady(); err != nil {
			redirectWithError(w, r, back, err.Error())
			return
		}
	}
	if err := a.store.SetVulnSettingsChoice(enabled, sc.Name()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if prev.Scanner != "" && prev.Scanner != sc.Name() {
		_ = a.store.DeleteImageScans(prev.Scanner)
	}

	if !enabled {
		a.audit(r, "scan.disable", sc.Name(), "")
		redirectWithSavedMessage(w, r, back, "Vulnerability scanning turned off")
		return
	}
	a.audit(r, "scan.enable", sc.Name(), "")
	if !a.vuln.start("starting "+sc.Label(), a.vuln.enableJob) {
		redirectWithError(w, r, back, "another scanning task is running: try again when it has finished")
		return
	}
	redirectWithSavedMessage(w, r, back, sc.Label()+" is being set up")
}

func (a *app) vulnActionHandler(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const back = "/settings/vulnerability-scanning"
		sc, ok := a.vuln.activeScanner()
		if !ok {
			redirectWithError(w, r, back, "turn vulnerability scanning on first")
			return
		}
		var started bool
		var msg, auditAction string
		switch action {
		case "scan":
			started, msg, auditAction = a.vuln.start("scanning", a.vuln.job(false)), "Scan started", "scan.run"
		case "update-db":
			started, msg, auditAction = a.vuln.start("updating the "+sc.Label()+" database", a.vuln.job(true)), "Database update started", "scan.update_db"
		}
		if !started {
			redirectWithError(w, r, back, "another scanning task is running: try again when it has finished")
			return
		}
		a.audit(r, auditAction, sc.Name(), "")
		redirectWithSavedMessage(w, r, back, msg)
	}
}

func (a *app) purgeVulnHandler(w http.ResponseWriter, r *http.Request) {
	const back = "/settings/vulnerability-scanning"
	if a.vuln.snapshot().Busy {
		redirectWithError(w, r, back, "a scanning task is running: try again when it has finished")
		return
	}
	prev, _ := a.store.GetVulnSettings()
	if err := a.store.SetVulnSettingsChoice(false, prev.Scanner); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.vuln.purge(); err != nil {
		redirectWithError(w, r, back, err.Error())
		return
	}
	a.audit(r, "scan.purge", prev.Scanner, "")
	redirectWithSavedMessage(w, r, back, "Scanner data deleted")
}

type scanFindingView struct {
	scanner.Finding
	URL string
}

// advisoryURL links a vulnerability id to its public advisory.
func advisoryURL(id string) string {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return "https://nvd.nist.gov/vuln/detail/" + id
	case strings.HasPrefix(id, "GHSA-"):
		return "https://github.com/advisories/" + id
	}
	return ""
}

func (a *app) scanDetailHandler(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.vuln.activeScanner()
	if !ok {
		http.NotFound(w, r)
		return
	}
	digest := r.PathValue("digest")
	platform := r.URL.Query().Get("platform")
	scan, found, err := a.store.GetImageScan(sc.Name(), digest, platform)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}

	var all []scanner.Finding
	_ = json.Unmarshal([]byte(scan.Findings), &all)

	onlyFixable := r.URL.Query().Get("fixable") != ""
	severity := r.URL.Query().Get("severity")
	var shown []scanFindingView
	for _, f := range all {
		if onlyFixable && f.FixedIn == "" {
			continue
		}
		if severity != "" && f.Severity != severity {
			continue
		}
		shown = append(shown, scanFindingView{Finding: f, URL: advisoryURL(f.ID)})
	}

	render(w, r, "layout", "scan_detail.html", map[string]any{
		"Title":       "Vulnerabilities",
		"Nav":         "images",
		"Scan":        scan,
		"Badge":       badgeFromScan(scan, sc.Label()),
		"Scanner":     sc.Label() + " " + sc.Version(),
		"Findings":    shown,
		"Total":       len(all),
		"Truncated":   scan.Critical+scan.High+scan.Medium+scan.Low+scan.Unknown > 0 && len(all) >= maxStoredFindings,
		"OnlyFixable": onlyFixable,
		"Severity":    severity,
		"Ref":         scan.Repository + "@" + scan.Digest,
	})
}
