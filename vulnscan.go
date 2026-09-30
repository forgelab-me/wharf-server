// Vulnerability scanning: a scanner (Trivy or Grype, cf. internal/scanner)
// reads each image the fleet runs straight from its registry, by digest,
// and the results are cached per (scanner, digest, platform). Off unless an
// admin enables it, cf. ARCHITECTURE.md, "Analyse de vulnérabilités".
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/forgelab-me/wharf-server/internal/registry"
	"github.com/forgelab-me/wharf-server/internal/scanner"
	"github.com/forgelab-me/wharf-server/internal/store"
)

const (
	// scanSchedule is a full pass with a database refresh, off the image poller's ticks.
	scanSchedule = "20 */6 * * *"
	scanTimeout  = 5 * time.Minute
	dbTimeout    = 20 * time.Minute
	// maxStoredFindings bounds what is kept per image; the counters cover all of them.
	maxStoredFindings = 1000
)

// dbSizeEstimate is the disk a scanner's database needs, measured on the
// pinned releases, used to refuse an install that cannot fit.
var dbSizeEstimate = map[string]int64{"trivy": 1_500_000_000, "grype": 3_000_000_000}

type vulnStatus struct {
	Busy  bool
	Phase string
	Since time.Time
	Err   string // failure of the last background job, cleared when the next starts
}

type vulnEngine struct {
	a        *app
	cacheDir string
	scanners []scanner.Scanner

	mu     sync.Mutex
	status vulnStatus
}

func newVulnEngine(a *app, cacheDir string) *vulnEngine {
	return &vulnEngine{a: a, cacheDir: cacheDir, scanners: scanner.All()}
}

func (e *vulnEngine) byName(name string) (scanner.Scanner, bool) {
	for _, s := range e.scanners {
		if s.Name() == name {
			return s, true
		}
	}
	return nil, false
}

func (e *vulnEngine) snapshot() vulnStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.status
}

func (e *vulnEngine) setPhase(phase string) {
	e.mu.Lock()
	e.status.Phase = phase
	e.mu.Unlock()
}

// cacheReady reports why scanner data cannot be kept, nil when it can.
func (e *vulnEngine) cacheReady() error {
	if err := os.MkdirAll(e.cacheDir, 0o755); err != nil {
		return fmt.Errorf("the cache directory %s cannot be created: mount a volume there", e.cacheDir)
	}
	probe, err := os.CreateTemp(e.cacheDir, ".write-test-*")
	if err != nil {
		return fmt.Errorf("the cache directory %s is not writable: mount a writable volume there", e.cacheDir)
	}
	probe.Close()
	os.Remove(probe.Name())
	return nil
}

// start runs job in the background unless another one is running.
func (e *vulnEngine) start(name string, job func(ctx context.Context) error) bool {
	e.mu.Lock()
	if e.status.Busy {
		e.mu.Unlock()
		return false
	}
	e.status = vulnStatus{Busy: true, Phase: name, Since: time.Now()}
	e.mu.Unlock()

	go func() {
		err := job(context.Background())
		e.mu.Lock()
		e.status.Busy, e.status.Phase = false, ""
		if err != nil {
			e.status.Err = err.Error()
			log.Println("vulnerability scanning:", name, "failed:", err)
		}
		e.mu.Unlock()
	}()
	return true
}

// activeScanner returns the enabled scanner, if any.
func (e *vulnEngine) activeScanner() (scanner.Scanner, bool) {
	st, err := e.a.store.GetVulnSettings()
	if err != nil || !st.Enabled {
		return nil, false
	}
	return e.byName(st.Scanner)
}

func platformFor(arch string) string {
	switch arch {
	case "":
		return "linux/" + runtime.GOARCH
	case "arm":
		return "linux/arm/v7"
	}
	return "linux/" + arch
}

// targets lists what is worth scanning: the applied and the latest digest
// of every image policy, and every image a container on any host runs, each
// for its host's platform, without duplicates.
func (e *vulnEngine) targets() ([]scanner.Target, error) {
	a := e.a
	hostPlatform := map[string]string{}
	platformOf := func(hostID string) string {
		if p, ok := hostPlatform[hostID]; ok {
			return p
		}
		arch, _ := a.store.HostArch(hostID)
		hostPlatform[hostID] = platformFor(arch)
		return hostPlatform[hostID]
	}

	seen := map[string]bool{}
	var out []scanner.Target
	add := func(ref registry.Ref, digest, platform string) {
		t := scanner.Target{Registry: ref.Host, Repository: ref.Repository, Digest: digest, Platform: platform}
		if err := t.Validate(); err != nil || seen[digest+"|"+platform] {
			return
		}
		seen[digest+"|"+platform] = true
		out = append(out, t)
	}

	stacks, err := a.store.ListStacks()
	if err != nil {
		return nil, err
	}
	stackHost := map[string]string{}
	for _, s := range stacks {
		stackHost[s.ID] = s.Host
	}
	policies, err := a.store.ListImagePolicies()
	if err != nil {
		return nil, err
	}
	for _, p := range policies {
		ref, ok := registry.ParseRef(p.ImageRef)
		if !ok {
			continue
		}
		platform := platformOf(stackHost[p.StackID])
		if p.AppliedDigest != "" {
			add(ref, p.AppliedDigest, platform)
		}
		if latest, ok, _ := a.store.GetImageDigestCache(ref.Canonical()); ok && latest != "" {
			add(ref, latest, platform)
		}
	}

	images, err := a.store.ListHostImages()
	if err != nil {
		return nil, err
	}
	containers, err := a.store.ListHostContainers()
	if err != nil {
		return nil, err
	}
	inUse := map[string]bool{}
	for _, c := range containers {
		if c.ImageID != "" {
			inUse[c.HostID+"|"+c.ImageID] = true
		}
	}
	for _, img := range images {
		if img.Digest == "" || img.Repository == "<none>" || !inUse[img.HostID+"|"+img.ImageID] {
			continue
		}
		if ref, ok := registry.ParseRef(img.Repository + ":" + img.Tag); ok {
			add(ref, img.Digest, platformOf(img.HostID))
		}
	}
	return out, nil
}

// enable installs what is missing, refreshes the database and scans.
func (e *vulnEngine) enableJob(ctx context.Context) error {
	sc, ok := e.activeScanner()
	if !ok {
		return errors.New("vulnerability scanning is not enabled")
	}
	if built, _ := sc.DBBuiltAt(ctx, e.cacheDir); built == "" {
		need := dbSizeEstimate[sc.Name()] * 3 / 2
		if free, known := scanner.FreeBytes(e.cacheDir); known && free < need {
			return fmt.Errorf("%s needs about %.1f GB free in %s for its database, %.1f GB available",
				sc.Label(), float64(need)/1e9, e.cacheDir, float64(free)/1e9)
		}
	}
	_, err := e.pass(ctx, true)
	return err
}

// pass scans every target that has no current result.
func (e *vulnEngine) pass(ctx context.Context, updateDB bool) (string, error) {
	a := e.a
	sc, ok := e.activeScanner()
	if !ok {
		return "", errors.New("vulnerability scanning is not enabled")
	}
	if err := e.cacheReady(); err != nil {
		return "", err
	}

	if !sc.Installed(e.cacheDir) {
		e.setPhase("installing " + sc.Label())
		ictx, cancel := context.WithTimeout(ctx, dbTimeout)
		err := sc.Install(ictx, e.cacheDir)
		cancel()
		if err != nil {
			return "", err
		}
	}
	dbBuilt, _ := sc.DBBuiltAt(ctx, e.cacheDir)
	if updateDB || dbBuilt == "" {
		e.setPhase("updating the " + sc.Label() + " database")
		uctx, cancel := context.WithTimeout(ctx, dbTimeout)
		err := sc.UpdateDB(uctx, e.cacheDir)
		cancel()
		if err != nil {
			return "", err
		}
		dbBuilt, _ = sc.DBBuiltAt(ctx, e.cacheDir)
	}

	targets, err := e.targets()
	if err != nil {
		return "", err
	}
	keep := map[store.ScanKey]bool{}
	var scanned, current, failed int
	for i, t := range targets {
		e.setPhase(fmt.Sprintf("scanning %d/%d", i+1, len(targets)))
		key := store.ScanKey{Scanner: sc.Name(), Digest: t.Digest, Platform: t.Platform}
		keep[key] = true

		prev, has, _ := a.store.GetImageScan(sc.Name(), t.Digest, t.Platform)
		if has && prev.Status == "ok" && prev.DBBuiltAt >= dbBuilt {
			current++
			continue
		}

		var auth *scanner.Auth
		if user, pass, found, err := a.keys.RegistryCredential(t.Registry); err == nil && found {
			auth = &scanner.Auth{Username: user, Password: pass}
		}
		sctx, cancel := context.WithTimeout(ctx, scanTimeout)
		report, err := sc.Scan(sctx, e.cacheDir, t, auth)
		cancel()
		if err != nil {
			failed++
			log.Println("vulnerability scanning:", t.Ref(), "failed:", err)
			if !(has && prev.Status == "ok") {
				_ = a.store.UpsertImageScan(store.ImageScan{
					Scanner: sc.Name(), Repository: t.Registry + "/" + t.Repository, Digest: t.Digest,
					Platform: t.Platform, Status: "error", Error: err.Error(),
				})
			}
			continue
		}

		counts := scanner.Summarize(report.Findings)
		findings := report.Findings
		if len(findings) > maxStoredFindings {
			findings = findings[:maxStoredFindings]
		}
		raw, _ := json.Marshal(findings)
		if err := a.store.UpsertImageScan(store.ImageScan{
			Scanner: sc.Name(), Repository: t.Registry + "/" + t.Repository, Digest: t.Digest, Platform: t.Platform,
			Status: "ok", Notice: report.Notice, DBBuiltAt: report.DBBuiltAt,
			Critical: counts.Critical, High: counts.High, Medium: counts.Medium, Low: counts.Low, Unknown: counts.Unknown,
			FixableCritical: counts.FixableCritical, FixableHigh: counts.FixableHigh, Findings: string(raw),
		}); err != nil {
			return "", err
		}
		scanned++
	}
	if _, err := a.store.PruneImageScans(keep); err != nil {
		log.Println("vulnerability scanning: prune:", err)
	}

	msg := fmt.Sprintf("%d image(s): %d scanned, %d already current, %d failed", len(targets), scanned, current, failed)
	if err := a.store.SetVulnLastPass(msg); err != nil {
		log.Println("vulnerability scanning: record pass:", err)
	}
	return msg, nil
}

// job returns a background job running one pass, with or without a database refresh.
func (e *vulnEngine) job(updateDB bool) func(context.Context) error {
	return func(ctx context.Context) error {
		_, err := e.pass(ctx, updateDB)
		return err
	}
}

// purge deletes every scanner's binary, database and results.
func (e *vulnEngine) purge() error {
	for _, sc := range e.scanners {
		for _, dir := range sc.DataDirs(e.cacheDir) {
			if err := os.RemoveAll(dir); err != nil {
				return fmt.Errorf("delete %s: %w", filepath.Base(dir), err)
			}
		}
	}
	return e.a.store.DeleteImageScans("")
}

// registerVulnScanning schedules the periodic pass; it does nothing while scanning is off.
func registerVulnScanning(a *app) error {
	_, err := a.cron.AddFunc(scanSchedule, func() {
		if _, ok := a.vuln.activeScanner(); ok {
			a.vuln.start("scheduled scan", a.vuln.job(true))
		}
	})
	return err
}
