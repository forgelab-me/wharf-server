package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/forgelab-me/wharf-server/internal/store"
	"github.com/robfig/cron/v3"
)

// Volume backups: starting a run, scheduling it, and receiving its report.
// Cf. ARCHITECTURE.md, "Sauvegardes de volumes".

// volumeBackups holds the live schedules and serializes the decision to start a run.
type volumeBackups struct {
	mu      sync.Mutex // guards entries
	entries map[string]cron.EntryID
	startMu sync.Mutex // one decision at a time: two clicks must not start the same volume twice
}

func newVolumeBackups() *volumeBackups {
	return &volumeBackups{entries: map[string]cron.EntryID{}}
}

var (
	safeVolumeName    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	snapshotIDPattern = regexp.MustCompile(`^[a-f0-9]{8,64}$`)
)

// Names of what the agent is told, and of the secrets kept for a destination.
const (
	backupCredPrefix = "backup-dest-"
	credSMBPassword  = "smb_password"
	credRepoPassword = "repo_password"

	// An agent gives up on a run after 12 hours; the controller gives up an hour later.
	backupRunGiveUp = 13 * time.Hour
)

func backupCredID(destID string) string { return backupCredPrefix + destID }

// backupDestinationSpec checks a destination's stored fields are complete.
func backupRequestFor(dest store.BackupDestination, creds map[string]string, job store.BackupJob) (agentBackupRequest, error) {
	cfg := dest.Config
	if creds[credSMBPassword] == "" || creds[credRepoPassword] == "" {
		return agentBackupRequest{}, errors.New("this destination has no password stored: edit it and set one")
	}
	return agentBackupRequest{
		Dest: agentBackupDestination{
			Server: cfg["server"], Share: cfg["share"], Subdir: cfg["subdir"], Version: cfg["version"],
			Username: cfg["username"], Password: creds[credSMBPassword], Domain: cfg["domain"],
			RepoDir: job.HostID, RepoPassword: creds[credRepoPassword],
		},
		HostTag: "wharf-" + job.HostID,
	}, nil
}

// requestForHost is backupRequestFor for an action that has a destination and a host but no job.
func (a *app) requestForHost(destID, hostID string) (agentBackupRequest, error) {
	dest, err := a.store.GetBackupDestination(destID)
	if err != nil {
		return agentBackupRequest{}, errors.New("that destination no longer exists")
	}
	creds, err := a.keys.SecretCredentials(backupCredID(destID))
	if err != nil {
		return agentBackupRequest{}, err
	}
	return backupRequestFor(dest, creds, store.BackupJob{HostID: hostID})
}

// backupAgent is what a backup needs of an agent: the tunnel, or a fake in a test.
type backupAgent interface {
	backupCommand(ctx context.Context, action string, req agentBackupRequest) ([]byte, error)
	startBackupAction(ctx context.Context, action string, req agentBackupRequest) error
}

// repoState says what is known of a host's repository on a destination: "ready",
// "missing", or "unknown" when nothing has told yet. checkedAt is when it was learned.
func (a *app) repoState(destID, hostID string) (state, checkedAt string) {
	initialized, known, at, err := a.store.BackupRepoState(destID, hostID)
	switch {
	case err != nil || !known:
		return "unknown", ""
	case initialized:
		return "ready", at
	}
	return "missing", at
}

// noteRepo records what an action just learned about a repository.
func (a *app) noteRepo(destID, hostID string, initialized bool) {
	if err := a.store.SetBackupRepoState(destID, hostID, initialized); err != nil {
		log.Println("backup:", err)
	}
}

// connectedAgent returns the live tunnel of a host that is able to run backups.
func (a *app) connectedAgent(hostID string) (backupAgent, error) {
	h, err := a.store.GetHost(hostID)
	if err != nil {
		return nil, errors.New("that host no longer exists")
	}
	if agentCannotBackUp(h.AgentVersion) {
		return nil, errors.New(agentTooOldForBackups(h.AgentVersion))
	}
	if a.agentHook != nil {
		if ag, ok := a.agentHook(hostID); ok {
			return ag, nil
		}
		return nil, fmt.Errorf("the host %q is not connected right now", h.Name)
	}
	tc, ok := a.tunnels.get(hostID)
	if !ok {
		return nil, fmt.Errorf("the host %q is not connected right now", h.Name)
	}
	return tc, nil
}

// overlapsRunning names a volume of the job that another run on the same host is already using.
func (a *app) overlapsRunning(job store.BackupJob, volumes []string) (string, error) {
	running, err := a.store.RunningBackupRuns()
	if err != nil {
		return "", err
	}
	for _, r := range running {
		other, err := a.store.GetBackupJob(r.JobID)
		if err != nil || other.HostID != job.HostID {
			continue
		}
		busy := map[string]bool{}
		for _, v := range other.Volumes {
			busy[v] = true
		}
		for _, v := range volumes {
			if busy[v] {
				return v, nil
			}
		}
	}
	return "", nil
}

// startVolumeBackup creates a run of a job and hands it to the agent. The run
// is recorded even when it cannot start, so a scheduled run that was skipped
// shows in the history instead of leaving no trace.
func (a *app) startVolumeBackup(job store.BackupJob, trigger, actor string) (store.BackupRun, error) {
	return a.startVolumeAction(job, "backup", trigger, actor, "", "", "")
}

func (a *app) startVolumeRestore(job store.BackupJob, snapshot, volume, newVolume, actor string) (store.BackupRun, error) {
	return a.startVolumeAction(job, "restore", "manual", actor, snapshot, volume, newVolume)
}

func (a *app) startVolumeAction(job store.BackupJob, kind, trigger, actor, snapshot, volume, newVolume string) (store.BackupRun, error) {
	a.volBackups.startMu.Lock()
	defer a.volBackups.startMu.Unlock()

	id, err := randomHex(8)
	if err != nil {
		return store.BackupRun{}, err
	}
	run := store.BackupRun{ID: id, JobID: job.ID, Kind: kind, Trigger: trigger, Actor: actor, Status: "running", Restored: newVolume}
	fail := func(code string, err error) (store.BackupRun, error) {
		// recorded as running, then finished, so it carries its end time like any other run
		if cerr := a.store.CreateBackupRun(run); cerr != nil {
			log.Println("backup: record failed run:", cerr)
			return run, err
		}
		a.store.FinishBackupRun(run.ID, "error", code, err.Error(), "", nil)
		run.Status, run.Code, run.Message = "error", code, err.Error()
		a.notifyBackupFailure(job, kind, err.Error())
		return run, err
	}

	volumes := job.Volumes
	if kind == "restore" {
		volumes = []string{volume}
	}
	if v, err := a.overlapsRunning(job, volumes); err != nil {
		return store.BackupRun{}, err
	} else if v != "" {
		return fail("CONCURRENCY", fmt.Errorf("a backup or restore of the volume %q is already running on this host", v))
	}
	dest, err := a.store.GetBackupDestination(job.DestinationID)
	if err != nil {
		return fail("VALIDATION", errors.New("the destination of this job no longer exists"))
	}
	creds, err := a.keys.SecretCredentials(backupCredID(dest.ID))
	if err != nil {
		return fail("INTERNAL", err)
	}
	req, err := backupRequestFor(dest, creds, job)
	if err != nil {
		return fail("VALIDATION", err)
	}
	// Known to have no repository: nothing is started, and the history says why. A
	// repository whose state is not known yet is left to the agent, which refuses
	// with the same code and teaches the controller.
	if state, _ := a.repoState(job.DestinationID, job.HostID); state == "missing" {
		return fail("REPO_NOT_INITIALIZED", fmt.Errorf("this host has no repository on the destination yet, so no %s was started: initialize it from the job's page first", kind))
	}
	tc, err := a.connectedAgent(job.HostID)
	if err != nil {
		return fail("HOST", err)
	}

	req.RunID = run.ID
	action := "backup_run"
	if kind == "restore" {
		action = "backup_restore"
		req.Snapshot, req.Volume, req.NewVolume = snapshot, volume, newVolume
	} else {
		req.Volumes, req.Mode = job.Volumes, job.Mode
		req.Retention = agentRetention(job.Retention)
	}
	if err := a.store.CreateBackupRun(run); err != nil {
		return store.BackupRun{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := tc.startBackupAction(ctx, action, req); err != nil {
		a.store.FinishBackupRun(run.ID, "error", "AGENT", err.Error(), "", nil)
		a.notifyBackupFailure(job, kind, err.Error())
		run.Status, run.Code, run.Message = "error", "AGENT", err.Error()
		return run, err
	}
	return run, nil
}

func (a *app) notifyBackupFailure(job store.BackupJob, kind, message string) {
	a.notify(fmt.Sprintf("Wharf: %s %q failed — %s", kind, job.Name, truncateForNotify(message)))
}

// volumeBackupReportHandler serves POST /agent/backup-runs/{id}/report: the
// agent says how a run ended. Only the host the run belongs to may say so.
func (a *app) volumeBackupReportHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	run, err := a.store.GetBackupRun(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "unknown run", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	job, err := a.store.GetBackupJob(run.JobID)
	if err != nil {
		http.Error(w, "unknown job", http.StatusNotFound)
		return
	}
	if err := verifyCaller(r, a.store, job.HostID); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	var rep agentRunReport
	if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	status := rep.Status
	if status != "success" && status != "warning" && status != "error" {
		http.Error(w, "unknown status", http.StatusBadRequest)
		return
	}

	results := make([]store.BackupVolumeResult, 0, len(rep.Volumes))
	for _, v := range rep.Volumes {
		results = append(results, store.BackupVolumeResult{
			Volume: v.Volume, Status: v.Status, SnapshotID: v.SnapshotID, FilesNew: v.FilesNew, FilesChanged: v.FilesChanged,
			FilesUnmodified: v.FilesUnmodified, DataAdded: v.DataAdded, TotalBytes: v.TotalBytes,
			Message: clip(v.Message, 1000), Retention: clip(v.Retention, 300),
		})
	}
	restored := run.Restored
	if rep.Restored != "" {
		restored = rep.Restored
	}
	changed, err := a.store.FinishBackupRun(run.ID, status, clip(rep.Code, 40), clip(rep.Message, 2000), restored, results)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if changed {
		switch {
		case rep.Code == "REPO_NOT_INITIALIZED":
			a.noteRepo(job.DestinationID, job.HostID, false)
		case status == "success" || status == "warning":
			a.noteRepo(job.DestinationID, job.HostID, true) // it was written to, or read from
		}
	}
	if changed && (status == "error" || rep.Code == "STOPPED_RESTART_FAILED") {
		a.notifyBackupFailure(job, run.Kind, rep.Message)
	}
	w.WriteHeader(http.StatusNoContent)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ---- schedules

// registerVolumeBackup (re-)adds the cron entry of a job that is enabled and has a schedule.
func registerVolumeBackup(a *app, job store.BackupJob) error {
	unregisterVolumeBackup(a, job.ID)
	if !job.Enabled || job.Schedule == "" {
		return nil
	}
	id, err := a.cron.AddFunc(job.Schedule, func() { runScheduledVolumeBackup(a, job.ID) })
	if err != nil {
		return fmt.Errorf("register the schedule %q of backup job %q: %w", job.Schedule, job.Name, err)
	}
	a.volBackups.mu.Lock()
	a.volBackups.entries[job.ID] = id
	a.volBackups.mu.Unlock()
	return nil
}

func unregisterVolumeBackup(a *app, jobID string) {
	a.volBackups.mu.Lock()
	id, had := a.volBackups.entries[jobID]
	delete(a.volBackups.entries, jobID)
	a.volBackups.mu.Unlock()
	if had {
		a.cron.Remove(id)
	}
}

// runScheduledVolumeBackup reloads the job at fire time: it may have been edited or disabled since.
func runScheduledVolumeBackup(a *app, jobID string) {
	job, err := a.store.GetBackupJob(jobID)
	if err != nil || !job.Enabled {
		return
	}
	run, err := a.startVolumeBackup(job, "schedule", "backup-schedule")
	if err != nil {
		log.Printf("backup: scheduled run of %q did not start: %v", job.Name, err)
		return
	}
	a.auditSystem("backup-schedule", "volume_backup.run", job.Name, "run "+run.ID)
}

// registerVolumeBackups schedules every job at startup, and gives up on runs
// whose agent never reported (a crash, or a controller that was down at the time).
func registerVolumeBackups(a *app) error {
	jobs, err := a.store.ListBackupJobs()
	if err != nil {
		return err
	}
	for _, j := range jobs {
		if err := registerVolumeBackup(a, j); err != nil {
			log.Println(err)
		}
	}
	giveUpOnLostRuns(a)
	_, err = a.cron.AddFunc("17 * * * *", func() { giveUpOnLostRuns(a) })
	return err
}

func giveUpOnLostRuns(a *app) {
	cutoff := time.Now().UTC().Add(-backupRunGiveUp).Format("2006-01-02 15:04:05")
	n, err := a.store.FailStaleBackupRuns(cutoff, "the agent never reported how this run ended (it may have crashed, or lost contact for good)")
	if err != nil {
		log.Println("backup: give up on lost runs:", err)
	} else if n > 0 {
		log.Printf("backup: %d run(s) never reported and were marked lost", n)
	}
}

// ---- small helpers shared by the pages

// namedVolumes keeps the volumes of a host that a person created: Docker's
// anonymous volumes (a 64-character hash) and the temporary share volumes are not.
func namedVolumes(vols []store.HostVolume, hostID string) []string {
	var out []string
	for _, v := range vols {
		if v.HostID != hostID || v.Driver != "local" || isAnonymousVolume(v.Name) || strings.HasPrefix(v.Name, "wharf-bk-") {
			continue
		}
		out = append(out, v.Name)
	}
	return out
}

func isAnonymousVolume(name string) bool {
	if len(name) != 64 {
		return false
	}
	for _, r := range name {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
