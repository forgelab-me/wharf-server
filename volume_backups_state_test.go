package main

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/forgelab-me/wharf-server/internal/store"
)

func TestTheRepositoryStateIsLearnedFromWhatHappens(t *testing.T) {
	f := newVBFixture(t)
	dest, _ := f.createDest(t, "nas")
	job := f.createJob(t, dest.ID, nil)
	state := func() string { s, _ := f.a.repoState(job.DestinationID, job.HostID); return s }
	if state() != "unknown" {
		t.Fatalf("nothing is known at first: %s", state())
	}

	// a test that finds no repository
	f.agent.replies = map[string][]byte{"backup_test": []byte(`{"mounted":true,"writable":true,"message":"the share is writable; the repository is not initialized yet"}`)}
	f.a.testDestination(context.Background(), dest.ID, f.host.ID)
	if state() != "missing" {
		t.Errorf("after a test that found none: %s", state())
	}
	// initializing it
	if code, loc := call(f.a.initVolumeBackupJobHandler, "/x", url.Values{}, map[string]string{"id": job.ID}); code != 303 || redirectParam(t, loc, "error") != "" {
		t.Fatalf("init: %d %s", code, loc)
	}
	if state() != "ready" {
		t.Errorf("after an initialization: %s", state())
	}
	// a repository that is there but whose password does not match is not a missing one
	f.agent.replies = map[string][]byte{"backup_test": []byte(`{"mounted":true,"writable":true,"message":"the repository password is wrong"}`)}
	f.a.testDestination(context.Background(), dest.ID, f.host.ID)
	if state() != "ready" {
		t.Errorf("a wrong password says nothing about whether it exists: %s", state())
	}
	// a share that could not be mounted tells nothing either
	f.a.noteRepo(job.DestinationID, job.HostID, false)
	f.agent.replies = map[string][]byte{"backup_test": []byte(`{"mounted":false,"message":"permission denied"}`)}
	f.a.testDestination(context.Background(), dest.ID, f.host.ID)
	if state() != "missing" {
		t.Errorf("an unreachable share leaves what was known: %s", state())
	}
	// a test that finds one
	f.agent.replies = map[string][]byte{"backup_test": []byte(`{"mounted":true,"writable":true,"initialized":true}`)}
	f.a.testDestination(context.Background(), dest.ID, f.host.ID)
	if state() != "ready" {
		t.Errorf("after a test that found it: %s", state())
	}

	// a repository that was already there is welcome, not an error
	f.a.noteRepo(job.DestinationID, job.HostID, false)
	f.agent.errs = map[string]error{"backup_init": errors.New("the repository is already initialized")}
	code, loc := call(f.a.initVolumeBackupJobHandler, "/x", url.Values{}, map[string]string{"id": job.ID})
	if code != 303 || redirectParam(t, loc, "error") != "" || state() != "ready" {
		t.Errorf("init on an existing repository: %d %s %s", code, loc, state())
	}
	f.agent.errs = nil

	// a run that reports a missing repository, then one that wrote to it
	f.a.noteRepo(job.DestinationID, job.HostID, true)
	run, _ := f.a.startVolumeBackup(job, "manual", "alice")
	reportCall(f, run.ID, map[string]any{"kind": "backup", "status": "error", "code": "REPO_NOT_INITIALIZED", "message": "x"}, resolveTestCert)
	if state() != "missing" {
		t.Errorf("the agent found no repository: %s", state())
	}
	f.a.noteRepo(job.DestinationID, job.HostID, true)
	run, _ = f.a.startVolumeBackup(job, "manual", "alice")
	f.a.noteRepo(job.DestinationID, job.HostID, false)
	reportCall(f, run.ID, map[string]any{"kind": "backup", "status": "success", "volumes": []map[string]any{{"volume": "db", "status": "success", "snapshot_id": "aabbccdd"}}}, resolveTestCert)
	if state() != "ready" {
		t.Errorf("a backup that succeeded proves the repository exists: %s", state())
	}
}

func TestBackupsAreBlockedWhileTheRepositoryIsMissing(t *testing.T) {
	f := newVBFixture(t)
	dest, _ := f.createDest(t, "nas")
	job := f.createJob(t, dest.ID, nil)
	f.a.noteRepo(dest.ID, f.host.ID, false)

	run, err := f.a.startVolumeBackup(job, "schedule", "backup-schedule")
	if err == nil || !strings.Contains(err.Error(), "no repository") || !strings.Contains(err.Error(), "initialize it") {
		t.Fatalf("a clear refusal: %v", err)
	}
	if len(f.agent.calls) != 0 {
		t.Errorf("the agent was not even asked: %v", f.agent.calls)
	}
	stored, _ := f.a.store.GetBackupRun(run.ID)
	if stored.Status != "error" || stored.Code != "REPO_NOT_INITIALIZED" || stored.FinishedAt == "" {
		t.Errorf("the refusal is in the history: %+v", stored)
	}
	// so is a restore: there is nothing to restore from
	if _, err := f.a.startVolumeRestore(job, "aabbccdd", "db", "db-restored", "alice"); err == nil || len(f.agent.calls) != 0 {
		t.Errorf("a restore needs a repository too: %v %v", err, f.agent.calls)
	}

	// once it exists, the same job runs
	f.a.noteRepo(dest.ID, f.host.ID, true)
	if _, err := f.a.startVolumeBackup(job, "manual", "alice"); err != nil {
		t.Errorf("after initialization: %v", err)
	}
	// another host's state does not matter
	f.a.noteRepo(dest.ID, "another-host", false)
	other := store.BackupJob{ID: job.ID, Name: job.Name, HostID: f.host.ID, DestinationID: dest.ID, Volumes: []string{"x"}, Mode: "live"}
	if _, err := f.a.startVolumeBackup(other, "manual", "alice"); err != nil {
		t.Errorf("states are per host: %v", err)
	}
}

func TestThePagesShowWhetherTheRepositoryExists(t *testing.T) {
	f := newVBFixture(t)
	dest, _ := f.createDest(t, "nas")
	job := f.createJob(t, dest.ID, nil)
	jobPage := func() string {
		return get(f.a.volumeBackupJobFormHandler, "/x", map[string]string{"id": job.ID}).Body.String()
	}
	listPage := func() string { return getAs("admin", f.a.volumeBackupsHandler, "/backups") }
	initForm := `action="/backups/jobs/` + job.ID + `/init"`
	runForm := `action="/backups/jobs/` + job.ID + `/run"`

	// unknown: it can be tested or initialized, and a backup can be tried
	p := jobPage()
	if !strings.Contains(p, "not known yet") || !strings.Contains(p, initForm) || !strings.Contains(p, runForm) {
		t.Errorf("unknown: %s", p)
	}

	// missing: the backup is blocked and the initialization is the way out
	f.a.noteRepo(dest.ID, f.host.ID, false)
	p = jobPage()
	if !strings.Contains(p, "backups and restores are blocked") || !strings.Contains(p, initForm) || strings.Contains(p, runForm) || !strings.Contains(p, "disabled") {
		t.Errorf("missing: %s", p)
	}
	if l := listPage(); !strings.Contains(l, "Initialize first") || strings.Contains(l, runForm) {
		t.Errorf("the list sends a job without repository to its page: %s", l)
	}

	// ready: nothing left to initialize
	f.a.noteRepo(dest.ID, f.host.ID, true)
	p = jobPage()
	if !strings.Contains(p, "repository ready") || strings.Contains(p, initForm) || !strings.Contains(p, runForm) {
		t.Errorf("ready: no initialize button any more: %s", p)
	}
	if l := listPage(); strings.Contains(l, "Initialize first") || !strings.Contains(l, runForm) {
		t.Errorf("the list lets a ready job run: %s", l)
	}
}

func TestChangingADestinationForgetsWhatWasKnownOfItsRepositories(t *testing.T) {
	f := newVBFixture(t)
	dest, _ := f.createDest(t, "nas")
	f.a.noteRepo(dest.ID, f.host.ID, true)
	form := smbForm("nas")
	form.Set("password", "")
	form.Set("folder", "elsewhere")
	call(f.a.updateVolumeBackupDestinationHandler, "/x", form, map[string]string{"id": dest.ID})
	if state, _ := f.a.repoState(dest.ID, f.host.ID); state != "unknown" {
		t.Errorf("a repository somewhere else is not known to exist: %s", state)
	}
}
