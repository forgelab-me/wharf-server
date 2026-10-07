package store

import (
	"errors"
	"path/filepath"
	"testing"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "wharf.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestBackupDestinationsAndJobs(t *testing.T) {
	s := openTest(t)
	dest := BackupDestination{ID: "d1", Name: "nas", Type: "smb", Config: map[string]string{"server": "nas.lan", "share": "backups"}}
	if err := s.CreateBackupDestination(dest); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateBackupDestination(BackupDestination{ID: "d2", Name: "nas", Type: "smb"}); err == nil {
		t.Error("two destinations with one name")
	}
	got, err := s.GetBackupDestination("d1")
	if err != nil || got.Config["share"] != "backups" || got.Type != "smb" {
		t.Fatalf("destination = %+v %v", got, err)
	}
	if err := s.UpdateBackupDestination("d1", "nas2", map[string]string{"server": "other"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetBackupDestination("d1"); got.Name != "nas2" || got.Config["server"] != "other" {
		t.Errorf("updated = %+v", got)
	}
	if _, err := s.GetBackupDestination("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing destination: %v", err)
	}

	job := BackupJob{ID: "j1", Name: "nightly", HostID: "h1", DestinationID: "d1", Volumes: []string{"blog", "db"},
		Schedule: "0 3 * * *", Mode: "stop", Retention: BackupRetention{KeepLast: 3, KeepDaily: 7}, Enabled: true}
	if err := s.CreateBackupJob(job); err != nil {
		t.Fatal(err)
	}
	gj, err := s.GetBackupJob("j1")
	if err != nil || len(gj.Volumes) != 2 || gj.Retention.KeepDaily != 7 || !gj.Enabled || gj.Mode != "stop" {
		t.Fatalf("job = %+v %v", gj, err)
	}
	gj.Enabled, gj.Schedule = false, ""
	if err := s.UpdateBackupJob(gj); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.GetBackupJob("j1"); again.Enabled || again.Schedule != "" {
		t.Errorf("updated job = %+v", again)
	}
	if (BackupRetention{}).None() == false || (BackupRetention{KeepLast: 1}).None() {
		t.Error("None() is true only when nothing is kept by a rule")
	}

	// a destination in use cannot be deleted
	if err := s.DeleteBackupDestination("d1"); err == nil {
		t.Error("deleting a destination a job writes to must be refused")
	}
	if err := s.DeleteBackupJob("j1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteBackupDestination("d1"); err != nil {
		t.Errorf("an unused destination can go: %v", err)
	}
}

func TestBackupRuns(t *testing.T) {
	s := openTest(t)
	if err := s.CreateBackupRun(BackupRun{ID: "r1", JobID: "j1", Kind: "backup", Trigger: "schedule", Actor: "backup-schedule", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	results := []BackupVolumeResult{{Volume: "blog", Status: "success", SnapshotID: "aabbccdd", DataAdded: 1500}}
	ok, err := s.FinishBackupRun("r1", "success", "", "", "", results)
	if err != nil || !ok {
		t.Fatalf("finish: %v %v", ok, err)
	}
	if again, _ := s.FinishBackupRun("r1", "error", "X", "late duplicate", "", nil); again {
		t.Error("a finished run is not changed by a second report")
	}
	r, err := s.GetBackupRun("r1")
	if err != nil || r.Status != "success" || len(r.Results) != 1 || r.Results[0].SnapshotID != "aabbccdd" || r.FinishedAt == "" || r.Trigger != "schedule" {
		t.Fatalf("run = %+v %v", r, err)
	}
	if _, err := s.GetBackupRun("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing run: %v", err)
	}

	s.CreateBackupRun(BackupRun{ID: "r2", JobID: "j1", Kind: "backup", Status: "running"})
	s.CreateBackupRun(BackupRun{ID: "r3", JobID: "j2", Kind: "restore", Status: "running", Restored: "blog-restored"})
	if running, _ := s.RunningBackupRuns(); len(running) != 2 {
		t.Errorf("running = %d", len(running))
	}
	if list, _ := s.ListBackupRuns("j1", 10); len(list) != 2 || list[0].ID != "r2" {
		t.Errorf("newest first, of one job: %+v", list)
	}
	if list, _ := s.ListBackupRuns("", 2); len(list) != 2 {
		t.Errorf("limit: %d", len(list))
	}

	// runs that never reported are given up after the cutoff
	n, err := s.FailStaleBackupRuns("2999-01-01 00:00:00", "the agent never reported")
	if err != nil || n != 2 {
		t.Fatalf("stale = %d %v", n, err)
	}
	if lost, _ := s.GetBackupRun("r2"); lost.Status != "error" || lost.Code != "LOST" || lost.Message == "" {
		t.Errorf("lost = %+v", lost)
	}
	if n, _ := s.FailStaleBackupRuns("2999-01-01 00:00:00", "x"); n != 0 {
		t.Error("already finished runs are left alone")
	}
}

func TestBackupRepoState(t *testing.T) {
	s := openTest(t)
	if _, known, _, err := s.BackupRepoState("d1", "h1"); err != nil || known {
		t.Fatalf("nothing is known at first: %v %v", known, err)
	}
	s.SetBackupRepoState("d1", "h1", false)
	if ok, known, at, _ := s.BackupRepoState("d1", "h1"); ok || !known || at == "" {
		t.Errorf("missing: %v %v %q", ok, known, at)
	}
	s.SetBackupRepoState("d1", "h1", true)
	s.SetBackupRepoState("d1", "h2", false)
	if ok, _, _, _ := s.BackupRepoState("d1", "h1"); !ok {
		t.Error("the last answer wins")
	}
	if ok, known, _, _ := s.BackupRepoState("d1", "h2"); ok || !known {
		t.Error("each host has its own state")
	}
	s.ClearBackupRepoStates("d1")
	if _, known, _, _ := s.BackupRepoState("d1", "h1"); known {
		t.Error("a cleared destination forgets every host")
	}

	// deleting a destination forgets its states
	s.CreateBackupDestination(BackupDestination{ID: "d2", Name: "x", Type: "smb"})
	s.SetBackupRepoState("d2", "h1", true)
	s.DeleteBackupDestination("d2")
	if _, known, _, _ := s.BackupRepoState("d2", "h1"); known {
		t.Error("a deleted destination leaves no state behind")
	}
}
