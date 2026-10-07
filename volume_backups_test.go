package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/forgelab-me/wharf-server/internal/identity"
	"github.com/forgelab-me/wharf-server/internal/keys"
	"github.com/forgelab-me/wharf-server/internal/store"
	"github.com/robfig/cron/v3"
)

// fakeBackupAgent stands in for an agent's tunnel.
type fakeBackupAgent struct {
	connected bool
	calls     []string
	requests  []agentBackupRequest
	replies   map[string][]byte
	errs      map[string]error // what a quick action answers with instead of a reply
	startErr  error
}

func (f *fakeBackupAgent) backupCommand(_ context.Context, action string, req agentBackupRequest) ([]byte, error) {
	f.calls, f.requests = append(f.calls, action), append(f.requests, req)
	if err, ok := f.errs[action]; ok {
		return nil, err
	}
	if r, ok := f.replies[action]; ok {
		return r, nil
	}
	return []byte(`{}`), nil
}

func (f *fakeBackupAgent) startBackupAction(_ context.Context, action string, req agentBackupRequest) error {
	f.calls, f.requests = append(f.calls, action), append(f.requests, req)
	return f.startErr
}

type vbFixture struct {
	a     *app
	host  store.Host
	agent *fakeBackupAgent
}

func newVBFixture(t *testing.T) *vbFixture {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "wharf.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	kc, err := keys.Open(filepath.Join(t.TempDir(), "keys.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { kc.Close() })

	host, _, err := st.UpsertHostByFingerprint("nas-01", identity.Fingerprint(resolveTestCert))
	if err != nil {
		t.Fatal(err)
	}
	st.ApproveHost(host.ID, "admin")
	st.SetHostAgentVersion(host.ID, "0.9.0")
	anonymous := strings.Repeat("ab", 32)
	if err := st.ReplaceHostVolumes(host.ID, []store.HostVolume{
		{HostID: host.ID, Name: "blog_data", Driver: "local"}, {HostID: host.ID, Name: "db", Driver: "local"},
		{HostID: host.ID, Name: anonymous, Driver: "local"}, {HostID: host.ID, Name: "wharf-bk-123", Driver: "local"},
	}); err != nil {
		t.Fatal(err)
	}
	f := &vbFixture{host: host, agent: &fakeBackupAgent{connected: true}}
	f.a = &app{store: st, keys: kc, tunnels: newTunnelRegistry(), volBackups: newVolumeBackups(), cron: cron.New(cron.WithParser(cronParser))}
	f.a.agentHook = func(string) (backupAgent, bool) { return f.agent, f.agent.connected }
	return f
}

func postPath(h http.HandlerFunc, target string, form url.Values, path map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range path {
		req.SetPathValue(k, v)
	}
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

func smbForm(name string) url.Values {
	return url.Values{"name": {name}, "server": {"nas.example.lan"}, "share": {"backups"}, "folder": {"wharf"},
		"version": {"3.0"}, "username": {"wharf"}, "password": {"s3cret-pw"}}
}

// createDest creates a destination through the real handler and returns it and its repository password.
func (f *vbFixture) createDest(t *testing.T, name string) (store.BackupDestination, string) {
	t.Helper()
	w := postPath(f.a.createVolumeBackupDestinationHandler, "/settings/backup-destinations", smbForm(name), nil)
	if w.Code != 200 {
		t.Fatalf("create destination: %d %s", w.Code, w.Header().Get("Location"))
	}
	m := regexp.MustCompile(`value="([0-9a-f]{64})"`).FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatalf("the repository password is shown once: %s", w.Body.String())
	}
	dests, _ := f.a.store.ListBackupDestinations()
	for _, d := range dests {
		if d.Name == name {
			return d, m[1]
		}
	}
	t.Fatal("destination not stored")
	return store.BackupDestination{}, ""
}

func (f *vbFixture) createJob(t *testing.T, destID string, extra url.Values) store.BackupJob {
	t.Helper()
	form := url.Values{"name": {"nightly"}, "host_id": {f.host.ID}, "destination_id": {destID}, "volumes": {"blog_data", "db"},
		"schedule": {"0 3 * * *"}, "mode": {"stop"}, "keep_last": {"3"}, "keep_daily": {"7"}, "enabled": {"1"}}
	for k, v := range extra {
		form[k] = v
	}
	code, loc := call(f.a.saveVolumeBackupJobHandler, "/backups/jobs", form, nil)
	if code != 303 || redirectParam(t, loc, "error") != "" {
		t.Fatalf("create job: %d %s", code, loc)
	}
	jobs, _ := f.a.store.ListBackupJobs()
	if len(jobs) == 0 {
		t.Fatal("job not stored")
	}
	return jobs[len(jobs)-1]
}

func TestDestinationFieldsAreValidatedLikeTheAgentDoes(t *testing.T) {
	base := func() smbFields {
		return smbFields{Name: "nas", Server: "nas.example.lan", Share: "backups", Folder: "wharf", Version: "3.0", Username: "u", Password: "p"}
	}
	if err := base().validate(true); err != nil {
		t.Fatalf("a good destination: %v", err)
	}
	for name, mutate := range map[string]func(*smbFields){
		"comma in the password":   func(f *smbFields) { f.Password = "a,b" },
		"comma in the user":       func(f *smbFields) { f.Username = "u,uid=0" },
		"an option in the share":  func(f *smbFields) { f.Share = "x,vers=1.0" },
		"a slash in the server":   func(f *smbFields) { f.Server = "nas/x" },
		"a folder going up":       func(f *smbFields) { f.Folder = "a/../b" },
		"a folder with a space":   func(f *smbFields) { f.Folder = "my backups" },
		"an unknown SMB version":  func(f *smbFields) { f.Version = "1.0" },
		"no password at creation": func(f *smbFields) { f.Password = "" },
		"a bad domain":            func(f *smbFields) { f.Domain = "a,b" },
		"no name":                 func(f *smbFields) { f.Name = "" },
		"a control character":     func(f *smbFields) { f.Password = "a\nb" },
	} {
		f := base()
		mutate(&f)
		if f.validate(true) == nil {
			t.Errorf("%s must be refused", name)
		}
	}
	f := base()
	f.Password = ""
	if err := f.validate(false); err != nil {
		t.Errorf("an edit may leave the password blank: %v", err)
	}
}

func TestCreatingADestinationShowsTheRepositoryPasswordOnceAndKeepsSecretsOutOfTheConfig(t *testing.T) {
	f := newVBFixture(t)
	dest, repoPw := f.createDest(t, "nas")

	creds, err := f.a.keys.SecretCredentials(backupCredID(dest.ID))
	if err != nil || creds[credSMBPassword] != "s3cret-pw" || creds[credRepoPassword] != repoPw {
		t.Fatalf("credentials = %v %v", creds, err)
	}
	cfg, _ := json.Marshal(dest.Config)
	if strings.Contains(string(cfg), "s3cret-pw") || strings.Contains(string(cfg), repoPw) || dest.Config["subdir"] != "wharf" || dest.Type != "smb" {
		t.Errorf("the main database holds the settings and no password: %s", cfg)
	}

	// shown again only through the reveal action, and that is audited
	w := postPath(f.a.revealVolumeBackupRepoPasswordHandler, "/x", nil, map[string]string{"id": dest.ID})
	if !strings.Contains(w.Body.String(), repoPw) {
		t.Error("reveal shows the repository password")
	}
	entries, _ := f.a.store.ListAudit(10)
	var actions []string
	for _, e := range entries {
		actions = append(actions, e.Action)
		if strings.Contains(e.Detail+e.Target, repoPw) || strings.Contains(e.Detail+e.Target, "s3cret-pw") {
			t.Errorf("a password reached the audit log: %+v", e)
		}
	}
	if !contains(actions, "volume_backup.destination_create") || !contains(actions, "volume_backup.repo_password_reveal") {
		t.Errorf("audit = %v", actions)
	}

	// the edit page never carries a password
	page := get(f.a.volumeBackupDestinationFormHandler, "/settings/backup-destinations/"+dest.ID, map[string]string{"id": dest.ID}).Body.String()
	if strings.Contains(page, "s3cret-pw") || strings.Contains(page, repoPw) {
		t.Error("a password is in the edit page")
	}
}

func TestUpdatingADestinationKeepsThePasswordsWhenLeftBlank(t *testing.T) {
	f := newVBFixture(t)
	dest, repoPw := f.createDest(t, "nas")

	form := smbForm("nas-renamed")
	form.Set("password", "")
	form.Set("share", "other")
	if code, loc := call(f.a.updateVolumeBackupDestinationHandler, "/x", form, map[string]string{"id": dest.ID}); code != 303 || redirectParam(t, loc, "error") != "" {
		t.Fatalf("update: %d %s", code, loc)
	}
	creds, _ := f.a.keys.SecretCredentials(backupCredID(dest.ID))
	if creds[credSMBPassword] != "s3cret-pw" || creds[credRepoPassword] != repoPw {
		t.Errorf("a blank password keeps the stored one, and the repository password never changes: %v", creds)
	}
	if got, _ := f.a.store.GetBackupDestination(dest.ID); got.Name != "nas-renamed" || got.Config["share"] != "other" {
		t.Errorf("destination = %+v", got)
	}

	form.Set("password", "new-pw")
	call(f.a.updateVolumeBackupDestinationHandler, "/x", form, map[string]string{"id": dest.ID})
	if creds, _ := f.a.keys.SecretCredentials(backupCredID(dest.ID)); creds[credSMBPassword] != "new-pw" || creds[credRepoPassword] != repoPw {
		t.Errorf("a new password replaces only the share's: %v", creds)
	}
}

func TestADestinationInUseCannotBeRemoved(t *testing.T) {
	f := newVBFixture(t)
	dest, _ := f.createDest(t, "nas")
	f.createJob(t, dest.ID, nil)

	code, loc := call(f.a.deleteVolumeBackupDestinationHandler, "/x", url.Values{}, map[string]string{"id": dest.ID})
	if code != 303 || !strings.Contains(redirectParam(t, loc, "error"), "nightly") {
		t.Errorf("the refusal names the job: %d %s", code, loc)
	}
	if _, err := f.a.store.GetBackupDestination(dest.ID); err != nil {
		t.Error("the destination is still there")
	}
	if creds, _ := f.a.keys.SecretCredentials(backupCredID(dest.ID)); creds == nil {
		t.Error("and so are its passwords")
	}
}

func TestJobValidation(t *testing.T) {
	f := newVBFixture(t)
	dest, _ := f.createDest(t, "nas")
	base := url.Values{"name": {"j"}, "host_id": {f.host.ID}, "destination_id": {dest.ID}, "volumes": {"blog_data"}, "mode": {"live"}}
	try := func(mutate func(url.Values)) string {
		form := url.Values{}
		for k, v := range base {
			form[k] = v
		}
		mutate(form)
		_, loc := call(f.a.saveVolumeBackupJobHandler, "/backups/jobs", form, nil)
		return redirectParam(t, loc, "error")
	}
	if msg := try(func(url.Values) {}); msg != "" {
		t.Fatalf("a valid job: %q", msg)
	}
	for name, mutate := range map[string]func(url.Values){
		"no volume":                     func(v url.Values) { v.Del("volumes"); v.Set("name", "a") },
		"an unknown volume":             func(v url.Values) { v.Set("volumes", "nope"); v.Set("name", "b") },
		"an anonymous volume":           func(v url.Values) { v.Set("volumes", strings.Repeat("ab", 32)); v.Set("name", "c") },
		"a temporary share volume":      func(v url.Values) { v.Set("volumes", "wharf-bk-123"); v.Set("name", "d") },
		"a bad schedule":                func(v url.Values) { v.Set("schedule", "every night"); v.Set("name", "e") },
		"a 6-field schedule":            func(v url.Values) { v.Set("schedule", "0 0 3 * * *"); v.Set("name", "f") },
		"a bad mode":                    func(v url.Values) { v.Set("mode", "pause"); v.Set("name", "g") },
		"a negative retention":          func(v url.Values) { v.Set("keep_last", "-1"); v.Set("name", "h") },
		"a retention that is no number": func(v url.Values) { v.Set("keep_daily", "x"); v.Set("name", "i") },
		"an unknown destination":        func(v url.Values) { v.Set("destination_id", "nope"); v.Set("name", "j2") },
		"an unknown host":               func(v url.Values) { v.Set("host_id", "nope"); v.Set("name", "k") },
		"no name":                       func(v url.Values) { v.Set("name", "") },
	} {
		if msg := try(mutate); msg == "" {
			t.Errorf("%s must be refused", name)
		}
	}
	if jobs, _ := f.a.store.ListBackupJobs(); len(jobs) != 1 {
		t.Errorf("only the valid job exists: %d", len(jobs))
	}
}

func TestAScheduledJobRegistersACronEntryAndADisabledOneDoesNot(t *testing.T) {
	f := newVBFixture(t)
	dest, _ := f.createDest(t, "nas")
	job := f.createJob(t, dest.ID, nil)
	if len(f.a.cron.Entries()) != 1 {
		t.Fatalf("an enabled job with a schedule is scheduled: %d", len(f.a.cron.Entries()))
	}

	form := url.Values{"name": {"nightly"}, "destination_id": {dest.ID}, "volumes": {"blog_data"}, "schedule": {"0 3 * * *"}, "mode": {"live"}}
	call(f.a.saveVolumeBackupJobHandler, "/x", form, map[string]string{"id": job.ID}) // enabled left out: off
	if len(f.a.cron.Entries()) != 0 {
		t.Errorf("a disabled job leaves the scheduler: %d", len(f.a.cron.Entries()))
	}
	form.Set("enabled", "1")
	call(f.a.saveVolumeBackupJobHandler, "/x", form, map[string]string{"id": job.ID})
	call(f.a.saveVolumeBackupJobHandler, "/x", form, map[string]string{"id": job.ID})
	if len(f.a.cron.Entries()) != 1 {
		t.Errorf("saving twice does not schedule twice: %d", len(f.a.cron.Entries()))
	}
	call(f.a.deleteVolumeBackupJobHandler, "/x", url.Values{}, map[string]string{"id": job.ID})
	if len(f.a.cron.Entries()) != 0 {
		t.Error("a removed job is unscheduled")
	}
}

func TestStartingARunSendsTheAgentEverythingItNeeds(t *testing.T) {
	f := newVBFixture(t)
	dest, repoPw := f.createDest(t, "nas")
	job := f.createJob(t, dest.ID, nil)

	run, err := f.a.startVolumeBackup(job, "manual", "alice")
	if err != nil || run.Status != "running" {
		t.Fatalf("run = %+v %v", run, err)
	}
	if len(f.agent.calls) != 1 || f.agent.calls[0] != "backup_run" {
		t.Fatalf("calls = %v", f.agent.calls)
	}
	req := f.agent.requests[0]
	if req.RunID != run.ID || req.Mode != "stop" || strings.Join(req.Volumes, ",") != "blog_data,db" || req.HostTag != "wharf-"+f.host.ID ||
		req.Retention.KeepLast != 3 || req.Retention.KeepDaily != 7 {
		t.Errorf("request = %+v", req)
	}
	d := req.Dest
	if d.Server != "nas.example.lan" || d.Share != "backups" || d.Subdir != "wharf" || d.Username != "wharf" || d.Password != "s3cret-pw" ||
		d.RepoPassword != repoPw || d.RepoDir != f.host.ID || d.Version != "3.0" {
		t.Errorf("destination = %+v", d)
	}
	if stored, _ := f.a.store.GetBackupRun(run.ID); stored.Status != "running" || stored.Actor != "alice" || stored.Trigger != "manual" {
		t.Errorf("stored run = %+v", stored)
	}
}

func TestARunThatCannotStartIsRecordedAndSaysWhy(t *testing.T) {
	f := newVBFixture(t)
	dest, _ := f.createDest(t, "nas")
	job := f.createJob(t, dest.ID, nil)

	cases := map[string]func(){
		"HOST":  func() { f.agent.connected = false },
		"AGENT": func() { f.agent.startErr = errors.New("docker is not reachable") },
	}
	// the host is offline
	cases["HOST"]()
	run, err := f.a.startVolumeBackup(job, "schedule", "backup-schedule")
	if err == nil || run.ID == "" {
		t.Fatalf("an offline host: %+v %v", run, err)
	}
	stored, _ := f.a.store.GetBackupRun(run.ID)
	if stored.Status != "error" || stored.Code != "HOST" || !strings.Contains(stored.Message, "not connected") || stored.FinishedAt == "" {
		t.Errorf("stored = %+v", stored)
	}

	// the agent refuses
	f.agent.connected = true
	cases["AGENT"]()
	run, err = f.a.startVolumeBackup(job, "manual", "alice")
	if err == nil {
		t.Fatal("the agent's refusal comes back")
	}
	if stored, _ := f.a.store.GetBackupRun(run.ID); stored.Status != "error" || stored.Code != "AGENT" || !strings.Contains(stored.Message, "docker") {
		t.Errorf("stored = %+v", stored)
	}

	// an agent too old
	f.agent.startErr = nil
	f.a.store.SetHostAgentVersion(f.host.ID, "0.8.0")
	if _, err := f.a.startVolumeBackup(job, "manual", "alice"); err == nil || !strings.Contains(err.Error(), "0.9.0") {
		t.Errorf("an old agent: %v", err)
	}
	// a development build is let through
	f.a.store.SetHostAgentVersion(f.host.ID, "dev")
	if _, err := f.a.startVolumeBackup(job, "manual", "alice"); err != nil {
		t.Errorf("a dev agent: %v", err)
	}
}

func TestTwoRunsOnTheSameVolumeNeverOverlap(t *testing.T) {
	f := newVBFixture(t)
	dest, _ := f.createDest(t, "nas")
	a := f.createJob(t, dest.ID, url.Values{"name": {"a"}, "volumes": {"blog_data"}})
	b := f.createJob(t, dest.ID, url.Values{"name": {"b"}, "volumes": {"blog_data", "db"}})
	c := f.createJob(t, dest.ID, url.Values{"name": {"c"}, "volumes": {"db"}})

	if _, err := f.a.startVolumeBackup(a, "manual", "alice"); err != nil {
		t.Fatal(err)
	}
	run, err := f.a.startVolumeBackup(b, "manual", "alice")
	if err == nil || !strings.Contains(err.Error(), "blog_data") {
		t.Fatalf("a second backup of blog_data must be refused: %v", err)
	}
	if stored, _ := f.a.store.GetBackupRun(run.ID); stored.Code != "CONCURRENCY" || stored.Status != "error" {
		t.Errorf("the refusal is in the history: %+v", stored)
	}
	if _, err := f.a.startVolumeBackup(c, "manual", "alice"); err != nil {
		t.Errorf("another volume is free to go: %v", err)
	}
	if len(f.agent.calls) != 2 {
		t.Errorf("only two runs reached the agent: %v", f.agent.calls)
	}
}

func reportCall(f *vbFixture, runID string, rep any, cert []byte) *httptest.ResponseRecorder {
	body, _ := json.Marshal(rep)
	req := httptest.NewRequest("POST", "/agent/backup-runs/"+runID+"/report", bytes.NewReader(body))
	req.SetPathValue("id", runID)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: cert}}}
	w := httptest.NewRecorder()
	f.a.volumeBackupReportHandler(w, req)
	return w
}

func TestTheAgentReportsHowARunEnded(t *testing.T) {
	f := newVBFixture(t)
	dest, _ := f.createDest(t, "nas")
	job := f.createJob(t, dest.ID, nil)
	run, _ := f.a.startVolumeBackup(job, "manual", "alice")

	rep := map[string]any{"kind": "backup", "status": "success", "volumes": []map[string]any{
		{"volume": "blog_data", "status": "success", "snapshot_id": "aabbccdd11", "data_added": 1500, "total_bytes": 9000, "files_new": 2, "retention": "kept 3, removed 1"},
	}}

	// a certificate that is not this host's
	if w := reportCall(f, run.ID, rep, []byte("someone else")); w.Code != http.StatusForbidden {
		t.Errorf("another host may not report this run: %d", w.Code)
	}
	if stored, _ := f.a.store.GetBackupRun(run.ID); stored.Status != "running" {
		t.Error("and nothing changed")
	}

	if w := reportCall(f, run.ID, rep, resolveTestCert); w.Code != http.StatusNoContent {
		t.Fatalf("report: %d %s", w.Code, w.Body)
	}
	stored, _ := f.a.store.GetBackupRun(run.ID)
	if stored.Status != "success" || len(stored.Results) != 1 || stored.Results[0].SnapshotID != "aabbccdd11" || stored.Results[0].Retention != "kept 3, removed 1" {
		t.Fatalf("stored = %+v", stored)
	}
	// a duplicate report (the agent retried) does not rewrite history
	rep["status"] = "error"
	reportCall(f, run.ID, rep, resolveTestCert)
	if again, _ := f.a.store.GetBackupRun(run.ID); again.Status != "success" {
		t.Errorf("a late duplicate changed the run: %+v", again)
	}

	if w := reportCall(f, "nope", rep, resolveTestCert); w.Code != http.StatusNotFound {
		t.Errorf("unknown run: %d", w.Code)
	}
	run2, _ := f.a.startVolumeBackup(store.BackupJob{ID: job.ID, Name: job.Name, HostID: job.HostID, DestinationID: job.DestinationID, Volumes: []string{"x"}, Mode: "live"}, "manual", "a")
	if w := reportCall(f, run2.ID, map[string]any{"status": "weird"}, resolveTestCert); w.Code != http.StatusBadRequest {
		t.Errorf("an unknown status: %d", w.Code)
	}
}

func TestARestoreRunNamesTheSnapshotAndTheNewVolume(t *testing.T) {
	f := newVBFixture(t)
	dest, _ := f.createDest(t, "nas")
	job := f.createJob(t, dest.ID, nil)

	form := url.Values{"volume": {"blog_data"}, "snapshot": {"aabbccdd"}, "new_volume": {"blog_data-restored"}}
	w := postPath(f.a.volumeBackupRestoreHandler, "/x", form, map[string]string{"id": job.ID})
	if w.Code != 303 || !strings.HasPrefix(w.Header().Get("Location"), "/backups/runs/") {
		t.Fatalf("restore: %d %s", w.Code, w.Header().Get("Location"))
	}
	req := f.agent.requests[len(f.agent.requests)-1]
	if f.agent.calls[len(f.agent.calls)-1] != "backup_restore" || req.Snapshot != "aabbccdd" || req.Volume != "blog_data" || req.NewVolume != "blog_data-restored" || len(req.Volumes) != 0 {
		t.Errorf("request = %+v", req)
	}
	runs, _ := f.a.store.ListBackupRuns(job.ID, 5)
	if runs[0].Kind != "restore" || runs[0].Restored != "blog_data-restored" {
		t.Errorf("run = %+v", runs[0])
	}

	for name, mut := range map[string]func(url.Values){
		"a snapshot that is a path": func(v url.Values) { v.Set("snapshot", "../x") },
		"a new name that is a path": func(v url.Values) { v.Set("new_volume", "../x") },
		"no snapshot":               func(v url.Values) { v.Set("snapshot", "") },
	} {
		bad := url.Values{"volume": {"db"}, "snapshot": {"aabbccdd"}, "new_volume": {"db-restored"}}
		mut(bad)
		before := len(f.agent.calls)
		code, loc := call(f.a.volumeBackupRestoreHandler, "/x", bad, map[string]string{"id": job.ID})
		if code != 303 || redirectParam(t, loc, "error") == "" || len(f.agent.calls) != before {
			t.Errorf("%s: %d %s", name, code, loc)
		}
	}
	// a volume that is not part of the job
	if code, _ := call(f.a.volumeBackupRestoreHandler, "/x", url.Values{"volume": {"other"}, "snapshot": {"aabbccdd"}, "new_volume": {"x"}}, map[string]string{"id": job.ID}); code != 404 {
		t.Errorf("a volume outside the job: %d", code)
	}
}

func TestTheRestorePageListsSnapshotsNewestFirst(t *testing.T) {
	f := newVBFixture(t)
	dest, _ := f.createDest(t, "nas")
	job := f.createJob(t, dest.ID, nil)
	f.agent.replies = map[string][]byte{"backup_snapshots": []byte(`{"snapshots":[
		{"id":"aaaaaaaa11","short_id":"aaaaaaaa","time":"2026-10-01T03:00:00Z"},
		{"id":"bbbbbbbb22","short_id":"bbbbbbbb","time":"2026-10-03T03:00:00Z"}]}`)}
	page := get(f.a.volumeBackupRestoreFormHandler, "/backups/jobs/"+job.ID+"/restore?volume=db", map[string]string{"id": job.ID}).Body.String()
	if strings.Index(page, "bbbbbbbb") > strings.Index(page, "aaaaaaaa") || !strings.Contains(page, `name="snapshot" value="bbbbbbbb22" checked`) {
		t.Errorf("the newest snapshot comes first and is chosen: %s", page)
	}
	if f.agent.requests[0].Volume != "db" {
		t.Errorf("the listing is asked for the chosen volume: %+v", f.agent.requests[0])
	}

	f.agent.connected = false
	page = get(f.a.volumeBackupRestoreFormHandler, "/backups/jobs/"+job.ID+"/restore", map[string]string{"id": job.ID}).Body.String()
	if !strings.Contains(page, "could not be listed") || !strings.Contains(page, "not connected") {
		t.Errorf("an offline host is explained: %s", page)
	}
}

func TestRunsThatNeverReportAreGivenUp(t *testing.T) {
	f := newVBFixture(t)
	f.a.store.CreateBackupRun(store.BackupRun{ID: "r1", JobID: "j", Kind: "backup", Status: "running"})
	giveUpOnLostRuns(f.a)
	if r, _ := f.a.store.GetBackupRun("r1"); r.Status != "running" {
		t.Error("a run that just started is not lost")
	}
	if n, _ := f.a.store.FailStaleBackupRuns("2999-01-01 00:00:00", "gone"); n != 1 {
		t.Errorf("an old run is given up: %d", n)
	}
}

func TestTheBackupPagesRenderForAnAdmin(t *testing.T) {
	f := newVBFixture(t)
	dest, _ := f.createDest(t, "nas")
	job := f.createJob(t, dest.ID, nil)
	run, _ := f.a.startVolumeBackup(job, "manual", "alice")
	reportCall(f, run.ID, map[string]any{"kind": "backup", "status": "warning", "message": "1 of 2 volumes were backed up with a warning",
		"volumes": []map[string]any{{"volume": "db", "status": "warning", "snapshot_id": "aabbccdd11", "data_added": 2048, "total_bytes": 4096, "message": "some files could not be read"}}}, resolveTestCert)

	for name, page := range map[string]string{
		"list":         getAs("admin", f.a.volumeBackupsHandler, "/backups"),
		"destinations": getAs("admin", f.a.volumeBackupDestinationsHandler, "/settings/backup-destinations"),
		"new job":      get(f.a.volumeBackupJobFormHandler, "/backups/jobs/new?host="+f.host.ID, nil).Body.String(),
		"job":          get(f.a.volumeBackupJobFormHandler, "/x", map[string]string{"id": job.ID}).Body.String(),
		"run":          get(f.a.volumeBackupRunHandler, "/x", map[string]string{"id": run.ID}).Body.String(),
		"destination":  get(f.a.volumeBackupDestinationFormHandler, "/x", map[string]string{"id": dest.ID}).Body.String(),
	} {
		if strings.Contains(page, "render error") || len(page) < 200 {
			t.Errorf("%s did not render: %.200s", name, page)
		}
	}
	runPage := get(f.a.volumeBackupRunHandler, "/x", map[string]string{"id": run.ID}).Body.String()
	for _, want := range []string{"warning", "aabbccdd", "2.00 KiB", "some files could not be read", "nightly"} {
		if !strings.Contains(runPage, want) {
			t.Errorf("the run page lacks %q", want)
		}
	}
	list := getAs("admin", f.a.volumeBackupsHandler, "/backups")
	if !strings.Contains(list, "nightly") || !strings.Contains(list, "nas-01") || !strings.Contains(list, "blog_data") || !strings.Contains(list, "0 3 * * *") {
		t.Errorf("the list shows the job: %.600s", list)
	}
	// the new-job form offers only named volumes
	form := get(f.a.volumeBackupJobFormHandler, "/backups/jobs/new?host="+f.host.ID, nil).Body.String()
	if !strings.Contains(form, `"n":"blog_data"`) || strings.Contains(form, "wharf-bk-123") || strings.Contains(form, strings.Repeat("ab", 32)) {
		t.Error("named volumes only: no anonymous volume, no temporary share volume")
	}
}

func TestTheSidebarLinksToBackupsForAdminsOnly(t *testing.T) {
	f := newVBFixture(t)
	admin := getAs("admin", f.a.volumeBackupDestinationsHandler, "/settings/backup-destinations")
	if !strings.Contains(admin, `href="/backups"`) || !strings.Contains(admin, `href="/settings/backup-destinations"`) {
		t.Error("an admin sees both links")
	}
	if !groupOpen(t, admin, "settings") {
		t.Error("on a Settings page of its own, the group is open")
	}
	if operator := getAs("operator", f.a.volumeBackupDestinationsHandler, "/x"); strings.Contains(operator, `<a href="/backups" class=`) {
		t.Error("an operator is not shown the backups")
	}
}

func TestADestinationTestSaysWhatTheHostSaw(t *testing.T) {
	f := newVBFixture(t)
	dest, _ := f.createDest(t, "nas")
	for reply, want := range map[string]string{
		`{"mounted":true,"writable":true,"initialized":true}`:                                                       "initialized",
		`{"mounted":true,"writable":true,"message":"the share is writable; the repository is not initialized yet"}`: "no repository there yet",
		`{"mounted":false,"message":"docker could not run the helper: permission denied"}`:                          "could not be used",
	} {
		f.agent.replies = map[string][]byte{"backup_test": []byte(reply)}
		msg, err := f.a.testDestination(context.Background(), dest.ID, f.host.ID)
		got := msg
		if err != nil {
			got = err.Error()
		}
		if !strings.Contains(got, want) {
			t.Errorf("%s: %q does not mention %q", reply, got, want)
		}
	}
	if _, err := f.a.testDestination(context.Background(), "nope", f.host.ID); err == nil {
		t.Error("an unknown destination")
	}
}

func TestAFailedRunOnAnUninitializedRepositoryOffersToInitializeIt(t *testing.T) {
	f := newVBFixture(t)
	dest, _ := f.createDest(t, "nas")
	job := f.createJob(t, dest.ID, nil)
	run, _ := f.a.startVolumeBackup(job, "manual", "alice")
	reportCall(f, run.ID, map[string]any{"kind": "backup", "status": "error", "code": "REPO_NOT_INITIALIZED", "message": "the repository is not initialized for this host"}, resolveTestCert)

	page := get(f.a.volumeBackupRunHandler, "/x", map[string]string{"id": run.ID}).Body.String()
	if !strings.Contains(page, `action="/backups/jobs/`+job.ID+`/init"`) || !strings.Contains(page, "Initialize the repository for") {
		t.Errorf("the failed run offers the initialization: %s", page)
	}
	f.a.noteRepo(job.DestinationID, job.HostID, true) // the report above taught that it was missing
	other, _ := f.a.startVolumeBackup(job, "manual", "alice")
	reportCall(f, other.ID, map[string]any{"kind": "backup", "status": "error", "code": "WRONG_PASSWORD", "message": "the repository password is wrong"}, resolveTestCert)
	if page := get(f.a.volumeBackupRunHandler, "/x", map[string]string{"id": other.ID}).Body.String(); strings.Contains(page, "/init") {
		t.Error("only a missing repository offers to create one")
	}
}
