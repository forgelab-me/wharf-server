package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/forgelab-me/wharf-server/internal/store"
)

// Volume backup jobs and their runs: Backups, admin only.

type jobRow struct {
	Job         store.BackupJob
	HostName    string
	Destination string
	Last        *runView
	RepoMissing bool     // known to have no repository: a run would be refused
	Selected    []string // the volumes the job covers now
}

// treeState is what the volume tree starts from: what the job selects.
type treeState struct {
	Stacks   []string `json:"stacks"`
	Picked   []string `json:"picked"`
	Excluded []string `json:"excluded"`
	Rules    []string `json:"rules"`
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

func nonNilChoices(l []volumeChoice) []volumeChoice {
	if l == nil {
		return []volumeChoice{}
	}
	for i := range l {
		if l[i].Labels == nil {
			l[i].Labels = map[string]string{}
		}
	}
	return l
}

// selectionSummary is what the audit log says a job selects: names, never anything secret.
func selectionSummary(j store.BackupJob) string {
	var parts []string
	if len(j.Volumes) > 0 {
		parts = append(parts, "volumes "+strings.Join(j.Volumes, ", "))
	}
	if len(j.Stacks) > 0 {
		parts = append(parts, "stacks "+strings.Join(j.Stacks, ", "))
	}
	if len(j.LabelRules) > 0 {
		parts = append(parts, "labels "+strings.Join(j.LabelRules, ", "))
	}
	if len(j.Excluded) > 0 {
		parts = append(parts, "left out "+strings.Join(j.Excluded, ", "))
	}
	return strings.Join(parts, "; ")
}

func (a *app) hostName(id string) string {
	if h, err := a.store.GetHost(id); err == nil && h.Name != "" {
		return h.Name
	}
	return id
}

func (a *app) volumeBackupsHandler(w http.ResponseWriter, r *http.Request) {
	jobs, err := a.store.ListBackupJobs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	dests, _ := a.store.ListBackupDestinations()
	destName := map[string]string{}
	for _, d := range dests {
		destName[d.ID] = d.Name
	}
	runs, _ := a.store.ListBackupRuns("", 30)
	views := a.runViews(runs)
	last := map[string]*runView{}
	for i := range views {
		if _, ok := last[views[i].JobID]; !ok {
			last[views[i].JobID] = &views[i]
		}
	}
	rows := make([]jobRow, 0, len(jobs))
	for _, j := range jobs {
		state, _ := a.repoState(j.DestinationID, j.HostID)
		rows = append(rows, jobRow{Job: j, HostName: a.hostName(j.HostID), Destination: destName[j.DestinationID], Last: last[j.ID], RepoMissing: state == "missing", Selected: a.resolveJobVolumes(j).Names()})
	}
	render(w, r, "layout", "volume_backups.html", map[string]any{
		"Title": "Backups", "Nav": "backups", "Jobs": rows, "Runs": views, "HasDestinations": len(dests) > 0,
	})
}

// jobFormData is what the job form needs, for a new job or an existing one.
func (a *app) jobFormData(job *store.BackupJob, hostID string) (map[string]any, error) {
	hosts, err := a.store.ListHosts()
	if err != nil {
		return nil, err
	}
	vols, _ := a.store.ListHostVolumes()
	dests, _ := a.store.ListBackupDestinations()
	var choices []hostChoice
	for _, h := range hosts {
		if h.Status == "connected" {
			choices = append(choices, hostChoice{ID: h.ID, Name: h.Name})
		}
	}
	if job != nil {
		hostID = job.HostID
	}
	// The tree: the host's named volumes with their labels, plus what the job ticked that the
	// host no longer reports (so it can still be unticked), and what the job selects.
	volumes := hostVolumeChoices(vols, hostID)
	state := treeState{Stacks: []string{}, Picked: []string{}, Excluded: []string{}, Rules: []string{}}
	if job != nil {
		state = treeState{Stacks: nonNil(job.Stacks), Picked: nonNil(job.Volumes), Excluded: nonNil(job.Excluded), Rules: nonNil(job.LabelRules)}
		known := map[string]bool{}
		for _, v := range volumes {
			known[v.Name] = true
		}
		for _, name := range append(append([]string{}, job.Volumes...), job.Excluded...) {
			if !known[name] {
				known[name] = true
				volumes = append(volumes, volumeChoice{Name: name, Labels: map[string]string{}})
			}
		}
	}
	names := map[string]string{}
	if stacks, err := a.store.ListStacks(); err == nil {
		for _, st := range stacks {
			names[st.ID] = st.Name
		}
	}
	tree, _ := json.Marshal(map[string]any{"volumes": nonNilChoices(volumes), "state": state, "names": names})
	data := map[string]any{"Nav": "backups", "Hosts": choices, "HostID": hostID, "HostName": a.hostName(hostID), "Destinations": dests, "TreeJSON": template.JS(tree)}
	if job != nil {
		data["Job"] = *job
		data["LabelRules"] = strings.Join(job.LabelRules, "\n")
	} else {
		data["Job"] = store.BackupJob{Mode: "live", Enabled: true}
	}
	return data, nil
}

func (a *app) volumeBackupJobFormHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		data, err := a.jobFormData(nil, r.URL.Query().Get("host"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		data["Title"] = "New backup job"
		render(w, r, "layout", "volume_backup_job.html", data)
		return
	}
	job, err := a.store.GetBackupJob(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data, err := a.jobFormData(&job, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	runs, _ := a.store.ListBackupRuns(job.ID, 15)
	data["Title"], data["Runs"], data["Existing"] = job.Name, a.runViews(runs), true
	data["RepoState"], data["RepoChecked"] = a.repoState(job.DestinationID, job.HostID)
	if d, err := a.store.GetBackupDestination(job.DestinationID); err == nil {
		data["DestName"] = d.Name
	}
	render(w, r, "layout", "volume_backup_job.html", data)
}

// jobFromForm validates a job form against what exists now.
func (a *app) jobFromForm(r *http.Request, existing *store.BackupJob) (store.BackupJob, error) {
	job := store.BackupJob{}
	if existing != nil {
		job = *existing
	}
	job.Name = strings.TrimSpace(r.FormValue("name"))
	if job.Name == "" || len(job.Name) > 80 {
		return job, errors.New("give the job a name (80 characters at most)")
	}
	if existing == nil {
		job.HostID = r.FormValue("host_id")
	}
	if _, err := a.store.GetHost(job.HostID); err != nil {
		return job, errors.New("pick a host")
	}
	job.DestinationID = r.FormValue("destination_id")
	if _, err := a.store.GetBackupDestination(job.DestinationID); err != nil {
		return job, errors.New("pick a destination")
	}

	r.ParseForm()
	vols, _ := a.store.ListHostVolumes()
	choices := hostVolumeChoices(vols, job.HostID)
	known, projects := map[string]bool{}, map[string]bool{}
	for _, c := range choices {
		known[c.Name] = true
		if c.Project != "" {
			projects[c.Project] = true
		}
	}
	const maxPicks = 500
	job.Volumes, job.Stacks, job.Excluded = nil, nil, nil
	for _, v := range r.Form["volumes"] {
		if !known[v] && !(existing != nil && contains(existing.Volumes, v)) {
			return job, fmt.Errorf("%q is not a named volume of this host", v)
		}
		job.Volumes = append(job.Volumes, v)
	}
	for _, s := range r.Form["stacks"] {
		if !projectNameRe.MatchString(s) {
			return job, fmt.Errorf("%q is not a stack name", s)
		}
		if !projects[s] && !(existing != nil && contains(existing.Stacks, s)) {
			return job, fmt.Errorf("this host has no volume of the stack %q", s)
		}
		job.Stacks = append(job.Stacks, s)
	}
	for _, v := range r.Form["excluded"] {
		if !safeVolumeName.MatchString(v) {
			return job, fmt.Errorf("%q is not a volume name", v)
		}
		job.Excluded = append(job.Excluded, v)
	}
	if len(job.Volumes) > maxPicks || len(job.Stacks) > maxPicks || len(job.Excluded) > maxPicks {
		return job, errors.New("too many volumes selected")
	}
	rules, err := parseLabelRules(r.FormValue("label_rules"))
	if err != nil {
		return job, err
	}
	job.LabelRules = rules
	if len(job.Volumes)+len(job.Stacks)+len(job.LabelRules) == 0 {
		return job, errors.New("pick at least one volume, one stack, or a label")
	}

	job.Schedule = strings.TrimSpace(r.FormValue("schedule"))
	if job.Schedule != "" {
		if _, err := cronParser.Parse(job.Schedule); err != nil {
			return job, fmt.Errorf("the schedule is not a 5-field cron expression: %v", err)
		}
	}
	job.Mode = r.FormValue("mode")
	if job.Mode != "live" && job.Mode != "stop" {
		return job, errors.New("pick a consistency mode")
	}
	ret := func(field string) (int, error) {
		v := strings.TrimSpace(r.FormValue(field))
		if v == "" {
			return 0, nil
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 9999 {
			return 0, errors.New("retention counts are whole numbers from 0 to 9999")
		}
		return n, nil
	}
	if job.Retention.KeepLast, err = ret("keep_last"); err != nil {
		return job, err
	}
	if job.Retention.KeepDaily, err = ret("keep_daily"); err != nil {
		return job, err
	}
	if job.Retention.KeepWeekly, err = ret("keep_weekly"); err != nil {
		return job, err
	}
	if job.Retention.KeepMonthly, err = ret("keep_monthly"); err != nil {
		return job, err
	}
	job.Enabled = r.FormValue("enabled") != ""
	return job, nil
}

func (a *app) saveVolumeBackupJobHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var existing *store.BackupJob
	back := "/backups/jobs/new"
	if id != "" {
		j, err := a.store.GetBackupJob(id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		existing, back = &j, "/backups/jobs/"+id
	} else if h := r.FormValue("host_id"); h != "" {
		back += "?host=" + h
	}
	job, err := a.jobFromForm(r, existing)
	if err != nil {
		redirectWithError(w, r, back, err.Error())
		return
	}
	if existing == nil {
		if job.ID, err = randomHex(8); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := a.store.CreateBackupJob(job); err != nil {
			redirectWithError(w, r, back, "could not create the job (name already taken?)")
			return
		}
		a.audit(r, "volume_backup.job_create", job.Name, selectionSummary(job))
	} else {
		if err := a.store.UpdateBackupJob(job); err != nil {
			redirectWithError(w, r, back, "could not save the job (name already taken?)")
			return
		}
		a.audit(r, "volume_backup.job_update", job.Name, selectionSummary(job))
	}
	if err := registerVolumeBackup(a, job); err != nil {
		redirectWithError(w, r, "/backups/jobs/"+job.ID, "saved, but the schedule could not be registered: "+err.Error())
		return
	}
	redirectWithSavedMessage(w, r, "/backups/jobs/"+job.ID, "Job saved")
}

func (a *app) deleteVolumeBackupJobHandler(w http.ResponseWriter, r *http.Request) {
	job, err := a.store.GetBackupJob(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if running, _ := a.store.RunningBackupRuns(); len(running) > 0 {
		for _, run := range running {
			if run.JobID == job.ID {
				redirectWithError(w, r, "/backups/jobs/"+job.ID, "a run of this job is in progress")
				return
			}
		}
	}
	unregisterVolumeBackup(a, job.ID)
	if err := a.store.DeleteBackupJob(job.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.audit(r, "volume_backup.job_delete", job.Name, "")
	redirectWithSavedMessage(w, r, "/backups", "Job removed. Its snapshots stay on the destination")
}

func (a *app) runVolumeBackupHandler(w http.ResponseWriter, r *http.Request) {
	job, err := a.store.GetBackupJob(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	run, err := a.startVolumeBackup(job, "manual", usernameFromContext(r.Context()))
	if run.ID == "" && err != nil {
		redirectWithError(w, r, "/backups/jobs/"+job.ID, err.Error())
		return
	}
	a.audit(r, "volume_backup.run", job.Name, "run "+run.ID)
	if err != nil {
		// the run exists, and says why it did not start
		http.Redirect(w, r, "/backups/runs/"+run.ID, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/backups/runs/"+run.ID, http.StatusSeeOther)
}

// jobAgentAction sends a quick action (test, initialize) for a job's host and destination.
func (a *app) jobAgentAction(ctx context.Context, job store.BackupJob, action string) ([]byte, error) {
	req, err := a.requestForHost(job.DestinationID, job.HostID)
	if err != nil {
		return nil, err
	}
	tc, err := a.connectedAgent(job.HostID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, backupQuickWait+10*time.Second)
	defer cancel()
	return tc.backupCommand(ctx, action, req)
}

func (a *app) testVolumeBackupJobHandler(w http.ResponseWriter, r *http.Request) {
	job, err := a.store.GetBackupJob(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	back := "/backups/jobs/" + job.ID
	msg, err := a.testDestination(r.Context(), job.DestinationID, job.HostID)
	if err != nil {
		redirectWithError(w, r, back, err.Error())
		return
	}
	redirectWithSavedMessage(w, r, back, msg)
}

func (a *app) initVolumeBackupJobHandler(w http.ResponseWriter, r *http.Request) {
	job, err := a.store.GetBackupJob(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	back := "/backups/jobs/" + job.ID
	if _, err := a.jobAgentAction(r.Context(), job, "backup_init"); err != nil {
		if strings.Contains(err.Error(), "already initialized") {
			a.noteRepo(job.DestinationID, job.HostID, true)
			redirectWithSavedMessage(w, r, back, "The repository was already initialized: it is ready")
			return
		}
		redirectWithError(w, r, back, err.Error())
		return
	}
	a.noteRepo(job.DestinationID, job.HostID, true)
	a.audit(r, "volume_backup.repository_init", job.Name, "host "+a.hostName(job.HostID))
	redirectWithSavedMessage(w, r, back, "The repository is initialized for this host")
}

func (a *app) volumeBackupRunHandler(w http.ResponseWriter, r *http.Request) {
	run, err := a.store.GetBackupRun(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	job, _ := a.store.GetBackupJob(run.JobID)
	render(w, r, "layout", "volume_backup_run.html", map[string]any{
		"Title": "Backup run", "Nav": "backups", "Run": newRunView(run, job.Name), "Job": job, "HostName": a.hostName(job.HostID),
	})
}

// ---- restore

type snapshotRow struct {
	ID, ShortID, Time string
}

func (a *app) volumeBackupRestoreFormHandler(w http.ResponseWriter, r *http.Request) {
	job, err := a.store.GetBackupJob(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	restorable := a.restorableVolumes(job)
	volume := r.URL.Query().Get("volume")
	if volume == "" && len(restorable) > 0 {
		volume = restorable[0]
	}
	if !contains(restorable, volume) {
		http.NotFound(w, r)
		return
	}
	data := map[string]any{"Title": "Restore " + volume, "Nav": "backups", "Job": job, "Volume": volume,
		"NewVolume": volume + "-restored", "Volumes": restorable}

	req, err := a.requestForHost(job.DestinationID, job.HostID)
	if err == nil {
		var tc backupAgent
		if tc, err = a.connectedAgent(job.HostID); err == nil {
			req.Volume = volume
			ctx, cancel := context.WithTimeout(r.Context(), backupQuickWait+10*time.Second)
			defer cancel()
			var raw []byte
			if raw, err = tc.backupCommand(ctx, "backup_snapshots", req); err == nil {
				var snaps []snapshotInfo
				if snaps, err = parseSnapshotList(raw); err == nil {
					sort.Slice(snaps, func(i, j int) bool { return snaps[i].Time > snaps[j].Time })
					rows := make([]snapshotRow, 0, len(snaps))
					for _, s := range snaps {
						rows = append(rows, snapshotRow{ID: s.ID, ShortID: s.ShortID, Time: snapshotTime(s.Time)})
					}
					data["Snapshots"] = rows
				}
			}
		}
	}
	if err != nil {
		data["LoadError"] = err.Error()
	}
	render(w, r, "layout", "volume_backup_restore.html", data)
}

func snapshotTime(raw string) string {
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return raw
	}
	return t.UTC().Format("2006-01-02 15:04:05") // UTC, converted in the browser (data-utc)
}

func (a *app) volumeBackupRestoreHandler(w http.ResponseWriter, r *http.Request) {
	job, err := a.store.GetBackupJob(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	volume := r.FormValue("volume")
	newVolume := strings.TrimSpace(r.FormValue("new_volume"))
	snapshot := strings.TrimSpace(r.FormValue("snapshot"))
	back := "/backups/jobs/" + job.ID + "/restore?volume=" + volume
	if !contains(a.restorableVolumes(job), volume) {
		http.NotFound(w, r)
		return
	}
	if !safeVolumeName.MatchString(newVolume) {
		redirectWithError(w, r, back, "the new volume's name must start with a letter or digit and use only letters, digits, . _ -")
		return
	}
	if !snapshotIDPattern.MatchString(snapshot) {
		redirectWithError(w, r, back, "pick a snapshot")
		return
	}
	run, err := a.startVolumeRestore(job, snapshot, volume, newVolume, usernameFromContext(r.Context()))
	if run.ID == "" && err != nil {
		redirectWithError(w, r, back, err.Error())
		return
	}
	a.audit(r, "volume_backup.restore", job.Name, volume+" → "+newVolume+" from "+snapshot[:8])
	http.Redirect(w, r, "/backups/runs/"+run.ID, http.StatusSeeOther)
}
