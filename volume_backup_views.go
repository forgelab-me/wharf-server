package main

import (
	"time"

	"github.com/forgelab-me/wharf-server/internal/store"
)

// What the backup pages show, with the sizes and times already written out:
// the templates have no functions of their own.

// dbTime reads a "YYYY-MM-DD HH:MM:SS" UTC time out of the database.
func dbTime(s string) (time.Time, bool) {
	t, err := time.ParseInLocation("2006-01-02 15:04:05", s, time.UTC)
	return t, err == nil
}

func runDuration(r store.BackupRun) string {
	start, ok := dbTime(r.StartedAt)
	if !ok {
		return ""
	}
	end := time.Now().UTC()
	if r.FinishedAt != "" {
		if t, ok := dbTime(r.FinishedAt); ok {
			end = t
		}
	}
	d := end.Sub(start).Round(time.Second)
	if d < 0 {
		d = 0
	}
	return d.String()
}

type volumeResultView struct {
	store.BackupVolumeResult
	Added, Total string
}

type runView struct {
	store.BackupRun
	Started, Duration string
	Volumes           []volumeResultView
	JobName           string
	Added             string // the data this run added to the repository, all volumes
}

func newRunView(r store.BackupRun, jobName string) runView {
	// Started stays UTC: the page marks it data-utc and the browser converts it.
	v := runView{BackupRun: r, Started: r.StartedAt, Duration: runDuration(r), JobName: jobName}
	var added int64
	for _, res := range r.Results {
		v.Volumes = append(v.Volumes, volumeResultView{BackupVolumeResult: res, Added: humanSize(res.DataAdded), Total: humanSize(res.TotalBytes)})
		added += res.DataAdded
	}
	if r.Kind == "backup" && len(r.Results) > 0 {
		v.Added = humanSize(added)
	}
	return v
}

func (a *app) runViews(runs []store.BackupRun) []runView {
	names := map[string]string{}
	out := make([]runView, 0, len(runs))
	for _, r := range runs {
		name, ok := names[r.JobID]
		if !ok {
			if j, err := a.store.GetBackupJob(r.JobID); err == nil {
				name = j.Name
			}
			names[r.JobID] = name
		}
		out = append(out, newRunView(r, name))
	}
	return out
}
