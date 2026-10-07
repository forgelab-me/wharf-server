package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// What the controller sends the agent for a volume backup action, and what a
// run reports back. The agent defines the same JSON (agent/backup.go): the two
// are kept in step by hand, like the rest of the agent protocol.

type agentBackupDestination struct {
	Server       string `json:"server"`
	Share        string `json:"share"`
	Subdir       string `json:"subdir,omitempty"`
	Version      string `json:"version"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Domain       string `json:"domain,omitempty"`
	RepoDir      string `json:"repo_dir"`
	RepoPassword string `json:"repo_password"`
}

type agentRetention struct {
	KeepLast    int `json:"keep_last,omitempty"`
	KeepDaily   int `json:"keep_daily,omitempty"`
	KeepWeekly  int `json:"keep_weekly,omitempty"`
	KeepMonthly int `json:"keep_monthly,omitempty"`
}

type agentBackupRequest struct {
	RunID     string                 `json:"run_id,omitempty"`
	Dest      agentBackupDestination `json:"dest"`
	HostTag   string                 `json:"host_tag"`
	Volumes   []string               `json:"volumes,omitempty"`
	Mode      string                 `json:"mode,omitempty"`
	Retention agentRetention         `json:"retention,omitempty"`
	Snapshot  string                 `json:"snapshot,omitempty"`
	Volume    string                 `json:"volume,omitempty"`
	NewVolume string                 `json:"new_volume,omitempty"`
}

// agentRunReport is what an agent posts to /agent/backup-runs/{id}/report.
type agentRunReport struct {
	Kind     string `json:"kind"`
	Status   string `json:"status"`
	Code     string `json:"code,omitempty"`
	Message  string `json:"message,omitempty"`
	Restored string `json:"restored,omitempty"`
	Volumes  []struct {
		Volume          string `json:"volume"`
		Status          string `json:"status"`
		SnapshotID      string `json:"snapshot_id,omitempty"`
		FilesNew        int    `json:"files_new,omitempty"`
		FilesChanged    int    `json:"files_changed,omitempty"`
		FilesUnmodified int    `json:"files_unmodified,omitempty"`
		DataAdded       int64  `json:"data_added,omitempty"`
		TotalBytes      int64  `json:"total_bytes,omitempty"`
		Message         string `json:"message,omitempty"`
		Retention       string `json:"retention,omitempty"`
	} `json:"volumes,omitempty"`
}

// minAgentForBackups is the first agent that knows the backup actions.
const minAgentForBackups = "0.9.0"

// agentCannotBackUp: an agent that never reported its version predates version
// reporting; a non-release build ("dev") is let through, as for secret references.
func agentCannotBackUp(agentVersion string) bool {
	return agentVersion == "" || semverLess(agentVersion, minAgentForBackups)
}

func agentTooOldForBackups(agentVersion string) string {
	if agentVersion == "" {
		agentVersion = "an unknown version"
	}
	return "volume backups need agent " + minAgentForBackups + " or later (this host runs " + agentVersion + "): update the agent first"
}

// Waits for the agent's reply to a quick action: it may begin by pulling the
// restic image, then mount a share.
const backupQuickWait = 150 * time.Second

// backupCommand sends one quick action and waits for its answer.
func (tc *tunnelConn) backupCommand(ctx context.Context, action string, req agentBackupRequest) ([]byte, error) {
	reply, err := tc.sendWithin(ctx, tunnelMessage{Action: action, Backup: &req}, backupQuickWait)
	if err != nil {
		return nil, err
	}
	if !reply.OK {
		return nil, errors.New(cleanAgentMessage(reply.Output))
	}
	return []byte(reply.Output), nil
}

// startBackupAction hands a run to the agent, which answers at once and reports later.
func (tc *tunnelConn) startBackupAction(ctx context.Context, action string, req agentBackupRequest) error {
	reply, err := tc.sendWithin(ctx, tunnelMessage{Action: action, Backup: &req}, 30*time.Second)
	if err != nil {
		return err
	}
	if !reply.OK {
		return errors.New(cleanAgentMessage(reply.Output))
	}
	return nil
}

func cleanAgentMessage(s string) string {
	if len(s) > 600 {
		s = s[:600] + "…"
	}
	return s
}

// quickTestResult is what the agent answers to backup_test.
type quickTestResult struct {
	Mounted     bool   `json:"mounted"`
	Writable    bool   `json:"writable"`
	Initialized bool   `json:"initialized"`
	Message     string `json:"message"`
}

func parseTestResult(raw []byte) (quickTestResult, error) {
	var r quickTestResult
	if err := json.Unmarshal(raw, &r); err != nil {
		return r, fmt.Errorf("the agent answered something unexpected")
	}
	return r, nil
}

// snapshotInfo is one snapshot as the agent lists it.
type snapshotInfo struct {
	ID       string   `json:"id"`
	ShortID  string   `json:"short_id"`
	Time     string   `json:"time"`
	Hostname string   `json:"hostname"`
	Tags     []string `json:"tags"`
}

func parseSnapshotList(raw []byte) ([]snapshotInfo, error) {
	var out struct {
		Snapshots []snapshotInfo `json:"snapshots"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("the agent answered something unexpected")
	}
	return out.Snapshots, nil
}
