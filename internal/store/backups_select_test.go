package store

import (
	"reflect"
	"testing"
)

func TestAJobKeepsItsSelection(t *testing.T) {
	s := openTest(t)
	job := BackupJob{ID: "j1", Name: "sel", HostID: "h1", DestinationID: "d1", Mode: "live", Enabled: true,
		Volumes: []string{"scratch"}, Stacks: []string{"monitoring", "pi-hole"}, LabelRules: []string{"wharf.backup=nightly", "tier"}, Excluded: []string{"monitoring_loki-data"}}
	if err := s.CreateBackupJob(job); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetBackupJob("j1")
	if err != nil || !reflect.DeepEqual(got.Stacks, job.Stacks) || !reflect.DeepEqual(got.LabelRules, job.LabelRules) ||
		!reflect.DeepEqual(got.Excluded, job.Excluded) || !reflect.DeepEqual(got.Volumes, job.Volumes) {
		t.Fatalf("job = %+v %v", got, err)
	}
	got.Stacks, got.Excluded = nil, nil
	if err := s.UpdateBackupJob(got); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.GetBackupJob("j1"); len(again.Stacks) != 0 || len(again.Excluded) != 0 || len(again.LabelRules) != 2 {
		t.Errorf("updated = %+v", again)
	}
	if list, _ := s.ListBackupJobs(); len(list) != 1 || len(list[0].LabelRules) != 2 {
		t.Errorf("list = %+v", list)
	}
}

func TestAJobSavedBeforeTheSelectionColumnsExistedStillLoads(t *testing.T) {
	s := openTest(t)
	// what an older database holds: the columns added later are empty text, not a JSON list
	if _, err := s.db.Exec(`INSERT INTO backup_jobs (id, name, host_id, destination_id, volumes, stacks, label_rules, excluded, mode) VALUES ('old', 'old', 'h', 'd', '["a","b"]', '', '', '', 'live')`); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetBackupJob("old")
	if err != nil || !reflect.DeepEqual(got.Volumes, []string{"a", "b"}) || len(got.Stacks) != 0 || len(got.LabelRules) != 0 || len(got.Excluded) != 0 {
		t.Errorf("old job = %+v %v", got, err)
	}
}

func TestVolumesKeepTheirLabels(t *testing.T) {
	s := openTest(t)
	h, _, _ := s.UpsertHostByFingerprint("nas", "sha256:1")
	err := s.ReplaceHostVolumes(h.ID, []HostVolume{
		{HostID: h.ID, Name: "monitoring_grafana-data", Driver: "local", Labels: map[string]string{"com.docker.compose.project": "monitoring", "note": "a,b=c"}},
		{HostID: h.ID, Name: "plain", Driver: "local"},
	})
	if err != nil {
		t.Fatal(err)
	}
	vols, err := s.ListHostVolumes()
	if err != nil || len(vols) != 2 {
		t.Fatalf("volumes = %+v %v", vols, err)
	}
	for _, v := range vols {
		switch v.Name {
		case "monitoring_grafana-data":
			if v.Labels["com.docker.compose.project"] != "monitoring" || v.Labels["note"] != "a,b=c" {
				t.Errorf("labels = %v", v.Labels)
			}
		case "plain":
			if len(v.Labels) != 0 {
				t.Errorf("no labels: %v", v.Labels)
			}
		}
	}
}
