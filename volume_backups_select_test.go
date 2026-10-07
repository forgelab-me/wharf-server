package main

import (
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/forgelab-me/wharf-server/internal/store"
)

func lbl(project string, kv ...string) map[string]string {
	m := map[string]string{}
	if project != "" {
		m[composeProjectLabel] = project
	}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

func demoChoices() []volumeChoice {
	return []volumeChoice{
		{Name: "monitoring_grafana-data", Project: "monitoring", Labels: lbl("monitoring", "wharf.backup", "nightly")},
		{Name: "monitoring_prometheus-data", Project: "monitoring", Labels: lbl("monitoring")},
		{Name: "pi-hole_etc-dnsmasq", Project: "pi-hole", Labels: lbl("pi-hole")},
		{Name: "pi-hole_etc-pihole", Project: "pi-hole", Labels: lbl("pi-hole", "wharf.backup", "nightly")},
		{Name: "uptime-kuma_data", Project: "uptime-kuma", Labels: lbl("uptime-kuma", "wharf.backup", "weekly")},
		{Name: "scratch-cache", Labels: map[string]string{}},
	}
}

func names(sel selection) []string { return sel.Names() }

func TestASelectionIsTheUnionOfTicksStacksAndLabels(t *testing.T) {
	job := store.BackupJob{
		Volumes:    []string{"scratch-cache"},
		Stacks:     []string{"uptime-kuma"},
		LabelRules: []string{"wharf.backup=nightly"},
	}
	sel := resolveSelection(job, demoChoices())
	want := []string{"monitoring_grafana-data", "pi-hole_etc-pihole", "scratch-cache", "uptime-kuma_data"}
	if got := names(sel); !reflect.DeepEqual(got, want) {
		t.Fatalf("selected = %v, want %v", got, want)
	}
	why := map[string][]string{}
	for _, v := range sel.Volumes {
		why[v.Name] = v.Why
	}
	if !reflect.DeepEqual(why["scratch-cache"], []string{"ticked"}) || !reflect.DeepEqual(why["uptime-kuma_data"], []string{"stack uptime-kuma"}) ||
		!reflect.DeepEqual(why["monitoring_grafana-data"], []string{"label wharf.backup=nightly"}) {
		t.Errorf("each volume says why: %v", why)
	}
	// a volume that two things select is taken once, with both reasons
	job.Stacks = []string{"monitoring"}
	sel = resolveSelection(job, demoChoices())
	for _, v := range sel.Volumes {
		if v.Name == "monitoring_grafana-data" && len(v.Why) != 2 {
			t.Errorf("both reasons: %v", v.Why)
		}
	}
	if n := len(names(sel)); n != 4 {
		t.Errorf("no duplicate: %v", names(sel))
	}
}

func TestAWholeStackTakesItsNewVolumesToo(t *testing.T) {
	job := store.BackupJob{Stacks: []string{"monitoring"}}
	choices := append(demoChoices(), volumeChoice{Name: "monitoring_loki-data", Project: "monitoring", Labels: lbl("monitoring")})
	got := names(resolveSelection(job, choices))
	if !reflect.DeepEqual(got, []string{"monitoring_grafana-data", "monitoring_loki-data", "monitoring_prometheus-data"}) {
		t.Errorf("a volume added to the stack is in the job: %v", got)
	}
	// a stack this host has nothing of selects nothing, and is not an error
	if got := names(resolveSelection(store.BackupJob{Stacks: []string{"gone"}}, demoChoices())); len(got) != 0 {
		t.Errorf("an empty stack: %v", got)
	}
}

func TestLabelRulesMatchByKeyOrByKeyAndValue(t *testing.T) {
	cases := []struct {
		rule   string
		labels map[string]string
		want   bool
	}{
		{"wharf.backup", lbl("", "wharf.backup", "nightly"), true},
		{"wharf.backup", lbl("", "wharf.backup", ""), true},
		{"wharf.backup", lbl("", "other", "x"), false},
		{"wharf.backup=nightly", lbl("", "wharf.backup", "nightly"), true},
		{"wharf.backup=nightly", lbl("", "wharf.backup", "weekly"), false},
		{"wharf.backup=nightly", lbl("", "wharf.backup2", "nightly"), false},
		{"wharf.backup=", lbl("", "wharf.backup", ""), true},
		{"wharf.backup=", lbl("", "wharf.backup", "x"), false},
		{"a=b=c", lbl("", "a", "b=c"), true},
		{"wharf.backup", nil, false},
	}
	for _, c := range cases {
		if got := labelRuleMatches(c.rule, c.labels); got != c.want {
			t.Errorf("rule %q on %v = %v, want %v", c.rule, c.labels, got, c.want)
		}
	}
	// several rules are an "or"
	job := store.BackupJob{LabelRules: []string{"wharf.backup=weekly", "wharf.backup=nightly"}}
	if n := len(names(resolveSelection(job, demoChoices()))); n != 3 {
		t.Errorf("a volume that fits any line is taken: %d", n)
	}
}

func TestExcludingAVolumeWinsOverEverythingThatSelectsIt(t *testing.T) {
	job := store.BackupJob{
		Volumes:    []string{"scratch-cache"},
		Stacks:     []string{"monitoring"},
		LabelRules: []string{"wharf.backup=nightly"},
		Excluded:   []string{"monitoring_prometheus-data", "monitoring_grafana-data", "scratch-cache", "pi-hole_etc-dnsmasq"},
	}
	sel := resolveSelection(job, demoChoices())
	if got := names(sel); !reflect.DeepEqual(got, []string{"pi-hole_etc-pihole"}) {
		t.Errorf("selected = %v", got)
	}
	// reported as left out: what was selected by the stack, a label or a tick; not what nothing selected
	if got := sel.Excluded; !reflect.DeepEqual(got, []string{"monitoring_grafana-data", "monitoring_prometheus-data", "scratch-cache"}) {
		t.Errorf("left out = %v (pi-hole_etc-dnsmasq was never selected)", got)
	}
}

func TestATickedVolumeThatIsGoneStaysSelectedSoTheAgentSaysSo(t *testing.T) {
	job := store.BackupJob{Volumes: []string{"vanished"}}
	if got := names(resolveSelection(job, demoChoices())); !reflect.DeepEqual(got, []string{"vanished"}) {
		t.Errorf("selected = %v", got)
	}
	job.Excluded = []string{"vanished"}
	if got := names(resolveSelection(job, demoChoices())); len(got) != 0 {
		t.Errorf("unless it is left out: %v", got)
	}
}

func TestHostVolumeChoicesKeepOnlyWhatAPersonMade(t *testing.T) {
	vols := []store.HostVolume{
		{HostID: "h", Name: "blog_data", Driver: "local", Labels: lbl("blog")},
		{HostID: "h", Name: strings.Repeat("ab", 32), Driver: "local"},
		{HostID: "h", Name: "wharf-bk-1", Driver: "local"},
		{HostID: "h", Name: "nfs", Driver: "nfs"},
		{HostID: "other", Name: "elsewhere", Driver: "local"},
		{HostID: "h", Name: "a_first", Driver: "local"},
	}
	got := hostVolumeChoices(vols, "h")
	if len(got) != 2 || got[0].Name != "a_first" || got[1].Name != "blog_data" || got[1].Project != "blog" {
		t.Errorf("choices = %+v", got)
	}
}

func TestParseLabelRules(t *testing.T) {
	got, err := parseLabelRules("  wharf.backup=nightly \n\nwharf.backup=nightly\nbackup/tier\n")
	if err != nil || !reflect.DeepEqual(got, []string{"wharf.backup=nightly", "backup/tier"}) {
		t.Errorf("rules = %v %v", got, err)
	}
	for _, bad := range []string{"=value", "has space=x", "a,b", "-lead", strings.Repeat("k", 200), "k=" + strings.Repeat("v", 300)} {
		if _, err := parseLabelRules(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	many := strings.Repeat("a=b\n", 1) + strings.Join(func() []string {
		var l []string
		for i := 0; i < 25; i++ {
			l = append(l, "k"+strings.Repeat("x", i)+"=1")
		}
		return l
	}(), "\n")
	if _, err := parseLabelRules(many); err == nil {
		t.Error("too many rules")
	}
	if rules, err := parseLabelRules(""); err != nil || len(rules) != 0 {
		t.Errorf("no rule is fine: %v %v", rules, err)
	}
}

// ---- through the pages and the runs

func (f *vbFixture) setVolumes(t *testing.T, vols ...store.HostVolume) {
	t.Helper()
	for i := range vols {
		vols[i].HostID, vols[i].Driver = f.host.ID, "local"
	}
	if err := f.a.store.ReplaceHostVolumes(f.host.ID, vols); err != nil {
		t.Fatal(err)
	}
}

func (f *vbFixture) saveJob(t *testing.T, destID string, form url.Values) (store.BackupJob, string) {
	t.Helper()
	base := url.Values{"name": {"sel"}, "host_id": {f.host.ID}, "destination_id": {destID}, "mode": {"live"}}
	for k, v := range form {
		base[k] = v
	}
	_, loc := call(f.a.saveVolumeBackupJobHandler, "/backups/jobs", base, nil)
	jobs, _ := f.a.store.ListBackupJobs()
	for _, j := range jobs {
		if j.Name == base.Get("name") {
			return j, redirectParam(t, loc, "error")
		}
	}
	return store.BackupJob{}, redirectParam(t, loc, "error")
}

func TestAJobFormSavesStacksExclusionsAndLabelRules(t *testing.T) {
	f := newVBFixture(t)
	dest, _ := f.createDest(t, "nas")
	f.setVolumes(t,
		store.HostVolume{Name: "monitoring_grafana-data", Labels: lbl("monitoring")},
		store.HostVolume{Name: "monitoring_prometheus-data", Labels: lbl("monitoring")},
		store.HostVolume{Name: "scratch-cache"})

	job, msg := f.saveJob(t, dest.ID, url.Values{
		"stacks": {"monitoring"}, "excluded": {"monitoring_prometheus-data"}, "volumes": {"scratch-cache"}, "label_rules": {"wharf.backup=nightly\nbackup"},
	})
	if msg != "" {
		t.Fatalf("a valid job: %q", msg)
	}
	if !reflect.DeepEqual(job.Stacks, []string{"monitoring"}) || !reflect.DeepEqual(job.Excluded, []string{"monitoring_prometheus-data"}) ||
		!reflect.DeepEqual(job.Volumes, []string{"scratch-cache"}) || !reflect.DeepEqual(job.LabelRules, []string{"wharf.backup=nightly", "backup"}) {
		t.Errorf("job = %+v", job)
	}
	if got := names(f.a.resolveJobVolumes(job)); !reflect.DeepEqual(got, []string{"monitoring_grafana-data", "scratch-cache"}) {
		t.Errorf("covers = %v", got)
	}
	// the audit log says what it selects
	entries, _ := f.a.store.ListAudit(5)
	found := false
	for _, e := range entries {
		if e.Action == "volume_backup.job_create" && strings.Contains(e.Detail, "stacks monitoring") && strings.Contains(e.Detail, "left out monitoring_prometheus-data") {
			found = true
		}
	}
	if !found {
		t.Errorf("audit = %+v", entries)
	}

	// only labels is a valid job, even before any volume has them
	if j, msg := f.saveJob(t, dest.ID, url.Values{"name": {"by-label"}, "label_rules": {"wharf.backup"}}); msg != "" || len(j.LabelRules) != 1 {
		t.Errorf("a job by label alone: %q %+v", msg, j)
	}
	for name, form := range map[string]url.Values{
		"nothing selected":       {"name": {"e1"}},
		"a stack the host lacks": {"name": {"e2"}, "stacks": {"nope"}},
		"a bad stack name":       {"name": {"e3"}, "stacks": {"../x"}},
		"a bad exclusion":        {"name": {"e4"}, "stacks": {"monitoring"}, "excluded": {"a/b"}},
		"a bad label":            {"name": {"e5"}, "label_rules": {"has space"}},
		"an unknown volume":      {"name": {"e6"}, "volumes": {"ghost"}},
	} {
		if _, msg := f.saveJob(t, dest.ID, form); msg == "" {
			t.Errorf("%s must be refused", name)
		}
	}
}

func TestARunTakesWhatTheJobCoversNow(t *testing.T) {
	f := newVBFixture(t)
	dest, _ := f.createDest(t, "nas")
	f.setVolumes(t,
		store.HostVolume{Name: "monitoring_grafana-data", Labels: lbl("monitoring")},
		store.HostVolume{Name: "db", Labels: lbl("", "wharf.backup", "nightly")},
		store.HostVolume{Name: "other"})
	job, msg := f.saveJob(t, dest.ID, url.Values{"stacks": {"monitoring"}, "label_rules": {"wharf.backup=nightly"}, "excluded": {"db"}})
	if msg != "" {
		t.Fatal(msg)
	}

	if _, err := f.a.startVolumeBackup(job, "manual", "alice"); err != nil {
		t.Fatal(err)
	}
	if got := f.agent.requests[0].Volumes; !reflect.DeepEqual(got, []string{"monitoring_grafana-data"}) {
		t.Errorf("the agent is sent explicit names, db being left out: %v", got)
	}

	// volumes appear on the host: one in the stack, one with the label. No change to the job.
	f.a.store.FailStaleBackupRuns("2999-01-01 00:00:00", "x") // the first run never reports in this test: close it
	f.setVolumes(t,
		store.HostVolume{Name: "monitoring_grafana-data", Labels: lbl("monitoring")},
		store.HostVolume{Name: "monitoring_loki-data", Labels: lbl("monitoring")},
		store.HostVolume{Name: "db", Labels: lbl("", "wharf.backup", "nightly")},
		store.HostVolume{Name: "blog_uploads", Labels: lbl("blog", "wharf.backup", "nightly")},
		store.HostVolume{Name: "other"})
	if _, err := f.a.startVolumeBackup(job, "manual", "alice"); err != nil {
		t.Fatal(err)
	}
	if got := f.agent.requests[1].Volumes; !reflect.DeepEqual(got, []string{"blog_uploads", "monitoring_grafana-data", "monitoring_loki-data"}) {
		t.Errorf("new volumes are taken without touching the job: %v", got)
	}
}

func TestAJobThatSelectsNothingNowIsRecordedAsAnError(t *testing.T) {
	f := newVBFixture(t)
	dest, _ := f.createDest(t, "nas")
	f.setVolumes(t, store.HostVolume{Name: "db", Labels: lbl("", "wharf.backup", "nightly")})
	job, msg := f.saveJob(t, dest.ID, url.Values{"label_rules": {"wharf.backup=nightly"}, "stacks": {}})
	if msg != "" {
		t.Fatal(msg)
	}
	f.setVolumes(t, store.HostVolume{Name: "db"}) // the label is gone

	run, err := f.a.startVolumeBackup(job, "schedule", "backup-schedule")
	if err == nil || !strings.Contains(err.Error(), "selects no volume right now") || !strings.Contains(err.Error(), "wharf.backup=nightly") {
		t.Fatalf("a clear refusal: %v", err)
	}
	if len(f.agent.calls) != 0 {
		t.Errorf("nothing was sent: %v", f.agent.calls)
	}
	if stored, _ := f.a.store.GetBackupRun(run.ID); stored.Status != "error" || stored.Code != "VALIDATION" {
		t.Errorf("recorded: %+v", stored)
	}
}

func TestTwoJobsThatCoverTheSameVolumeByDifferentMeansDoNotOverlap(t *testing.T) {
	f := newVBFixture(t)
	dest, _ := f.createDest(t, "nas")
	f.setVolumes(t, store.HostVolume{Name: "db", Labels: lbl("shop", "wharf.backup", "nightly")}, store.HostVolume{Name: "cache"})
	byLabel, _ := f.saveJob(t, dest.ID, url.Values{"name": {"by-label"}, "label_rules": {"wharf.backup=nightly"}})
	byStack, _ := f.saveJob(t, dest.ID, url.Values{"name": {"by-stack"}, "stacks": {"shop"}})
	other, _ := f.saveJob(t, dest.ID, url.Values{"name": {"cache"}, "volumes": {"cache"}})

	if _, err := f.a.startVolumeBackup(byLabel, "manual", "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.startVolumeBackup(byStack, "manual", "a"); err == nil || !strings.Contains(err.Error(), `"db"`) {
		t.Errorf("the same volume, covered another way: %v", err)
	}
	if _, err := f.a.startVolumeBackup(other, "manual", "a"); err != nil {
		t.Errorf("a different volume is free: %v", err)
	}
}

func TestAVolumeThatWasBackedUpCanBeRestoredAfterItIsGone(t *testing.T) {
	f := newVBFixture(t)
	dest, _ := f.createDest(t, "nas")
	f.setVolumes(t, store.HostVolume{Name: "db", Labels: lbl("shop")})
	job, _ := f.saveJob(t, dest.ID, url.Values{"stacks": {"shop"}})
	run, _ := f.a.startVolumeBackup(job, "manual", "a")
	reportCall(f, run.ID, map[string]any{"kind": "backup", "status": "success", "volumes": []map[string]any{
		{"volume": "db", "status": "success", "snapshot_id": "aabbccdd"}, {"volume": "uploads", "status": "success", "snapshot_id": "11223344"}, {"volume": "bad", "status": "error"}}}, resolveTestCert)

	f.setVolumes(t) // the host has no volume any more
	got := f.a.restorableVolumes(job)
	if !reflect.DeepEqual(got, []string{"db", "uploads"}) {
		t.Errorf("what the job has backed up, and not a volume that failed: %v", got)
	}
	form := url.Values{"volume": {"uploads"}, "snapshot": {"11223344"}, "new_volume": {"uploads-restored"}}
	if code, loc := call(f.a.volumeBackupRestoreHandler, "/x", form, map[string]string{"id": job.ID}); code != 303 || !strings.HasPrefix(loc, "/backups/runs/") {
		t.Errorf("restore of a gone volume: %d %s", code, loc)
	}
	if code, _ := call(f.a.volumeBackupRestoreHandler, "/x", url.Values{"volume": {"never"}, "snapshot": {"aabbccdd"}, "new_volume": {"x"}}, map[string]string{"id": job.ID}); code != 404 {
		t.Errorf("a volume the job never had: %d", code)
	}
}

func TestThePagesShowTheTreeAndWhatTheJobCovers(t *testing.T) {
	f := newVBFixture(t)
	dest, _ := f.createDest(t, "nas")
	f.setVolumes(t, store.HostVolume{Name: "monitoring_grafana-data", Labels: lbl("monitoring", "wharf.backup", "nightly")}, store.HostVolume{Name: "scratch"})
	job, _ := f.saveJob(t, dest.ID, url.Values{"stacks": {"monitoring"}, "excluded": {"scratch"}})

	page := get(f.a.volumeBackupJobFormHandler, "/x", map[string]string{"id": job.ID}).Body.String()
	for _, want := range []string{`id="vt-data"`, `"n":"monitoring_grafana-data"`, `"p":"monitoring"`, `"stacks":["monitoring"]`, `"excluded":["scratch"]`, `id="vtree"`, "Expand all", `name="label_rules"`} {
		if !strings.Contains(page, want) {
			t.Errorf("the job page lacks %q", want)
		}
	}
	list := getAs("admin", f.a.volumeBackupsHandler, "/backups")
	if !strings.Contains(list, "monitoring_grafana-data") {
		t.Errorf("the list names the volumes the job covers: %s", list)
	}
	// a volume name or a label cannot break out of the data block
	f.setVolumes(t, store.HostVolume{Name: "x", Labels: map[string]string{"k": "</script><b>"}})
	page = get(f.a.volumeBackupJobFormHandler, "/backups/jobs/new?host="+f.host.ID, nil).Body.String()
	if strings.Contains(page, "</script><b>") {
		t.Error("labels are escaped in the data block")
	}

	f.setVolumes(t)
	if list := getAs("admin", f.a.volumeBackupsHandler, "/backups"); !strings.Contains(list, "none right now") {
		t.Errorf("and says so when there are none: %s", list)
	}
}
