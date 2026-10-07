package main

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/forgelab-me/wharf-server/internal/store"
)

// Which volumes a backup job covers. A job takes the union of three things:
// volumes ticked one by one, every volume of some stacks (Compose's project
// label), and every volume with one of some labels. A volume the job excludes is
// never taken, whatever else selects it. Cf. ARCHITECTURE.md, "Choisir les
// volumes d'un job par stack et par label".

// composeProjectLabel is the label Docker Compose puts on a volume it creates:
// the project's name, which for a stack Wharf deployed is the stack's id.
const composeProjectLabel = "com.docker.compose.project"

var (
	labelKeyRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
	projectNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
)

const maxLabelRules = 20

// volumeChoice is a named volume of a host, with what its selection depends on.
type volumeChoice struct {
	Name    string            `json:"n"`
	Project string            `json:"p"`
	Labels  map[string]string `json:"l"`
}

// hostVolumeChoices lists the volumes of a host that a person made: no anonymous
// volume, none of the temporary share volumes, only the local driver.
func hostVolumeChoices(vols []store.HostVolume, hostID string) []volumeChoice {
	var out []volumeChoice
	for _, v := range vols {
		if v.HostID != hostID || v.Driver != "local" || isAnonymousVolume(v.Name) || strings.HasPrefix(v.Name, "wharf-bk-") {
			continue
		}
		out = append(out, volumeChoice{Name: v.Name, Project: v.Labels[composeProjectLabel], Labels: v.Labels})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// labelRuleMatches: "key" matches a volume that has the label, "key=value" one whose value is exactly that.
func labelRuleMatches(rule string, labels map[string]string) bool {
	key, value, hasValue := strings.Cut(rule, "=")
	have, ok := labels[key]
	return ok && (!hasValue || have == value)
}

type selectedVolume struct {
	Name string
	Why  []string // "ticked", "stack x", "label k=v"
}

// selection is what a job covers now.
type selection struct {
	Volumes  []selectedVolume
	Excluded []string // volumes something selected and the job leaves out
}

func (s selection) Names() []string {
	names := make([]string, len(s.Volumes))
	for i, v := range s.Volumes {
		names[i] = v.Name
	}
	return names
}

// resolveSelection works out the volumes of a job from the volumes of its host.
func resolveSelection(job store.BackupJob, choices []volumeChoice) selection {
	ticked, stacks, excluded := set(job.Volumes), set(job.Stacks), set(job.Excluded)
	var sel selection
	seen := map[string]bool{}
	for _, c := range choices {
		seen[c.Name] = true
		var why []string
		if ticked[c.Name] {
			why = append(why, "ticked")
		}
		if c.Project != "" && stacks[c.Project] {
			why = append(why, "stack "+c.Project)
		}
		for _, rule := range job.LabelRules {
			if labelRuleMatches(rule, c.Labels) {
				why = append(why, "label "+rule)
			}
		}
		switch {
		case len(why) == 0:
		case excluded[c.Name]:
			sel.Excluded = append(sel.Excluded, c.Name)
		default:
			sel.Volumes = append(sel.Volumes, selectedVolume{Name: c.Name, Why: why})
		}
	}
	// a ticked volume the host no longer reports stays in the selection: the agent says so, volume by volume
	for _, name := range job.Volumes {
		if !seen[name] && !excluded[name] {
			sel.Volumes = append(sel.Volumes, selectedVolume{Name: name, Why: []string{"ticked"}})
		}
	}
	sort.Slice(sel.Volumes, func(i, j int) bool { return sel.Volumes[i].Name < sel.Volumes[j].Name })
	return sel
}

func set(list []string) map[string]bool {
	m := make(map[string]bool, len(list))
	for _, s := range list {
		m[s] = true
	}
	return m
}

// resolveJobVolumes is resolveSelection against what the host last reported.
func (a *app) resolveJobVolumes(job store.BackupJob) selection {
	vols, _ := a.store.ListHostVolumes()
	return resolveSelection(job, hostVolumeChoices(vols, job.HostID))
}

// restorableVolumes are the volumes a restore can be asked for: what the job
// covers now, what it ticked, and what it has ever backed up, since a volume that
// was removed is exactly the one to bring back.
func (a *app) restorableVolumes(job store.BackupJob) []string {
	seen := set(a.resolveJobVolumes(job).Names())
	for _, v := range job.Volumes {
		seen[v] = true
	}
	if runs, err := a.store.ListBackupRuns(job.ID, 300); err == nil {
		for _, r := range runs {
			if r.Kind != "backup" {
				continue
			}
			for _, res := range r.Results {
				if res.SnapshotID != "" && safeVolumeName.MatchString(res.Volume) {
					seen[res.Volume] = true
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// parseLabelRules reads the textarea of a job: one rule per line, "key" or "key=value".
func parseLabelRules(text string) ([]string, error) {
	var rules []string
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		rule := strings.TrimSpace(line)
		if rule == "" || seen[rule] {
			continue
		}
		key, value, _ := strings.Cut(rule, "=")
		switch {
		case !labelKeyRe.MatchString(key):
			return nil, fmt.Errorf("%q is not a label name: use letters, digits, . _ - and /", key)
		case len(value) > 256 || strings.ContainsAny(value, "\r\x00"):
			return nil, fmt.Errorf("the value of %q is not valid", key)
		}
		seen[rule] = true
		rules = append(rules, rule)
	}
	if len(rules) > maxLabelRules {
		return nil, errors.New("at most 20 label rules")
	}
	return rules, nil
}

// emptySelectionMessage says why a job covers nothing, in the words of what it selects.
func emptySelectionMessage(job store.BackupJob) string {
	var parts []string
	if len(job.Stacks) > 0 {
		parts = append(parts, "stacks "+strings.Join(job.Stacks, ", "))
	}
	if len(job.LabelRules) > 0 {
		parts = append(parts, "labels "+strings.Join(job.LabelRules, ", "))
	}
	if len(job.Volumes) > 0 {
		parts = append(parts, "ticked volumes")
	}
	what := "this job"
	if len(parts) > 0 {
		what = "this job (" + strings.Join(parts, "; ") + ")"
	}
	if len(job.Excluded) > 0 {
		return what + " selects no volume right now, with " + fmt.Sprint(len(job.Excluded)) + " left out: nothing was started"
	}
	return what + " selects no volume right now: nothing was started"
}
