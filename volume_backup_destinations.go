package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/forgelab-me/wharf-server/internal/store"
)

// Backup destinations: a SMB share, set up once and used by any number of jobs.
// Settings → Backup destinations, admin only.

const destTypeSMB = "smb"

var (
	smbServerRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)
	smbShareRe  = regexp.MustCompile(`^[A-Za-z0-9._$ -]+$`)
	smbFolderRe = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)
	smbDomainRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	smbVersions = []string{"3.0", "3.1.1", "3.02", "2.1", "2.0"}
)

// smbFields are what a destination form carries.
type smbFields struct {
	Name, Server, Share, Folder, Version, Username, Domain, Password string
}

func smbFieldsFromForm(r *http.Request) smbFields {
	v := func(k string) string { return strings.TrimSpace(r.FormValue(k)) }
	return smbFields{Name: v("name"), Server: v("server"), Share: v("share"), Folder: strings.Trim(v("folder"), "/"),
		Version: v("version"), Username: v("username"), Domain: v("domain"), Password: r.FormValue("password")}
}

// validate checks everything that ends up in a mount option or a path: the same
// rules the agent applies, so a bad value is refused here, with a plain message,
// and not only when a backup fails.
func (f smbFields) validate(needPassword bool) error {
	switch {
	case f.Name == "" || len(f.Name) > 80:
		return errors.New("give the destination a name (80 characters at most)")
	case !smbServerRe.MatchString(f.Server):
		return errors.New("the server must be a host name or an IP address")
	case !smbShareRe.MatchString(f.Share):
		return errors.New("the share name has characters a share cannot have")
	case f.Folder != "" && !smbFolderRe.MatchString(f.Folder):
		return errors.New("the folder must be plain path segments (letters, digits, . _ -), without a space")
	case !contains(smbVersions, f.Version):
		return errors.New("pick an SMB version")
	case f.Domain != "" && !smbDomainRe.MatchString(f.Domain):
		return errors.New("the domain has characters a domain cannot have")
	}
	for _, seg := range strings.Split(f.Folder, "/") {
		if seg == "." || seg == ".." {
			return errors.New("the folder must not contain . or .. segments")
		}
	}
	if err := checkMountText("the user name", f.Username); err != nil {
		return err
	}
	if f.Password != "" || needPassword {
		if err := checkMountText("the password", f.Password); err != nil {
			return err
		}
	}
	return nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// checkMountText: a user name or password becomes part of a comma separated option string.
func checkMountText(what, v string) error {
	if v == "" {
		return fmt.Errorf("%s is required", what)
	}
	if strings.ContainsRune(v, ',') {
		return fmt.Errorf("%s cannot contain a comma: it would end the mount options", what)
	}
	for _, r := range v {
		if r < ' ' || r == 0x7f {
			return fmt.Errorf("%s cannot contain control characters", what)
		}
	}
	return nil
}

func (f smbFields) config() map[string]string {
	cfg := map[string]string{"server": f.Server, "share": f.Share, "version": f.Version, "username": f.Username}
	if f.Folder != "" {
		cfg["subdir"] = f.Folder
	}
	if f.Domain != "" {
		cfg["domain"] = f.Domain
	}
	return cfg
}

func (a *app) volumeBackupDestinationsHandler(w http.ResponseWriter, r *http.Request) {
	dests, err := a.store.ListBackupDestinations()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jobs, _ := a.store.ListBackupJobs()
	type row struct {
		ID, Name, Address, Version string
		Jobs                       int
	}
	rows := make([]row, 0, len(dests))
	for _, d := range dests {
		n := 0
		for _, j := range jobs {
			if j.DestinationID == d.ID {
				n++
			}
		}
		rows = append(rows, row{ID: d.ID, Name: d.Name, Address: smbAddress(d.Config), Version: d.Config["version"], Jobs: n})
	}
	render(w, r, "layout", "volume_backup_destinations.html", map[string]any{
		"Title": "Backup destinations", "Nav": "backup-destinations", "Rows": rows,
	})
}

func smbAddress(cfg map[string]string) string {
	addr := `\\` + cfg["server"] + `\` + cfg["share"]
	if cfg["subdir"] != "" {
		addr += `\` + strings.ReplaceAll(cfg["subdir"], "/", `\`)
	}
	return addr
}

func (a *app) volumeBackupDestinationFormHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{"Title": "New backup destination", "Nav": "backup-destinations", "Versions": smbVersions,
		"F": smbFields{Version: "3.0"}}
	if id := r.PathValue("id"); id != "" {
		d, err := a.store.GetBackupDestination(id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		cfg := d.Config
		data["Title"], data["Dest"] = d.Name, d
		data["F"] = smbFields{Name: d.Name, Server: cfg["server"], Share: cfg["share"], Folder: cfg["subdir"], Version: cfg["version"],
			Username: cfg["username"], Domain: cfg["domain"]}
		data["Hosts"] = a.backupCapableHosts()
		jobs, _ := a.store.ListBackupJobs()
		var users []string
		for _, j := range jobs {
			if j.DestinationID == d.ID {
				users = append(users, j.Name)
			}
		}
		data["Jobs"] = users
	}
	render(w, r, "layout", "volume_backup_destination_form.html", data)
}

type hostChoice struct{ ID, Name string }

// backupCapableHosts are the hosts that are connected and run an agent that can back up.
func (a *app) backupCapableHosts() []hostChoice {
	hosts, err := a.store.ListHosts()
	if err != nil {
		return nil
	}
	var out []hostChoice
	for _, h := range hosts {
		if _, live := a.tunnels.get(h.ID); live && !agentCannotBackUp(h.AgentVersion) {
			out = append(out, hostChoice{ID: h.ID, Name: h.Name})
		}
	}
	return out
}

func (a *app) createVolumeBackupDestinationHandler(w http.ResponseWriter, r *http.Request) {
	f := smbFieldsFromForm(r)
	back := "/settings/backup-destinations/new"
	if err := f.validate(true); err != nil {
		redirectWithError(w, r, back, err.Error())
		return
	}
	id, err := randomHex(8)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	repoPassword, err := randomHex(32)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.keys.SetSecretCredentials(backupCredID(id), map[string]string{credSMBPassword: f.Password, credRepoPassword: repoPassword}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.store.CreateBackupDestination(store.BackupDestination{ID: id, Name: f.Name, Type: destTypeSMB, Config: f.config()}); err != nil {
		_ = a.keys.DeleteSecretCredentials(backupCredID(id))
		redirectWithError(w, r, back, "could not create the destination (name already taken?)")
		return
	}
	a.audit(r, "volume_backup.destination_create", f.Name, "smb "+smbAddress(f.config()))

	// The repository password is shown here once, in this response and not in a redirect URL.
	render(w, r, "layout", "volume_backup_repo_password.html", map[string]any{
		"Title": "Repository password", "Nav": "backup-destinations", "Name": f.Name, "ID": id, "RepoPassword": repoPassword, "Fresh": true,
	})
}

func (a *app) updateVolumeBackupDestinationHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	d, err := a.store.GetBackupDestination(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	f := smbFieldsFromForm(r)
	back := "/settings/backup-destinations/" + id
	if err := f.validate(false); err != nil {
		redirectWithError(w, r, back, err.Error())
		return
	}
	if f.Password != "" {
		creds, err := a.keys.SecretCredentials(backupCredID(id))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if creds == nil {
			creds = map[string]string{}
		}
		creds[credSMBPassword] = f.Password
		if err := a.keys.SetSecretCredentials(backupCredID(id), creds); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if err := a.store.UpdateBackupDestination(id, f.Name, f.config()); err != nil {
		redirectWithError(w, r, back, "could not save (name already taken?)")
		return
	}
	// the repositories may now be elsewhere: what was known of them no longer holds
	_ = a.store.ClearBackupRepoStates(id)
	a.audit(r, "volume_backup.destination_update", f.Name, "smb "+smbAddress(f.config()))
	_ = d
	redirectWithSavedMessage(w, r, "/settings/backup-destinations", "Destination saved")
}

func (a *app) deleteVolumeBackupDestinationHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	d, err := a.store.GetBackupDestination(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := a.store.DeleteBackupDestination(id); err != nil {
		redirectWithError(w, r, "/settings/backup-destinations/"+id, err.Error()+": remove or repoint those jobs first")
		return
	}
	_ = a.keys.DeleteSecretCredentials(backupCredID(id))
	a.audit(r, "volume_backup.destination_delete", d.Name, "")
	redirectWithSavedMessage(w, r, "/settings/backup-destinations", "Destination removed. The snapshots already on the share are untouched")
}

// revealVolumeBackupRepoPasswordHandler shows the repository password again: it is
// needed to restore on a machine that is not this controller.
func (a *app) revealVolumeBackupRepoPasswordHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	d, err := a.store.GetBackupDestination(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	creds, err := a.keys.SecretCredentials(backupCredID(id))
	if err != nil || creds[credRepoPassword] == "" {
		redirectWithError(w, r, "/settings/backup-destinations/"+id, "this destination has no repository password")
		return
	}
	a.audit(r, "volume_backup.repo_password_reveal", d.Name, "")
	render(w, r, "layout", "volume_backup_repo_password.html", map[string]any{
		"Title": "Repository password", "Nav": "backup-destinations", "Name": d.Name, "ID": id, "RepoPassword": creds[credRepoPassword],
	})
}

// testVolumeBackupDestinationHandler mounts the share from one host and says what it found.
func (a *app) testVolumeBackupDestinationHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	back := "/settings/backup-destinations/" + id
	hostID := r.FormValue("host_id")
	msg, err := a.testDestination(r.Context(), id, hostID)
	if err != nil {
		redirectWithError(w, r, back, err.Error())
		return
	}
	redirectWithSavedMessage(w, r, back, msg)
}

// testDestination returns a sentence on what a host sees of a destination.
func (a *app) testDestination(ctx context.Context, destID, hostID string) (string, error) {
	req, err := a.requestForHost(destID, hostID)
	if err != nil {
		return "", err
	}
	tc, err := a.connectedAgent(hostID)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, backupQuickWait+10*time.Second)
	defer cancel()
	raw, err := tc.backupCommand(ctx, "backup_test", req)
	if err != nil {
		return "", err
	}
	res, err := parseTestResult(raw)
	if err != nil {
		return "", err
	}
	switch {
	case res.Mounted && res.Writable && res.Initialized:
		a.noteRepo(destID, hostID, true)
	case res.Mounted && res.Writable && strings.Contains(res.Message, "not initialized"):
		a.noteRepo(destID, hostID, false)
	}
	switch {
	case !res.Mounted:
		return "", errors.New("the share could not be used: " + res.Message)
	case res.Message != "" && !res.Initialized && res.Writable && strings.Contains(res.Message, "not initialized"):
		return "The share is reachable and writable. This host has no repository there yet: initialize it from a backup job.", nil
	case res.Message != "":
		return "", errors.New(res.Message)
	case res.Initialized:
		return "The share is reachable and writable, and this host's repository is initialized.", nil
	}
	return "The share is reachable and writable.", nil
}
