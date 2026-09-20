// Backup/restore — a full snapshot of everything that makes this
// controller *this* controller: wharf.db (stacks, hosts, users,
// deployments, audit log), keys.db (every private key and credential),
// and the controller's own TLS identity (cf. internal/identity) --
// without which every already-enrolled agent refuses to reconnect, mTLS
// fingerprint pinning being the whole point of that identity.
//
// Deliberately not a hot in-place restore: both databases are open via
// live SQLite connections and the identity is already bound into the
// running HTTPS listener by the time any of this runs. A restore only
// ever stages files under dataDir/restore-pending and asks for a
// restart -- applyPendingRestore (called from main(), before anything
// is opened) is what actually moves them into place.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
)

const (
	backupFormatVersion = 1
	maxBackupUploadSize = 200 << 20 // 200 MiB -- generous for a homelab-scale wharf.db/keys.db pair, still bounded
	ageMagic            = "age-encryption.org/v1"
)

type backupManifest struct {
	FormatVersion int    `json:"format_version"`
	WharfVersion  string `json:"wharf_version"`
	CreatedAt     string `json:"created_at"`
}

func (a *app) settingsBackupHandler(w http.ResponseWriter, r *http.Request) {
	render(w, r, "layout", "settings_backup.html", map[string]any{
		"Title": "Backup & Restore",
		"Nav":   "backup",
	})
}

// downloadBackupHandler serves POST /settings/backup/download. Builds
// the snapshot fresh on every request rather than keeping one lying
// around: a backup is only ever as good as the moment it was taken, and
// there's no reason to let a stale copy sit on disk between downloads.
func (a *app) downloadBackupHandler(w http.ResponseWriter, r *http.Request) {
	tmpDir, err := os.MkdirTemp("", "wharf-backup-*")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(tmpDir)

	wharfSnapshot := filepath.Join(tmpDir, "wharf.db")
	if err := a.store.BackupTo(wharfSnapshot); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	keysSnapshot := filepath.Join(tmpDir, "keys.db")
	if err := a.keys.BackupTo(keysSnapshot); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	archive, err := buildBackupArchive(wharfSnapshot, keysSnapshot, a.dataDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	payload := archive
	filename := "wharf-backup-" + time.Now().UTC().Format("20060102-150405") + ".tar.gz"
	encrypted := false
	if passphrase := r.FormValue("passphrase"); passphrase != "" {
		payload, err = encryptBackup(archive, passphrase)
		if err != nil {
			http.Error(w, "encrypt backup: "+err.Error(), http.StatusInternalServerError)
			return
		}
		filename += ".age"
		encrypted = true
	}

	a.audit(r, "backup.download", filename, fmt.Sprintf("%d bytes, encrypted=%v", len(payload), encrypted))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Write(payload)
}

// buildBackupArchive tars+gzips the two DB snapshots plus the identity
// keypair (cf. internal/identity.LoadOrGenerate for its exact filenames)
// and a manifest -- stdlib archive/tar + compress/gzip, no new
// dependency for a format this simple.
func buildBackupArchive(wharfDBPath, keysDBPath, dataDir string) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	manifest, err := json.Marshal(backupManifest{
		FormatVersion: backupFormatVersion,
		WharfVersion:  version,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return nil, err
	}
	if err := addTarFile(tw, "manifest.json", manifest); err != nil {
		return nil, err
	}
	if err := addTarFileFromDisk(tw, "wharf.db", wharfDBPath); err != nil {
		return nil, err
	}
	if err := addTarFileFromDisk(tw, "keys.db", keysDBPath); err != nil {
		return nil, err
	}
	if err := addTarFileFromDisk(tw, "identity/identity.cert.pem", filepath.Join(dataDir, "identity", "identity.cert.pem")); err != nil {
		return nil, err
	}
	if err := addTarFileFromDisk(tw, "identity/identity.key.pem", filepath.Join(dataDir, "identity", "identity.key.pem")); err != nil {
		return nil, err
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close backup archive: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("close backup archive: %w", err)
	}
	return buf.Bytes(), nil
}

func addTarFile(tw *tar.Writer, name string, content []byte) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content))}); err != nil {
		return fmt.Errorf("write tar header for %s: %w", name, err)
	}
	if _, err := tw.Write(content); err != nil {
		return fmt.Errorf("write tar entry %s: %w", name, err)
	}
	return nil
}

func addTarFileFromDisk(tw *tar.Writer, name, path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s for backup: %w", name, err)
	}
	return addTarFile(tw, name, content)
}

// encryptBackup wraps the archive with age's passphrase (scrypt) mode --
// the same library this app already uses for every stack's secrets, so
// this reuses code that's already the trust boundary here rather than
// hand-rolling a second encryption scheme.
func encryptBackup(plaintext []byte, passphrase string) ([]byte, error) {
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	wc, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := wc.Write(plaintext); err != nil {
		return nil, err
	}
	if err := wc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decryptBackup(ciphertext []byte, passphrase string) ([]byte, error) {
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// restoreBackupHandler serves POST /settings/backup/restore. multipart
// like volumeBrowseUploadHandler, so it verifies its own CSRF token the
// same way and for the same reason: requireAuth's CSRF check skips
// multipart/form-data entirely, and reading a field via r.FormValue
// before an explicit, size-capped r.ParseMultipartForm would trigger an
// unbounded default parse ahead of it.
func (a *app) restoreBackupHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBackupUploadSize+1<<20)
	if err := r.ParseMultipartForm(maxBackupUploadSize); err != nil {
		redirectWithError(w, r, "/settings/backup", "upload too large or invalid (max 200 MiB)")
		return
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || !verifyCSRF(cookie.Value, r.FormValue("csrf_token")) {
		redirectWithError(w, r, "/settings/backup", "Your session or this form is stale — please reload the page and try again.")
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		redirectWithError(w, r, "/settings/backup", "no file selected")
		return
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxBackupUploadSize+1))
	if err != nil {
		redirectWithError(w, r, "/settings/backup", "could not read upload: "+err.Error())
		return
	}
	if len(raw) > maxBackupUploadSize {
		redirectWithError(w, r, "/settings/backup", "file too large (max 200 MiB)")
		return
	}

	if bytes.HasPrefix(raw, []byte(ageMagic)) {
		passphrase := r.FormValue("passphrase")
		if passphrase == "" {
			redirectWithError(w, r, "/settings/backup", "this backup is encrypted — enter its passphrase")
			return
		}
		decrypted, err := decryptBackup(raw, passphrase)
		if err != nil {
			redirectWithError(w, r, "/settings/backup", "could not decrypt backup: wrong passphrase, or the file is corrupt")
			return
		}
		raw = decrypted
	}

	if err := stageRestore(a.dataDir, raw); err != nil {
		redirectWithError(w, r, "/settings/backup", "invalid backup: "+err.Error())
		return
	}

	a.audit(r, "backup.restore_staged", "", "")
	redirectWithSavedMessage(w, r, "/settings/backup", "Restore staged — restart the controller to apply it")
}

// stageRestore validates and extracts a decrypted backup archive under
// dataDir/restore-pending. Never touches the live wharf.db/keys.db/
// identity -- applyPendingRestore does that, at the next process start.
func stageRestore(dataDir string, archive []byte) error {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return fmt.Errorf("not a valid backup archive: %w", err)
	}
	tr := tar.NewReader(gz)

	staging := filepath.Join(dataDir, "restore-pending")
	if err := os.RemoveAll(staging); err != nil {
		return fmt.Errorf("clear previous staged restore: %w", err)
	}
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return fmt.Errorf("create staging dir: %w", err)
	}

	found := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			os.RemoveAll(staging)
			return fmt.Errorf("corrupt archive: %w", err)
		}
		// Every entry this format ever writes (cf. buildBackupArchive) is a
		// bare relative name -- reject anything else outright rather than
		// trust a hostile or corrupt archive to stay inside staging.
		if strings.Contains(hdr.Name, "..") || strings.HasPrefix(hdr.Name, "/") {
			os.RemoveAll(staging)
			return fmt.Errorf("unsafe path in archive: %s", hdr.Name)
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			os.RemoveAll(staging)
			return fmt.Errorf("read %s: %w", hdr.Name, err)
		}
		if hdr.Name == "manifest.json" {
			var m backupManifest
			if err := json.Unmarshal(content, &m); err != nil {
				os.RemoveAll(staging)
				return fmt.Errorf("unreadable manifest: %w", err)
			}
			if m.FormatVersion != backupFormatVersion {
				os.RemoveAll(staging)
				return fmt.Errorf("backup format v%d isn't supported by this version of wharf-server", m.FormatVersion)
			}
		}
		dest := filepath.Join(staging, hdr.Name)
		if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
			os.RemoveAll(staging)
			return err
		}
		if err := os.WriteFile(dest, content, 0o600); err != nil {
			os.RemoveAll(staging)
			return fmt.Errorf("write %s: %w", hdr.Name, err)
		}
		found[hdr.Name] = true
	}

	for _, want := range []string{"manifest.json", "wharf.db", "keys.db", "identity/identity.cert.pem", "identity/identity.key.pem"} {
		if !found[want] {
			os.RemoveAll(staging)
			return fmt.Errorf("missing %s — not a complete wharf-server backup", want)
		}
	}
	return nil
}

// applyPendingRestore is called from main(), before store.Open/
// keys.Open/identity.LoadOrGenerate -- a no-op unless
// restoreBackupHandler staged something on a previous run. The
// currently-in-place files are renamed aside with a timestamp suffix,
// never deleted: a bad restore should be recoverable by hand, and losing
// the previous identity for nothing would force every already-enrolled
// agent to be re-pointed at a new fingerprint.
func applyPendingRestore(dataDir string) error {
	staging := filepath.Join(dataDir, "restore-pending")
	if _, err := os.Stat(staging); os.IsNotExist(err) {
		return nil
	}
	log.Println("restore: applying staged backup from", staging)

	suffix := ".pre-restore-" + time.Now().UTC().Format("20060102-150405")
	for _, name := range []string{"wharf.db", "wharf.db-wal", "wharf.db-shm", "keys.db"} {
		src := filepath.Join(dataDir, name)
		if _, err := os.Stat(src); err == nil {
			if err := os.Rename(src, src+suffix); err != nil {
				return fmt.Errorf("set aside existing %s: %w", name, err)
			}
		}
	}
	identityDir := filepath.Join(dataDir, "identity")
	if _, err := os.Stat(identityDir); err == nil {
		if err := os.Rename(identityDir, identityDir+suffix); err != nil {
			return fmt.Errorf("set aside existing identity: %w", err)
		}
	}

	for _, name := range []string{"wharf.db", "keys.db"} {
		if err := os.Rename(filepath.Join(staging, name), filepath.Join(dataDir, name)); err != nil {
			return fmt.Errorf("apply restore: move %s: %w", name, err)
		}
	}
	if err := os.Rename(filepath.Join(staging, "identity"), identityDir); err != nil {
		return fmt.Errorf("apply restore: move identity: %w", err)
	}
	if err := os.RemoveAll(staging); err != nil {
		log.Println("restore: could not clean up staging dir (harmless):", err)
	}
	log.Println("restore: applied — previous data kept alongside with a", suffix, "suffix")
	return nil
}
