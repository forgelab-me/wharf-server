package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptDecryptBackupRoundTrip(t *testing.T) {
	plaintext := []byte("wharf.db and keys.db pretend-contents")
	ciphertext, err := encryptBackup(plaintext, "correct horse battery staple")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext must not equal plaintext")
	}
	if !bytes.HasPrefix(ciphertext, []byte(ageMagic)) {
		t.Fatalf("ciphertext missing expected age header %q", ageMagic)
	}

	got, err := decryptBackup(ciphertext, "correct horse battery staple")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypt = %q, want %q", got, plaintext)
	}

	if _, err := decryptBackup(ciphertext, "wrong passphrase"); err == nil {
		t.Fatal("decrypt with wrong passphrase should fail")
	}
}

// fakeDataDir builds a directory that looks like a real wharf dataDir
// (wharf.db, keys.db, identity/*.pem) with distinguishable placeholder
// content, since buildBackupArchive/stageRestore only care about file
// presence and the manifest, never the DB's actual contents.
func fakeDataDir(t *testing.T, wharfContent, keysContent string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "wharf.db"), []byte(wharfContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keys.db"), []byte(keysContent), 0o600); err != nil {
		t.Fatal(err)
	}
	identityDir := filepath.Join(dir, "identity")
	if err := os.MkdirAll(identityDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(identityDir, "identity.cert.pem"), []byte("fake cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(identityDir, "identity.key.pem"), []byte("fake key"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestBuildArchiveThenStageRestore(t *testing.T) {
	srcDir := fakeDataDir(t, "wharf-db-content", "keys-db-content")

	archive, err := buildBackupArchive(filepath.Join(srcDir, "wharf.db"), filepath.Join(srcDir, "keys.db"), srcDir)
	if err != nil {
		t.Fatalf("buildBackupArchive: %v", err)
	}

	destDir := t.TempDir()
	if err := stageRestore(destDir, archive); err != nil {
		t.Fatalf("stageRestore: %v", err)
	}

	staging := filepath.Join(destDir, "restore-pending")
	wantContent := map[string]string{
		"wharf.db":                   "wharf-db-content",
		"keys.db":                    "keys-db-content",
		"identity/identity.cert.pem": "fake cert",
		"identity/identity.key.pem":  "fake key",
	}
	for name, want := range wantContent {
		got, err := os.ReadFile(filepath.Join(staging, name))
		if err != nil {
			t.Fatalf("staged %s: %v", name, err)
		}
		if string(got) != want {
			t.Errorf("staged %s = %q, want %q", name, got, want)
		}
	}
}

// buildTestArchive gives the path-traversal/missing-file tests full
// control over exactly which entries end up in the tar.gz, independent
// of buildBackupArchive's own (safe) behavior.
func buildTestArchive(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func validManifest(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(backupManifest{FormatVersion: backupFormatVersion})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStageRestoreRejectsPathTraversal(t *testing.T) {
	archive := buildTestArchive(t, map[string][]byte{
		"manifest.json":              validManifest(t),
		"wharf.db":                   []byte("x"),
		"keys.db":                    []byte("x"),
		"identity/identity.cert.pem": []byte("x"),
		"identity/identity.key.pem":  []byte("x"),
		"../../etc/passwd":           []byte("pwned"),
	})
	if err := stageRestore(t.TempDir(), archive); err == nil {
		t.Fatal("expected an error for a path-traversal entry, got nil")
	}
}

func TestStageRestoreRejectsIncompleteArchive(t *testing.T) {
	archive := buildTestArchive(t, map[string][]byte{
		"manifest.json": validManifest(t),
		"wharf.db":      []byte("x"),
		// keys.db and identity/* deliberately missing
	})
	err := stageRestore(t.TempDir(), archive)
	if err == nil {
		t.Fatal("expected an error for an incomplete backup, got nil")
	}
}

func TestStageRestoreRejectsUnsupportedFormatVersion(t *testing.T) {
	badManifest, err := json.Marshal(backupManifest{FormatVersion: backupFormatVersion + 1})
	if err != nil {
		t.Fatal(err)
	}
	archive := buildTestArchive(t, map[string][]byte{
		"manifest.json":              badManifest,
		"wharf.db":                   []byte("x"),
		"keys.db":                    []byte("x"),
		"identity/identity.cert.pem": []byte("x"),
		"identity/identity.key.pem":  []byte("x"),
	})
	if err := stageRestore(t.TempDir(), archive); err == nil {
		t.Fatal("expected an error for an unsupported format version, got nil")
	}
}

func TestApplyPendingRestoreNoopWithoutStaging(t *testing.T) {
	dir := t.TempDir()
	if err := applyPendingRestore(dir); err != nil {
		t.Fatalf("applyPendingRestore on a clean dataDir should be a no-op, got: %v", err)
	}
}

func TestApplyPendingRestoreReplacesFilesAndKeepsOldOnesAside(t *testing.T) {
	dataDir := fakeDataDir(t, "old-wharf-content", "old-keys-content")

	// Build a "new" backup from a different source dir, then stage it
	// into dataDir exactly the way restoreBackupHandler would.
	newSrc := fakeDataDir(t, "new-wharf-content", "new-keys-content")
	archive, err := buildBackupArchive(filepath.Join(newSrc, "wharf.db"), filepath.Join(newSrc, "keys.db"), newSrc)
	if err != nil {
		t.Fatalf("buildBackupArchive: %v", err)
	}
	if err := stageRestore(dataDir, archive); err != nil {
		t.Fatalf("stageRestore: %v", err)
	}

	if err := applyPendingRestore(dataDir); err != nil {
		t.Fatalf("applyPendingRestore: %v", err)
	}

	// The new content is now live.
	got, err := os.ReadFile(filepath.Join(dataDir, "wharf.db"))
	if err != nil {
		t.Fatalf("read restored wharf.db: %v", err)
	}
	if string(got) != "new-wharf-content" {
		t.Fatalf("wharf.db = %q, want new-wharf-content", got)
	}

	// The old content wasn't deleted -- it's sitting aside with a
	// .pre-restore-<timestamp> suffix.
	matches, err := filepath.Glob(filepath.Join(dataDir, "wharf.db.pre-restore-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected exactly one set-aside wharf.db, found %d", len(matches))
	}
	oldContent, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("read set-aside wharf.db: %v", err)
	}
	if string(oldContent) != "old-wharf-content" {
		t.Fatalf("set-aside wharf.db = %q, want old-wharf-content", oldContent)
	}

	// Staging is cleaned up, and re-running is a no-op.
	if _, err := os.Stat(filepath.Join(dataDir, "restore-pending")); !os.IsNotExist(err) {
		t.Fatal("restore-pending should be removed after applying")
	}
	if err := applyPendingRestore(dataDir); err != nil {
		t.Fatalf("second applyPendingRestore call should be a no-op, got: %v", err)
	}
}
