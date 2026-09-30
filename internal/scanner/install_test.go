package scanner

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type tarEntry struct {
	name string
	body string
	mode byte
}

func makeTarGz(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.mode
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: typ}
		if typ == tar.TypeSymlink {
			hdr.Linkname, hdr.Size = "/etc/passwd", 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// serve returns a scanner whose pinned release points at a local server.
func serve(t *testing.T, archive []byte, pinned string, status int) *trivy {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			http.Error(w, "nope", status)
			return
		}
		w.Write(archive)
	}))
	t.Cleanup(srv.Close)
	rel := release{Version: "9.9.9", Assets: map[string]asset{runtime.GOARCH: {URL: srv.URL + "/trivy.tar.gz", SHA256: pinned}}}
	return newTrivy(rel, srv.Client())
}

func TestInstallVerifiesAndUnpacksTheBinary(t *testing.T) {
	archive := makeTarGz(t,
		tarEntry{name: "LICENSE", body: "mit"},
		tarEntry{name: "contrib/html.tpl", body: "<html>"},
		tarEntry{name: "trivy", body: "#!/bin/sh\necho hi\n"},
	)
	s := serve(t, archive, sum(archive), http.StatusOK)
	cache := t.TempDir()

	if s.Installed(cache) {
		t.Fatal("nothing installed yet")
	}
	if err := s.Install(context.Background(), cache); err != nil {
		t.Fatal(err)
	}
	if !s.Installed(cache) {
		t.Fatal("Installed() is false after Install")
	}
	info, err := os.Stat(s.binPath(cache))
	if err != nil || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("binary is missing or not executable: %v %v", info, err)
	}
	if got, _ := os.ReadFile(s.binPath(cache)); string(got) != "#!/bin/sh\necho hi\n" {
		t.Fatalf("binary content = %q", got)
	}
	entries, _ := os.ReadDir(s.binDir(cache))
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

func TestInstallRefusesAMismatchedDownload(t *testing.T) {
	archive := makeTarGz(t, tarEntry{name: "trivy", body: "#!/bin/sh\nrm -rf /\n"})
	s := serve(t, archive, strings.Repeat("0", 64), http.StatusOK)
	cache := t.TempDir()

	err := s.Install(context.Background(), cache)
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("err = %v, want a checksum mismatch", err)
	}
	if s.Installed(cache) {
		t.Fatal("a download that does not match the pin must never be installed")
	}
}

func TestInstallFailures(t *testing.T) {
	archive := makeTarGz(t, tarEntry{name: "trivy", body: "x"})

	if err := serve(t, archive, sum(archive), http.StatusNotFound).Install(context.Background(), t.TempDir()); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("a 404 must be reported, got %v", err)
	}

	noBinary := makeTarGz(t, tarEntry{name: "LICENSE", body: "mit"})
	if err := serve(t, noBinary, sum(noBinary), http.StatusOK).Install(context.Background(), t.TempDir()); err == nil || !strings.Contains(err.Error(), "no \"trivy\"") {
		t.Errorf("an archive without the binary must fail, got %v", err)
	}

	notGzip := []byte("not an archive")
	if err := serve(t, notGzip, sum(notGzip), http.StatusOK).Install(context.Background(), t.TempDir()); err == nil {
		t.Error("a corrupt archive must fail")
	}

	other := newTrivy(release{Version: "1", Assets: map[string]asset{"riscv64": {URL: "http://x", SHA256: "0"}}}, nil)
	if err := other.Install(context.Background(), t.TempDir()); err == nil || !strings.Contains(err.Error(), runtime.GOARCH) {
		t.Errorf("an architecture with no pinned release must be reported, got %v", err)
	}
}

func TestExtractBinaryIgnoresEverythingButTheNamedRegularFile(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "trivy")
	archive := makeTarGz(t,
		tarEntry{name: "../../etc/trivy", body: "escape"}, // wrong place, same base name: still just "trivy"
		tarEntry{name: "trivy", mode: tar.TypeSymlink},    // a symlink is not the binary
		tarEntry{name: "bin/trivy", body: "the real one"},
	)
	if err := extractBinary(bytes.NewReader(archive), "trivy", dest); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "escape" {
		// The first regular entry named trivy wins, wherever it is stored: it is
		// written to dest, never to the path the archive names.
		t.Fatalf("content = %q", got)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dest), "..", "..", "etc", "trivy")); err == nil {
		t.Fatal("the archive's own path must never be written to")
	}
}
