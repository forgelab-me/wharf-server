package scanner

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"time"
)

const (
	maxDownload = 400 << 20
	maxBinary   = 400 << 20
)

// asset is one downloadable release archive and the SHA-256 it must have.
type asset struct{ URL, SHA256 string }

// release pins one scanner version, with an archive per CPU architecture.
type release struct {
	Version string
	Assets  map[string]asset // keyed by GOARCH
}

// base holds what Trivy and Grype share: where they live under the cache
// directory and how the pinned release is installed.
type base struct {
	name, label string
	rel         release
	client      *http.Client
}

func (b *base) Name() string    { return b.name }
func (b *base) Label() string   { return b.label }
func (b *base) Version() string { return b.rel.Version }

func (b *base) binDir(cacheDir string) string {
	return filepath.Join(cacheDir, "scanners", b.name, b.rel.Version)
}

func (b *base) binPath(cacheDir string) string { return filepath.Join(b.binDir(cacheDir), b.name) }
func (b *base) dbDir(cacheDir string) string   { return filepath.Join(cacheDir, "db", b.name) }

// DataDirs returns the binary and database directories of this scanner.
func (b *base) DataDirs(cacheDir string) []string {
	return []string{filepath.Join(cacheDir, "scanners", b.name), b.dbDir(cacheDir)}
}

func (b *base) Installed(cacheDir string) bool {
	info, err := os.Stat(b.binPath(cacheDir))
	return err == nil && info.Mode().IsRegular()
}

// Install downloads the pinned release for this machine's architecture,
// checks it against the pinned SHA-256 and unpacks the binary. A download
// that does not match is discarded, never run.
func (b *base) Install(ctx context.Context, cacheDir string) error {
	a, ok := b.rel.Assets[runtime.GOARCH]
	if !ok {
		return fmt.Errorf("%s has no pinned release for %s", b.label, runtime.GOARCH)
	}
	if err := os.MkdirAll(b.binDir(cacheDir), 0o755); err != nil {
		return fmt.Errorf("create %s directory: %w", b.label, err)
	}

	archive, err := os.CreateTemp(b.binDir(cacheDir), "download-*")
	if err != nil {
		return fmt.Errorf("create download file: %w", err)
	}
	defer os.Remove(archive.Name())
	defer archive.Close()

	if err := b.download(ctx, a, archive); err != nil {
		return err
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return extractBinary(archive, b.name, b.binPath(cacheDir))
}

func (b *base) download(ctx context.Context, a asset, dst io.Writer) error {
	client := b.client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Minute}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
	if err != nil {
		return fmt.Errorf("download %s: %w", b.label, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", b.label, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: the server answered %d", b.label, resp.StatusCode)
	}

	sum := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, sum), io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		return fmt.Errorf("download %s: %w", b.label, err)
	}
	if n > maxDownload {
		return fmt.Errorf("download %s: the archive is larger than %d MiB", b.label, maxDownload>>20)
	}
	if got := hex.EncodeToString(sum.Sum(nil)); got != a.SHA256 {
		return fmt.Errorf("download %s: checksum mismatch (got %s, pinned %s): not installed", b.label, got, a.SHA256)
	}
	return nil
}

// extractBinary writes the archive's entry named want (at any depth) to dest,
// atomically. Nothing else in the archive is read or written.
func extractBinary(archive io.Reader, want, dest string) error {
	gz, err := gzip.NewReader(archive)
	if err != nil {
		return fmt.Errorf("unpack archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("unpack archive: no %q in it", want)
		}
		if err != nil {
			return fmt.Errorf("unpack archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || path.Base(hdr.Name) != want {
			continue
		}
		if hdr.Size > maxBinary {
			return fmt.Errorf("unpack archive: %q is larger than %d MiB", want, maxBinary>>20)
		}
		tmp, err := os.CreateTemp(filepath.Dir(dest), want+"-*")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		if _, err := io.Copy(tmp, io.LimitReader(tr, maxBinary)); err != nil {
			tmp.Close()
			return fmt.Errorf("unpack archive: %w", err)
		}
		if err := tmp.Chmod(0o755); err != nil {
			tmp.Close()
			return err
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		return os.Rename(tmp.Name(), dest)
	}
}
