package store

import (
	"testing"
)

func TestImageScanRoundTrip(t *testing.T) {
	s := newTestStore(t)
	sc := ImageScan{
		Scanner: "trivy", Repository: "docker.io/library/nginx", Digest: "sha256:aaa", Platform: "linux/amd64",
		Status: "ok", Notice: "nothing was recognized", DBBuiltAt: "2026-09-30T00:00:00Z",
		Critical: 1, High: 2, Medium: 3, Low: 4, Unknown: 5, FixableCritical: 1, FixableHigh: 2,
		Findings: `[{"id":"CVE-2026-0001"}]`,
	}
	if err := s.UpsertImageScan(sc); err != nil {
		t.Fatal(err)
	}

	got, ok, err := s.GetImageScan("trivy", "sha256:aaa", "linux/amd64")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if got.Notice != "nothing was recognized" || got.Critical != 1 || got.FixableHigh != 2 || got.Findings != sc.Findings || got.Repository != sc.Repository || got.ScannedAt == "" {
		t.Fatalf("got %+v", got)
	}
	if _, ok, _ := s.GetImageScan("grype", "sha256:aaa", "linux/amd64"); ok {
		t.Fatal("another scanner's result must not be returned")
	}
	if _, ok, _ := s.GetImageScan("trivy", "sha256:aaa", "linux/arm64"); ok {
		t.Fatal("another platform's result must not be returned")
	}

	sc.Critical, sc.Status, sc.Findings = 0, "error", ""
	sc.Error = "registry unreachable"
	if err := s.UpsertImageScan(sc); err != nil {
		t.Fatal(err)
	}
	got, _, _ = s.GetImageScan("trivy", "sha256:aaa", "linux/amd64")
	if got.Status != "error" || got.Error != "registry unreachable" || got.Findings != "[]" {
		t.Fatalf("an upsert must replace the previous scan: %+v", got)
	}
}

func TestListPruneAndDeleteImageScans(t *testing.T) {
	s := newTestStore(t)
	for _, k := range []ScanKey{
		{"trivy", "sha256:a", "linux/amd64"}, {"trivy", "sha256:b", "linux/amd64"}, {"grype", "sha256:a", "linux/amd64"},
	} {
		if err := s.UpsertImageScan(ImageScan{Scanner: k.Scanner, Digest: k.Digest, Platform: k.Platform, Status: "ok", Findings: `[{"id":"x"}]`}); err != nil {
			t.Fatal(err)
		}
	}

	list, err := s.ListImageScans("trivy")
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	for _, sc := range list {
		if sc.Findings != "" {
			t.Fatal("the list feeds counters and must not load findings")
		}
	}

	n, err := s.PruneImageScans(map[ScanKey]bool{{"trivy", "sha256:a", "linux/amd64"}: true, {"grype", "sha256:a", "linux/amd64"}: true})
	if err != nil || n != 1 {
		t.Fatalf("pruned %d, %v; want only trivy/b", n, err)
	}
	if _, ok, _ := s.GetImageScan("trivy", "sha256:b", "linux/amd64"); ok {
		t.Fatal("trivy/b should be pruned")
	}

	if err := s.DeleteImageScans("trivy"); err != nil {
		t.Fatal(err)
	}
	if l, _ := s.ListImageScans("trivy"); len(l) != 0 {
		t.Fatal("trivy scans left behind")
	}
	if l, _ := s.ListImageScans("grype"); len(l) != 1 {
		t.Fatal("deleting one scanner's scans must not touch another's")
	}
	if err := s.DeleteImageScans(""); err != nil {
		t.Fatal(err)
	}
	if l, _ := s.ListImageScans("grype"); len(l) != 0 {
		t.Fatal("an empty scanner name deletes everything")
	}
}

func TestVulnSettings(t *testing.T) {
	s := newTestStore(t)
	if v, err := s.GetVulnSettings(); err != nil || v.Enabled || v.Scanner != "" {
		t.Fatalf("default = %+v, %v; want disabled", v, err)
	}

	if err := s.SetVulnSettingsChoice(true, "trivy"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetVulnLastPass("12 scanned, 1 failed"); err != nil {
		t.Fatal(err)
	}
	v, _ := s.GetVulnSettings()
	if !v.Enabled || v.Scanner != "trivy" || v.LastPassMsg != "12 scanned, 1 failed" || v.LastPassAt == "" {
		t.Fatalf("settings = %+v", v)
	}

	if err := s.SetVulnSettingsChoice(false, "grype"); err != nil {
		t.Fatal(err)
	}
	v, _ = s.GetVulnSettings()
	if v.Enabled || v.Scanner != "grype" || v.LastPassMsg != "12 scanned, 1 failed" {
		t.Fatalf("changing the choice must keep the last pass report: %+v", v)
	}
}

func TestHostImageDigestContainerImageIDAndArch(t *testing.T) {
	s := newTestStore(t)
	host, _, err := s.UpsertHostByFingerprint("h", "sha256:f")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceHostImages(host.ID, []HostImage{{HostID: host.ID, ImageID: "1a2b3c4d5e6f", Repository: "nginx", Tag: "1", Digest: "sha256:aaa"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceHostContainers(host.ID, []HostContainer{{HostID: host.ID, ContainerID: "c1", Name: "web", Image: "nginx:1", ImageID: "1a2b3c4d5e6f"}}); err != nil {
		t.Fatal(err)
	}
	images, _ := s.ListHostImages()
	if len(images) != 1 || images[0].Digest != "sha256:aaa" {
		t.Fatalf("images = %+v", images)
	}
	containers, _ := s.ListHostContainers()
	if len(containers) != 1 || containers[0].ImageID != "1a2b3c4d5e6f" {
		t.Fatalf("containers = %+v", containers)
	}
	one, err := s.GetHostContainerByID("c1")
	if err != nil || one.ImageID != "1a2b3c4d5e6f" {
		t.Fatalf("by id = %+v, %v", one, err)
	}

	if arch, _ := s.HostArch(host.ID); arch != "" {
		t.Fatalf("arch before any report = %q", arch)
	}
	if err := s.SetHostArch(host.ID, "arm64"); err != nil {
		t.Fatal(err)
	}
	if arch, _ := s.HostArch(host.ID); arch != "arm64" {
		t.Fatalf("arch = %q", arch)
	}
	if _, err := s.HostArch("nope"); err == nil {
		t.Fatal("an unknown host must be an error")
	}
}

func TestReplaceHostImagesToleratesDuplicateRows(t *testing.T) {
	s := newTestStore(t)
	host, _, _ := s.UpsertHostByFingerprint("h", "sha256:f")
	err := s.ReplaceHostImages(host.ID, []HostImage{
		{HostID: host.ID, ImageID: "1102bfe49106", Repository: "node", Tag: "24-alpine", Digest: "sha256:be80"},
		{HostID: host.ID, ImageID: "1102bfe49106", Repository: "node", Tag: "24-alpine", Digest: "sha256:50c8"},
		{HostID: host.ID, ImageID: "1102bfe49106", Repository: "node", Tag: "lts-alpine"},
		{HostID: host.ID, ImageID: "1102bfe49106", Repository: "node", Tag: "lts-alpine", Digest: "sha256:be80"},
	})
	if err != nil {
		t.Fatalf("one duplicate must not fail the whole snapshot: %v", err)
	}
	images, _ := s.ListHostImages()
	if len(images) != 2 {
		t.Fatalf("images = %+v", images)
	}
	got := map[string]string{}
	for _, i := range images {
		got[i.Tag] = i.Digest
	}
	if got["24-alpine"] != "sha256:50c8" || got["lts-alpine"] != "sha256:be80" {
		t.Fatalf("digests = %v", got)
	}
}
