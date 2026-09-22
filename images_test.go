package main

import "testing"

// familiarImageRef is what lets a docker-ps Image string be matched
// against a docker-images Repository:Tag despite Docker normalizing
// them differently for an official/single-namespace image -- see its
// own comment for the real "traefik" mismatch that surfaced this.
func TestFamiliarImageRef(t *testing.T) {
	cases := []struct {
		name, ref, want string
	}{
		{"official image, fully qualified", "docker.io/library/traefik:latest", "traefik:latest"},
		{"official image, already short", "traefik:latest", "traefik:latest"},
		{"single-namespace, fully qualified", "docker.io/someuser/repo:latest", "someuser/repo:latest"},
		{"single-namespace, already short", "someuser/repo:latest", "someuser/repo:latest"},
		{"explicit third-party registry, untouched", "ghcr.io/forgelab-me/wharf-server:latest", "ghcr.io/forgelab-me/wharf-server:latest"},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := familiarImageRef(c.ref); got != c.want {
				t.Errorf("familiarImageRef(%q) = %q, want %q", c.ref, got, c.want)
			}
		})
	}
}
