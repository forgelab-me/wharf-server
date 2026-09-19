package main

import "testing"

// semverLess exists specifically because plain string comparison gets
// "0.9.0" vs "0.10.0" backwards -- this pins that exact case, plus the
// "not a real release" cases (dev builds, malformed input) that must
// never trigger an update nag.
func TestSemverLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"0.1.0", "0.2.0", true},
		{"0.2.0", "0.1.0", false},
		{"0.1.0", "0.1.0", false},
		{"0.9.0", "0.10.0", true},   // the case plain string comparison gets wrong
		{"0.10.0", "0.9.0", false},
		{"1.2.3", "1.2.4", true},
		{"1.2.3", "1.3.0", true},
		{"dev", "0.1.0", false},        // running build isn't a tagged release -- never "outdated"
		{"dev-local", "0.1.0", false},
		{"0.1.0", "dev", false},        // "latest" failed to resolve to a real semver -- never claim an update exists
		{"", "0.1.0", false},
		{"0.1.0", "", false},
		{"0.1", "0.2.0", false}, // malformed (only two components) -- not a crash, just never "less"
	}
	for _, c := range cases {
		if got := semverLess(c.a, c.b); got != c.want {
			t.Errorf("semverLess(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
