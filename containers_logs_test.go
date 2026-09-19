package main

import (
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
)

// splitLogLines feeds container_logs.html's per-line search filter --
// getting the trailing-newline trim wrong either leaves a stray empty
// line at the end (docker logs always ends with one) or eats a real
// blank line the container actually printed.
func TestSplitLogLines(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"single line, trailing newline", "hello\n", []string{"hello"}},
		{"single line, no trailing newline", "hello", []string{"hello"}},
		{"multiple lines", "a\nb\nc\n", []string{"a", "b", "c"}},
		{"real trailing blank line preserved", "a\n\n", []string{"a", ""}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := splitLogLines(c.in)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("splitLogLines(%q) = %#v, want %#v", c.in, got, c.want)
			}
		})
	}
}

// logTailFromQuery is the only thing standing between a request's own
// ?tail= and an argv passed to the agent's exec.Command -- must reject
// anything outside the fixed allowlist, not just anything non-numeric.
func TestLogTailFromQuery(t *testing.T) {
	cases := []struct {
		name, tail, want string
	}{
		{"absent", "", "500"},
		{"in allowlist", "200", "200"},
		{"all", "all", "all"},
		{"not in allowlist", "9999999", "500"},
		{"shell-metacharacter-shaped, still just a string not in the allowlist", "200;rm -rf /", "500"},
		{"trailing space, not an exact match", "200 ", "500"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/containers/x/logs?"+url.Values{"tail": {c.tail}}.Encode(), nil)
			if got := logTailFromQuery(r); got != c.want {
				t.Errorf("logTailFromQuery(tail=%q) = %q, want %q", c.tail, got, c.want)
			}
		})
	}
}
