package main

import "testing"

// appendQuery exists because several redirect targets already carry
// their own query string (a volume browser's backTo's "?path=...", a
// bulk delete's "?refreshing=1") -- a naive path+"?k=v" there doesn't
// start a new parameter, it gets glued onto the end of whatever query
// value came before it. Found exactly this way: redirectWithError
// against a volumebrowse.go backTo was producing
// ".../browse?path=foo?error=bar", one mangled "path" value instead of
// two separate params.
func TestAppendQuery(t *testing.T) {
	cases := []struct {
		path, query, want string
	}{
		{"/stacks/x", "saved=1", "/stacks/x?saved=1"},
		{"/images?refreshing=1", "saved=1&saved_msg=done", "/images?refreshing=1&saved=1&saved_msg=done"},
		{"/volumes/h/n/browse?path=%2Ffoo", "error=oops", "/volumes/h/n/browse?path=%2Ffoo&error=oops"},
	}
	for _, c := range cases {
		if got := appendQuery(c.path, c.query); got != c.want {
			t.Errorf("appendQuery(%q, %q) = %q, want %q", c.path, c.query, got, c.want)
		}
	}
}

func TestLocalPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/stacks/x", "/stacks/x"},
		{"/containers//evil.com", "/containers//evil.com"},
		{"//evil.com", "/"},
		{`/\evil.com`, "/"},
		{"https://evil.com", "/"},
		{"evil.com", "/"},
		{"", "/"},
		{"/ok\r\nSet-Cookie: x=1", "/"},
	}
	for _, c := range cases {
		if got := localPath(c.in); got != c.want {
			t.Errorf("localPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := appendQuery("//evil.com", "error=x"); got != "/?error=x" {
		t.Errorf("appendQuery must not carry an off-site path: %q", got)
	}
}
