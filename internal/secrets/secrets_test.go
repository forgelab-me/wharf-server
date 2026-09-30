package secrets

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestParseRef(t *testing.T) {
	valid := map[string]Ref{
		"ref+vault://secret/blog/db#/password":  {"vault", "secret/blog/db", "password"},
		"ref+sops://secrets.enc.yaml#/API_KEY":  {"sops", "secrets.enc.yaml", "API_KEY"},
		"ref+awsssm://prod/blog/token#/value":   {"awsssm", "prod/blog/token", "value"},
		"ref+vault://mount/a.b/c-d_e#/f.g-h_i1": {"vault", "mount/a.b/c-d_e", "f.g-h_i1"},
	}
	for in, want := range valid {
		got, err := ParseRef(in)
		if err != nil || got != want {
			t.Errorf("ParseRef(%q) = %+v, %v; want %+v", in, got, err, want)
		}
		if got.String() != in {
			t.Errorf("String() = %q, want %q", got.String(), in)
		}
	}

	invalid := []string{
		"",
		"hunter2",
		"vault://secret/x#/y",
		"ref+vault:/secret/x#/y",
		"ref+Vault://secret/x#/y",
		"ref+://secret/x#/y",
		"ref+vault://secret/x",
		"ref+vault://secret/x#password",
		"ref+vault://secret/x#/",
		"ref+vault://secret/x#/a/b",
		"ref+vault://#/y",
		"ref+vault://secret/x?address=https://evil.example#/y",
		"ref+vault://secret/x#/y?version=3",
		"ref+vault://secret/../prod/db#/y",
		"ref+vault://secret/./db#/y",
		"ref+vault://secret//db#/y",
		"ref+vault:///secret/db#/y",
		"ref+vault://secret/db/#/y",
		"ref+vault://secret/%2e%2e/db#/y",
		"ref+vault://secret\\db#/y",
		"ref+vault://secret/my db#/y",
		"ref+vault://secret/db#/my field",
		"ref+vault://secret/db\n#/y",
	}
	for _, in := range invalid {
		if got, err := ParseRef(in); err == nil {
			t.Errorf("ParseRef(%q) = %+v, want an error", in, got)
		}
	}
}

func TestParseFile(t *testing.T) {
	entries, err := ParseFile([]byte(`
# comment
DB_PASSWORD: ref+vault://secret/blog/db#/password
API_KEY: "ref+sops://secrets.enc.yaml#/API_KEY"
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Key != "DB_PASSWORD" || entries[1].Ref.Scheme != "sops" {
		t.Fatalf("entries = %+v", entries)
	}

	for _, empty := range []string{"", "# only a comment\n", "---\n"} {
		entries, err := ParseFile([]byte(empty))
		if err != nil || len(entries) != 0 {
			t.Errorf("ParseFile(%q) = %+v, %v; want no entries, no error", empty, entries, err)
		}
	}
}

func TestParseFileRejects(t *testing.T) {
	cases := map[string]struct{ in, wantErr string }{
		"literal":       {"PASSWORD: hunter2\n", "PASSWORD: literal values are not allowed"},
		"number":        {"PORT: 5432\n", "PORT: value must be a ref"},
		"nested":        {"DB:\n  password: ref+vault://a/b#/c\n", "DB: value must be a ref"},
		"list":          {"- ref+vault://a/b#/c\n", "not a valid flat"},
		"bad key":       {"1BAD: ref+vault://a/b#/c\n", "entry 1: key is not a valid environment variable name"},
		"dashed key":    {"MY-KEY: ref+vault://a/b#/c\n", "entry 1: key is not a valid environment variable name"},
		"query":         {"K: ref+vault://a/b?address=x#/c\n", "K: query parameters are not allowed"},
		"traversal":     {"K: ref+vault://a/../b#/c\n", "K: path:"},
		"duplicate key": {"K: ref+vault://a/b#/c\nK: ref+vault://a/b#/d\n", ""},
		"broken yaml":   {"K: [unclosed\n", "not a valid flat"},
	}
	for name, tc := range cases {
		_, err := ParseFile([]byte(tc.in))
		if err == nil {
			t.Errorf("%s: want an error", name)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: error %q does not contain %q", name, err, tc.wantErr)
		}
	}
}

func TestParseFileListsEveryProblem(t *testing.T) {
	_, err := ParseFile([]byte("A: literal\nB: ref+vault://a/b#/c\nC: 12\n"))
	if err == nil || !strings.Contains(err.Error(), "A:") || !strings.Contains(err.Error(), "C:") || strings.Contains(err.Error(), "B:") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseFileNeverEchoesContent(t *testing.T) {
	const secret = "root:x:0:0:top-secret-marker"
	for _, in := range []string{
		secret + "\n",
		secret + ": ref+vault://a/b#/c\n",
		"K: " + secret + "\n",
		"K: [" + secret + "\n",
	} {
		_, err := ParseFile([]byte(in))
		if err == nil {
			t.Fatalf("ParseFile(%q) succeeded", in)
		}
		if strings.Contains(err.Error(), "top-secret-marker") {
			t.Errorf("error echoes file content: %v", err)
		}
	}
}

func TestParseFileSizeCap(t *testing.T) {
	big := strings.Repeat("# padding\n", MaxRefsFileSize/8)
	if _, err := ParseFile([]byte(big)); err == nil {
		t.Fatal("want an error for an oversized file")
	}
}

func asResolveError(err error, target **ResolveError) bool { return errors.As(err, target) }

func fakeDecrypt(calls *int, values map[string]string, err error) func(string, []byte) (map[string]string, error) {
	return func(stackID string, ciphertext []byte) (map[string]string, error) {
		*calls++
		return values, err
	}
}

func TestResolveSOPS(t *testing.T) {
	calls := 0
	job := &Job{
		StackID:    "blog",
		EncFile:    []byte("ciphertext"),
		DecryptEnc: fakeDecrypt(&calls, map[string]string{"API_KEY": "k", "OTHER": "o", "UNUSED": "u"}, nil),
	}
	entries := []Entry{
		{"API_KEY", Ref{"sops", EncFileName, "API_KEY"}},
		{"RENAMED", Ref{"sops", EncFileName, "OTHER"}},
	}

	res, err := NewResolver(SOPSProvider()).Resolve(context.Background(), job, entries)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Env) != 2 || res.Env["API_KEY"] != "k" || res.Env["RENAMED"] != "o" {
		t.Fatalf("Env = %v", res.Env)
	}
	if _, leaked := res.Env["UNUSED"]; leaked {
		t.Fatal("an unreferenced key must never be returned")
	}
	if calls != 1 {
		t.Fatalf("secrets.enc.yaml decrypted %d times, want 1", calls)
	}
	if len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "UNUSED") || strings.Contains(res.Notes[0], "OTHER") {
		t.Fatalf("Notes = %v", res.Notes)
	}
}

func TestResolveFailsClosedAndListsEveryFailure(t *testing.T) {
	calls := 0
	job := &Job{
		StackID:    "blog",
		EncFile:    []byte("ciphertext"),
		DecryptEnc: fakeDecrypt(&calls, map[string]string{"OK": "v"}, nil),
	}
	entries := []Entry{
		{"GOOD", Ref{"sops", EncFileName, "OK"}},
		{"MISSING", Ref{"sops", EncFileName, "NOPE"}},
		{"WRONG_FILE", Ref{"sops", "other.yaml", "OK"}},
		{"NO_PROVIDER", Ref{"vault", "secret/blog/db", "password"}},
	}

	res, err := NewResolver(SOPSProvider()).Resolve(context.Background(), job, entries)
	var rerr *ResolveError
	if !errors.As(err, &rerr) {
		t.Fatalf("err = %v, want *ResolveError", err)
	}
	if len(rerr.Failures) != 3 {
		t.Fatalf("Failures = %+v, want 3", rerr.Failures)
	}
	if res.Env != nil {
		t.Fatalf("a failed job must return no environment, got %v", res.Env)
	}
	for _, want := range []string{"MISSING", "WRONG_FILE", "NO_PROVIDER"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %s: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "GOOD") {
		t.Errorf("error names a key that resolved: %v", err)
	}
}

func TestResolveSOPSWithoutEncFile(t *testing.T) {
	job := &Job{StackID: "blog"}
	_, err := NewResolver(SOPSProvider()).Resolve(context.Background(), job,
		[]Entry{{"K", Ref{"sops", EncFileName, "K"}}})
	if err == nil || !strings.Contains(err.Error(), "was not found next to the compose file") {
		t.Fatalf("err = %v", err)
	}
}

func TestUnreferencedUndecryptableEncFileIsNotAnError(t *testing.T) {
	calls := 0
	job := &Job{
		StackID:    "blog",
		EncFile:    []byte("garbage"),
		DecryptEnc: fakeDecrypt(&calls, nil, errors.New("decrypt: no identity matched")),
	}
	res, err := NewResolver(SOPSProvider()).Resolve(context.Background(), job, nil)
	if err != nil || len(res.Env) != 0 || len(res.Notes) != 0 {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}
