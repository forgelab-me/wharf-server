package keys

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretCredentials(t *testing.T) {
	c, err := Open(filepath.Join(t.TempDir(), "keys.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })

	if got, err := c.SecretCredentials("conn"); err != nil || got != nil {
		t.Fatalf("no credentials yet: %v, %v", got, err)
	}

	if err := c.SetSecretCredentials("conn", map[string]string{"role_id": "r", "secret_id": "s3cret", "token": ""}); err != nil {
		t.Fatal(err)
	}
	got, err := c.SecretCredentials("conn")
	if err != nil || got["role_id"] != "r" || got["secret_id"] != "s3cret" {
		t.Fatalf("got %v, %v", got, err)
	}
	names, _ := c.SecretCredentialFields("conn")
	if strings.Join(names, ",") != "role_id,secret_id" {
		t.Fatalf("fields = %v: only non-empty ones, and never a value", names)
	}

	if err := c.SetSecretCredentials("conn", map[string]string{"token": "s.new"}); err != nil {
		t.Fatal(err)
	}
	got, _ = c.SecretCredentials("conn")
	if len(got) != 1 || got["token"] != "s.new" {
		t.Fatalf("a second Set must replace the whole group, got %v", got)
	}

	if err := c.SetSecretCredentials("conn", nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := c.SecretCredentials("conn"); got != nil {
		t.Fatalf("empty Set must remove them, got %v", got)
	}
	if err := c.DeleteSecretCredentials("never-existed"); err != nil {
		t.Fatalf("deleting nothing must not fail: %v", err)
	}
}
