package secrets

import (
	"context"
	"os"
	"testing"
)

// TestInfisicalLive reads one real secret from Infisical. It is skipped unless
// INFISICAL_REF is set, e.g. INFISICAL_REF='ref+infisical://<project id>/dev/db#/password',
// with INFISICAL_CLIENT_ID and INFISICAL_CLIENT_SECRET (or INFISICAL_TOKEN), and
// optionally INFISICAL_SITE_URL. It never prints the value, only its length.
func TestInfisicalLive(t *testing.T) {
	raw := os.Getenv("INFISICAL_REF")
	if raw == "" {
		t.Skip("INFISICAL_REF is not set")
	}
	ref, err := ParseRef(raw)
	if err != nil {
		t.Fatalf("INFISICAL_REF: %v", err)
	}
	if ref.Scheme != infisicalScheme {
		t.Fatalf("INFISICAL_REF must be a ref+infisical:// reference, got %q", ref.Scheme)
	}

	site := os.Getenv("INFISICAL_SITE_URL")
	if site == "" {
		site = "https://app.infisical.com"
	}
	creds := map[string]string{}
	for env, key := range map[string]string{"INFISICAL_TOKEN": "token", "INFISICAL_CLIENT_ID": "client_id", "INFISICAL_CLIENT_SECRET": "client_secret"} {
		if v := os.Getenv(env); v != "" {
			creds[key] = v
		}
	}

	p := InfisicalProvider()
	eff := NewEffective(infisicalScheme, map[string]string{"site_url": site}, creds, []string{"*"}, "live test")

	if err := p.Check(context.Background(), eff); err != nil {
		t.Fatalf("Check: %v", err)
	}
	t.Log("Check: ok")

	job := &Job{StackID: "live", Binding: func(string) (*Effective, error) { return eff, nil }}
	v, err := p.Resolve(context.Background(), job, ref)
	if err != nil {
		t.Fatalf("Resolve %s: %v", ref, err)
	}
	t.Logf("Resolve %s: ok, value of %d characters", ref, len(v))
}
