package secrets

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	vaultScheme      = "vault"
	vaultMaxResponse = 1 << 20
	// vaultTokenMargin: a cached AppRole token is renewed this long before it expires.
	vaultTokenMargin = 30 * time.Second
)

// VaultProvider serves ref+vault://<mount>/<path>#/<field> from OpenBao or
// HashiCorp Vault (KV v1 or v2), authenticating with a token or AppRole.
func VaultProvider() Connector {
	return &vaultProvider{clients: map[string]*http.Client{}, tokens: map[string]vaultToken{}}
}

type vaultToken struct {
	value   string
	expires time.Time
}

type vaultProvider struct {
	mu      sync.Mutex
	clients map[string]*http.Client
	tokens  map[string]vaultToken // keyed by Effective.Identity
}

func (*vaultProvider) Scheme() string { return vaultScheme }
func (*vaultProvider) Label() string  { return "OpenBao / Vault" }

func (*vaultProvider) Fields() []Field {
	return []Field{
		{Name: "address", Label: "Address", Required: true, Placeholder: "https://openbao.example.lan:8200"},
		{Name: "kv_version", Label: "KV engine version", Input: "select", Options: []string{"2", "1"}, Default: "2"},
		{Name: "namespace", Label: "Namespace", Help: "Optional."},
		{Name: "approle_mount", Label: "AppRole auth mount", Default: "approle", Help: "Only used with a role ID and secret ID."},
		{Name: "ca_pem", Label: "CA certificate (PEM)", Input: "textarea", Help: "Only needed when the server uses a private CA."},
		PathRulesField,
		{Name: "token", Label: "Token", Credential: true, Help: "Either a token, or an AppRole role ID and secret ID."},
		{Name: "role_id", Label: "AppRole role ID", Credential: true},
		{Name: "secret_id", Label: "AppRole secret ID", Credential: true},
	}
}

func (*vaultProvider) ValidateConfig(config map[string]string) error {
	u, err := url.Parse(strings.TrimSpace(config["address"]))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("address must be a full http(s) URL, e.g. https://openbao.example.lan:8200")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("address must not contain credentials, a query or a fragment")
	}
	if v := config["kv_version"]; v != "" && v != "1" && v != "2" {
		return errors.New("KV engine version must be 1 or 2")
	}
	for _, name := range []string{"namespace", "approle_mount"} {
		if v := config[name]; v != "" {
			if err := checkPath(v); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	if pem := config["ca_pem"]; strings.TrimSpace(pem) != "" {
		if !x509.NewCertPool().AppendCertsFromPEM([]byte(pem)) {
			return errors.New("CA certificate is not a valid PEM certificate")
		}
	}
	return ValidatePathRules(config)
}

func (*vaultProvider) ValidateCredentials(creds map[string]string) error {
	token, role, secret := creds["token"], creds["role_id"], creds["secret_id"]
	switch {
	case token != "" && (role != "" || secret != ""):
		return errors.New("use either a token or a role ID and secret ID, not both")
	case token != "":
		return nil
	case role != "" && secret != "":
		return nil
	case role != "" || secret != "":
		return errors.New("an AppRole needs both a role ID and a secret ID")
	}
	return errors.New("provide a token, or an AppRole role ID and secret ID")
}

func (p *vaultProvider) Check(ctx context.Context, eff *Effective) error {
	if err := p.ValidateConfig(eff.Config); err != nil {
		return err
	}
	if err := p.ValidateCredentials(eff.Credentials); err != nil {
		return err
	}
	client, err := p.client(eff)
	if err != nil {
		return err
	}
	if t := eff.Credentials["token"]; t != "" {
		status, body, err := p.call(ctx, client, eff, http.MethodGet, "auth/token/lookup-self", t, nil)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return vaultStatusError("check", "the token", status, body)
		}
		return nil
	}
	_, err = p.login(ctx, client, eff)
	return err
}

func (p *vaultProvider) Resolve(ctx context.Context, job *Job, ref Ref) (string, error) {
	eff, err := job.Effective(vaultScheme)
	if err != nil {
		return "", err
	}
	mount, rest, ok := strings.Cut(ref.Path, "/")
	if !ok {
		return "", errors.New("path must be <mount>/<secret path>")
	}
	data, err := job.Memo("vault|"+eff.Identity+"|"+ref.Path, func() (any, error) {
		return p.read(ctx, eff, mount, rest, ref.Path)
	})
	if err != nil {
		return "", err
	}
	raw, ok := data.(map[string]any)[ref.Field]
	if !ok {
		return "", fmt.Errorf("field %q not found at %s", ref.Field, ref.Path)
	}
	switch v := raw.(type) {
	case string:
		return v, nil
	case float64, bool:
		return fmt.Sprint(v), nil
	}
	return "", fmt.Errorf("field %q at %s is not a string", ref.Field, ref.Path)
}

// read fetches one secret, logging in again once if a cached token was refused.
func (p *vaultProvider) read(ctx context.Context, eff *Effective, mount, rest, path string) (map[string]any, error) {
	client, err := p.client(eff)
	if err != nil {
		return nil, err
	}
	segments := []string{escapePath(mount)}
	kv2 := eff.Config["kv_version"] != "1"
	if kv2 {
		segments = append(segments, "data")
	}
	segments = append(segments, escapePath(rest))
	apiPath := strings.Join(segments, "/")

	static := eff.Credentials["token"] != ""
	for attempt := 0; ; attempt++ {
		token, err := p.token(ctx, client, eff, attempt > 0)
		if err != nil {
			return nil, err
		}
		status, body, err := p.call(ctx, client, eff, http.MethodGet, apiPath, token, nil)
		if err != nil {
			return nil, err
		}
		if status == http.StatusForbidden && !static && attempt == 0 {
			continue
		}
		if status != http.StatusOK {
			return nil, vaultStatusError("read", path, status, body)
		}
		var out struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, errors.New("unexpected response from OpenBao")
		}
		if !kv2 {
			return out.Data, nil
		}
		inner, ok := out.Data["data"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("no current version at %s (deleted or destroyed?)", path)
		}
		return inner, nil
	}
}

// token returns a usable token: the static one, or a cached AppRole login.
func (p *vaultProvider) token(ctx context.Context, client *http.Client, eff *Effective, forceLogin bool) (string, error) {
	if t := eff.Credentials["token"]; t != "" {
		return t, nil
	}
	if !forceLogin {
		p.mu.Lock()
		t, ok := p.tokens[eff.Identity]
		p.mu.Unlock()
		if ok && time.Now().Before(t.expires) {
			return t.value, nil
		}
	}
	return p.login(ctx, client, eff)
}

func (p *vaultProvider) login(ctx context.Context, client *http.Client, eff *Effective) (string, error) {
	mount := eff.Config["approle_mount"]
	if mount == "" {
		mount = "approle"
	}
	status, body, err := p.call(ctx, client, eff, http.MethodPost, "auth/"+escapePath(mount)+"/login", "", map[string]string{
		"role_id":   eff.Credentials["role_id"],
		"secret_id": eff.Credentials["secret_id"],
	})
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", vaultStatusError("login", "", status, body)
	}
	var out struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Auth.ClientToken == "" {
		return "", errors.New("login succeeded but returned no token")
	}

	ttl := time.Duration(out.Auth.LeaseDuration)*time.Second - vaultTokenMargin
	if ttl < 10*time.Second {
		ttl = 10 * time.Second
	}
	now := time.Now()
	p.mu.Lock()
	for id, t := range p.tokens {
		if now.After(t.expires) {
			delete(p.tokens, id)
		}
	}
	p.tokens[eff.Identity] = vaultToken{value: out.Auth.ClientToken, expires: now.Add(ttl)}
	p.mu.Unlock()
	return out.Auth.ClientToken, nil
}

// call sends one API request. It never follows a redirect: the token would
// travel with it.
func (p *vaultProvider) call(ctx context.Context, client *http.Client, eff *Effective, method, apiPath, token string, payload any) (int, []byte, error) {
	address := strings.TrimRight(strings.TrimSpace(eff.Config["address"]), "/")
	var body io.Reader
	if payload != nil {
		raw, _ := json.Marshal(payload)
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, address+"/v1/"+apiPath, body)
	if err != nil {
		return 0, nil, errors.New("invalid OpenBao address or path")
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if ns := eff.Config["namespace"]; ns != "" {
		req.Header.Set("X-Vault-Namespace", ns)
	}

	resp, err := client.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		if ctx.Err() != nil {
			return 0, nil, fmt.Errorf("timed out talking to OpenBao at %s", address)
		}
		return 0, nil, fmt.Errorf("cannot reach OpenBao at %s: %v", address, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, vaultMaxResponse))
	if err != nil {
		return 0, nil, fmt.Errorf("reading the OpenBao response: %v", err)
	}
	return resp.StatusCode, raw, nil
}

func (p *vaultProvider) client(eff *Effective) (*http.Client, error) {
	key := eff.Config["address"] + "\n" + eff.Config["ca_pem"]
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.clients[key]; ok {
		return c, nil
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if pem := strings.TrimSpace(eff.Config["ca_pem"]); pem != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(pem)) {
			return nil, errors.New("CA certificate is not a valid PEM certificate")
		}
		tlsConfig.RootCAs = pool
	}
	transport.TLSClientConfig = tlsConfig
	c := &http.Client{
		Transport:     transport,
		Timeout:       CallTimeout + 2*time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	p.clients[key] = c
	return c, nil
}

func escapePath(p string) string {
	segments := strings.Split(p, "/")
	for i, s := range segments {
		segments[i] = url.PathEscape(s)
	}
	return strings.Join(segments, "/")
}

// vaultStatusError turns an API failure into a message that says which step
// failed and why, without echoing anything but the server's own error text.
func vaultStatusError(step, subject string, status int, body []byte) error {
	detail := vaultErrorText(body)
	switch {
	case status == http.StatusServiceUnavailable:
		return errors.New("OpenBao is sealed or not ready (503)")
	case status == http.StatusTooManyRequests:
		return errors.New("OpenBao node is on standby (429)")
	case status >= 300 && status < 400:
		return fmt.Errorf("OpenBao answered with a redirect (%d), which is not followed", status)
	case step == "login":
		if detail == "" {
			detail = fmt.Sprintf("status %d", status)
		}
		return fmt.Errorf("login refused: %s", detail)
	case step == "read" && status == http.StatusForbidden:
		return fmt.Errorf("permission denied by the OpenBao policy for %s", subject)
	case step == "read" && status == http.StatusNotFound:
		return fmt.Errorf("no secret at %s", subject)
	case step == "check" && status == http.StatusForbidden:
		return fmt.Errorf("%s was refused by OpenBao", subject)
	}
	if detail == "" {
		detail = "no details"
	}
	return fmt.Errorf("OpenBao answered %d: %s", status, detail)
}

func vaultErrorText(body []byte) string {
	var out struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(body, &out) != nil {
		return ""
	}
	text := strings.Join(out.Errors, "; ")
	if len(text) > 200 {
		text = text[:200] + "..."
	}
	return text
}
