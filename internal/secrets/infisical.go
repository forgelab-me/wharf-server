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
	infisicalScheme      = "infisical"
	infisicalMaxResponse = 1 << 20
	// infisicalTokenMargin: a cached Universal Auth token is renewed this long before it expires.
	infisicalTokenMargin = 30 * time.Second
)

// InfisicalProvider serves ref+infisical://<project id>/<environment>[/<secret
// path>]#/<secret name> from Infisical (cloud or self-hosted), authenticating
// with a machine identity access token or Universal Auth (client ID + secret).
func InfisicalProvider() Connector {
	return &infisicalProvider{clients: map[string]*http.Client{}, tokens: map[string]infisicalToken{}}
}

type infisicalToken struct {
	value   string
	expires time.Time
}

type infisicalProvider struct {
	mu      sync.Mutex
	clients map[string]*http.Client
	tokens  map[string]infisicalToken // keyed by Effective.Identity
}

func (*infisicalProvider) Scheme() string { return infisicalScheme }
func (*infisicalProvider) Label() string  { return "Infisical" }

func (*infisicalProvider) Fields() []Field {
	return []Field{
		{Name: "site_url", Label: "Site URL", Required: true, Default: "https://app.infisical.com",
			Placeholder: "https://app.infisical.com", Help: "Infisical Cloud, or a self-hosted instance's URL."},
		{Name: "ca_pem", Label: "CA certificate (PEM)", Input: "textarea", Help: "Only needed when a self-hosted instance uses a private CA."},
		PathRulesField,
		{Name: "token", Label: "Access token", Credential: true,
			Help: "A machine identity access token. Either this, or a Universal Auth client ID and secret."},
		{Name: "client_id", Label: "Universal Auth client ID", Credential: true},
		{Name: "client_secret", Label: "Universal Auth client secret", Credential: true},
	}
}

func (*infisicalProvider) ValidateConfig(config map[string]string) error {
	u, err := url.Parse(strings.TrimSpace(config["site_url"]))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("site URL must be a full http(s) URL, e.g. https://app.infisical.com")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("site URL must not contain credentials, a query or a fragment")
	}
	if pem := config["ca_pem"]; strings.TrimSpace(pem) != "" {
		if !x509.NewCertPool().AppendCertsFromPEM([]byte(pem)) {
			return errors.New("CA certificate is not a valid PEM certificate")
		}
	}
	return ValidatePathRules(config)
}

func (*infisicalProvider) ValidateCredentials(creds map[string]string) error {
	token, id, secret := creds["token"], creds["client_id"], creds["client_secret"]
	switch {
	case token != "" && (id != "" || secret != ""):
		return errors.New("use either an access token or a client ID and secret, not both")
	case token != "":
		return nil
	case id != "" && secret != "":
		return nil
	case id != "" || secret != "":
		return errors.New("Universal Auth needs both a client ID and a client secret")
	}
	return errors.New("provide an access token, or a client ID and secret (Universal Auth)")
}

// Check logs in (fresh, not from the cache) and asks Infisical for the
// identity's own details: proof the credentials work, without reading a secret.
func (p *infisicalProvider) Check(ctx context.Context, eff *Effective) error {
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
	token := eff.Credentials["token"]
	if token == "" {
		if token, err = p.login(ctx, client, eff); err != nil {
			return err
		}
	}
	status, body, err := p.call(ctx, client, eff, http.MethodGet, "api/v1/identities/details", token, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return infisicalStatusError("check", "the connection", status, body)
	}
	return nil
}

func (p *infisicalProvider) Resolve(ctx context.Context, job *Job, ref Ref) (string, error) {
	eff, err := job.Effective(infisicalScheme)
	if err != nil {
		return "", err
	}
	project, environment, secretPath, err := splitInfisicalPath(ref.Path)
	if err != nil {
		return "", err
	}
	v, err := job.Memo("infisical|"+eff.Identity+"|"+ref.Path+"#/"+ref.Field, func() (any, error) {
		return p.read(ctx, eff, project, environment, secretPath, ref.Field, ref.Path+"#/"+ref.Field)
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

// splitInfisicalPath pulls the project id and environment slug out of a
// reference's path; what is left, if anything, is the secret's folder path.
func splitInfisicalPath(path string) (project, environment, secretPath string, err error) {
	segs := strings.SplitN(path, "/", 3)
	if len(segs) < 2 {
		return "", "", "", errors.New("path must be <project id>/<environment>[/<secret path>]")
	}
	secretPath = "/"
	if len(segs) == 3 {
		secretPath += segs[2]
	}
	return segs[0], segs[1], secretPath, nil
}

// read fetches one secret by name, logging in again once if a cached
// Universal Auth token was refused.
func (p *infisicalProvider) read(ctx context.Context, eff *Effective, project, environment, secretPath, name, subject string) (string, error) {
	client, err := p.client(eff)
	if err != nil {
		return "", err
	}
	q := url.Values{"projectId": {project}, "environment": {environment}, "secretPath": {secretPath}}
	apiPath := "api/v4/secrets/" + url.PathEscape(name) + "?" + q.Encode()

	static := eff.Credentials["token"] != ""
	for attempt := 0; ; attempt++ {
		token, err := p.token(ctx, client, eff, attempt > 0)
		if err != nil {
			return "", err
		}
		status, body, err := p.call(ctx, client, eff, http.MethodGet, apiPath, token, nil)
		if err != nil {
			return "", err
		}
		if (status == http.StatusUnauthorized || status == http.StatusForbidden) && !static && attempt == 0 {
			continue
		}
		if status != http.StatusOK {
			return "", infisicalStatusError("read", subject, status, body)
		}
		var out struct {
			Secret struct {
				SecretValue string `json:"secretValue"`
			} `json:"secret"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return "", errors.New("unexpected response from Infisical")
		}
		return out.Secret.SecretValue, nil
	}
}

// token returns a usable access token: the static one, or a cached Universal Auth login.
func (p *infisicalProvider) token(ctx context.Context, client *http.Client, eff *Effective, forceLogin bool) (string, error) {
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

func (p *infisicalProvider) login(ctx context.Context, client *http.Client, eff *Effective) (string, error) {
	status, body, err := p.call(ctx, client, eff, http.MethodPost, "api/v1/auth/universal-auth/login", "", map[string]string{
		"clientId":     eff.Credentials["client_id"],
		"clientSecret": eff.Credentials["client_secret"],
	})
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", infisicalStatusError("login", "", status, body)
	}
	var out struct {
		AccessToken string `json:"accessToken"`
		ExpiresIn   int64  `json:"expiresIn"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		return "", errors.New("login succeeded but returned no access token")
	}

	ttl := time.Duration(out.ExpiresIn)*time.Second - infisicalTokenMargin
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
	p.tokens[eff.Identity] = infisicalToken{value: out.AccessToken, expires: now.Add(ttl)}
	p.mu.Unlock()
	return out.AccessToken, nil
}

// call sends one API request. It never follows a redirect: the token would
// travel with it.
func (p *infisicalProvider) call(ctx context.Context, client *http.Client, eff *Effective, method, apiPath, token string, payload any) (int, []byte, error) {
	address := strings.TrimRight(strings.TrimSpace(eff.Config["site_url"]), "/")
	var body io.Reader
	if payload != nil {
		raw, _ := json.Marshal(payload)
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, address+"/"+apiPath, body)
	if err != nil {
		return 0, nil, errors.New("invalid Infisical site URL or path")
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		if ctx.Err() != nil {
			return 0, nil, fmt.Errorf("timed out talking to Infisical at %s", address)
		}
		return 0, nil, fmt.Errorf("cannot reach Infisical at %s: %v", address, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, infisicalMaxResponse))
	if err != nil {
		return 0, nil, fmt.Errorf("reading the Infisical response: %v", err)
	}
	return resp.StatusCode, raw, nil
}

func (p *infisicalProvider) client(eff *Effective) (*http.Client, error) {
	key := eff.Config["site_url"] + "\n" + eff.Config["ca_pem"]
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

// infisicalStatusError turns an API failure into a message that says which
// step failed and why, without echoing anything but the server's own error text.
func infisicalStatusError(step, subject string, status int, body []byte) error {
	detail := infisicalErrorText(body)
	switch {
	case status >= 300 && status < 400:
		return fmt.Errorf("Infisical answered with a redirect (%d), which is not followed", status)
	case step == "login":
		if detail == "" {
			detail = fmt.Sprintf("status %d", status)
		}
		return fmt.Errorf("login refused: %s", detail)
	case step == "read" && (status == http.StatusUnauthorized || status == http.StatusForbidden):
		return fmt.Errorf("permission denied by Infisical for %s", subject)
	case step == "read" && status == http.StatusNotFound:
		return fmt.Errorf("no secret at %s", subject)
	case step == "check" && (status == http.StatusUnauthorized || status == http.StatusForbidden):
		return fmt.Errorf("%s was refused by Infisical", subject)
	}
	if detail == "" {
		detail = "no details"
	}
	return fmt.Errorf("Infisical answered %d: %s", status, detail)
}

func infisicalErrorText(body []byte) string {
	var out struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &out) != nil {
		return ""
	}
	text := out.Message
	if len(text) > 200 {
		text = text[:200] + "..."
	}
	return text
}
