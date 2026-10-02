// Secret provider connections (/settings/secret-providers): the shared
// backends (OpenBao, ...) that a Git stack's secrets.refs.yaml can read
// from, cf. ARCHITECTURE.md, "Secrets externes".
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/forgelab-me/wharf-server/internal/secrets"
	"github.com/forgelab-me/wharf-server/internal/store"
)

const checkTimeout = 15 * time.Second

// effectiveFor resolves a connection into what a resolution needs: the
// config (inherited from the parent for a local connection that has one)
// and the credentials that apply.
func (a *app) effectiveFor(conn store.SecretConnection, prefixes []string) (*secrets.Effective, error) {
	return a.effectiveForStack(conn, "", prefixes)
}

// effectiveForStack is effectiveFor for a given stack, whose id the connection's
// path rules are written around.
func (a *app) effectiveForStack(conn store.SecretConnection, stackID string, prefixes []string) (*secrets.Effective, error) {
	config := conn.Config
	var source string
	switch {
	case conn.ParentID != "":
		parent, err := a.store.GetSecretConnection(conn.ParentID)
		if err != nil {
			return nil, fmt.Errorf("load the connection %q inherits from: %w", conn.Name, err)
		}
		config = parent.Config
		source = fmt.Sprintf("this stack's own credentials on %q", parent.Name)
	case conn.StackID != "":
		source = "this stack's own connection"
	default:
		source = fmt.Sprintf("connection %q", conn.Name)
	}
	creds, err := a.keys.SecretCredentials(conn.ID)
	if err != nil {
		return nil, err
	}
	if len(creds) == 0 {
		return nil, fmt.Errorf("connection %q has no credentials: give this stack its own", conn.Name)
	}
	eff := secrets.NewEffective(conn.Type, config, creds, prefixes, source)
	if err := eff.ApplyPathRules(stackID); err != nil {
		return nil, err
	}
	return eff, nil
}

// stackBinding returns the lookup a Job uses to find a stack's connection for a scheme.
func (a *app) stackBinding(stackID string) func(scheme string) (*secrets.Effective, error) {
	return func(scheme string) (*secrets.Effective, error) {
		b, err := a.store.GetSecretBinding(stackID, scheme)
		if errors.Is(err, store.ErrNotFound) {
			return nil, &secrets.NoBindingError{Scheme: scheme}
		}
		if err != nil {
			return nil, err
		}
		conn, err := a.store.GetSecretConnection(b.ConnectionID)
		if err != nil {
			return nil, fmt.Errorf("load this stack's %s connection: %w", scheme, err)
		}
		return a.effectiveForStack(conn, stackID, b.Prefixes)
	}
}

// dropLocalConnection removes a stack-private connection and its credentials.
func (a *app) dropLocalConnection(id string) error {
	if err := a.keys.DeleteSecretCredentials(id); err != nil {
		return err
	}
	return a.store.DeleteSecretConnection(id)
}

// fieldView is one form input, with the current value already filled in.
type fieldView struct {
	secrets.Field
	InputName string
	Value     string
	Set       bool // credential fields: a value is stored (never shown)
	Options   []optionView
}

type optionView struct {
	Value    string
	Selected bool
}

func (f fieldView) IsSelect() bool   { return f.Input == "select" }
func (f fieldView) IsTextarea() bool { return f.Input == "textarea" }

// fieldViews splits a connector's fields into config and credential inputs.
func fieldViews(c secrets.Connector, config map[string]string, setCredentials []string) (configFields, credFields []fieldView) {
	isSet := map[string]bool{}
	for _, n := range setCredentials {
		isSet[n] = true
	}
	for _, f := range c.Fields() {
		v := fieldView{Field: f}
		if f.Credential {
			v.InputName = "cred_" + f.Name
			v.Set = isSet[f.Name]
			credFields = append(credFields, v)
			continue
		}
		v.InputName = "cfg_" + f.Name
		v.Value = config[f.Name]
		if v.Value == "" {
			v.Value = f.Default
		}
		for _, o := range f.Options {
			v.Options = append(v.Options, optionView{Value: o, Selected: o == v.Value})
		}
		configFields = append(configFields, v)
	}
	return configFields, credFields
}

// configFromForm reads the cfg_* inputs, applying defaults.
func configFromForm(r *http.Request, c secrets.Connector) map[string]string {
	config := map[string]string{}
	for _, f := range c.Fields() {
		if f.Credential {
			continue
		}
		v := strings.TrimSpace(r.FormValue("cfg_" + f.Name))
		if v == "" {
			v = f.Default
		}
		if v != "" {
			config[f.Name] = v
		}
	}
	return config
}

// credentialsFromForm reads the cred_* inputs; empty ones are left out.
func credentialsFromForm(r *http.Request, c secrets.Connector) map[string]string {
	creds := map[string]string{}
	for _, f := range c.Fields() {
		if !f.Credential {
			continue
		}
		if v := strings.TrimSpace(r.FormValue("cred_" + f.Name)); v != "" {
			creds[f.Name] = v
		}
	}
	return creds
}

// connectorSummary is the one-line description shown in lists: the first required config field.
func connectorSummary(c secrets.Connector, config map[string]string) string {
	if s, ok := c.(interface {
		Summary(map[string]string) string
	}); ok {
		return s.Summary(config)
	}
	for _, f := range c.Fields() {
		if !f.Credential && f.Required {
			return config[f.Name]
		}
	}
	return ""
}

type secretProviderRow struct {
	ID             string
	Name           string
	Label          string
	Summary        string
	HasCredentials bool
	Rules          []string // the connection's path rules, {stack} as written
	Shared, Own    []string
}

func (a *app) secretProvidersHandler(w http.ResponseWriter, r *http.Request) {
	conns, err := a.store.ListGlobalSecretConnections()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows := make([]secretProviderRow, 0, len(conns))
	for _, c := range conns {
		row := secretProviderRow{ID: c.ID, Name: c.Name, Label: c.Type}
		row.Rules, _ = secrets.ParseRules(c.Config[secrets.PathRulesKey])
		if connector, ok := a.resolver.Connector(c.Type); ok {
			row.Label = connector.Label()
			row.Summary = connectorSummary(connector, c.Config)
		}
		if names, err := a.keys.SecretCredentialFields(c.ID); err == nil {
			row.HasCredentials = len(names) > 0
		}
		row.Shared, row.Own, _ = a.store.SecretConnectionUsers(c.ID)
		rows = append(rows, row)
	}
	render(w, r, "layout", "secret_providers.html", map[string]any{
		"Title":      "Secret providers",
		"Nav":        "secret-providers",
		"Rows":       rows,
		"Connectors": a.resolver.Connectors(),
		"Bws":        a.bwsStatus(),
	})
}

func (a *app) newSecretProviderFormHandler(w http.ResponseWriter, r *http.Request) {
	connector, ok := a.resolver.Connector(r.URL.Query().Get("type"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	configFields, credFields := fieldViews(connector, nil, nil)
	render(w, r, "layout", "secret_provider_form.html", map[string]any{
		"Title":        "New " + connector.Label() + " connection",
		"Nav":          "secret-providers",
		"Connector":    connector,
		"ConfigFields": configFields,
		"CredFields":   credFields,
	})
}

func (a *app) createSecretProviderHandler(w http.ResponseWriter, r *http.Request) {
	connector, ok := a.resolver.Connector(r.FormValue("type"))
	if !ok {
		http.Error(w, "unknown provider type", http.StatusBadRequest)
		return
	}
	back := "/settings/secret-providers/new?type=" + connector.Scheme()

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" || len(name) > 80 {
		redirectWithError(w, r, back, "give the connection a name (80 characters at most)")
		return
	}
	config := configFromForm(r, connector)
	if err := connector.ValidateConfig(config); err != nil {
		redirectWithError(w, r, back, err.Error())
		return
	}
	creds := credentialsFromForm(r, connector)
	if len(creds) > 0 {
		if err := connector.ValidateCredentials(creds); err != nil {
			redirectWithError(w, r, back, err.Error())
			return
		}
	}

	id, err := randomHex(8)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.keys.SetSecretCredentials(id, creds); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = a.store.CreateSecretConnection(store.SecretConnection{ID: id, Name: name, Type: connector.Scheme(), Config: config})
	if err != nil {
		_ = a.keys.DeleteSecretCredentials(id)
		redirectWithError(w, r, back, "could not create the connection (name already taken?)")
		return
	}
	a.audit(r, "secrets.connection_create", name, connector.Scheme())
	redirectWithSavedMessage(w, r, "/settings/secret-providers", "Connection created")
}

func (a *app) globalSecretConnection(w http.ResponseWriter, r *http.Request) (store.SecretConnection, secrets.Connector, bool) {
	conn, err := a.store.GetSecretConnection(r.PathValue("id"))
	if err != nil || conn.StackID != "" {
		http.NotFound(w, r)
		return conn, nil, false
	}
	connector, ok := a.resolver.Connector(conn.Type)
	if !ok {
		http.Error(w, "this connection's provider is not available", http.StatusInternalServerError)
		return conn, nil, false
	}
	return conn, connector, true
}

func (a *app) editSecretProviderFormHandler(w http.ResponseWriter, r *http.Request) {
	conn, connector, ok := a.globalSecretConnection(w, r)
	if !ok {
		return
	}
	set, _ := a.keys.SecretCredentialFields(conn.ID)
	configFields, credFields := fieldViews(connector, conn.Config, set)
	children, _ := a.store.SecretConnectionChildren(conn.ID)
	render(w, r, "layout", "secret_provider_form.html", map[string]any{
		"Title":        conn.Name,
		"Nav":          "secret-providers",
		"Connector":    connector,
		"Connection":   conn,
		"ConfigFields": configFields,
		"CredFields":   credFields,
		"HasCreds":     len(set) > 0,
		"Inheriting":   len(children),
	})
}

func (a *app) updateSecretProviderHandler(w http.ResponseWriter, r *http.Request) {
	conn, connector, ok := a.globalSecretConnection(w, r)
	if !ok {
		return
	}
	back := "/settings/secret-providers/" + conn.ID

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" || len(name) > 80 {
		redirectWithError(w, r, back, "give the connection a name (80 characters at most)")
		return
	}
	config := configFromForm(r, connector)
	if err := connector.ValidateConfig(config); err != nil {
		redirectWithError(w, r, back, err.Error())
		return
	}

	// The credential group is replaced as a whole: leaving every field empty
	// keeps what is stored, typing any of them replaces the full set.
	creds := credentialsFromForm(r, connector)
	switch {
	case r.FormValue("clear_credentials") != "":
		if err := a.keys.DeleteSecretCredentials(conn.ID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case len(creds) > 0:
		if err := connector.ValidateCredentials(creds); err != nil {
			redirectWithError(w, r, back, err.Error())
			return
		}
		if err := a.keys.SetSecretCredentials(conn.ID, creds); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if err := a.store.UpdateSecretConnection(conn.ID, name, config); err != nil {
		redirectWithError(w, r, back, "could not save (name already taken?)")
		return
	}
	a.audit(r, "secrets.connection_update", name, connector.Scheme())
	redirectWithSaved(w, r, back)
}

func (a *app) deleteSecretProviderHandler(w http.ResponseWriter, r *http.Request) {
	conn, _, ok := a.globalSecretConnection(w, r)
	if !ok {
		return
	}
	back := "/settings/secret-providers/" + conn.ID
	shared, own, err := a.store.SecretConnectionUsers(conn.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if users := append(shared, own...); len(users) > 0 {
		redirectWithError(w, r, back, "still used by: "+strings.Join(users, ", ")+" — remove it from those stacks first")
		return
	}
	if err := a.keys.DeleteSecretCredentials(conn.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.store.DeleteSecretConnection(conn.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.audit(r, "secrets.connection_delete", conn.Name, conn.Type)
	redirectWithSavedMessage(w, r, "/settings/secret-providers", "Connection deleted")
}

// testSecretProviderHandler proves the connection's default credentials work.
func (a *app) testSecretProviderHandler(w http.ResponseWriter, r *http.Request) {
	conn, connector, ok := a.globalSecretConnection(w, r)
	if !ok {
		return
	}
	a.runConnectionCheck(w, r, conn, connector, nil, "/settings/secret-providers")
}

// runConnectionCheck runs a provider's Check and redirects with the outcome.
func (a *app) runConnectionCheck(w http.ResponseWriter, r *http.Request, conn store.SecretConnection, connector secrets.Connector, prefixes []string, back string) {
	eff, err := a.effectiveFor(conn, prefixes)
	if err != nil {
		redirectWithError(w, r, back, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), checkTimeout)
	defer cancel()
	if err := connector.Check(ctx, eff); err != nil {
		a.audit(r, "secrets.connection_test", conn.Name, "failed")
		redirectWithError(w, r, back, "connection test failed: "+err.Error())
		return
	}
	a.audit(r, "secrets.connection_test", conn.Name, "ok")
	redirectWithSavedMessage(w, r, back, "Connection OK — "+eff.Source)
}
