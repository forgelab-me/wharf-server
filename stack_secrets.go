// A Git stack's secret connections (the "Secret references" panel of its
// page): which providers its secrets.refs.yaml may use, with which
// credentials, and which paths it may read.
package main

import (
	"errors"
	"net/http"
	"strings"

	"github.com/forgelab-me/wharf-server/internal/secrets"
	"github.com/forgelab-me/wharf-server/internal/store"
)

// minAgentForSecretRefs is the first agent that understands secrets.refs.yaml.
const minAgentForSecretRefs = "0.5.0"

// agentTooOldForSecretRefs: an agent that never reported a version predates
// version reporting altogether; a non-release build ("dev") is let through.
func agentTooOldForSecretRefs(agentVersion string) bool {
	return agentVersion == "" || semverLess(agentVersion, minAgentForSecretRefs)
}

func agentTooOldMessage(agentVersion string) string {
	if agentVersion == "" {
		agentVersion = "an unknown version"
	}
	return "this stack uses secret providers, which need agent " + minAgentForSecretRefs +
		" or later (this host runs " + agentVersion + "): update the agent, then deploy again"
}

const (
	modeShared   = "shared"   // the global connection, as is
	modeOwn      = "own"      // the global connection's address, this stack's credentials
	modeSeparate = "separate" // a connection of its own
)

type bindingRow struct {
	Type       string
	Label      string
	Connection string
	Mode       string
	Prefixes   string
	Rules      string // the connection's path rules for this stack, {stack} replaced
}

// stackSecretsView fills the stack page's "Secret references" panel.
func (a *app) stackSecretsView(stackID string) (rows []bindingRow, unbound []secrets.Connector) {
	bound := map[string]bool{}
	bindings, _ := a.store.ListSecretBindings(stackID)
	for _, b := range bindings {
		bound[b.Type] = true
		row := bindingRow{Type: b.Type, Label: b.Type, Prefixes: strings.Join(b.Prefixes, ", ")}
		if c, ok := a.resolver.Connector(b.Type); ok {
			row.Label = c.Label()
		}
		if conn, err := a.store.GetSecretConnection(b.ConnectionID); err == nil {
			row.Mode, row.Connection = bindingMode(a, conn)
			row.Rules = a.bindingRules(conn, stackID)
		} else {
			row.Mode, row.Connection = "broken", "connection missing"
		}
		rows = append(rows, row)
	}
	for _, c := range a.resolver.Connectors() {
		if !bound[c.Scheme()] {
			unbound = append(unbound, c)
		}
	}
	return rows, unbound
}

// bindingRules is what a connection's path rules allow a stack, for display.
func (a *app) bindingRules(conn store.SecretConnection, stackID string) string {
	config := conn.Config
	if conn.ParentID != "" {
		if parent, err := a.store.GetSecretConnection(conn.ParentID); err == nil {
			config = parent.Config
		}
	}
	rules, err := secrets.ParseRules(config[secrets.PathRulesKey])
	if err != nil {
		return ""
	}
	return strings.Join(secrets.ExpandRules(rules, stackID), ", ")
}

// bindingMode describes a binding's connection for display.
func bindingMode(a *app, conn store.SecretConnection) (mode, name string) {
	switch {
	case conn.StackID == "":
		return modeShared, conn.Name
	case conn.ParentID != "":
		parent := conn.ParentID
		if p, err := a.store.GetSecretConnection(conn.ParentID); err == nil {
			parent = p.Name
		}
		return modeOwn, parent
	}
	return modeSeparate, "its own connection"
}

// stackBindingTarget loads the stack and connector a binding route refers to.
func (a *app) stackBindingTarget(w http.ResponseWriter, r *http.Request) (store.Stack, secrets.Connector, bool) {
	st, err := a.store.GetStack(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return st, nil, false
	}
	connector, ok := a.resolver.Connector(r.PathValue("type"))
	if !ok || st.SourceType != "git" {
		http.NotFound(w, r)
		return st, nil, false
	}
	return st, connector, true
}

func (a *app) stackBindingFormHandler(w http.ResponseWriter, r *http.Request) {
	st, connector, ok := a.stackBindingTarget(w, r)
	if !ok {
		return
	}

	globals, err := a.store.ListGlobalSecretConnections()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	type globalOption struct {
		ID, Name string
		Selected bool
		HasCreds bool
		Rules    []string // what this connection's path rules allow this stack, {stack} replaced
	}
	var options []globalOption
	for _, g := range globals {
		if g.Type != connector.Scheme() {
			continue
		}
		set, _ := a.keys.SecretCredentialFields(g.ID)
		rules, _ := secrets.ParseRules(g.Config[secrets.PathRulesKey])
		options = append(options, globalOption{ID: g.ID, Name: g.Name, HasCreds: len(set) > 0, Rules: secrets.ExpandRules(rules, st.ID)})
	}

	mode := modeShared
	prefixes := ""
	var config map[string]string
	var setCreds []string
	existing := false
	if b, err := a.store.GetSecretBinding(st.ID, connector.Scheme()); err == nil {
		existing = true
		prefixes = strings.Join(b.Prefixes, "\n")
		if conn, err := a.store.GetSecretConnection(b.ConnectionID); err == nil {
			selected := conn.ID
			if conn.StackID != "" {
				config = conn.Config
				setCreds, _ = a.keys.SecretCredentialFields(conn.ID)
				selected = conn.ParentID
				mode = modeSeparate
				if conn.ParentID != "" {
					mode = modeOwn
				}
			}
			for i := range options {
				options[i].Selected = options[i].ID == selected
			}
		}
	}

	configFields, credFields := fieldViews(connector, config, setCreds)
	render(w, r, "layout", "secret_binding_form.html", map[string]any{
		"Title":         connector.Label() + " — " + st.Name,
		"Nav":           "stacks",
		"Stack":         st,
		"Connector":     connector,
		"Existing":      existing,
		"Mode":          mode,
		"Globals":       options,
		"Prefixes":      prefixes,
		"PathRulesDocs": secrets.PathRulesDocsURL,
		"ConfigFields":  configFields,
		"CredFields":    credFields,
	})
}

func (a *app) saveStackBindingHandler(w http.ResponseWriter, r *http.Request) {
	st, connector, ok := a.stackBindingTarget(w, r)
	if !ok {
		return
	}
	typ := connector.Scheme()
	back := "/stacks/" + st.ID + "/secrets/bindings/" + typ

	mode := r.FormValue("mode")
	prefixes, err := a.bindingPrefixes(r, mode)
	if err != nil {
		redirectWithError(w, r, back, err.Error())
		return
	}

	var previous store.SecretConnection
	hasPrevious := false
	if b, err := a.store.GetSecretBinding(st.ID, typ); err == nil {
		if c, err := a.store.GetSecretConnection(b.ConnectionID); err == nil {
			previous, hasPrevious = c, true
		}
	}

	var target store.SecretConnection
	switch mode {
	case modeShared, modeOwn:
		parent, err := a.store.GetSecretConnection(r.FormValue("connection_id"))
		if err != nil || parent.StackID != "" || parent.Type != typ {
			redirectWithError(w, r, back, "choose one of the shared connections")
			return
		}
		if mode == modeShared {
			if set, _ := a.keys.SecretCredentialFields(parent.ID); len(set) == 0 {
				redirectWithError(w, r, back, "this connection has no default credentials: give the stack its own")
				return
			}
			target = parent
		} else if target, err = a.localConnection(w, r, st, connector, previous, hasPrevious, parent.ID, nil, back); err != nil {
			return
		}
	case modeSeparate:
		config := configFromForm(r, connector)
		if err := connector.ValidateConfig(config); err != nil {
			redirectWithError(w, r, back, err.Error())
			return
		}
		if target, err = a.localConnection(w, r, st, connector, previous, hasPrevious, "", config, back); err != nil {
			return
		}
	default:
		redirectWithError(w, r, back, "choose how this stack connects")
		return
	}

	if err := a.store.SetSecretBinding(store.SecretBinding{StackID: st.ID, Type: typ, ConnectionID: target.ID, Prefixes: prefixes}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// A previous stack-private connection that is no longer the target is dropped.
	if hasPrevious && previous.StackID != "" && previous.ID != target.ID {
		if err := a.dropLocalConnection(previous.ID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	a.audit(r, "secrets.binding_set", st.Name, typ+" ("+mode+"): "+strings.Join(prefixes, ", "))
	redirectWithSavedMessage(w, r, "/stacks/"+st.ID, connector.Label()+" connection saved")
}

// bindingPrefixes reads a binding's allowed paths. They are required, unless the
// connection has path rules: then they are optional extras, and a "*" is
// refused, since rules exist to keep a stack from being given everything.
func (a *app) bindingPrefixes(r *http.Request, mode string) ([]string, error) {
	var rulesText string
	switch mode {
	case modeShared, modeOwn:
		if parent, err := a.store.GetSecretConnection(r.FormValue("connection_id")); err == nil {
			rulesText = parent.Config[secrets.PathRulesKey]
		}
	case modeSeparate:
		rulesText = r.FormValue("cfg_" + secrets.PathRulesKey)
	}
	rules, err := secrets.ParseRules(rulesText)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return secrets.NormalizePrefixes(r.FormValue("prefixes"))
	}
	extras, err := secrets.ParsePrefixes(r.FormValue("prefixes"))
	if err != nil {
		return nil, err
	}
	for _, p := range extras {
		if p == "*" {
			return nil, errors.New("this connection has path rules: list the extra paths this stack may read, not *")
		}
	}
	if extras == nil {
		extras = []string{}
	}
	return extras, nil
}

// localConnection creates or updates the stack-private connection for a
// binding. parentID is empty for a fully separate one. The credentials typed
// in the form replace the stored group; left empty they keep it when the
// same connection is being edited.
func (a *app) localConnection(w http.ResponseWriter, r *http.Request, st store.Stack, connector secrets.Connector,
	previous store.SecretConnection, hasPrevious bool, parentID string, config map[string]string, back string) (store.SecretConnection, error) {

	creds := credentialsFromForm(r, connector)
	reuse := hasPrevious && previous.StackID == st.ID && previous.ParentID == parentID
	if len(creds) == 0 && reuse {
		if set, _ := a.keys.SecretCredentialFields(previous.ID); len(set) > 0 {
			creds = nil // keep what is stored
		}
	}
	if creds != nil || !reuse {
		if err := connector.ValidateCredentials(creds); err != nil {
			redirectWithError(w, r, back, err.Error())
			return store.SecretConnection{}, err
		}
	}

	conn := store.SecretConnection{Name: st.ID + "/" + connector.Scheme(), Type: connector.Scheme(), StackID: st.ID, ParentID: parentID, Config: config}
	if reuse {
		conn.ID = previous.ID
		if err := a.store.UpdateSecretConnection(conn.ID, conn.Name, config); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return conn, err
		}
	} else {
		id, err := randomHex(8)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return conn, err
		}
		conn.ID = id
	}
	if creds != nil {
		if err := a.keys.SetSecretCredentials(conn.ID, creds); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return conn, err
		}
	}
	if !reuse {
		if err := a.store.CreateSecretConnection(conn); err != nil {
			_ = a.keys.DeleteSecretCredentials(conn.ID)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return conn, err
		}
	}
	return conn, nil
}

func (a *app) deleteStackBindingHandler(w http.ResponseWriter, r *http.Request) {
	st, connector, ok := a.stackBindingTarget(w, r)
	if !ok {
		return
	}
	b, err := a.store.GetSecretBinding(st.ID, connector.Scheme())
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.store.DeleteSecretBinding(st.ID, b.Type); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if conn, err := a.store.GetSecretConnection(b.ConnectionID); err == nil && conn.StackID != "" {
		if err := a.dropLocalConnection(conn.ID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	a.audit(r, "secrets.binding_remove", st.Name, b.Type)
	redirectWithSavedMessage(w, r, "/stacks/"+st.ID, connector.Label()+" connection removed")
}

func (a *app) testStackBindingHandler(w http.ResponseWriter, r *http.Request) {
	st, connector, ok := a.stackBindingTarget(w, r)
	if !ok {
		return
	}
	b, err := a.store.GetSecretBinding(st.ID, connector.Scheme())
	if err != nil {
		http.NotFound(w, r)
		return
	}
	conn, err := a.store.GetSecretConnection(b.ConnectionID)
	if err != nil {
		redirectWithError(w, r, "/stacks/"+st.ID, "this stack's connection no longer exists")
		return
	}
	a.runConnectionCheck(w, r, conn, connector, b.Prefixes, "/stacks/"+st.ID)
}
