package store

import (
	"errors"
	"strings"
	"testing"
)

func TestSecretConnectionRoundTrip(t *testing.T) {
	s := newTestStore(t)
	global := SecretConnection{ID: "g1", Name: "openbao-home", Type: "vault", Config: map[string]string{"address": "https://bao.lan:8200", "kv_version": "2"}}
	if err := s.CreateSecretConnection(global); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetSecretConnection("g1")
	if err != nil || got.Name != "openbao-home" || got.Config["address"] != "https://bao.lan:8200" || got.StackID != "" {
		t.Fatalf("got %+v, %v", got, err)
	}

	if err := s.UpdateSecretConnection("g1", "openbao-lan", map[string]string{"address": "https://other:8200"}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetSecretConnection("g1")
	if got.Name != "openbao-lan" || got.Config["address"] != "https://other:8200" || len(got.Config) != 1 {
		t.Fatalf("after update: %+v", got)
	}

	if _, err := s.GetSecretConnection("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing connection: %v", err)
	}
	if err := s.UpdateSecretConnection("nope", "x", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update of a missing connection: %v", err)
	}
}

func TestGlobalSecretConnectionNamesAreUnique(t *testing.T) {
	s := newTestStore(t)
	newTestStack(t, s, "blog")
	if err := s.CreateSecretConnection(SecretConnection{ID: "g1", Name: "shared", Type: "vault"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSecretConnection(SecretConnection{ID: "g2", Name: "shared", Type: "vault"}); err == nil {
		t.Fatal("two global connections with the same name")
	}
	// Local connections are named after their stack, so the same name may repeat.
	for _, id := range []string{"l1", "l2"} {
		if err := s.CreateSecretConnection(SecretConnection{ID: id, Name: "blog/vault", Type: "vault", StackID: "blog"}); err != nil {
			t.Fatalf("local connection %s: %v", id, err)
		}
	}
}

func TestSecretBindings(t *testing.T) {
	s := newTestStore(t)
	newTestStack(t, s, "blog")

	if err := s.SetSecretBinding(SecretBinding{StackID: "blog", Type: "vault", ConnectionID: "g1", Prefixes: []string{"secret/blog", "kv/app"}}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSecretBinding("blog", "vault")
	if err != nil || got.ConnectionID != "g1" || strings.Join(got.Prefixes, ",") != "secret/blog,kv/app" {
		t.Fatalf("got %+v, %v", got, err)
	}

	if err := s.SetSecretBinding(SecretBinding{StackID: "blog", Type: "vault", ConnectionID: "l1", Prefixes: []string{"*"}}); err != nil {
		t.Fatal(err)
	}
	list, _ := s.ListSecretBindings("blog")
	if len(list) != 1 || list[0].ConnectionID != "l1" || list[0].Prefixes[0] != "*" {
		t.Fatalf("a second SetSecretBinding must replace the first, got %+v", list)
	}

	if err := s.DeleteSecretBinding("blog", "vault"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSecretBinding("blog", "vault"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}

func TestSecretConnectionUsersAndChildren(t *testing.T) {
	s := newTestStore(t)
	for _, id := range []string{"blog", "wiki", "docs"} {
		newTestStack(t, s, id)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.CreateSecretConnection(SecretConnection{ID: "g1", Name: "bao", Type: "vault", Config: map[string]string{"address": "a"}}))
	must(s.CreateSecretConnection(SecretConnection{ID: "l-wiki", Name: "wiki/vault", Type: "vault", StackID: "wiki", ParentID: "g1"}))
	must(s.SetSecretBinding(SecretBinding{StackID: "blog", Type: "vault", ConnectionID: "g1", Prefixes: []string{"a"}}))
	must(s.SetSecretBinding(SecretBinding{StackID: "wiki", Type: "vault", ConnectionID: "l-wiki", Prefixes: []string{"b"}}))
	must(s.SetSecretBinding(SecretBinding{StackID: "docs", Type: "sops", ConnectionID: "unrelated", Prefixes: []string{"c"}}))

	shared, own, err := s.SecretConnectionUsers("g1")
	if err != nil || strings.Join(shared, ",") != "blog" || strings.Join(own, ",") != "wiki" {
		t.Fatalf("shared=%v own=%v err=%v", shared, own, err)
	}
	children, err := s.SecretConnectionChildren("g1")
	if err != nil || len(children) != 1 || children[0].ID != "l-wiki" {
		t.Fatalf("children = %+v, %v", children, err)
	}
	global, _ := s.ListGlobalSecretConnections()
	if len(global) != 1 || global[0].ID != "g1" {
		t.Fatalf("global = %+v", global)
	}
}

func TestDeleteStackRemovesItsSecretBindingsAndLocalConnections(t *testing.T) {
	s := newTestStore(t)
	newTestStack(t, s, "blog")
	newTestStack(t, s, "wiki")
	s.CreateSecretConnection(SecretConnection{ID: "g1", Name: "bao", Type: "vault"})
	s.CreateSecretConnection(SecretConnection{ID: "l-blog", Name: "blog/vault", Type: "vault", StackID: "blog", ParentID: "g1"})
	s.SetSecretBinding(SecretBinding{StackID: "blog", Type: "vault", ConnectionID: "l-blog", Prefixes: []string{"a"}})
	s.SetSecretBinding(SecretBinding{StackID: "wiki", Type: "vault", ConnectionID: "g1", Prefixes: []string{"a"}})

	if err := s.DeleteStack("blog"); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.ListSecretBindings("blog"); len(list) != 0 {
		t.Errorf("bindings left behind: %+v", list)
	}
	if _, err := s.GetSecretConnection("l-blog"); !errors.Is(err, ErrNotFound) {
		t.Errorf("local connection left behind: %v", err)
	}
	if _, err := s.GetSecretConnection("g1"); err != nil {
		t.Errorf("the global connection must survive: %v", err)
	}
	if list, _ := s.ListSecretBindings("wiki"); len(list) != 1 {
		t.Errorf("another stack's binding was touched: %+v", list)
	}
}
