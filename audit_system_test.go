package main

import (
	"path/filepath"
	"testing"

	"github.com/forgelab-me/wharf-server/internal/store"
)

func auditApp(t *testing.T) *app {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "wharf.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return &app{store: st}
}

func TestAPolledDeployIsInTheAuditLog(t *testing.T) {
	a := auditApp(t)
	stack := store.Stack{ID: "blog", Name: "Blog", SourceType: "git", Branch: "main", Trigger: "polling", Host: "h1"}
	if err := a.store.CreateStack(stack); err != nil {
		t.Fatal(err)
	}

	queuePolledDeploy(a, stack, "0123456789abcdef0123456789abcdef01234567")

	entries, _ := a.store.ListAudit(10)
	if len(entries) != 1 {
		t.Fatalf("one deploy, one entry: %+v", entries)
	}
	e := entries[0]
	if e.Username != "polling" || e.Action != "stack.deploy_polling" || e.Target != "Blog" || e.Detail != "commit 0123456" {
		t.Errorf("entry = %+v", e)
	}
	if dep, ok, _ := a.store.LatestDeploymentForStack("blog"); !ok || dep.Trigger != "polling" {
		t.Errorf("the deployment is queued with its trigger: %+v", dep)
	}
}

func TestAnAutoUpdateIsInTheAuditLogOnlyWhenItQueuesADeploy(t *testing.T) {
	a := auditApp(t)
	if err := a.store.CreateStack(store.Stack{ID: "web", Name: "web", SourceType: "git", Branch: "main", Trigger: "manual", Host: "h1"}); err != nil {
		t.Fatal(err)
	}
	policy := store.ImagePolicy{StackID: "web", ServiceName: "nginx", ImageRef: "nginx:1.27", Policy: "auto"}

	enqueueImageUpdate(a, policy, "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	entries, _ := a.store.ListAudit(10)
	if len(entries) != 1 {
		t.Fatalf("one update, one entry: %+v", entries)
	}
	e := entries[0]
	if e.Username != "auto-update" || e.Action != "stack.image_update_auto" || e.Target != "web" || e.Detail != "nginx: nginx:1.27 → sha256:0123456789ab" {
		t.Errorf("entry = %+v", e)
	}

	// a deployment is already waiting: nothing new is queued, so nothing is recorded
	enqueueImageUpdate(a, policy, "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
	if entries, _ := a.store.ListAudit(10); len(entries) != 1 {
		t.Errorf("a skipped update must not be audited: %+v", entries)
	}
}
