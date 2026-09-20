// Image auto-update: discovering which images a stack's services use, and
// tracking whether the registry has moved past what's currently deployed.
// Kept separate from main.go for the same reason poller.go is — this is a
// self-contained concern with its own file. Cf. ARCHITECTURE.md and the
// plan for this chunk for the full design.
package main

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/forgelab-me/wharf-server/internal/registry"
	"github.com/forgelab-me/wharf-server/internal/store"
	"github.com/goccy/go-yaml"
)

// composeServices is the minimal shape we read out of a compose file —
// everything else in it is none of this feature's business.
type composeServices struct {
	Services map[string]struct {
		Image string `yaml:"image"`
	} `yaml:"services"`
}

// parseComposeImages returns service name -> image reference for every
// service that has one, skipping build-only services (no "image:").
// Digest-pinned images (image@sha256:...) are included here — they still
// count as a service worth knowing about for pruning purposes — and
// filtered out later, at the point where a policy row would otherwise be
// created for them (cf. isDigestPinned in syncImagePolicies).
func parseComposeImages(composeYAML string) (map[string]string, error) {
	var doc composeServices
	if err := yaml.Unmarshal([]byte(composeYAML), &doc); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for name, svc := range doc.Services {
		if svc.Image == "" {
			continue
		}
		out[name] = svc.Image
	}
	return out, nil
}

func isDigestPinned(image string) bool {
	return strings.Contains(image, "@sha256:")
}

// syncImagePolicies runs after every successful deployment (git, local,
// manual, webhook, polling, or image-update — doesn't matter which) to
// keep image_policies in step with whatever's actually on disk now: new
// services get a row (default policy "pinned"), removed services lose
// theirs, and every tracked service gets its applied_digest refreshed
// from a live registry check right away rather than waiting for the next
// poll tick — otherwise a stack would show a false "update available"
// badge for the minutes between deploying and the next scheduled check.
func syncImagePolicies(a *app, stackID, composeYAML string) {
	images, err := parseComposeImages(composeYAML)
	if err != nil {
		log.Println("image policies:", stackID, "parse compose:", err)
		return
	}

	var services []string
	for name, image := range images {
		services = append(services, name)
		if isDigestPinned(image) {
			continue
		}
		if err := a.store.UpsertImagePolicy(stackID, name, image); err != nil {
			log.Println("image policies:", stackID, name, "upsert:", err)
		}
	}
	if err := a.store.PruneImagePolicies(stackID, services); err != nil {
		log.Println("image policies:", stackID, "prune:", err)
	}

	policies, err := a.store.ListImagePoliciesForStack(stackID)
	if err != nil {
		log.Println("image policies:", stackID, "list for resync:", err)
		return
	}

	ctx := context.Background()
	seen := map[string]string{} // canonical ref -> digest, dedup within this one pass
	for _, p := range policies {
		ref, supported := registry.ParseRef(p.ImageRef)
		if !supported {
			continue
		}
		canon := ref.Canonical()
		digest, ok := seen[canon]
		if !ok {
			username, password, _, credErr := a.keys.RegistryCredential(ref.Host)
			if credErr != nil {
				log.Println("image policies:", stackID, p.ServiceName, "registry credential lookup:", credErr)
			}
			d, err := registry.Digest(ctx, ref, username, password)
			if err != nil {
				log.Println("image policies:", stackID, p.ServiceName, "digest check:", err)
				_ = a.store.SetImageDigestCacheError(canon, err.Error())
				continue
			}
			digest = d
			seen[canon] = d
			_ = a.store.SetImageDigestCache(canon, d)
		}
		if err := a.store.SetAppliedDigest(stackID, p.ServiceName, digest); err != nil {
			log.Println("image policies:", stackID, p.ServiceName, "set applied digest:", err)
		}
	}
}

// imagePolicyViewRow is what stack_view.html actually renders — the raw
// store.ImagePolicy plus the latest digest known from the shared cache,
// so the template can compare it against AppliedDigest without knowing
// anything about canonical refs or the cache table. Digests are
// pre-truncated here (html/template has no string-slicing helper wired
// up) rather than in the template.
type imagePolicyViewRow struct {
	store.ImagePolicy
	LatestDigest    string
	AppliedShort    string
	LatestShort     string
	UpdateAvailable bool
}

func shortDigest(digest string) string {
	if i := strings.Index(digest, ":"); i >= 0 {
		digest = digest[i+1:]
	}
	if len(digest) > 12 {
		digest = digest[:12]
	}
	return digest
}

func imagePolicyViewRows(a *app, stackID string) ([]imagePolicyViewRow, error) {
	policies, err := a.store.ListImagePoliciesForStack(stackID)
	if err != nil {
		return nil, err
	}
	rows := make([]imagePolicyViewRow, 0, len(policies))
	for _, p := range policies {
		row := imagePolicyViewRow{ImagePolicy: p, AppliedShort: shortDigest(p.AppliedDigest)}
		// p.ImageRef is guaranteed parseable here: syncImagePolicies never
		// creates a row for a digest-pinned image in the first place (cf.
		// its own isDigestPinned skip), and ParseRef only ever rejects a
		// digest-pinned ref -- the "unsupported registry" branch this used
		// to have was therefore dead code with a stale message, removed
		// rather than fixed in place.
		ref, _ := registry.ParseRef(p.ImageRef)
		if digest, ok, err := a.store.GetImageDigestCache(ref.Canonical()); err == nil && ok {
			row.LatestDigest = digest
			row.LatestShort = shortDigest(digest)
			row.UpdateAvailable = digest != p.AppliedDigest
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// setImagePolicyHandler serves POST /stacks/{id}/images/{service}/policy —
// the pinned/auto/propose selector on the stack page.
func (a *app) setImagePolicyHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	service := r.PathValue("service")
	policy := r.FormValue("policy")
	if policy != "pinned" && policy != "auto" && policy != "propose" {
		http.Error(w, "invalid policy", http.StatusBadRequest)
		return
	}
	if err := a.store.SetImagePolicy(id, service, policy); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.audit(r, "stack.image_policy_change", id, service+" -> "+policy)
	redirectWithSaved(w, r, "/stacks/"+id)
}

// applyImageUpdateHandler serves POST /stacks/{id}/images/{service}/apply
// — the "Apply" button on a pending update (works regardless of policy:
// applying a known-available update is always a reasonable thing to ask
// for, whether or not it would have happened on its own).
func (a *app) applyImageUpdateHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, err := a.store.GetStack(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if st.Host == "" {
		http.Error(w, "this stack has no target host assigned", http.StatusBadRequest)
		return
	}
	if dep, ok, err := a.store.LatestDeploymentForStack(id); err == nil && ok {
		if dep.Status == "queued" || dep.Status == "running" {
			http.Redirect(w, r, "/stacks/"+id, http.StatusSeeOther)
			return
		}
	}
	if _, err := a.store.EnqueueDeployment(st.ID, st.Host, "image-update", "up"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.audit(r, "stack.image_update_apply", st.Name, r.PathValue("service"))
	redirectWithSavedMessage(w, r, "/stacks/"+id, "Update queued")
}
