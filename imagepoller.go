// Registry digest polling — the second half of image auto-update, cf.
// imagepolicies.go for discovery/resync. Kept in its own file, same
// convention as poller.go for Git polling.
package main

import (
	"context"
	"log"

	"github.com/forgelab-me/wharf-server/internal/registry"
	"github.com/forgelab-me/wharf-server/internal/store"
)

// imagePollInterval is global and fixed rather than configurable per
// stack (unlike Git polling): the whole point of the shared digest cache
// is that N stacks on the same image collapse into one registry check, so
// per-stack schedules would work against that. Revisit if that ever
// becomes a real limitation. Standard 5-field form ("every 15 minutes",
// on the clock) rather than robfig/cron's "@every 15m" descriptor syntax
// — a.cron's parser (cronParser in poller.go) is deliberately built
// without the descriptor option, since it also validates user-supplied
// Git poll schedules and a stray "@" there shouldn't silently parse.
const imagePollInterval = "*/15 * * * *"

func registerImagePolling(a *app) error {
	_, err := a.cron.AddFunc(imagePollInterval, func() { pollImages(a) })
	return err
}

// pollImages checks every non-"pinned" tracked image once, deduplicated
// by canonical reference, and acts on whatever policy governs each row
// that turns out to be behind the registry.
func pollImages(a *app) {
	policies, err := a.store.ListImagePolicies()
	if err != nil {
		log.Println("image poll: list policies failed:", err)
		return
	}

	ctx := context.Background()
	digests := map[string]string{} // canonical ref -> digest, one registry call per unique ref this tick
	checked := 0
	for _, p := range policies {
		if p.Policy == "pinned" {
			continue
		}
		ref, supported := registry.ParseRef(p.ImageRef)
		if !supported {
			continue
		}
		canon := ref.Canonical()
		if _, ok := digests[canon]; ok {
			continue
		}
		username, password, _, credErr := a.keys.RegistryCredential(ref.Host)
		if credErr != nil {
			log.Println("image poll:", canon, "registry credential lookup:", credErr)
		}
		d, err := registry.Digest(ctx, ref, username, password)
		if err != nil {
			log.Println("image poll:", canon, "digest check failed:", err)
			_ = a.store.SetImageDigestCacheError(canon, err.Error())
			continue
		}
		digests[canon] = d
		checked++
		_ = a.store.SetImageDigestCache(canon, d)
	}
	if checked > 0 {
		log.Println("image poll: checked", checked, "unique image ref(s) for", len(policies), "tracked service(s)")
	}

	for _, p := range policies {
		if p.Policy == "pinned" {
			continue
		}
		ref, supported := registry.ParseRef(p.ImageRef)
		if !supported {
			continue
		}
		digest, ok := digests[ref.Canonical()]
		if !ok || digest == "" || digest == p.AppliedDigest {
			continue
		}
		if p.Policy != "auto" || !shouldApplyNow(p) {
			continue // propose: leave it for the UI/Apply button
		}
		enqueueImageUpdate(a, p)
	}
}

// shouldApplyNow is the single decision point for whether an "auto"
// policy acts on a detected update immediately. v1: always yes. Kept
// separate so a future per-image apply window (e.g. "anytime" for a
// throwaway service like nginx vs. "03:00 only" for something slow to
// restart like Nextcloud or SonarQube) is a change to this one function
// plus one new column, not a rewrite of the poller or the propose/Apply
// flow.
func shouldApplyNow(policy store.ImagePolicy) bool {
	return policy.Policy == "auto"
}

func enqueueImageUpdate(a *app, p store.ImagePolicy) {
	if dep, ok, err := a.store.LatestDeploymentForStack(p.StackID); err == nil && ok {
		if dep.Status == "queued" || dep.Status == "running" {
			return
		}
	}
	st, err := a.store.GetStack(p.StackID)
	if err != nil {
		log.Println("image poll: load stack", p.StackID, "failed:", err)
		return
	}
	if st.Host == "" {
		return
	}
	log.Println("image poll:", p.StackID, p.ServiceName, "new digest — enqueueing deploy")
	if _, err := a.store.EnqueueDeployment(st.ID, st.Host, "image-update", "up"); err != nil {
		log.Println("image poll: enqueue deploy for", p.StackID, "failed:", err)
	}
}
