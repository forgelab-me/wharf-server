package main

import (
	"fmt"

	"github.com/forgelab-me/wharf-server/internal/store"
)

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// scanChips answers each container's vulnerability badge; with scanning off
// there is no index and no chip is drawn.
func (a *app) scanChips() func(store.HostContainer) *scanBadge {
	ix := a.newScanIndex()
	if ix == nil {
		return nil
	}
	return func(c store.HostContainer) *scanBadge { return ix.forImage(c.HostID, c.ImageID) }
}

// stackGraph is the stack page's topology: nil when no container runs.
func (a *app) stackGraph(st store.Stack, policies []imagePolicyViewRow, bindings []bindingRow, secretKeys []string) *graph {
	containers, err := a.store.ListHostContainersByStack(st.ID)
	if err != nil {
		return nil
	}

	var sources []gSource
	if st.SourceType == "git" {
		src := gSource{Label: "Git source · " + st.Branch, Detail: shortRepo(st.Repo)}
		if st.GitConnectionID != "" {
			src.Href = "/git-connections/" + st.GitConnectionID
		}
		sources = append(sources, src)
	} else {
		sources = append(sources, gSource{Label: "Compose file", Detail: "local", Href: "/stacks/" + st.ID + "/edit"})
	}
	for _, b := range bindings {
		sources = append(sources, gSource{Label: "Secrets · " + b.Label, Detail: b.Connection, Href: "/stacks/" + st.ID + "/secrets/bindings/" + b.Type})
	}
	if len(secretKeys) > 0 {
		sources = append(sources, gSource{Label: "Secrets", Detail: plural(len(secretKeys), "key")})
	}
	if len(policies) > 0 {
		updates := 0
		for _, p := range policies {
			if p.UpdateAvailable {
				updates++
			}
		}
		detail := plural(len(policies), "service")
		if updates > 0 {
			detail += " · " + plural(updates, "update")
		}
		sources = append(sources, gSource{Label: "Image policy", Detail: detail})
	}

	status := ""
	if dep, ok, err := a.store.LatestDeploymentForStack(st.ID); err == nil && ok {
		switch {
		case dep.Status == "succeeded" && dep.Action == "up":
			status = "deployed"
		case dep.Status == "succeeded":
			status = "stopped"
		default:
			status = dep.Status
		}
	}

	return buildStackGraph(stackGraphInput{
		Stack: st, Host: a.hostLabel(st.Host), Status: status,
		Sources: sources, Containers: containers, Scan: a.scanChips(),
	})
}

// hostTopology is the host page's topology: nil when the host runs nothing.
func (a *app) hostTopology(h store.Host) *topology {
	all, err := a.store.ListHostContainers()
	if err != nil {
		return nil
	}
	var containers []store.HostContainer
	for _, c := range all {
		if c.HostID == h.ID {
			containers = append(containers, c)
		}
	}
	var volumes []store.HostVolume
	if all, err := a.store.ListHostVolumes(); err == nil {
		for _, v := range all {
			if v.HostID == h.ID {
				volumes = append(volumes, v)
			}
		}
	}
	names := map[string]string{}
	if stacks, err := a.store.ListStacks(); err == nil {
		for _, s := range stacks {
			names[s.ID] = s.Name
		}
	}
	return buildHostTopology(hostGraphInput{Host: h, Containers: containers, Volumes: volumes, StackNames: names, Scan: a.scanChips()})
}
