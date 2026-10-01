# Changelog

All notable changes to `wharf-server` are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions match the `vX.Y.Z` git tags that trigger a release build.

## [0.17.0] - 2026-10-01

### Added
- The stacks list is now an overview with live figures. Each stack is one row: its host, its state (running 3/3, partial, stopped, failed, deploying), its trigger, the worst vulnerability of its images, and its CPU, memory, network and disk. A row unfolds into one card per container with its image, vulnerabilities, ports, volumes and four live curves; a stack with nothing running keeps its cards, greyed. Rows are folded by default and what you unfolded is remembered by the browser. Figures refresh every 5 seconds while the tab is visible, and the hosts are measured once however many pages are open. It needs agent 0.7.0 on the host; an older agent shows an "update the agent" note instead. There is no history: the curves fill in while the page is open.

### Changed
- The stacks list no longer has a "Last status" and a "Last sha" column: the state column replaces them (the last deployment's status is its tooltip), and the commit a polling stack last saw is on its own page.

## [0.16.0] - 2026-10-01

### Added
- A **Topology** panel on the stack page and on the host page draws the containers, volumes and networks as a graph. On a stack: its sources (Git repository, secret providers, local secrets, image policies), the stack, its containers with their image and worst vulnerability, and the volumes and network they use. On a host: its containers grouped by stack, one table each with the image, the worst vulnerability, the networks (colored, with a legend saying which stacks each one links) and the volumes of every container, and what Wharf does not manage in a group of its own. It uses what agents already report, so no agent update is needed. Only Docker volumes appear: a bind mount is not drawn.

## [0.15.4] - 2026-09-30

### Security
- Every redirect that carries a banner or a toast now refuses a target that leaves the site (one starting with `//` or a backslash) and goes to `/` instead. No such target could be built from a request today: they all start with a fixed path. This is a guard for the day one could, and it answers CodeQL's "open URL redirect" finding.

## [0.15.3] - 2026-09-30

### Security
- The image is built on Alpine 3.24.2 instead of 3.24.1, which brings OpenSSL 3.5.8 (CVE-2026-14456 in `libcrypto3` and `libssl3`).

## [0.15.2] - 2026-09-30

### Fixed
- The image is built on Alpine 3.24.2 instead of 3.24.1, which brings OpenSSL 3.5.8 (CVE-2026-14456 in `libcrypto3` and `libssl3`).

### Fixed
- With several hosts connected, a host's state (containers, images, volumes, networks) could fail to be stored with `database is locked`, and stayed stale until its next push. Each agent resent its whole state every 45 seconds and on every Docker event, and every push rewrote every table even when nothing had changed, so the hosts queued for SQLite's single writer for nothing. Now only a table that actually changed is written, and a write that finds the database busy is retried a few times before giving up.

## [0.15.1] - 2026-09-30

### Changed
- Same code as 0.15.0, whose image was never published: its CI run failed on a test that depended on the order of a map. The test is fixed.

## [0.15.0] - 2026-09-30

### Added
- Optional vulnerability scanning (Settings → Vulnerability scanning, admin only, off by default) with **Trivy** or **Grype**, one at a time. The controller reads each image straight from its registry, by digest, for the platform of the host that runs it: nothing is pulled onto a host. It scans every image a container runs on any host, managed by Wharf or not, and, for each image policy, the applied digest and the one an update would bring. Results show as badges next to images (Containers, a container's page, Images, and a stack's Images panel, applied against latest) and open a findings page: severity, package, installed and fixed-in version, filterable to what has a fix. Counts are per distinct vulnerability. An image the scanner could not read (no operating system detected) shows "nothing detected", never "clean"; a failed scan (wrong registry password, unreachable registry) shows "scan failed" with the reason, and is retried on the next pass.
- The scanner is downloaded when scanning is turned on, not shipped in the image: a pinned release whose SHA-256 is verified before it is ever run (Trivy 0.74.0, Grype 0.119.0), stored with its database (about 1.4 GB for Trivy, 2.8 GB for Grype) in a new `/cache` volume, after checking that the free space is enough. It runs without a shell, with a minimal environment and a time limit per image; registry credentials (Settings → Registry) reach it through its environment, never its command line. A full pass with a database refresh runs every six hours; **Scan now**, **Update database** and **Delete scanner data** are available, and each action is recorded in the audit log (`scan.*`).
- Container-to-image links are exact: the controller now keeps the image id each container runs, each image's registry digest and each host's CPU architecture, all reported by agent 0.6.0 (an older agent's containers show "update agent" instead of a scan).

## [0.14.1] - 2026-09-29

### Fixed
- The Hosts table overflowed its card once fingerprints were real length (they have no break point), pushing the Address field out of view. A fingerprint now wraps inside its cell.

## [0.14.0] - 2026-09-29

### Added
- An optional `secrets.refs.yaml` for Git stacks, listing exactly which variables a stack gets and where each value comes from (`KEY: ref+<scheme>://<path>#/<field>`). When present it is the only source, so keys of `secrets.enc.yaml` that no reference picks up are not deployed (the deployment output names them, never their values). Literal values and query strings are refused, and a single unresolvable reference fails the deploy, listing every failing key. Stacks without the file behave exactly as before. Two schemes: `ref+sops://secrets.enc.yaml#/KEY` reads the stack's own encrypted file (and allows renaming a key), `ref+vault://<mount>/<path>#/<field>` reads from OpenBao or HashiCorp Vault.
- Secret providers (Settings, admin only): shared connections to an OpenBao / Vault server (KV v1 or v2, token or AppRole login, optional namespace and private CA), with a **Test** button. A connection holds the address and optional default credentials; credentials are write-only and kept in the controller's isolated key store. A Git stack's page gets a **Secret references** panel to attach one, as is, with credentials of the stack's own (the address stays inherited), or as a connection of its own, plus the **allowed paths** it may read (required, compared by whole path segments: a reference outside them fails the deploy without reaching the server). A connection still used by a stack cannot be deleted. The reference never carries an address or credentials, redirects are not followed, and an AppRole login is cached per identity so two stacks never share a token.
- Resolution is recorded in the audit log (`secrets.resolve` / `secrets.resolve_failed`, variable names and connection only, never a value). A stack with a secret connection is refused, with a clear message, on an agent older than 0.5.0 instead of deploying with empty variables; the agent side is in the agent's changelog.

### Changed
- "Encrypt secrets" moved out of Settings into a new **Tools** section of the sidebar: it is a stateless utility, not a setting.

## [0.13.1] - 2026-09-28

### Security
- Bumped `golang.org/x/crypto` (v0.55.0 → v0.57.0), fixing two SSH denial-of-service issues (CVE-2026-78662, CVE-2026-56855) in the library used for Git deploy keys.
- Bumped `github.com/go-jose/go-jose/v4` (v4.1.4 → v4.1.5), used by the OIDC/SSO login path, fixing several hardening issues (panics on malformed input, a JSON parsing DoS, JWT validation bypass edge cases).

## [0.13.0] - 2026-09-28

### Added
- A manual secrets-encrypt helper (`/tools/secrets`, admin only) for a Git stack's `secrets.enc.yaml`: paste or upload a flat `KEY: value` document, pick a public key (an existing stack's, via a dropdown, or pasted directly), and get back ciphertext to copy or download — plain age (armored, safe to copy/display as text) or real SOPS (age backend), without installing either CLI locally. SOPS output is produced by the real `sops` binary, now bundled in the image, rather than a hand-rolled encoder, so it's byte-for-byte what `sops` itself would write (real MAC included) — encryption only ever needs the recipient's public key, so this never involves a private key, and that key is validated as a real `age1...` recipient before it's ever used. Nothing typed or uploaded here is ever stored; it's a stateless utility, not a second way to manage a stack's own secrets. A stack's own page links straight into it with that stack's public key already filled in (`?stack=<id>`), instead of a copy-paste round trip.

### Fixed
- Every `<input type=file>` in the app (backup restore, the volume browser upload, and this new page) rendered the browser's own light-themed default control regardless of the rest of the page's theme. Restyled globally to match every other field.

## [0.12.0] - 2026-09-21

### Added
- The container detail page's Overview now shows the actual image id the container was created from (`docker inspect`'s own `.Image`, not the reference string), truncated the same way `/images` already shows an image's own id — a direct way to tell whether a running container is still on the image `/images` lists as current, or on one that's since gone dangling underneath it.

### Fixed
- `/images`' "Used by" (and the "unused" flag "Clean up unused" relies on) never matched a container against its own image when the compose file referenced it fully-qualified (e.g. `docker.io/library/traefik:latest`) — Docker's own `docker images` always shows the short form for an official/single-namespace image, `docker ps` preserves whichever form created the container, and a naive string comparison between the two never matched. Found on a real host: a running `traefik` container's image always showed "unused".

## [0.11.0] - 2026-09-21

### Added
- A "Remove" action on `/containers` and a container's own detail page, for a stopped container Wharf didn't deploy (e.g. something left over from Portainer, sharing the same compose-project label convention). Refuses to run on anything still running or on a container that belongs to a stack Wharf actually manages — that one goes through undeploy instead, so its whole stack comes down together rather than one container at a time.

### Fixed
- The "Stack" column on `/containers` linked to `/stacks/{label}` for any compose-project label it saw, including ones from another tool like Portainer that Wharf never created a stack for — a 404. It now only links when that id is an actual Wharf-managed stack, and shows the label as plain text otherwise.

## [0.10.1] - 2026-09-20

### Added
- Sign-in and sign-out are now recorded in the audit log (`auth.login`/`auth.logout`, both local and SSO), under a new "Sign-in / sign-out" retention category.

## [0.10.0] - 2026-09-20

### Added
- Configurable retention for the audit log, per category (containers, stacks, hosts, users, Git connections, registry credentials, SSO, images, volumes, networks, notifications, backup) rather than one blanket setting — a new panel on `/audit-log` with a days-to-keep field per category, `0`/blank meaning forever (the default until set otherwise). Checked once a day; a category never touched keeps every entry indefinitely.

## [0.9.0] - 2026-09-20

### Added
- Webhook notifications (Slack, Discord, ntfy, or a generic JSON POST) for the events worth knowing about without staring at the UI: a deployment failing (fires immediately), an enrolled agent going dark, an agent falling behind on updates, or a newer controller version becoming available (the last three checked every 5 minutes, debounced so a routine restart's brief reconnect gap doesn't spam a disconnect alert — each notifies once when the condition starts, and resets once it clears). Configurable at `/settings/notifications`, with a "Send test" button that exercises the exact same send path as a real event. The webhook URL is treated as a credential (stored in the secrets custodian, never shown again once saved, never written to the audit log).

## [0.8.0] - 2026-09-19

### Added
- Encrypted backup/restore (`/settings/backup`, admin only). A backup is a consistent snapshot (SQLite `VACUUM INTO`, safe against the live WAL) of both databases plus the controller's own TLS identity — without the identity, restoring onto a new box would force every already-enrolled agent to be re-pointed at a new fingerprint. Optional passphrase encryption reuses `age`'s scrypt mode, the same library already used for every stack's secrets. A restore is staged, never applied hot: the uploaded file is validated and set aside, and only takes effect on the controller's next restart, before anything opens a database or binds the TLS identity. The previous data is never deleted, only renamed aside with a timestamp suffix.

## [0.7.0] - 2026-09-19

### Added
- Append-only audit log (`/audit-log`, admin only) recording who did what across roughly thirty mutating actions — container restart/stop, stack lifecycle (create/deploy/undeploy/delete/rename/trigger/image policy/secrets), hosts (approve/reject/rename/address), users, Git connections, registry credentials, OIDC configuration, and the volume file browser. Never records a secret, password, or token value, only that the action happened. Client-side filter by user, action, or target.

## [0.6.0] - 2026-09-19

### Added
- Full-page container logs view (`/containers/{id}/logs`, linked from the container detail page) with a configurable tail size (100 to 2000 lines, or all), a client-side search filter, auto-refresh every 5 seconds (only re-scrolls to the bottom if you were already there), and a download link. The agent's `docker logs --tail` is now controller-configurable per request instead of a hardcoded 200.

## [0.5.0] - 2026-09-18

### Changed
- The one-shot "this succeeded" toast moved from bottom-right to top-right (clear of the topbar), and is now shown for every mutating action that previously redirected silently — bulk image/volume/network deletion, host approve/reject, stack create/deploy/undeploy/delete/rename/trigger/image-policy changes, user management, Git connections, registry credentials, OIDC configuration, and the volume file browser's rename/delete/upload/save.

### Fixed
- A redirect whose target already carried its own query string (a volume browser path, a bulk-delete `?refreshing=1`) could end up with a malformed URL — `?path=foo?error=bar` instead of two separate parameters, breaking both the error message and the path itself. Every redirect helper now composes query strings through one shared, correct helper.

## [0.4.0] - 2026-09-18

### Added
- Version-available detection for both the controller and its agents, checked every 6 hours against the real GitHub tags (not a formal Release object, which this project doesn't publish). A badge next to the version number in the sidebar links straight to the corresponding GitHub release page when the controller itself is behind. Each connected agent now reports its own version on every state push, shown as a column on `/hosts` with the same "update available" badge per host.

## [0.3.0] - 2026-09-18

### Added
- A toast now confirms a container restart/stop instead of leaving the page to redirect silently — by the time the redirect lands, the agent has already finished the action, so this is the only visible confirmation it happened at all.

### Fixed
- Restarting or stopping a container from the containers *list* page no longer drags you into that container's detail page — the redirect now goes back to wherever the click actually came from.

## [0.2.0] - 2026-09-17

### Added
- A stack's trigger mode (manual/webhook/polling) can now be changed after creation, not just chosen once at creation time (`POST /stacks/{id}/trigger`, Git stacks only). Switching to `polling` without an existing schedule defaults to `*/15 * * * *`, immediately editable. Switching to `webhook` without an existing secret generates one. A value already set from a previous stint in that mode is preserved rather than regenerated.
- Favicon on the controller UI (previously missing entirely — every page fell back to a 404 `/favicon.ico` request).

### Fixed
- Leaving polling mode now actually deregisters the stack's cron entry — previously, switching a stack to manual/webhook left its old schedule running underneath, invisible from the UI.

## [0.1.0] - 2026-09-16

Initial public release.
