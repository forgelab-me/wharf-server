# Changelog

All notable changes to `wharf-server` are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions match the `vX.Y.Z` git tags that trigger a release build.

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
