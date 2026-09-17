# Changelog

All notable changes to `wharf-server` are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions match the `vX.Y.Z` git tags that trigger a release build.

## [0.2.0] - 2026-09-17

### Added
- A stack's trigger mode (manual/webhook/polling) can now be changed after creation, not just chosen once at creation time (`POST /stacks/{id}/trigger`, Git stacks only). Switching to `polling` without an existing schedule defaults to `*/15 * * * *`, immediately editable. Switching to `webhook` without an existing secret generates one. A value already set from a previous stint in that mode is preserved rather than regenerated.
- Favicon on the controller UI (previously missing entirely — every page fell back to a 404 `/favicon.ico` request).

### Fixed
- Leaving polling mode now actually deregisters the stack's cron entry — previously, switching a stack to manual/webhook left its old schedule running underneath, invisible from the UI.

## [0.1.0] - 2026-09-16

Initial public release.
