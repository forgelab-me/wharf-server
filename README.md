# wharf-server

[![CI](https://github.com/forgelab-me/wharf-server/actions/workflows/server.yml/badge.svg)](https://github.com/forgelab-me/wharf-server/actions/workflows/server.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

The controller: serves the UI and API, holds all persistent state, custodies every private key/secret, and talks to enrolled agents over a pinned-mTLS WebSocket tunnel. Wharf is a self-hosted GitOps deployment controller and agent for Docker standalone and Compose — deliberately not Swarm, not Kubernetes. See [wharf-agent](https://github.com/forgelab-me/wharf-agent) for the other half of the picture.

## Building and running

Pull the published image, or build the same thing locally — no local Go toolchain needed either way:

```bash
docker build -t wharf-server:latest .   # or: docker pull ghcr.io/forgelab-me/wharf-server:latest
```

The controller needs two things to start: an admin bootstrap account (`WHARF_ADMIN_USER` / `WHARF_ADMIN_PASSWORD`, only used the very first time — see `EnsureFirstUser` in `internal/store`) and a place to keep its state (`/data`, expected to be a persistent volume):

```yaml
services:
  controller:
    image: ghcr.io/forgelab-me/wharf-server:latest
    restart: unless-stopped
    ports:
      - "8080:8080"   # UI (HTTP)
      - "8443:8443"   # agent enrollment/command channel
      - "9443:9443"   # UI (HTTPS)
    environment:
      WHARF_ADMIN_USER: ${WHARF_ADMIN_USER:?WHARF_ADMIN_USER must be set}
      WHARF_ADMIN_PASSWORD: ${WHARF_ADMIN_PASSWORD:?WHARF_ADMIN_PASSWORD must be set}
    volumes:
      - wharf-data:/data

volumes:
  wharf-data:
```

### Ports

| Port | Purpose |
|---|---|
| `8080` | UI, plain HTTP |
| `9443` | UI, HTTPS (self-signed) |
| `8443` | Agent enrollment + command channel (mTLS, fingerprint-pinned) |

## Layout

```
server/
├── main.go              route registration, stack/host handlers, render() helper
├── auth.go               session cookies, login, forced password change
├── oidc.go                OIDC relying-party flow (login, callback, group→role sync)
├── settings.go            authentication settings page (OIDC, local-auth toggle)
├── registries.go          private registry credential CRUD
├── users.go               user management (admin-only)
├── containers.go          container list/detail, env-var masking, port parsing
├── images.go, volumes.go, networks.go   Docker resource list/detail pages
├── imagepolicies.go       pin/auto/propose image-update tracking
├── imagepoller.go         background digest-check scheduler
├── poller.go              Git polling-trigger scheduler
├── stats.go               live CPU/mem/disk stats (container + host)
├── tunnel.go              the agent-facing WebSocket protocol
├── internal/
│   ├── store/             main application database (SQLite) — stacks, hosts,
│   │                      deployments, users, sessions
│   ├── keys/               the secrets custodian — a *separate* SQLite database
│   │                      holding every age/SSH private key, registry and OIDC
│   │                      secrets. Never imports internal/store.
│   ├── registry/           generic Docker Registry v2 client (WWW-Authenticate
│   │                      discovery — no per-vendor hardcoding beyond docker.io's
│   │                      own domain quirk)
│   └── identity/           the controller's self-signed TLS identity
└── web/
    ├── templates/          html/template views, one file per page
    └── static/             a single stylesheet, no build step, no CDN
```

## Design notes worth knowing before changing something

- **Two physically separate databases.** `internal/store` is the main application database; `internal/keys` is an isolated custodian that's the only code path ever holding a private key or a credential in plaintext. Keeping this boundary intact is the whole point — don't reach into one from the other.
- **Server-rendered, no build step.** Views are `html/template` + `embed`, no Node, no client-side framework. JavaScript in `web/static` is hand-written and small on purpose.
- **The agent tunnel is push, not poll.** The controller never reaches out to an agent for routine state (container lists, image inventory, etc.) — an agent pushes snapshots over its own persistent connection. On-demand actions (restart, logs, inspect, live stats) use the same tunnel as a request/reply.
- **Every DB schema change needs a migration.** `internal/store` and `internal/keys` both run idempotent `ALTER TABLE ... ADD COLUMN` migrations on startup (see `isDuplicateColumn`) — `CREATE TABLE IF NOT EXISTS` alone only covers a fresh database, not one that's been running in production.

Most non-trivial functions in this package carry a comment explaining *why*, not just what — that's the primary source of design rationale here.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE).
