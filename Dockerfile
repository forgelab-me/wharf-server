# Builds without a local Go toolchain: `docker build .` does everything.
# Versions pinned exactly on purpose (cf. ARCHITECTURE.md conventions) --
# bump deliberately, don't float on `latest`/`alpine`.
FROM golang:1.27.1-alpine3.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# VERSION defaults to "dev" for a plain local `docker build .` -- CI passes
# the real one via --build-arg (git tag on a release, branch+sha otherwise).
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION}" -o /out/wharf-server .

FROM alpine:3.24.1
# git + openssh-client-default: the controller runs `git ls-remote`
# itself for polling-mode stacks (cheap, read-only, no reason to route
# through an agent - cf. ARCHITECTURE.md, "Déclenchement du déploiement").
RUN apk add --no-cache ca-certificates git openssh-client-default
COPY --from=build /out/wharf-server /usr/local/bin/wharf-server
# Static baseline for a plain local `docker build` -- CI's own --label
# flags (docker/metadata-action, cf. .github/workflows/server.yml) take
# precedence and add version/created/revision, which only make sense
# coming from the actual build's git context.
LABEL org.opencontainers.image.title="wharf-server" \
      org.opencontainers.image.description="Wharf controller -- self-hosted GitOps deployment for Docker standalone + Compose" \
      org.opencontainers.image.source="https://github.com/forgelab-me/wharf-server" \
      org.opencontainers.image.licenses="MIT"
# cf. ARCHITECTURE.md: le fichier SQLite principal et le store du
# secrets-service doivent survivre aux recréations du container.
VOLUME /data
ENTRYPOINT ["wharf-server"]
