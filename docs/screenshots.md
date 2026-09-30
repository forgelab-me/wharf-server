# Screenshots

A tour of the UI, using invented sample data. The full documentation is at **[wharf.forgelab.me](https://wharf.forgelab.me/)**.

## Stacks and hosts

### Dashboard
Connected hosts, active stacks and the latest deployments at a glance.

![Dashboard](screenshots/dashboard.png)

### New stack
A stack lives in Git (deployed with a dedicated deploy key or a shared connection) or is authored in Wharf. Pick a trigger — manual, webhook or polling — and the host it runs on.

![New stack form](screenshots/stack-form.png)

### Stack
Its containers, the last deployment's output, and Deploy / Undeploy.

![Stack page](screenshots/stack-view.png)

### Image update policies
Each service's image is tracked against its registry: pinned, auto-redeploy, or propose.

![Image update policies](screenshots/image-policies.png)

### Hosts
An agent shows up as pending until you approve it; its certificate fingerprint is pinned from then on.

![Hosts](screenshots/hosts.png)

### Host
Live CPU, memory and I/O across the host's containers, and Docker's disk footprint.

![Host details](screenshots/host-detail.png)

## Docker resources

### Containers
Every container on every host, with stack, image freshness, ports and quick actions.

![Containers](screenshots/containers.png)

### Container
Overview, live resources, processes, logs, environment (secrets masked), volumes and networks.

![Container details](screenshots/container-detail.png)

### Images
Unused and dangling images, ready for a bulk clean-up.

![Images](screenshots/images-bulk-delete.png)

### Volume browser
Browse, edit, upload and download files inside a volume (admin only).

![Volume browser](screenshots/volume-browse.png)

## Secrets

### Encrypt secrets
Encrypt a `secrets.enc.yaml` for a stack in the browser, as plain age or SOPS, without installing either.

![Encrypt secrets](screenshots/secrets-tool.png)

### Secret providers
Shared connections to an OpenBao / Vault server, for `ref+vault://` references in a stack's `secrets.refs.yaml`.

![Secret providers](screenshots/secret-providers.png)

### Attaching a provider to a stack
Which connection a stack goes through, with which credentials, and the paths it may read.

![Attaching a provider to a stack](screenshots/secret-binding.png)

![Secret references on a stack page](screenshots/stack-secret-references.png)

## Access and settings

### Git connections
Shared SSH keys or HTTP credentials several stacks can use.

![Git connections](screenshots/git-connections.png)

![New Git connection](screenshots/git-connection-form.png)

### Private registries
Credentials used both for the image update check and for pulls at deploy time.

![Private registries](screenshots/registries.png)

### Users
Admin and operator roles, local and SSO accounts.

![Users](screenshots/users.png)

### Single sign-on
Any standard OIDC provider, with admin and operator groups.

![Single sign-on](screenshots/authentication.png)
