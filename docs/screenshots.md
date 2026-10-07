# Screenshots

A tour of the UI, using invented sample data. The full documentation is at **[wharf.forgelab.me](https://wharf.forgelab.me/)**.

## Stacks and hosts

### Dashboard
Connected hosts, active stacks and the latest deployments at a glance.

![Dashboard](screenshots/dashboard.png)

### Stacks
One row per stack with its state, worst vulnerability and live CPU, memory, network and disk; a row unfolds into one card per container with four live curves. A stack with nothing running keeps its cards, greyed.

![Stacks list](screenshots/stacks.png)

### New stack
A stack lives in Git (deployed with a dedicated deploy key or a shared connection) or is authored in Wharf. Pick a trigger — manual, webhook or polling — and the host it runs on.

![New stack form](screenshots/stack-form.png)

### Stack
Its containers, a topology graph of what feeds them and what they use, the last deployment's output, and Deploy / Undeploy.

![Stack page](screenshots/stack-view.png)

### Stack topology
The stack's sources, containers (with their worst vulnerability), volumes and networks, drawn left to right.

![Stack topology](screenshots/topology-stack.png)

### Image update policies
Each service's image is tracked against its registry: pinned, auto-redeploy, or propose.

![Image update policies](screenshots/image-policies.png)

### Hosts
An agent shows up as pending until you approve it; its certificate fingerprint is pinned from then on.

![Hosts](screenshots/hosts.png)

### Host
A topology of the host's containers, live CPU, memory and I/O across them, and Docker's disk footprint.

![Host details](screenshots/host-detail.png)

### Host topology
Containers grouped by stack, each with its image, vulnerabilities, networks and volumes; a legend says which stacks a network links.

![Host topology](screenshots/topology-host.png)

## Docker resources

### Containers
Every container on every host, with stack, image freshness, ports and quick actions.

![Containers](screenshots/containers.png)

### Container
Overview, live resources, processes, logs, environment (secrets masked), volumes and networks.

![Container details](screenshots/container-detail.png)

### Images
Unused and dangling images, ready for a bulk clean-up, and each image in use with its vulnerabilities when scanning is on.

![Images](screenshots/images-bulk-delete.png)

### Volume browser
Browse, edit, upload and download files inside a volume (admin only).

![Volume browser](screenshots/volume-browse.png)

## Volume backups

### Backups
Named volumes copied to a SMB share on a schedule: the jobs, and the history of their runs.

![Backups](screenshots/backups.png)

### A job
Its volumes, schedule, how the containers are treated, the retention rule, whether the repository exists on the share, and the history.

![A backup job](screenshots/backup-job.png)

### Choosing the volumes
Stacks with their volumes in a tree, label rules, and a preview of what the job covers and why.

![Choosing the volumes of a backup job](screenshots/backup-volumes.png)

### A run
Each volume with its snapshot, its size, what it added to the repository and what retention did.

![A backup run](screenshots/backup-run.png)

### Destinations
Where the backups go: a SMB share, set up once and used by any number of jobs.

![Backup destinations](screenshots/backup-destinations.png)

![A backup destination](screenshots/backup-destination.png)

### Repository password
Shown once when a destination is created; an administrator can show it again, which is audited.

![The repository password](screenshots/backup-repo-password.png)

## Vulnerability scanning

### Settings
Optional, off by default: Trivy or Grype, downloaded on demand, reading each image from its registry by digest.

![Vulnerability scanning settings](screenshots/vulnerability-scanning.png)

### A stack's images
What is applied and what an update would bring, each with its vulnerabilities.

![Vulnerabilities in a stack's Images panel](screenshots/stack-image-scans.png)

### Findings
Every vulnerability of an image, filterable to what has a fix.

![Findings of an image](screenshots/scan-findings.png)

## Secrets

### Encrypt secrets
Encrypt a `secrets.enc.yaml` for a stack in the browser, as plain age or SOPS, without installing either.

![Encrypt secrets](screenshots/secrets-tool.png)

### Secret providers
Shared connections to OpenBao / Vault and to Bitwarden Secrets Manager, for `ref+vault://` and `ref+bws://` references in a stack's `secrets.refs.yaml`. Each connection lists its address and its path rules; Bitwarden's tool is downloaded from here, after the licence is accepted.

![Secret providers](screenshots/secret-providers.png)

### Attaching a provider to a stack
Which connection a stack goes through, with which credentials. When the connection has path rules, the paths box is optional and says what the rules already give the stack; without rules it lists every path the stack may read.

![Attaching a provider to a stack](screenshots/secret-binding.png)

![The paths box of a stack whose connection has rules](screenshots/path-rules-extra.png)

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
