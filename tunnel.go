// Persistent agent tunnel — agent-initiated, mTLS-pinned WebSocket, kept
// open for as long as the agent runs. Carries live host state (container,
// image, volume and network snapshots together, pushed on `docker
// events` + a periodic safety resync — cf. agent/tunnel.go) without a
// fixed poll interval, and now also controller->agent commands
// (restart/stop a container) over the same connection, the other
// direction the message envelope's "type" field was always meant for.
//
// Deliberately separate from the deployment-queue poll on
// GET /agent/commands (cf. commandsHandler in main.go): GitOps
// deployment doesn't need to be real-time, and keeping it on its own
// simple, already-proven poll loop means this tunnel can fail or
// reconnect without ever affecting whether a deploy gets picked up.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/forgelab-me/wharf-server/internal/store"
)

type containerReport struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Image       string   `json:"image"`
	State       string   `json:"state"`
	Status      string   `json:"status"`
	Ports       string   `json:"ports"`
	Created     string   `json:"created"`
	StackID     string   `json:"stack_id"`
	ServiceName string   `json:"service_name"`
	Mounts      []string `json:"mounts,omitempty"`
	Networks    []string `json:"networks,omitempty"`
	ImageID     string   `json:"image_id,omitempty"`
}

type imageReport struct {
	ID         string `json:"id"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Size       string `json:"size"`
	Digest     string `json:"digest,omitempty"`
}

type volumeReport struct {
	Name   string `json:"name"`
	Driver string `json:"driver"`
}

type networkReport struct {
	Name   string `json:"name"`
	Driver string `json:"driver"`
	Scope  string `json:"scope"`
}

// tunnelMessage covers three message kinds sharing one envelope:
// "state" (agent->controller, the fields above), "command"
// (controller->agent: RequestID/Action/ContainerID), and
// "command_result" (agent->controller reply: RequestID/OK/Output).
type tunnelMessage struct {
	Type       string            `json:"type"`
	Containers []containerReport `json:"containers,omitempty"`
	Images     []imageReport     `json:"images,omitempty"`
	Volumes    []volumeReport    `json:"volumes,omitempty"`
	Networks   []networkReport   `json:"networks,omitempty"`
	Arch       string            `json:"arch,omitempty"`    // "state" only -- the host's CPU architecture, cf. store.SetHostArch
	Version    string            `json:"version,omitempty"` // "state" only -- the reporting agent's own build, cf. versioncheck.go

	// "command" (controller -> agent)
	RequestID   string `json:"request_id,omitempty"`
	Action      string `json:"action,omitempty"` // "restart" | "stop" | "logs" | "inspect" | "stats" | "stats_many" | "top" | "host_stats" | "image_inspect" | "image_history" | "volume_inspect" | "network_inspect" | "volume_sizes" | "volume_list" | "volume_read" | "volume_write" | "volume_rename" | "volume_delete"
	ContainerID string `json:"container_id,omitempty"`
	Tail        string `json:"tail,omitempty"` // "logs" only, cf. sendLogsCommand

	ContainerIDs []string `json:"container_ids,omitempty"` // "stats_many" only, cf. stackstats.go

	// Volume browsing (controller -> agent) -- Path/NewPath are always
	// the full in-container path under the ephemeral helper's /vol mount
	// (cf. agent/tunnel.go), already joined and validated by the
	// controller before this is ever sent; the agent trusts them as-is.
	// Data is base64, used only by volume_write (the content to write).
	VolumeName string `json:"volume_name,omitempty"`
	Path       string `json:"path,omitempty"`
	NewPath    string `json:"new_path,omitempty"`
	Data       string `json:"data,omitempty"`

	// "command_result" (agent -> controller)
	OK     bool   `json:"ok,omitempty"`
	Output string `json:"output,omitempty"`
}

// tunnelConn is one agent's live connection, registered in a
// tunnelRegistry for the lifetime of tunnelHandler. writeMu serializes
// writes: multiple HTTP requests could try to send a command to the same
// host at once. pending correlates a "command_result" back to whichever
// sendCommand call is waiting for it, by RequestID.
type tunnelConn struct {
	conn *websocket.Conn

	writeMu sync.Mutex

	pendingMu sync.Mutex
	pending   map[string]chan tunnelMessage
}

// sendCommand sends a command and blocks until either the matching
// "command_result" arrives or ctx/the timeout expires. The reply channel
// is buffered(1) so a reply that arrives after a timeout still has
// somewhere to land instead of leaking a blocked goroutine on the read
// side.
func (tc *tunnelConn) sendCommand(ctx context.Context, action, containerID string) (tunnelMessage, error) {
	return tc.send(ctx, tunnelMessage{Action: action, ContainerID: containerID})
}

// sendLogsCommand is sendCommand's counterpart for the full logs page
// (cf. containers.go) -- tail picks how many lines back, validated
// against a fixed allowlist by the caller before this is ever sent
// (logTailFromQuery), not passed through from a request query param
// unchecked.
func (tc *tunnelConn) sendLogsCommand(ctx context.Context, containerID, tail string) (tunnelMessage, error) {
	return tc.send(ctx, tunnelMessage{Action: "logs", ContainerID: containerID, Tail: tail})
}

// sendVolumeCommand is sendCommand's counterpart for volume browsing --
// a single "container id" string isn't enough here (a volume name, a
// path, sometimes a second path for a rename or a data payload for a
// write). path/newPath are always the full in-container path under the
// agent's ephemeral helper's /vol mount (cf. volumeContainerPath),
// already validated by the caller before this is ever sent.
func (tc *tunnelConn) sendVolumeCommand(ctx context.Context, action, volumeName, path, newPath, data string) (tunnelMessage, error) {
	return tc.send(ctx, tunnelMessage{Action: action, VolumeName: volumeName, Path: path, NewPath: newPath, Data: data})
}

// send is sendCommand/sendVolumeCommand's shared core: fills in the
// envelope fields every command needs (type, request id) and blocks
// until either the matching "command_result" arrives or ctx/the
// timeout expires. The reply channel is buffered(1) so a reply that
// arrives after a timeout still has somewhere to land instead of
// leaking a blocked goroutine on the read side.
func (tc *tunnelConn) send(ctx context.Context, msg tunnelMessage) (tunnelMessage, error) {
	id, err := randomHex(8)
	if err != nil {
		return tunnelMessage{}, fmt.Errorf("generate request id: %w", err)
	}

	reply := make(chan tunnelMessage, 1)
	tc.pendingMu.Lock()
	tc.pending[id] = reply
	tc.pendingMu.Unlock()
	defer func() {
		tc.pendingMu.Lock()
		delete(tc.pending, id)
		tc.pendingMu.Unlock()
	}()

	msg.Type = "command"
	msg.RequestID = id
	tc.writeMu.Lock()
	err = wsjson.Write(ctx, tc.conn, msg)
	tc.writeMu.Unlock()
	if err != nil {
		return tunnelMessage{}, fmt.Errorf("send command: %w", err)
	}

	select {
	case result := <-reply:
		return result, nil
	case <-time.After(15 * time.Second):
		return tunnelMessage{}, fmt.Errorf("timed out waiting for agent response")
	case <-ctx.Done():
		return tunnelMessage{}, ctx.Err()
	}
}

// tunnelRegistry tracks the one live connection per connected host, so
// an HTTP handler (e.g. a container restart/stop request) can reach an
// agent it never otherwise talks to directly.
type tunnelRegistry struct {
	mu    sync.Mutex
	conns map[string]*tunnelConn
}

func newTunnelRegistry() *tunnelRegistry {
	return &tunnelRegistry{conns: map[string]*tunnelConn{}}
}

func (r *tunnelRegistry) set(hostID string, tc *tunnelConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.conns[hostID] = tc
}

// remove only deletes the entry if it still holds this exact connection
// -- if the agent reconnected in the tiny window before the old
// handler's deregistration runs, the newer connection must survive.
func (r *tunnelRegistry) remove(hostID string, tc *tunnelConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conns[hostID] == tc {
		delete(r.conns, hostID)
	}
}

func (r *tunnelRegistry) get(hostID string) (*tunnelConn, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	tc, ok := r.conns[hostID]
	return tc, ok
}

// tunnelHandler serves GET /agent/tunnel on agentMux. Authenticated
// exactly like commandsHandler: purely by the caller's pinned mTLS
// certificate, resolved to a host with no id in the URL — an agent
// doesn't get to claim which host it's reporting for, its certificate
// already says so.
func (a *app) tunnelHandler(w http.ResponseWriter, r *http.Request) {
	fp, err := callerFingerprint(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	host, err := a.store.GetHostByFingerprint(fp)
	if err != nil {
		http.Error(w, "unknown caller", http.StatusForbidden)
		return
	}

	// InsecureSkipVerify here only disables the browser Origin check --
	// meaningless for a Go client that never sends an Origin header in
	// the first place. The real authentication already happened above,
	// via the pinned client certificate.
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		log.Println("tunnel: accept failed for host", host.ID, ":", err)
		return
	}
	defer conn.CloseNow()
	// coder/websocket defaults to a 32KB read limit -- fine for a handful
	// of containers, but a real host's combined containers+images+
	// volumes+networks snapshot can exceed that easily (hit during
	// testing on a host with a lot of accumulated state: the server
	// closed the connection with "read limited at 32769 bytes" on every
	// single snapshot, an unrecoverable reconnect loop for a busy host).
	// 8MiB comfortably covers even a heavily used homelab fleet while
	// still bounding worst-case memory per connection.
	conn.SetReadLimit(8 << 20)

	tc := &tunnelConn{conn: conn, pending: map[string]chan tunnelMessage{}}
	a.tunnels.set(host.ID, tc)
	defer a.tunnels.remove(host.ID, tc)

	ctx := r.Context()
	cache := stateCache{}
	for {
		var msg tunnelMessage
		if err := wsjson.Read(ctx, conn, &msg); err != nil {
			log.Println("tunnel: closed for host", host.ID, ":", err)
			return
		}

		switch msg.Type {
		case "command_result":
			tc.pendingMu.Lock()
			reply, ok := tc.pending[msg.RequestID]
			tc.pendingMu.Unlock()
			if ok {
				reply <- msg
			}
		case "state":
			a.applyState(host.ID, msg, cache)
		default:
			log.Println("tunnel: unknown message type", msg.Type, "from host", host.ID)
		}
	}
}

// stateCache remembers, for one tunnel connection, a hash of what was last
// written to the database per table. An agent resends its whole state every
// 45 seconds and on every Docker event, and on a quiet host almost every
// push is identical: rewriting it each time made several hosts queue for
// SQLite's single writer for nothing.
type stateCache map[string]string

// unchanged reports whether table's content is what was last written, and
// returns the hash to remember once the write has succeeded.
func (c stateCache) unchanged(table string, rows any) (hash string, same bool) {
	raw, err := json.Marshal(rows)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(raw)
	hash = hex.EncodeToString(sum[:])
	return hash, c[table] == hash
}

// applyState stores one "state" push. A table is only rewritten when it
// changed, a write that hits a busy database is retried, and a table whose
// write failed is not remembered, so the next push tries it again.
func (a *app) applyState(hostID string, msg tunnelMessage, cache stateCache) {
	containers := make([]store.HostContainer, 0, len(msg.Containers))
	for _, c := range msg.Containers {
		containers = append(containers, store.HostContainer{
			HostID:      hostID,
			ContainerID: c.ID,
			Name:        c.Name,
			Image:       c.Image,
			State:       c.State,
			Status:      c.Status,
			Ports:       c.Ports,
			Created:     c.Created,
			StackID:     c.StackID,
			ServiceName: c.ServiceName,
			Mounts:      strings.Join(c.Mounts, ","),
			Networks:    strings.Join(c.Networks, ","),
			ImageID:     c.ImageID,
		})
	}
	images := make([]store.HostImage, 0, len(msg.Images))
	for _, img := range msg.Images {
		images = append(images, store.HostImage{
			HostID:     hostID,
			ImageID:    img.ID,
			Repository: img.Repository,
			Tag:        img.Tag,
			Size:       img.Size,
			Digest:     img.Digest,
		})
	}
	volumes := make([]store.HostVolume, 0, len(msg.Volumes))
	for _, v := range msg.Volumes {
		volumes = append(volumes, store.HostVolume{HostID: hostID, Name: v.Name, Driver: v.Driver})
	}
	networks := make([]store.HostNetwork, 0, len(msg.Networks))
	for _, n := range msg.Networks {
		networks = append(networks, store.HostNetwork{HostID: hostID, Name: n.Name, Driver: n.Driver, Scope: n.Scope})
	}

	replace := func(table string, rows any, write func() error) {
		hash, same := cache.unchanged(table, rows)
		if same {
			return
		}
		if err := retryOnBusy(write); err != nil {
			log.Println("tunnel: replace host", table, "for", hostID, "failed:", err)
			delete(cache, table)
			return
		}
		cache[table] = hash
	}
	replace("containers", containers, func() error { return a.store.ReplaceHostContainers(hostID, containers) })
	replace("images", images, func() error { return a.store.ReplaceHostImages(hostID, images) })
	replace("volumes", volumes, func() error { return a.store.ReplaceHostVolumes(hostID, volumes) })
	replace("networks", networks, func() error { return a.store.ReplaceHostNetworks(hostID, networks) })

	// version and architecture change a few times in a host's life, not per push
	facts := msg.Version + "|" + msg.Arch
	if cache["facts"] == facts {
		return
	}
	ok := true
	if msg.Version != "" {
		if err := retryOnBusy(func() error { return a.store.SetHostAgentVersion(hostID, msg.Version) }); err != nil {
			log.Println("tunnel: set agent version for", hostID, "failed:", err)
			ok = false
		}
	}
	if msg.Arch != "" {
		if err := retryOnBusy(func() error { return a.store.SetHostArch(hostID, msg.Arch) }); err != nil {
			log.Println("tunnel: set host arch for", hostID, "failed:", err)
			ok = false
		}
	}
	if ok {
		cache["facts"] = facts
	}
}

// retryOnBusy runs write, trying again a few times when SQLite reports the
// database as busy: another writer held the lock for longer than the busy
// timeout, which passes once it commits. Any other error returns at once.
func retryOnBusy(write func() error) error {
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		if err = write(); err == nil || !isBusy(err) {
			return err
		}
		busyBackoff(attempt)
	}
	return err
}

// busyBackoff waits before a retry; a variable so tests need not sit through it.
var busyBackoff = func(attempt int) { time.Sleep(time.Duration(attempt+1) * 250 * time.Millisecond) }

func isBusy(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "SQLITE_BUSY") || strings.Contains(msg, "database is locked")
}
