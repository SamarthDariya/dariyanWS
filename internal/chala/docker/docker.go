// Package docker is the smallest Docker Engine API client chala needs, spoken directly over the
// daemon's unix socket.
//
// Hand-rolled rather than the official SDK for the reason clients/cpp bundles its own SHA-256:
// the SDK drags in a large dependency tree to reach a dozen endpoints, and every one of those
// endpoints is a plain JSON-over-HTTP call that fits on a screen. Being able to read the whole
// surface chala uses is also the point — decision 13b is a claim that chala cannot express a
// bind mount or a privileged container, and that claim is only checkable if the code that talks
// to the daemon is short enough to audit. Nothing in this file can mount a host path, because
// nothing in this file has a field for one.
//
// This package knows nothing about accounts, instances or tags. It is a transport; chala decides
// what the labels and names mean.
package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// APIVersion pins the wire format. 1.44 is Docker 25, old enough to be on any daemon a laptop
// has and new enough that duplicate network names are refused by the daemon rather than silently
// created — which EnsureNetwork relies on.
const APIVersion = "v1.44"

var (
	ErrNotFound = errors.New("docker: not found")

	// ErrConflict is what makes a container name usable as a lock: two creates racing for the
	// same name cannot both succeed, and the loser learns it here rather than by finding a twin.
	ErrConflict = errors.New("docker: conflict")
)

// Error is a non-2xx answer from the daemon, with the message it gave.
type Error struct {
	Status  int
	Message string
	kind    error
}

func (e *Error) Error() string { return fmt.Sprintf("docker: %d: %s", e.Status, e.Message) }
func (e *Error) Unwrap() error { return e.kind }

// Client talks to one daemon.
type Client struct {
	http *http.Client
}

// DefaultSocket is where the daemon listens unless DOCKER_HOST says otherwise.
func DefaultSocket() string {
	if host := os.Getenv("DOCKER_HOST"); strings.HasPrefix(host, "unix://") {
		return strings.TrimPrefix(host, "unix://")
	}
	return "/var/run/docker.sock"
}

// New returns a client for the daemon at socketPath. It does not connect; Ping does.
func New(socketPath string) *Client {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	return &Client{http: &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "unix", socketPath)
			},
			MaxIdleConns:    8,
			IdleConnTimeout: 30 * time.Second,
		},
	}}
}

// do sends one request. The host in the URL is a placeholder; the transport ignores it.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, into any) (int, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = bytes.NewReader(encoded)
	}

	u := "http://docker/" + APIVersion + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("docker: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotModified {
		var msg struct {
			Message string `json:"message"`
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = json.Unmarshal(raw, &msg)
		if msg.Message == "" {
			msg.Message = strings.TrimSpace(string(raw))
		}
		e := &Error{Status: resp.StatusCode, Message: msg.Message}
		switch resp.StatusCode {
		case http.StatusNotFound:
			e.kind = ErrNotFound
		case http.StatusConflict:
			e.kind = ErrConflict
		}
		return resp.StatusCode, e
	}

	if into != nil {
		if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
			return resp.StatusCode, fmt.Errorf("docker: decoding %s %s: %w", method, path, err)
		}
	} else {
		// Drained so the connection goes back to the pool. An image pull streams progress
		// here, and returning before it ends would abandon the pull half way.
		_, _ = io.Copy(io.Discard, resp.Body)
	}
	return resp.StatusCode, nil
}

// Ping confirms the daemon is reachable.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.do(ctx, "GET", "/_ping", nil, nil, nil)
	return err
}

// ---------------------------------------------------------------------------
// Images
// ---------------------------------------------------------------------------

// ImageExists reports whether ref is present locally.
func (c *Client) ImageExists(ctx context.Context, ref string) (bool, error) {
	_, err := c.do(ctx, "GET", "/images/"+ref+"/json", nil, nil, nil)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// PullImage fetches ref from its registry and returns once the pull has finished.
//
// The daemon answers 200 as soon as the pull starts and reports failures inside the progress
// stream, so success is confirmed afterwards by looking for the image rather than by the status.
func (c *Client) PullImage(ctx context.Context, ref string) error {
	name, tag := ref, "latest"
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		name, tag = ref[:i], ref[i+1:]
	}
	if _, err := c.do(ctx, "POST", "/images/create",
		url.Values{"fromImage": {name}, "tag": {tag}}, nil, nil); err != nil {
		return err
	}
	ok, err := c.ImageExists(ctx, ref)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("docker: pulled %s but it is not present — check the name and the registry", ref)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Networks
// ---------------------------------------------------------------------------

// NetworkSpec is everything chala sets on a network.
type NetworkSpec struct {
	Name   string
	Labels map[string]string

	// Internal networks have no route off the host. Instances can reach each other and nothing
	// else, which is the right default for a mini-VPC with no NAT gateway to speak of.
	Internal bool
}

// EnsureNetwork creates the network if it does not exist, and is safe to race.
func (c *Client) EnsureNetwork(ctx context.Context, spec NetworkSpec) error {
	if _, err := c.do(ctx, "GET", "/networks/"+spec.Name, nil, nil, nil); err == nil {
		return nil
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}

	_, err := c.do(ctx, "POST", "/networks/create", nil, map[string]any{
		"Name":     spec.Name,
		"Driver":   "bridge",
		"Internal": spec.Internal,
		"Labels":   spec.Labels,
	}, nil)
	// Somebody else created it between the look and the create. Since API 1.44 the daemon
	// refuses the duplicate rather than making a second network with the same name, so losing
	// the race is harmless.
	if errors.Is(err, ErrConflict) {
		return nil
	}
	return err
}

// ConnectNetwork attaches an existing container to a second network, under the given DNS aliases.
// Connecting a container that is already on the network is not an error, so a half-finished
// attach can be retried to completion.
func (c *Client) ConnectNetwork(ctx context.Context, network, containerID string, aliases []string) error {
	_, err := c.do(ctx, "POST", "/networks/"+network+"/connect", nil, map[string]any{
		"Container":      containerID,
		"EndpointConfig": map[string]any{"Aliases": aliases},
	}, nil)
	var e *Error
	if errors.As(err, &e) && e.Status == http.StatusForbidden && strings.Contains(e.Message, "already exists") {
		return nil
	}
	return err
}

// RemoveNetwork deletes a network that has no containers left on it. chala does not call it yet —
// an account network outlives its instances, and nothing deletes accounts — so today it is only
// what tests clean up with.
func (c *Client) RemoveNetwork(ctx context.Context, name string) error {
	_, err := c.do(ctx, "DELETE", "/networks/"+name, nil, nil, nil)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// ---------------------------------------------------------------------------
// Containers
// ---------------------------------------------------------------------------

// ContainerSpec is everything chala is able to ask the daemon for.
//
// Read what is absent as carefully as what is present. There is no field for a bind mount, a
// volume, a device, a host network, host PID or IPC namespace, a published port, an added
// capability or privileged mode, and therefore no request chala can be talked into making that
// sets one. That is decision 13b's security claim, in the only form that can be checked.
type ContainerSpec struct {
	Image  string
	Cmd    []string
	Env    []string
	Labels map[string]string

	// Network is the one network the container starts on, and Aliases are its DNS names there
	// (DESIGN.md decision 13h).
	Network string
	Aliases []string

	MemoryBytes int64
	PidsLimit   int64
}

// CreateContainer creates, but does not start, a container called name.
//
// A name that is taken fails with ErrConflict, and that is the idempotency mechanism: two
// RunInstance calls racing for one instance name cannot both create a container.
func (c *Client) CreateContainer(ctx context.Context, name string, spec ContainerSpec) (string, error) {
	body := map[string]any{
		"Image":  spec.Image,
		"Cmd":    spec.Cmd,
		"Env":    spec.Env,
		"Labels": spec.Labels,
		"HostConfig": map[string]any{
			"NetworkMode": spec.Network,
			"Memory":      spec.MemoryBytes,
			"PidsLimit":   spec.PidsLimit,

			// Stated rather than left to defaults, so the posture is visible in a request log.
			"Privileged":  false,
			"CapDrop":     []string{"ALL"},
			"SecurityOpt": []string{"no-new-privileges"},

			// No restart policy. A container that exits must STAY exited, because a death the
			// daemon quietly papers over is one the reconciler never sees — and noticing death
			// is the thing decision 13g is built to do.
			"RestartPolicy": map[string]any{"Name": "no"},
		},
		"NetworkingConfig": map[string]any{
			"EndpointsConfig": map[string]any{
				spec.Network: map[string]any{"Aliases": spec.Aliases},
			},
		},
	}

	var out struct {
		ID string `json:"Id"`
	}
	if _, err := c.do(ctx, "POST", "/containers/create", url.Values{"name": {name}}, body, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// StartContainer starts a created container. Starting one already running is not an error.
func (c *Client) StartContainer(ctx context.Context, id string) error {
	_, err := c.do(ctx, "POST", "/containers/"+id+"/start", nil, nil, nil)
	return err
}

// RemoveContainer kills and removes a container. Removing one that is already gone is not an
// error, so a terminate can be retried until it is seen to succeed.
func (c *Client) RemoveContainer(ctx context.Context, id string) error {
	_, err := c.do(ctx, "DELETE", "/containers/"+id, url.Values{"force": {"true"}, "v": {"true"}}, nil, nil)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// Container is the part of an inspect chala reads.
type Container struct {
	ID      string
	Name    string
	Image   string
	Labels  map[string]string
	Created time.Time

	// Status is the daemon's word: created, running, paused, restarting, removing, exited, dead.
	Status   string
	ExitCode int

	// Networks maps network name to this container's address on it.
	Networks map[string]string
}

// InspectContainer returns one container by name or id, or ErrNotFound.
func (c *Client) InspectContainer(ctx context.Context, nameOrID string) (*Container, error) {
	var raw struct {
		ID      string `json:"Id"`
		Name    string `json:"Name"`
		Created time.Time
		State   struct {
			Status   string
			ExitCode int
		}
		Config struct {
			Image  string
			Labels map[string]string
		}
		NetworkSettings struct {
			Networks map[string]struct {
				IPAddress string
			}
		}
	}
	if _, err := c.do(ctx, "GET", "/containers/"+nameOrID+"/json", nil, nil, &raw); err != nil {
		return nil, err
	}

	nets := make(map[string]string, len(raw.NetworkSettings.Networks))
	for name, ep := range raw.NetworkSettings.Networks {
		nets[name] = ep.IPAddress
	}
	return &Container{
		ID:       raw.ID,
		Name:     strings.TrimPrefix(raw.Name, "/"),
		Image:    raw.Config.Image,
		Labels:   raw.Config.Labels,
		Created:  raw.Created,
		Status:   raw.State.Status,
		ExitCode: raw.State.ExitCode,
		Networks: nets,
	}, nil
}

// ListContainers returns the ids of every container, running or not, carrying ALL of the given
// labels ("key=value"). The daemon ANDs label filters, which is the semantics tag filtering wants.
func (c *Client) ListContainers(ctx context.Context, labels []string) ([]string, error) {
	filters, err := json.Marshal(map[string][]string{"label": labels})
	if err != nil {
		return nil, err
	}
	var out []struct {
		ID string `json:"Id"`
	}
	if _, err := c.do(ctx, "GET", "/containers/json",
		url.Values{"all": {"true"}, "filters": {string(filters)}}, nil, &out); err != nil {
		return nil, err
	}
	ids := make([]string, len(out))
	for i, c := range out {
		ids[i] = c.ID
	}
	return ids, nil
}
