// Package nache is the managed cache's control plane (DESIGN.md decision 13): an API that records
// what the customer wants, and a reconciler that makes it so on chala.
//
// The API never talks to chala. CreateCacheCluster writes a row and returns 202; Describe reads the
// row, including the nodes the reconciler last observed. So the API keeps answering when chala is
// down, and a slow container start can never be a slow request — the split decision 13g made, at
// the level of which code can block on what.
package nache

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	capabilityv1 "dariyanws/gen/dariya/capability/v1"
	commonv1 "dariyanws/gen/dariya/common/v1"
	nachev1 "dariyanws/gen/dariya/nache/v1"
	"dariyanws/internal/apierr"
	"dariyanws/internal/httpx"
	"dariyanws/internal/nache/store"
	"dariyanws/internal/servicekit"
)

// Service is the ARN service segment.
const Service = "nache"

const APIVersion = "2026-09-30"

// Prefix is where the routes live, on the front door and here alike.
const Prefix = "/nache/" + APIVersion

// Port is where every engine listens.
const Port = 6379

// A DNS label, capped at 40 so the node's instance name — n-<account>-<name> — still is one.
var clusterName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$`)

// Endpoint is the cluster's stable name on the customer's network (13h). Derived from the
// account and name alone, so it exists from creation and survives any node being replaced.
func Endpoint(account, name string) string {
	return fmt.Sprintf("%s.%s.nache.dariya.internal", name, account)
}

// APIConfig is what the API is told at boot.
type APIConfig struct {
	Region string

	// MaxClustersPerAccount bounds one tenant. Each cluster is a container on one laptop.
	MaxClustersPerAccount int

	Dev bool
	Log *slog.Logger
}

type API struct {
	store *store.Store
	guard *servicekit.Guard
	cfg   APIConfig
}

func NewAPI(s *store.Store, g *servicekit.Guard, cfg APIConfig) *API {
	if cfg.MaxClustersPerAccount <= 0 {
		cfg.MaxClustersPerAccount = 5
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &API{store: s, guard: g, cfg: cfg}
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("PUT "+Prefix+"/clusters/{name}", a.create)
	mux.HandleFunc("GET "+Prefix+"/clusters/{name}", a.describe)
	mux.HandleFunc("DELETE "+Prefix+"/clusters/{name}", a.delete)
	mux.HandleFunc("GET "+Prefix+"/clusters", a.list)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
	})
	return httpx.Chain(mux, httpx.AdoptRequestID, httpx.Recover(a.cfg.Dev), httpx.AccessLog(a.cfg.Log))
}

// create records the cluster and returns 202: accepted, not yet real. A repeat returns 200 with
// the cluster as it now stands, so a client that retried a timed-out create learns it worked.
func (a *API) create(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	cap, err := a.authorize(r, "nache:CreateCacheCluster", name)
	if err != nil {
		a.fail(w, r, err)
		return
	}

	// The body is optional today — a cluster has no settings yet — but if one is sent it must
	// parse, so a client sending settings this server does not know hears about it.
	var req nachev1.CreateCacheClusterRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}

	ctx := r.Context()
	if _, err := a.store.Get(ctx, cap, name); errors.Is(err, store.ErrNotFound) {
		n, err := a.store.Count(ctx, cap)
		if err != nil {
			a.fail(w, r, apierr.Internal(err, "could not count clusters"))
			return
		}
		if n >= a.cfg.MaxClustersPerAccount {
			a.fail(w, r, &apierr.Error{Code: apierr.CodeLimitExceeded, Message: fmt.Sprintf(
				"the account already has %d cache clusters, the most it may have", n)})
			return
		}
	} else if err != nil {
		a.fail(w, r, apierr.Internal(err, "could not look up the cluster"))
		return
	}

	c, created, err := a.store.Create(ctx, cap, name)
	if errors.Is(err, store.ErrDeleting) {
		a.fail(w, r, apierr.AlreadyExists("cluster %q is still being deleted; retry once it is gone", name))
		return
	}
	if err != nil {
		a.fail(w, r, apierr.Internal(err, "could not record the cluster"))
		return
	}

	status := http.StatusOK
	if created {
		status = http.StatusAccepted
	}
	writeProto(w, r, status, &nachev1.CreateCacheClusterResponse{Cluster: a.render(c)})
}

func (a *API) describe(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	cap, err := a.authorize(r, "nache:DescribeCacheCluster", name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	c, err := a.store.Get(r.Context(), cap, name)
	if err != nil {
		a.fail(w, r, notFound(err, name))
		return
	}
	writeProto(w, r, http.StatusOK, &nachev1.DescribeCacheClusterResponse{Cluster: a.render(c)})
}

// delete marks the cluster deleting and returns 202. The reconciler removes the node, then the row.
func (a *API) delete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	cap, err := a.authorize(r, "nache:DeleteCacheCluster", name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	c, err := a.store.MarkDeleting(r.Context(), cap, name)
	if err != nil {
		a.fail(w, r, notFound(err, name))
		return
	}
	writeProto(w, r, http.StatusAccepted, &nachev1.DeleteCacheClusterResponse{Cluster: a.render(c)})
}

// list is unpaginated for chala's reason: the quota bounds it.
func (a *API) list(w http.ResponseWriter, r *http.Request) {
	cap, err := a.guard.AuthorizeAccount(r, "nache:ListCacheClusters")
	if err != nil {
		a.fail(w, r, denied(err))
		return
	}
	clusters, err := a.store.List(r.Context(), cap)
	if err != nil {
		a.fail(w, r, apierr.Internal(err, "could not list clusters"))
		return
	}
	resp := &nachev1.ListCacheClustersResponse{Page: &commonv1.PageResponse{}}
	for _, c := range clusters {
		resp.Clusters = append(resp.Clusters, a.render(c))
	}
	writeProto(w, r, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------

func (a *API) authorize(r *http.Request, action, name string) (*capabilityv1.Capability, error) {
	if !clusterName.MatchString(name) {
		return nil, apierr.Validation(
			"a cluster name is 1-40 of [a-z0-9-], not starting or ending with '-': %q", name)
	}
	cap, err := a.guard.Authorize(r, servicekit.Intent{Action: action, ResourceType: "cluster", ResourceID: name})
	if err != nil {
		return nil, denied(err)
	}
	return cap, nil
}

func (a *API) render(c *store.Cluster) *nachev1.CacheCluster {
	out := &nachev1.CacheCluster{
		Name:            c.Name,
		Arn:             fmt.Sprintf("arn:dariya:nache:%s:%s:cluster/%s", a.cfg.Region, c.Account(), c.Name),
		AccountId:       c.Account(),
		State:           resourceState(c.State),
		Endpoint:        fmt.Sprintf("%s:%d", Endpoint(c.Account(), c.Name), Port),
		CreatedAtUnixMs: c.CreatedAt.UnixMilli(),
		UpdatedAtUnixMs: c.UpdatedAt.UnixMilli(),
	}
	for _, n := range c.Nodes {
		out.Nodes = append(out.Nodes, &nachev1.CacheNode{
			NodeId: n.ID, Status: nodeStatus(n.Status), ObservedAtUnixMs: n.ObservedAt.UnixMilli(),
		})
	}
	return out
}

func resourceState(s store.State) commonv1.ResourceState {
	switch s {
	case store.Creating:
		return commonv1.ResourceState_RESOURCE_STATE_CREATING
	case store.Active:
		return commonv1.ResourceState_RESOURCE_STATE_ACTIVE
	case store.Deleting:
		return commonv1.ResourceState_RESOURCE_STATE_DELETING
	default:
		return commonv1.ResourceState_RESOURCE_STATE_UNSPECIFIED
	}
}

// Node statuses as stored. Strings in the row so the JSON stays readable in psql.
const (
	nodeCreating  = "creating"
	nodeAvailable = "available"
	nodeImpaired  = "impaired"
)

func nodeStatus(s string) nachev1.CacheNodeStatus {
	switch s {
	case nodeCreating:
		return nachev1.CacheNodeStatus_CACHE_NODE_STATUS_CREATING
	case nodeAvailable:
		return nachev1.CacheNodeStatus_CACHE_NODE_STATUS_AVAILABLE
	case nodeImpaired:
		return nachev1.CacheNodeStatus_CACHE_NODE_STATUS_IMPAIRED
	default:
		return nachev1.CacheNodeStatus_CACHE_NODE_STATUS_UNSPECIFIED
	}
}

func notFound(err error, name string) error {
	if errors.Is(err, store.ErrNotFound) {
		return apierr.NotFound("no cache cluster %q", name)
	}
	return apierr.Internal(err, "could not look up the cluster")
}

func denied(err error) error {
	return &apierr.Error{Code: apierr.CodeAccessDenied,
		Message: "the capability does not authorise this request", Cause: err}
}

func (a *API) fail(w http.ResponseWriter, r *http.Request, err error) {
	httpx.WriteError(w, r, err, a.cfg.Dev)
}

func decodeOptionalJSON(r *http.Request, into proto.Message) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		return apierr.Validation("could not read the request body")
	}
	if len(body) == 0 {
		return nil
	}
	if err := (protojson.UnmarshalOptions{}).Unmarshal(body, into); err != nil {
		return apierr.Validation("the request body is not valid JSON for this operation: %v", err)
	}
	return nil
}

func writeProto(w http.ResponseWriter, r *http.Request, status int, msg proto.Message) {
	body, err := protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(msg)
	if err != nil {
		httpx.WriteError(w, r, apierr.Internal(err, "could not encode the response"), false)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
