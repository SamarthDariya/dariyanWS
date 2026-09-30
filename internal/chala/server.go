// Package chala is dariyachala, the compute service: the one process in the region that holds the
// Docker socket (DESIGN.md decision 13b).
//
// It sits behind the front door like any data plane. Every request carries a capability, and the
// capability's account is the only account chala will act in — it is baked into the container
// name, the labels, the network and the DNS alias, so an instance cannot be created in, found in,
// or removed from an account the caller does not hold a capability for.
//
// # What chala stores
//
// Nothing of its own. The daemon's containers ARE the instance table: each carries its account,
// name, image and tags as labels, and the container name is unique per daemon. That is enough for
// every call chala serves, and it means there is no second copy of the truth to drift from the
// first — the drift a reconciler exists to repair would otherwise start inside chala itself. The
// cost is what EC2 keeps and this does not: a terminated instance vanishes at once rather than
// staying visible, and there is no history. When chala needs either, it needs a store.
package chala

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	capabilityv1 "dariyanws/gen/dariya/capability/v1"
	chalav1 "dariyanws/gen/dariya/chala/v1"
	commonv1 "dariyanws/gen/dariya/common/v1"
	"dariyanws/internal/apierr"
	"dariyanws/internal/chala/docker"
	"dariyanws/internal/httpx"
	"dariyanws/internal/servicekit"
)

// Service is the ARN service segment, and what a signature must be scoped to.
const Service = "chala"

// APIVersion dates chala's surface, independently of the control plane's.
const APIVersion = "2026-09-30"

// Prefix is where chala's routes live on the front door and on chala alike. The front door
// forwards the path unchanged, so the two must agree, and this constant is the agreement.
const Prefix = "/chala/" + APIVersion

// Config is everything chala is told at boot.
type Config struct {
	Region  string
	Catalog []Image

	// MaxInstancesPerAccount bounds what one tenant can start. The region is one laptop.
	MaxInstancesPerAccount int

	// ServiceAccounts maps an account id to the service segment it runs as ("nache"). Only these
	// accounts may attach an instance to another account's network (decision 13i). It is
	// configuration, not policy, on purpose: it names which control planes the region trusts to
	// act across tenants, and that is an operator's decision, not something a policy in one of
	// those tenants could grant.
	ServiceAccounts map[string]string

	Dev bool
	Log *slog.Logger
}

type Server struct {
	docker  *docker.Client
	guard   *servicekit.Guard
	catalog catalog
	cfg     Config
}

func New(d *docker.Client, guard *servicekit.Guard, cfg Config) (*Server, error) {
	cat, err := newCatalog(cfg.Catalog)
	if err != nil {
		return nil, err
	}
	for acct, svc := range cfg.ServiceAccounts {
		// A service account configured as chala could claim chala's own instance names on any
		// account's network, which is every other tenant's DNS.
		if !accountID.MatchString(acct) || !instanceName.MatchString(svc) || svc == Service {
			return nil, fmt.Errorf("chala: service account %q=%q is not <12 digits>=<service>, "+
				"and the service may not be chala", acct, svc)
		}
	}
	if cfg.MaxInstancesPerAccount <= 0 {
		cfg.MaxInstancesPerAccount = 20
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Server{docker: d, guard: guard, catalog: cat, cfg: cfg}, nil
}

// Handler serves chala's routes. The front door decides which action a request needs; chala
// checks that the capability says the same, which is the pairing decision 6 depends on.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("PUT "+Prefix+"/instances/{name}", s.runInstance)
	mux.HandleFunc("GET "+Prefix+"/instances/{name}", s.describeInstance)
	mux.HandleFunc("DELETE "+Prefix+"/instances/{name}", s.terminateInstance)
	mux.HandleFunc("GET "+Prefix+"/instances", s.describeInstances)
	mux.HandleFunc("GET "+Prefix+"/images", s.describeImages)

	// Unauthenticated on purpose, like cmd/echo's: it is how "chala is up" is told apart from
	// "chala is refusing me", and it says nothing about any tenant.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.docker.Ping(r.Context()); err != nil {
			httpx.WriteJSON(w, r, http.StatusServiceUnavailable, map[string]string{"status": "no daemon"})
			return
		}
		httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
	})

	return httpx.Chain(mux, httpx.AdoptRequestID, httpx.Recover(s.cfg.Dev), httpx.AccessLog(s.cfg.Log))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// runInstance is a PUT, so a retry is the same request. The container name is the lock: of two
// racing creates the daemon lets exactly one through, and the loser finds the winner's instance
// and returns it — provided it asked for the same thing.
func (s *Server) runInstance(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	cap, err := s.authorize(r, "chala:RunInstance", name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	account := cap.GetAccountId()

	var req chalav1.RunInstanceRequest
	if err := decodeJSON(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	req.Name = name // the path wins, as the account id does in the control plane

	img, ok := s.catalog[req.GetImageId()]
	if !ok {
		s.fail(w, r, apierr.Validation("no image %q in the catalog — see DescribeImages", req.GetImageId()))
		return
	}
	if err := validateTags(req.GetTags()); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := validateAttach(account, s.cfg.ServiceAccounts[account],
		req.GetAttachAccountId(), req.GetAttachDnsAliases()); err != nil {
		s.fail(w, r, err)
		return
	}

	ctx := r.Context()
	cname := containerName(account, name)

	existing, err := s.docker.InspectContainer(ctx, cname)
	switch {
	case err == nil:
		// A retry, or a second caller asking for the same instance.
		s.adopt(w, r, existing, &req)
		return
	case !errors.Is(err, docker.ErrNotFound):
		s.fail(w, r, apierr.Internal(err, "could not look up the instance"))
		return
	}

	// The quota is checked only for a name that does not exist yet, so a retry at the limit is
	// still answered. Two racing creates can each see one slot free and overshoot by one; the
	// bound is on runaway starting, not an exact count, and exactness would need a lock or a
	// store that chala does not otherwise have.
	ids, err := s.docker.ListContainers(ctx, accountFilter(account))
	if err != nil {
		s.fail(w, r, apierr.Internal(err, "could not count the account's instances"))
		return
	}
	if len(ids) >= s.cfg.MaxInstancesPerAccount {
		s.fail(w, r, &apierr.Error{Code: apierr.CodeLimitExceeded, Message: fmt.Sprintf(
			"the account already has %d instances, the most it may have", len(ids))})
		return
	}

	net := NetworkName(account)
	if err := s.docker.EnsureNetwork(ctx, docker.NetworkSpec{
		Name:     net,
		Labels:   map[string]string{labelKind: kindNetwork, labelAccount: account},
		Internal: true,
	}); err != nil {
		s.fail(w, r, apierr.Internal(err, "could not prepare the account network"))
		return
	}

	labels := instanceLabels(account, name, img.ID, req.GetTags())
	if attach := req.GetAttachAccountId(); attach != "" {
		labels[labelAttachAccount] = attach
		labels[labelAttachAliases] = strings.Join(req.GetAttachDnsAliases(), ",")
	}

	id, err := s.docker.CreateContainer(ctx, cname, docker.ContainerSpec{
		Image:       img.Ref,
		Cmd:         img.Cmd,
		Labels:      labels,
		Network:     net,
		Aliases:     []string{DNSName(account, name)},
		MemoryBytes: img.MemoryBytes,
		PidsLimit:   img.PidsLimit,
	})
	if errors.Is(err, docker.ErrConflict) {
		// Lost the race to another create of the same name. Theirs is the instance now.
		existing, err := s.docker.InspectContainer(ctx, cname)
		if err != nil {
			s.fail(w, r, apierr.Internal(err, "could not look up the instance"))
			return
		}
		s.adopt(w, r, existing, &req)
		return
	}
	if err != nil {
		s.fail(w, r, apierr.Internal(err, "could not create the instance"))
		return
	}

	// Everything after create is finish(), shared with the retry path, so a RunInstance that dies
	// at any step leaves something the same PUT completes rather than something to clean up.
	c, err := s.docker.InspectContainer(ctx, id)
	if err != nil {
		s.fail(w, r, apierr.Internal(err, "the instance was created but could not be described"))
		return
	}
	if err := s.finish(ctx, c, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	s.respondWith(w, r, http.StatusOK, id)
}

// finish brings a created container to the state the request asked for: attached where it
// should be, then started. Each step is safe to repeat.
//
// The attach happens BEFORE the start, so an instance is never running and reachable from its own
// network while not yet reachable where its caller needs it. That order matters to the reconciler:
// RUNNING has to mean "done", or it would have to check the network separately.
func (s *Server) finish(ctx context.Context, c *docker.Container, req *chalav1.RunInstanceRequest) error {
	if attach := req.GetAttachAccountId(); attach != "" {
		net := NetworkName(attach)
		if _, on := c.Networks[net]; !on {
			if err := s.docker.EnsureNetwork(ctx, docker.NetworkSpec{
				Name:     net,
				Labels:   map[string]string{labelKind: kindNetwork, labelAccount: attach},
				Internal: true,
			}); err != nil {
				return apierr.Internal(err, "could not prepare the attached account's network")
			}
			if err := s.docker.ConnectNetwork(ctx, net, c.ID, req.GetAttachDnsAliases()); err != nil {
				return apierr.Internal(err, "the instance was created but could not be attached")
			}
		}
	}
	if c.Status == "created" {
		if err := s.docker.StartContainer(ctx, c.ID); err != nil {
			// PENDING. A retry of the same PUT starts it.
			return apierr.Internal(err, "the instance was created but did not start")
		}
	}
	return nil
}

// adopt answers a RunInstance for a name that already exists. Same image and tags: it is the same
// request, and it is finished if needed. Anything else is a different request reusing the name.
func (s *Server) adopt(w http.ResponseWriter, r *http.Request, c *docker.Container, req *chalav1.RunInstanceRequest) {
	if c.Labels[labelImage] != req.GetImageId() || !sameTags(tagsFrom(c.Labels), req.GetTags()) ||
		c.Labels[labelAttachAccount] != req.GetAttachAccountId() ||
		c.Labels[labelAttachAliases] != strings.Join(req.GetAttachDnsAliases(), ",") {
		s.fail(w, r, &apierr.Error{Code: apierr.CodeIdempotencyMis, Message: fmt.Sprintf(
			"instance %q exists with a different image, tags or attachment", req.GetName())})
		return
	}
	if err := s.finish(r.Context(), c, req); err != nil {
		s.fail(w, r, err)
		return
	}
	s.respondWith(w, r, http.StatusOK, c.ID)
}

func (s *Server) describeInstance(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	cap, err := s.authorize(r, "chala:DescribeInstance", name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := s.find(r.Context(), cap.GetAccountId(), name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeProto(w, r, http.StatusOK, &chalav1.DescribeInstanceResponse{Instance: s.instance(c)})
}

// terminateInstance removes the container. A second terminate of the same name is a
// ResourceNotFound; a caller that retries terminates until it sees one, and treats it as done.
func (s *Server) terminateInstance(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	cap, err := s.authorize(r, "chala:TerminateInstance", name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := s.find(r.Context(), cap.GetAccountId(), name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.docker.RemoveContainer(r.Context(), c.ID); err != nil {
		s.fail(w, r, apierr.Internal(err, "could not terminate the instance"))
		return
	}
	writeProto(w, r, http.StatusOK, &chalav1.TerminateInstanceResponse{})
}

// describeInstances lists the caller's instances, optionally filtered by tag.
//
// It does not paginate: the quota bounds an account at MaxInstancesPerAccount, and a page that
// can never be more than one is not worth a token scheme. The response carries an empty
// PageResponse so a client written against decision 12's convention already loops correctly.
func (s *Server) describeInstances(w http.ResponseWriter, r *http.Request) {
	cap, err := s.guard.AuthorizeAccount(r, "chala:DescribeInstances")
	if err != nil {
		s.fail(w, r, denied(err))
		return
	}
	account := cap.GetAccountId()

	filter := accountFilter(account)
	for key, values := range r.URL.Query() {
		tag, ok := strings.CutPrefix(key, "tag.")
		if !ok {
			continue
		}
		if !tagKey.MatchString(tag) || len(values) != 1 {
			s.fail(w, r, apierr.Validation("a tag filter is tag.<key>=<value>, once per key: %q", key))
			return
		}
		filter = append(filter, labelTag+tag+"="+values[0])
	}

	ids, err := s.docker.ListContainers(r.Context(), filter)
	if err != nil {
		s.fail(w, r, apierr.Internal(err, "could not list instances"))
		return
	}

	resp := &chalav1.DescribeInstancesResponse{Page: &commonv1.PageResponse{}}
	for _, id := range ids {
		c, err := s.docker.InspectContainer(r.Context(), id)
		if errors.Is(err, docker.ErrNotFound) {
			continue // terminated between the list and the look
		}
		if err != nil {
			s.fail(w, r, apierr.Internal(err, "could not describe an instance"))
			return
		}
		// The daemon filtered by account already. Checked again because this is the line
		// between tenants, and a filter typo would otherwise be a silent cross-account listing.
		if c.Labels[labelAccount] != account {
			continue
		}
		resp.Instances = append(resp.Instances, s.instance(c))
	}
	sort.Slice(resp.Instances, func(i, j int) bool {
		return resp.Instances[i].GetName() < resp.Instances[j].GetName()
	})
	writeProto(w, r, http.StatusOK, resp)
}

func (s *Server) describeImages(w http.ResponseWriter, r *http.Request) {
	if _, err := s.guard.AuthorizeAccount(r, "chala:DescribeImages"); err != nil {
		s.fail(w, r, denied(err))
		return
	}
	resp := &chalav1.DescribeImagesResponse{}
	for _, img := range s.catalog {
		resp.Images = append(resp.Images, &chalav1.Image{ImageId: img.ID, Description: img.Description})
	}
	sort.Slice(resp.Images, func(i, j int) bool { return resp.Images[i].GetImageId() < resp.Images[j].GetImageId() })
	writeProto(w, r, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// authorize validates the name before verifying the capability against it, so a name that could
// not be an instance is a ValidationException rather than a confusing AccessDenied.
func (s *Server) authorize(r *http.Request, action, name string) (*capabilityv1.Capability, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	cap, err := s.guard.Authorize(r, servicekit.Intent{
		Action: action, ResourceType: "instance", ResourceID: name,
	})
	if err != nil {
		return nil, denied(err)
	}
	return cap, nil
}

// find returns the caller's instance by name. The account is in the container name, so the lookup
// itself is tenant-scoped; the label is checked as well, for the same reason as in the listing.
func (s *Server) find(ctx context.Context, account, name string) (*docker.Container, error) {
	c, err := s.docker.InspectContainer(ctx, containerName(account, name))
	if errors.Is(err, docker.ErrNotFound) || (err == nil && c.Labels[labelAccount] != account) {
		return nil, apierr.NotFound("no instance %q", name)
	}
	if err != nil {
		return nil, apierr.Internal(err, "could not look up the instance")
	}
	return c, nil
}

func (s *Server) respondWith(w http.ResponseWriter, r *http.Request, status int, id string) {
	c, err := s.docker.InspectContainer(r.Context(), id)
	if err != nil {
		s.fail(w, r, apierr.Internal(err, "the instance was started but could not be described"))
		return
	}
	writeProto(w, r, status, &chalav1.RunInstanceResponse{Instance: s.instance(c)})
}

func (s *Server) instance(c *docker.Container) *chalav1.Instance {
	account, name := c.Labels[labelAccount], c.Labels[labelInstance]
	var aliases []string
	if a := c.Labels[labelAttachAliases]; a != "" {
		aliases = strings.Split(a, ",")
	}
	attach := c.Labels[labelAttachAccount]
	var attachedIP string
	if attach != "" {
		attachedIP = c.Networks[NetworkName(attach)]
	}
	return &chalav1.Instance{
		AttachedAccountId:  attach,
		AttachedPrivateIp:  attachedIP,
		AttachedDnsAliases: aliases,
		Name:               name,
		Arn:                ARN(s.cfg.Region, account, name),
		AccountId:          account,
		ImageId:            c.Labels[labelImage],
		State:              state(c.Status),
		ExitCode:           int32(c.ExitCode),
		Tags:               tagsFrom(c.Labels),
		PrivateDnsName:     DNSName(account, name),
		PrivateIp:          c.Networks[NetworkName(account)],
		CreatedAtUnixMs:    c.Created.UnixMilli(),
	}
}

func state(status string) chalav1.InstanceState {
	switch status {
	case "created":
		return chalav1.InstanceState_INSTANCE_STATE_PENDING
	case "running", "restarting", "paused":
		return chalav1.InstanceState_INSTANCE_STATE_RUNNING
	case "exited", "dead":
		return chalav1.InstanceState_INSTANCE_STATE_STOPPED
	case "removing":
		return chalav1.InstanceState_INSTANCE_STATE_TERMINATING
	default:
		return chalav1.InstanceState_INSTANCE_STATE_UNSPECIFIED
	}
}

func sameTags(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// denied turns a Guard refusal into the contract's AccessDenied. The reason stays in the log: a
// caller who was refused is not told which check fired, the same rule as the front door's.
func denied(err error) error {
	return &apierr.Error{Code: apierr.CodeAccessDenied,
		Message: "the capability does not authorise this request", Cause: err}
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	httpx.WriteError(w, r, err, s.cfg.Dev)
}

func decodeJSON(r *http.Request, into proto.Message) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		return apierr.Validation("could not read the request body")
	}
	if len(body) == 0 {
		return apierr.Validation("a request body is required")
	}
	// Unknown fields refused, for the control plane's reason: a client built against another
	// contract should hear so rather than have its intent quietly ignored.
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
