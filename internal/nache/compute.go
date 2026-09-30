package nache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	chalav1 "dariyanws/gen/dariya/chala/v1"
	"dariyanws/internal/nache/store"
	"dariyanws/internal/signing"
)

// Compute is what the reconciler needs from chala. An interface so the reconciler's decisions can
// be tested against a fake whose every answer is chosen, while the real one is exercised end to
// end through the front door.
type Compute interface {
	// Nodes lists every instance nache runs, in every customer's cluster.
	Nodes(ctx context.Context) ([]*chalav1.Instance, error)

	// RunNode starts — or finishes starting — the node for c. There is no parameter naming an
	// account: the node is attached to c.Account(), and c can only have come from the store.
	RunNode(ctx context.Context, c *store.Cluster) (*chalav1.Instance, error)

	// Terminate removes a node. A node already gone is not an error.
	Terminate(ctx context.Context, node string) error
}

// Tags nache puts on every node, and finds them again by (decision 13g).
const (
	tagManagedBy      = "managed-by"
	tagClusterAccount = "cluster-account"
	tagCluster        = "cluster"
)

// NodeName is the one node's instance name in nache's service account. Deterministic, so that
// RunNode is the same PUT every time it is retried — the property that makes a crash between
// "chala started it" and "nache recorded it" leave nothing duplicated.
func NodeName(account, cluster string) string { return "n-" + account + "-" + cluster }

// ChalaClient calls chala through the front door, signed as nache's service account.
//
// Through the front door and not straight to chala, although both run on the same host: nache is
// an ordinary same-account caller (decision 13c), and an ordinary caller is authorized by IAM.
// Going around the door would make nache the one principal in the region whose calls no policy
// governs.
type ChalaClient struct {
	FrontDoor   string // e.g. http://127.0.0.1:8080
	Region      string
	Credentials signing.Credentials
	HTTP        *http.Client
	Now         func() time.Time
}

const chalaPrefix = "/chala/2026-09-30"

func (c *ChalaClient) Nodes(ctx context.Context) ([]*chalav1.Instance, error) {
	var resp chalav1.DescribeInstancesResponse
	q := url.Values{"tag." + tagManagedBy: {Service}}
	if err := c.do(ctx, "GET", chalaPrefix+"/instances", q, nil, &resp); err != nil {
		return nil, err
	}
	return resp.GetInstances(), nil
}

func (c *ChalaClient) RunNode(ctx context.Context, cl *store.Cluster) (*chalav1.Instance, error) {
	account := cl.Account()
	req := &chalav1.RunInstanceRequest{
		ImageId: "img-nache-engine",
		Tags: map[string]string{
			tagManagedBy:      Service,
			tagClusterAccount: account,
			tagCluster:        cl.Name,
		},
		AttachAccountId:  account,
		AttachDnsAliases: []string{Endpoint(account, cl.Name)},
	}
	var resp chalav1.RunInstanceResponse
	if err := c.do(ctx, "PUT", chalaPrefix+"/instances/"+NodeName(account, cl.Name), nil, req, &resp); err != nil {
		return nil, err
	}
	return resp.GetInstance(), nil
}

func (c *ChalaClient) Terminate(ctx context.Context, node string) error {
	err := c.do(ctx, "DELETE", chalaPrefix+"/instances/"+node, nil, nil, nil)
	var ce *ChalaError
	if errors.As(err, &ce) && ce.Code == "ResourceNotFound" {
		return nil
	}
	return err
}

// ChalaError is a contract-shaped refusal from chala or the front door.
type ChalaError struct {
	Status    int
	Code      string
	Message   string
	RequestID string
}

func (e *ChalaError) Error() string {
	return fmt.Sprintf("chala: %d %s: %s (request %s)", e.Status, e.Code, e.Message, e.RequestID)
}

func (c *ChalaClient) do(ctx context.Context, method, path string, query url.Values, body proto.Message, into proto.Message) error {
	var raw []byte
	if body != nil {
		var err error
		if raw, err = protojson.Marshal(body); err != nil {
			return err
		}
	}

	u := c.FrontDoor + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	auth, headers := signing.Sign(signing.Request{Method: method, Path: path, Query: query, Body: raw},
		c.Credentials, c.Region, "chala", now())
	req.Header.Set("Authorization", auth)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("chala: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}

	if resp.StatusCode >= 300 {
		e := &ChalaError{Status: resp.StatusCode}
		var shape struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		}
		_ = json.Unmarshal(out, &shape)
		e.Code, e.Message, e.RequestID = shape.Code, shape.Message, shape.RequestID
		return e
	}
	if into != nil {
		// Unknown fields refused, as the console does: a renamed field in chala's contract fails
		// here, at the boundary, rather than as a node that silently reads as unhealthy.
		if err := (protojson.UnmarshalOptions{}).Unmarshal(out, into); err != nil {
			return fmt.Errorf("chala: decoding %s %s: %w", method, path, err)
		}
	}
	return nil
}
