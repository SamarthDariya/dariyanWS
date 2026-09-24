// Package controlapi exposes the control plane over HTTP.
//
// Until now accounts, credentials and policies existed only as Go methods, reachable through
// dariyactl talking to Postgres in-process. That was fine while the only client was a CLI on the
// same machine; it is not fine for a console, and it was never going to be — an operator tool
// with direct database access quietly becomes the second way to do everything, with none of the
// authorization the first way has.
//
// # What is exposed, and what deliberately is not
//
// Everything here acts on the caller's OWN account, taken from the authenticated principal and
// never from the request. There is no route that names an account, because a route that named one
// would be a route that could name someone else's.
//
// CreateAccount and ListAccounts are therefore absent. Creating a tenant is not an operation a
// tenant can perform, and listing them is an operator view across the whole cloud. Both stay in
// dariyactl, out of band — which is also how it works everywhere else: nobody creates their first
// AWS account through the AWS API, because they have no credentials to sign the call with.
package controlapi

import (
	"io"
	"net/http"
	"strconv"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	commonv1 "dariyanws/gen/dariya/common/v1"
	"dariyanws/internal/apierr"
	"dariyanws/internal/control"
	"dariyanws/internal/httpx"
	"dariyanws/internal/iam"
	"dariyanws/internal/session"
)

// API holds what the handlers need. Constructed by the front door, which owns the lifetimes.
//
// The dependencies are the concrete servers rather than interfaces. An interface per service here
// would be three declarations restating what the servers already are, for one implementation
// each — the handlers below are thin enough that testing them against the real servers and a real
// database is both easier and a better test.
type API struct {
	Accounts *control.AccountsServer
	Policies *iam.Server
	Sessions *session.Manager
	Region   string
	Dev      bool
}

// SignInPath is where the front door mounts the one unauthenticated route.
const SignInPath = "/" + APIVersion + "/session/sign-in"

// principal is the caller, and the only source of the account every handler scopes to.
func principal(r *http.Request) (*commonv1.Principal, error) {
	p, ok := httpx.PrincipalFrom(r.Context())
	if !ok {
		// Unreachable behind the chain. Handled because a handler mounted outside it must fail
		// closed rather than act on an empty account, which every storage key prefix matches.
		return nil, apierr.Internal(nil, "internal failure")
	}
	return p, nil
}

// decodeJSON reads a request body into a proto message.
//
// The body is already bounded by the authn middleware, which had to buffer it to verify the
// signature — so there is no second limit to apply here, and applying one would invite the two
// to disagree.
func decodeJSON(r *http.Request, into proto.Message) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return apierr.Validation("could not read the request body")
	}
	if len(body) == 0 {
		return apierr.Validation("a request body is required")
	}

	// DiscardUnknown is off. A client sending a field this server does not know is a client
	// built against a different contract, and accepting it silently means their intent is
	// quietly ignored — the failure that looks like the server losing writes.
	if err := (protojson.UnmarshalOptions{}).Unmarshal(body, into); err != nil {
		return apierr.Validation("the request body is not valid JSON for this operation: %v", err)
	}
	return nil
}

// writeProto renders a proto message as the response.
//
// EmitUnpopulated so a client sees every field the contract promises, with its zero value, rather
// than having to distinguish "absent" from "empty" for fields the server simply did not set.
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

// pageParams reads the two pagination query parameters every list route accepts.
func pageParams(r *http.Request) (*commonv1.PageRequest, error) {
	page := &commonv1.PageRequest{NextToken: r.URL.Query().Get("next_token")}

	if raw := r.URL.Query().Get("max_results"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return nil, apierr.Validation("max_results must be a number, got %q", raw)
		}
		page.MaxResults = int32(n)
	}
	return page, nil
}

// pathSegment returns the nth segment after a prefix, or "" if there is none.
func pathSegment(path, prefix string, n int) string {
	rest := strings.TrimPrefix(path, prefix)
	parts := strings.Split(rest, "/")
	if n >= len(parts) {
		return ""
	}
	return parts[n]
}
