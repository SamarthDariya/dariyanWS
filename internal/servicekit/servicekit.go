// Package servicekit is what a data-plane service uses to honour a capability.
//
// It is the piece dariyakyu and dariyafunc will vendor, so its shape is a decision about what
// those repos will find easy to do. BREAK.md E4 asked whether "easy" and "correct" were the same
// thing here. At M4.3 they were not: a helper that verified a signature and handed back the
// capability produced a nine-line service holding a skeleton key, because nothing obliged the
// author to compare the token against the request.
//
// # What changed at M5.3
//
// Intent names a resource TYPE and ID rather than a whole ARN, and the Guard assembles the
// expected ARN using the account from the verified token. This was forced by writing the first
// real service against the M4.4 API: a data plane cannot know whose resource it is serving until
// the token is verified, so asking it for a complete ARN pushed it toward reading the capability
// first and checking it afterwards — reinventing the hole M4.4 had just closed. The account is
// now the one field a service cannot supply and cannot get wrong.
//
// # What changed at M4.4
//
// The helper that could be misused is gone rather than documented. `Guard.Authorize` cannot be
// called without stating what the request is for, so the comparison happens inside the helper and
// the vulnerable service is unwriteable rather than discouraged.
//
// A rule in a comment is a rule every future service author has to read. A rule in a function
// signature is one they cannot skip. This project has now reached for that answer twice —
// decision 4 put account_id in every storage key so tenant isolation is structural rather than
// remembered — and it is the more reliable kind of safety by some distance.
package servicekit

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"google.golang.org/protobuf/proto"

	capabilityv1 "dariyanws/gen/dariya/capability/v1"
	"dariyanws/internal/arn"
	"dariyanws/internal/capability"
	"dariyanws/internal/httpx"
)

var (
	ErrNoCapability = errors.New("servicekit: no capability on the request")

	// ErrMismatch is the error E4 exists to make reachable. A token that verifies perfectly but
	// authorises something other than what is being served is a rejection, not a pass.
	ErrMismatch = errors.New("servicekit: the capability does not authorise this request")
)

// Intent is what the service is about to do, stated before it is permitted to do it.
//
// There is no constructor and no zero-value default on purpose. A caller must write every field,
// which is the whole mechanism: the comparison cannot be forgotten because the information
// needed to perform it cannot be omitted.
//
// What is deliberately NOT here is the account. A service cannot know whose resource it is
// serving until the token is verified, and asking it to supply one would push it toward reading
// the capability first and checking it afterwards. The Guard takes the account from the verified
// token instead, so it is the one part of the expected ARN a service cannot get wrong.
type Intent struct {
	// Action, service-qualified and exactly as policy writes it: "func:Invoke".
	Action string

	// ResourceType is the ARN type segment: "function", "queue".
	ResourceType string

	// ResourceID is the specific resource, fully resolved. Never a pattern — by the time a
	// service is serving a request it knows precisely which resource it is acting on, and a
	// pattern here would re-introduce the wildcard matching that belongs in policy.
	ResourceID string
}

// Guard verifies capabilities on behalf of one service.
type Guard struct {
	verifier *capability.Verifier

	// service is the ARN service segment this process serves — "func", "kyu". It comes from the
	// process's own configuration, never from a request, so a service cannot be talked into
	// acting on another service's resource.
	service string

	// region likewise. Both are needed to assemble the ARN the token must match.
	region string
}

func NewGuard(v *capability.Verifier, service, region string) *Guard {
	return &Guard{verifier: v, service: service, region: region}
}

// Authorize verifies the capability on a request and confirms it authorises exactly this intent.
//
// Offline (DESIGN.md decision 6): no call to IAM, no call to the front door, nothing on the data
// path that can be down. A service holding the public key honours a decision made by a control
// plane that is no longer running, which is what E1 is built to demonstrate.
//
// The checks, in order, cheapest and most diagnostic first:
//
//  1. a capability is present, decodes, and its signature and expiry verify;
//  2. the action matches;
//  3. the resource matches exactly — assembled from this process's own service and region, the
//     type and id the caller stated, and the account from the verified token;
//  4. the account in the token agrees with the account in its own resource ARN.
//
// Check 4 is redundant given 3 and a correctly minted token, and is kept because it is the one
// that fails loudly if the front door is ever changed to mint a token whose account and resource
// disagree — a mistake that would otherwise be invisible until it was a cross-tenant incident.
func (g *Guard) Authorize(r *http.Request, intent Intent) (*capabilityv1.Capability, error) {
	if intent.Action == "" || intent.ResourceType == "" || intent.ResourceID == "" {
		// A programming error in the service, not a client error. Refusing here means an
		// incompletely stated intent cannot accidentally match a token.
		return nil, fmt.Errorf(
			"servicekit: intent must state an action, a resource type and a resource id")
	}

	header := r.Header.Get(httpx.CapabilityHeader)
	if header == "" {
		return nil, ErrNoCapability
	}

	raw, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return nil, fmt.Errorf("servicekit: capability header is not base64: %w", err)
	}

	var token capabilityv1.SignedCapability
	if err := proto.Unmarshal(raw, &token); err != nil {
		return nil, fmt.Errorf("servicekit: capability header is not a SignedCapability: %w", err)
	}

	cap, err := g.verifier.Verify(&token)
	if err != nil {
		return nil, err
	}

	if cap.GetAction() != intent.Action {
		return nil, fmt.Errorf("%w: authorises %q, this request is %q",
			ErrMismatch, cap.GetAction(), intent.Action)
	}

	// The expected ARN, assembled rather than supplied. Everything in it comes either from this
	// process's configuration or from the verified token — nothing from the request.
	expected := fmt.Sprintf("arn:dariya:%s:%s:%s:%s/%s",
		g.service, g.region, cap.GetAccountId(), intent.ResourceType, intent.ResourceID)

	// Exact string equality, not a prefix and not a pattern. This is the line E4 was about.
	if cap.GetResourceArn() != expected {
		return nil, fmt.Errorf("%w: authorises %q, this request is for %q",
			ErrMismatch, cap.GetResourceArn(), expected)
	}

	resource, err := arn.Parse(cap.GetResourceArn())
	if err != nil {
		return nil, fmt.Errorf("%w: resource is not a valid ARN: %v", ErrMismatch, err)
	}
	if cap.GetAccountId() != resource.Account {
		return nil, fmt.Errorf("%w: token names account %s but its resource belongs to %s",
			ErrMismatch, cap.GetAccountId(), resource.Account)
	}

	return cap, nil
}
