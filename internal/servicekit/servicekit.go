// Package servicekit is what a data-plane service uses to honour a capability.
//
// It is the piece dariyakyu and dariyafunc will vendor. Everything about its shape is therefore a
// decision about what those repos will find easy to do, and BREAK.md E4 exists to find out
// whether "easy" and "correct" are the same thing here.
//
// # The state of this file at M4.3
//
// Authenticate verifies the signature and the expiry and hands back what the token asserts. The
// service is then expected to check that the token's action and resource match the request it is
// about to serve. Nothing makes it. E4 predicted that this shape makes the wrong thing easy to
// write, and skeleton_key_test.go demonstrates the consequence rather than describing it.
//
// M4.4 changes this API. If you are reading this comment in a commit later than M4.4, the change
// did not land.
package servicekit

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"google.golang.org/protobuf/proto"

	capabilityv1 "dariyanws/gen/dariya/capability/v1"
	"dariyanws/internal/capability"
	"dariyanws/internal/httpx"
)

var ErrNoCapability = errors.New("servicekit: no capability on the request")

// Authenticate reads the capability header and verifies it offline.
//
// Offline is the point (DESIGN.md decision 6): no call to IAM, no call to the front door, nothing
// on the data path that can be down. A service holding the public key can honour a decision made
// by a control plane that is no longer running, which is what E1 is built to demonstrate.
func Authenticate(r *http.Request, v *capability.Verifier) (*capabilityv1.Capability, error) {
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

	return v.Verify(&token)
}
