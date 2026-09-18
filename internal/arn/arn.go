// Package arn parses and formats dariya resource names.
//
//	arn:dariya:<service>:<region>:<account>:<type>/<id>
//	arn:dariya:kyu:hind-1:000000000001:queue/orders
//	arn:dariya:func:hind-1:000000000001:function/resize-image
//
// AWS's ARN minus the partition segment (DESIGN.md decision 4). The region field is kept although
// there is one region, because retrofitting a segment into an identifier that is already parsed in
// four languages is miserable work.
//
// This package is the reason ARNs are not compared as strings anywhere else. A resource name is a
// structure that happens to serialise as a string, and the account field in particular is a
// security boundary — code that wants to know "is this mine?" must ask the parsed Account, never
// strings.Contains.
package arn

import (
	"errors"
	"fmt"
	"strings"
)

// Partition is fixed. AWS has several (aws, aws-cn, aws-us-gov); this cloud has one, and the
// segment exists only so the shape is recognisable.
const Partition = "dariya"

// AccountIDLen is the zero-padded width of an account id. Fixed width means an ARN can be validated
// without a table lookup, and means account ids sort lexicographically in storage keys.
const AccountIDLen = 12

var (
	ErrMalformed  = errors.New("arn: malformed")
	ErrPartition  = errors.New("arn: wrong partition")
	ErrAccountID  = errors.New("arn: account id must be 12 digits")
	ErrEmptyField = errors.New("arn: empty required field")
	ErrNoResource = errors.New("arn: resource must be <type>/<id>")
)

// ARN is a parsed resource name.
type ARN struct {
	Service string // "kyu", "func", "iam"
	Region  string // "hind-1"
	Account string // "000000000001"
	Type    string // "queue", "function", "user", "role"
	ID      string // "orders", "resize-image". May itself contain '/'.
}

// String renders the ARN. Parse(a.String()) == a for any ARN that Parse produced.
func (a ARN) String() string {
	return strings.Join([]string{"arn", Partition, a.Service, a.Region, a.Account, a.Type + "/" + a.ID}, ":")
}

// Parse validates and splits a resource name.
//
// Deliberately strict: no empty segments, no unknown partition, no account id that is not exactly
// twelve digits. An ARN that reaches a service has already crossed a trust boundary, and a lenient
// parser here is how a request for account "1" ends up matching storage keys for account "10".
func Parse(s string) (ARN, error) {
	// Six parts, because the resource segment may itself contain colons in other clouds and may
	// contain slashes here. Everything after the fifth colon is the resource.
	parts := strings.SplitN(s, ":", 6)
	if len(parts) != 6 {
		return ARN{}, fmt.Errorf("%w: expected 6 colon-separated segments, got %d in %q", ErrMalformed, len(parts), s)
	}
	if parts[0] != "arn" {
		return ARN{}, fmt.Errorf("%w: must begin with \"arn\", got %q", ErrMalformed, parts[0])
	}
	if parts[1] != Partition {
		return ARN{}, fmt.Errorf("%w: got %q, want %q", ErrPartition, parts[1], Partition)
	}

	a := ARN{Service: parts[2], Region: parts[3], Account: parts[4]}
	if a.Service == "" || a.Region == "" {
		return ARN{}, fmt.Errorf("%w: service and region are required in %q", ErrEmptyField, s)
	}
	if err := ValidateAccountID(a.Account); err != nil {
		return ARN{}, err
	}

	typ, id, ok := strings.Cut(parts[5], "/")
	if !ok || typ == "" || id == "" {
		return ARN{}, fmt.Errorf("%w: got %q", ErrNoResource, parts[5])
	}
	a.Type, a.ID = typ, id
	return a, nil
}

// MustParse is Parse for constants and tests. It panics, so it must never see request input.
func MustParse(s string) ARN {
	a, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return a
}

// ValidateAccountID enforces exactly twelve decimal digits.
func ValidateAccountID(id string) error {
	if len(id) != AccountIDLen {
		return fmt.Errorf("%w: got %d chars in %q", ErrAccountID, len(id), id)
	}
	for i := 0; i < len(id); i++ {
		if id[i] < '0' || id[i] > '9' {
			return fmt.Errorf("%w: non-digit at %d in %q", ErrAccountID, i, id)
		}
	}
	return nil
}

// SameAccount reports whether two parsed ARNs belong to the same tenant.
//
// Exists so that the isolation check is one named call rather than a field comparison repeated at
// every call site — the one that gets forgotten is the cross-tenant leak.
func (a ARN) SameAccount(other ARN) bool { return a.Account == other.Account }
