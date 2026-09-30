package servicekit

import (
	"errors"
	"net/http/httptest"
	"testing"

	"dariyanws/internal/httpx"
)

// M7.1: the account-scoped shape the second service needed (DESIGN.md decision 9).

const (
	chalaAccount      = "arn:dariya:chala:hind-1:000000000001:account/000000000001"
	chalaOtherAccount = "arn:dariya:chala:hind-1:000000000002:account/000000000002"
	chalaInstance     = "arn:dariya:chala:hind-1:000000000001:instance/web-1"
)

func TestAuthorizeAccount(t *testing.T) {
	m, v := testKeys(t)
	g := NewGuard(v, "chala", "hind-1")

	cases := map[string]struct {
		header string
		want   error
	}{
		"own account": {
			tokenFor(t, m, "chala:DescribeInstances", chalaAccount, accountID), nil,
		},
		"wrong action": {
			tokenFor(t, m, "chala:RunInstance", chalaAccount, accountID), ErrMismatch,
		},
		// A token for one instance is not a token for the whole account. Without this the
		// account shape would be a way to widen any capability into a listing.
		"a named resource instead": {
			tokenFor(t, m, "chala:DescribeInstances", chalaInstance, accountID), ErrMismatch,
		},
		// The token's own account and its resource disagree. The front door never mints this;
		// the check exists for the day it does.
		"resource names another account": {
			tokenFor(t, m, "chala:DescribeInstances", chalaOtherAccount, accountID), ErrMismatch,
		},
		"another service's account resource": {
			tokenFor(t, m, "chala:DescribeInstances",
				"arn:dariya:func:hind-1:000000000001:account/000000000001", accountID),
			ErrMismatch,
		},
		"no capability": {"", ErrNoCapability},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/instances", nil)
			if c.header != "" {
				r.Header.Set(httpx.CapabilityHeader, c.header)
			}
			got, err := g.AuthorizeAccount(r, "chala:DescribeInstances")
			if c.want == nil {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if got.GetAccountId() != accountID {
					t.Fatalf("account = %q", got.GetAccountId())
				}
				return
			}
			if !errors.Is(err, c.want) {
				t.Errorf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func TestAuthorizeAccountWithoutAnActionIsRefused(t *testing.T) {
	m, v := testKeys(t)
	g := NewGuard(v, "chala", "hind-1")

	r := httptest.NewRequest("GET", "/instances", nil)
	r.Header.Set(httpx.CapabilityHeader,
		tokenFor(t, m, "chala:DescribeInstances", chalaAccount, accountID))

	if _, err := g.AuthorizeAccount(r, ""); err == nil {
		t.Fatal("an empty action was accepted")
	}
}
