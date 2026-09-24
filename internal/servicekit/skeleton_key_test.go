package servicekit

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"dariyanws/internal/capability"
	"dariyanws/internal/httpx"
)

// BREAK.md E4, after the fix.
//
// At M4.3 this file asserted that the breach HAPPENED: a helper that verified a signature and
// returned the capability let a service be written in nine obvious lines, and that service
// treated a token for function/a as permission to invoke function/b. The signature check was
// correct and irrelevant.
//
// M4.4 removed that helper. The tests below now assert the opposite, and the reason the fix is
// believed to work is not that a check was added — it is that the vulnerable service can no
// longer be expressed: Guard.Authorize cannot be called without stating which resource is being
// served, so there is nothing to forget.

const (
	accountID = "000000000001"
	otherAcct = "000000000002"
	functionA = "arn:dariya:func:hind-1:000000000001:function/a"
	functionB = "arn:dariya:func:hind-1:000000000001:function/b"
	queueOne  = "arn:dariya:kyu:hind-1:000000000001:queue/orders"
	principal = "arn:dariya:iam:hind-1:000000000001:user/root"
)

func testKeys(t *testing.T) (*capability.Minter, *capability.Verifier) {
	t.Helper()
	seed, pub, err := capability.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	m, err := capability.NewMinter("k1", seed, capability.DefaultTTL, time.Now)
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	return m, capability.NewVerifier(map[string]ed25519.PublicKey{"k1": pub}, time.Now)
}

func tokenFor(t *testing.T, m *capability.Minter, action, resourceARN, account string) string {
	t.Helper()
	token, err := m.Mint(capability.Claims{
		AccountID:    account,
		PrincipalARN: principal,
		Action:       action,
		ResourceARN:  resourceARN,
		RequestID:    "req-1",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	encoded, err := proto.Marshal(token)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return base64.StdEncoding.EncodeToString(encoded)
}

// service is now the shortest correct implementation, which is also the only one the API allows.
func service(g *Guard, servesFunction string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := g.Authorize(r, Intent{
			Action:       "func:Invoke",
			ResourceType: "function",
			ResourceID:   servesFunction,
		}); err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("invoked " + servesFunction))
	})
}

func request(t *testing.T, url, header string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("POST", url+"/invoke", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if header != "" {
		req.Header.Set(httpx.CapabilityHeader, header)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return resp
}

// E4, inverted. This is the test that was passing at M4.3 with the opposite assertion.
func TestSkeletonKeyIsClosed(t *testing.T) {
	m, v := testKeys(t)
	srv := httptest.NewServer(service(NewGuard(v, "func", "hind-1"), "b"))
	defer srv.Close()

	resp := request(t, srv.URL, tokenFor(t, m, "func:Invoke", functionA, accountID))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a capability for %s invoked %s: status = %d", functionA, functionB, resp.StatusCode)
	}
}

func TestTheRightCapabilityStillWorks(t *testing.T) {
	m, v := testKeys(t)
	srv := httptest.NewServer(service(NewGuard(v, "func", "hind-1"), "b"))
	defer srv.Close()

	resp := request(t, srv.URL, tokenFor(t, m, "func:Invoke", functionB, accountID))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a correct capability was refused: status = %d", resp.StatusCode)
	}
}

// Each check, exercised directly, so a failure names the rule that fired rather than just "403".
func TestAuthorizeChecks(t *testing.T) {
	m, v := testKeys(t)
	g := NewGuard(v, "func", "hind-1")

	cases := map[string]struct {
		header string
		intent Intent
		want   error
	}{
		"wrong resource": {
			tokenFor(t, m, "func:Invoke", functionA, accountID),
			Intent{Action: "func:Invoke", ResourceType: "function", ResourceID: "b"},
			ErrMismatch,
		},
		"wrong action": {
			tokenFor(t, m, "func:DeleteFunction", functionB, accountID),
			Intent{Action: "func:Invoke", ResourceType: "function", ResourceID: "b"},
			ErrMismatch,
		},
		// A kyu token presented to the func service: the guard assembles the expected ARN with
		// its OWN service segment, so it cannot be talked into honouring another service's
		// capability however the intent is written.
		"another service's resource": {
			tokenFor(t, m, "kyu:SendMessage", queueOne, accountID),
			Intent{Action: "kyu:SendMessage", ResourceType: "queue", ResourceID: "orders"},
			ErrMismatch,
		},
		// The account comes from the token, so a token for another account simply builds a
		// different expected ARN and fails to match.
		"another account's token": {
			tokenFor(t, m, "func:Invoke", functionB, otherAcct),
			Intent{Action: "func:Invoke", ResourceType: "function", ResourceID: "b"},
			ErrMismatch,
		},
		"no capability": {
			"",
			Intent{Action: "func:Invoke", ResourceType: "function", ResourceID: "b"},
			ErrNoCapability,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/invoke", nil)
			if c.header != "" {
				r.Header.Set(httpx.CapabilityHeader, c.header)
			}
			_, err := g.Authorize(r, c.intent)
			if !errors.Is(err, c.want) {
				t.Errorf("err = %v, want %v", err, c.want)
			}
		})
	}
}

// An intent that does not say what it is for must be refused rather than matched loosely.
func TestIncompleteIntentIsRefused(t *testing.T) {
	m, v := testKeys(t)
	g := NewGuard(v, "func", "hind-1")

	r := httptest.NewRequest("POST", "/invoke", nil)
	r.Header.Set(httpx.CapabilityHeader, tokenFor(t, m, "func:Invoke", functionB, accountID))

	for name, intent := range map[string]Intent{
		"no action":        {ResourceType: "function", ResourceID: "b"},
		"no resource type": {Action: "func:Invoke", ResourceID: "b"},
		"no resource id":   {Action: "func:Invoke", ResourceType: "function"},
		"empty":            {},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := g.Authorize(r, intent); err == nil {
				t.Error("an incomplete intent was accepted")
			}
		})
	}
}

// The controls from M4.3, kept: the fix must not have been achieved by breaking verification.
func TestStillRejectsTheObviousThings(t *testing.T) {
	m, v := testKeys(t)
	srv := httptest.NewServer(service(NewGuard(v, "func", "hind-1"), "b"))
	defer srv.Close()

	t.Run("no capability", func(t *testing.T) {
		resp := request(t, srv.URL, "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("forged capability", func(t *testing.T) {
		header := tokenFor(t, m, "func:Invoke", functionB, accountID)
		raw, _ := base64.StdEncoding.DecodeString(header)
		raw[len(raw)-1] ^= 0xff

		resp := request(t, srv.URL, base64.StdEncoding.EncodeToString(raw))
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("capability from another key", func(t *testing.T) {
		other, _ := testKeys(t)
		resp := request(t, srv.URL, tokenFor(t, other, "func:Invoke", functionB, accountID))
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})
}
