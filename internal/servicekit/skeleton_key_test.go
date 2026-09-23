package servicekit

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"dariyanws/internal/capability"
	"dariyanws/internal/httpx"
)

// BREAK.md E4, planted deliberately.
//
// A service that verifies the capability's signature correctly and ignores its resource_arn turns
// any valid token into a skeleton key for that service. The prediction written before this code
// existed was: "the naive helper signature makes the bug easy to write."
//
// The test below asserts that the breach HAPPENS. That is not a mistake — it is the experiment.
// M4.4 changes the API so the same service cannot be written, and inverts this test.

const (
	accountID = "000000000001"
	functionA = "arn:dariya:func:hind-1:000000000001:function/a"
	functionB = "arn:dariya:func:hind-1:000000000001:function/b"
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

func tokenFor(t *testing.T, m *capability.Minter, resourceARN string) string {
	t.Helper()
	token, err := m.Mint(capability.Claims{
		AccountID:    accountID,
		PrincipalARN: principal,
		Action:       "func:Invoke",
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

// naiveService is how a service author would plausibly write this against the M4.3 API: verify
// the capability, then serve the request. It never compares the two.
//
// Note what is NOT wrong with it. The signature check is correct. The expiry check is correct. It
// rejects forged and unsigned requests. Every individual thing it does, it does right.
func naiveService(v *capability.Verifier, servesResourceARN string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap, err := Authenticate(r, v)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// The service knows which resource it is about to act on. It simply never checks that
		// the capability is for that one.
		_ = cap
		_ = servesResourceARN

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("invoked " + servesResourceARN))
	})
}

// E4: a token for function/a invokes function/b.
func TestSkeletonKey(t *testing.T) {
	m, v := testKeys(t)

	// A service that serves function/b, and a caller holding a capability only for function/a.
	srv := httptest.NewServer(naiveService(v, functionB))
	defer srv.Close()

	req, err := http.NewRequest("POST", srv.URL+"/invoke", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set(httpx.CapabilityHeader, tokenFor(t, m, functionA))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the skeleton key did not work, status = %d — if this now fails, M4.4 landed "+
			"and this test should have been inverted with it", resp.StatusCode)
	}

	t.Log("E4 CONFIRMED: a capability minted for " + functionA + " successfully invoked " +
		functionB + ". The signature check was correct and irrelevant.")
}

// The controls, so the finding is about the missing comparison and not about the verifier being
// broken in some more boring way.
func TestNaiveServiceStillRejectsTheObviousThings(t *testing.T) {
	m, v := testKeys(t)
	srv := httptest.NewServer(naiveService(v, functionB))
	defer srv.Close()

	t.Run("no capability", func(t *testing.T) {
		resp, err := http.Post(srv.URL+"/invoke", "", nil)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("forged capability", func(t *testing.T) {
		header := tokenFor(t, m, functionB)
		raw, _ := base64.StdEncoding.DecodeString(header)
		raw[len(raw)-1] ^= 0xff // break the signature

		req, _ := http.NewRequest("POST", srv.URL+"/invoke", nil)
		req.Header.Set(httpx.CapabilityHeader, base64.StdEncoding.EncodeToString(raw))

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("capability from another key", func(t *testing.T) {
		otherMinter, _ := testKeys(t)

		req, _ := http.NewRequest("POST", srv.URL+"/invoke", nil)
		req.Header.Set(httpx.CapabilityHeader, tokenFor(t, otherMinter, functionB))

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})
}
