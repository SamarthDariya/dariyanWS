package controlapi_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"

	"dariyanws/internal/controlapi"
	"dariyanws/internal/session"
)

// The console's whole authentication story, exercised the way a browser will: sign in with an
// access key pair once, then carry a cookie.

type console struct {
	client *http.Client
	base   string
	csrf   string
}

func (rg *region_) console(t *testing.T, accessKeyID, secret string) (*console, *http.Response) {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	c := &console{client: &http.Client{Jar: jar}, base: rg.server.URL}

	body := `{"accessKeyId":"` + accessKeyID + `","secretAccessKey":"` + secret + `"}`
	resp, err := c.client.Post(rg.server.URL+controlapi.SignInPath, "application/json",
		strings.NewReader(body))
	if err != nil {
		t.Fatalf("sign-in: %v", err)
	}

	if resp.StatusCode == http.StatusOK {
		var out struct {
			CSRFToken string `json:"csrfToken"`
		}
		raw, _ := io.ReadAll(resp.Body)
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("sign-in response is not JSON: %s", raw)
		}
		c.csrf = out.CSRFToken
		resp.Body = io.NopCloser(strings.NewReader(string(raw)))
	}
	return c, resp
}

func (c *console) do(t *testing.T, method, path, body string, withCSRF bool) *http.Response {
	t.Helper()

	req, err := http.NewRequest(method, c.base+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if withCSRF {
		req.Header.Set(session.CSRFHeader, c.csrf)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return resp
}

func TestConsoleSignInAndUse(t *testing.T) {
	rg := newRegion(t)
	id, cred := rg.admin(t)

	c, signIn := rg.console(t, cred.AccessKeyID, string(cred.Secret))
	defer signIn.Body.Close()

	if signIn.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(signIn.Body)
		t.Fatalf("sign-in status = %d, body = %s", signIn.StatusCode, body)
	}
	if c.csrf == "" {
		t.Fatal("sign-in returned no CSRF token")
	}

	// The cookie a browser will carry: unreadable by script, and not sent cross-site.
	var found *http.Cookie
	for _, cookie := range signIn.Cookies() {
		if cookie.Name == session.CookieName {
			found = cookie
		}
	}
	if found == nil {
		t.Fatal("no session cookie was set")
	}
	if !found.HttpOnly {
		t.Error("the session cookie is readable by script")
	}
	if found.SameSite != http.SameSiteStrictMode {
		t.Error("the session cookie is not SameSite=Strict")
	}

	// A read, with no signature anywhere.
	resp := c.do(t, "GET", "/2026-09-01/account", "", false)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /account status = %d, body = %s", resp.StatusCode, body)
	}
	if got := decode(t, resp)["accountId"]; got != id {
		t.Errorf("accountId = %v, want %s", got, id)
	}

	// And whoami, which is the same principal a signed client would see.
	who := c.do(t, "GET", "/2026-09-01/session", "", false)
	defer who.Body.Close()
	if who.StatusCode != http.StatusOK {
		t.Fatalf("GET /session status = %d", who.StatusCode)
	}
}

// The CSRF token is required on anything that changes state, and is not in a cookie — a forged
// request carries the cookie automatically and cannot read the token.
func TestMutationRequiresTheCSRFToken(t *testing.T) {
	rg := newRegion(t)
	_, cred := rg.admin(t)

	c, signIn := rg.console(t, cred.AccessKeyID, string(cred.Secret))
	signIn.Body.Close()

	without := c.do(t, "POST", "/2026-09-01/access-keys", `{}`, false)
	defer without.Body.Close()
	if without.StatusCode != http.StatusUnauthorized {
		t.Errorf("a mutation without a CSRF token: status = %d, want 401", without.StatusCode)
	}

	with := c.do(t, "POST", "/2026-09-01/access-keys", `{}`, true)
	defer with.Body.Close()
	if with.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(with.Body)
		t.Errorf("a mutation with a CSRF token: status = %d, body = %s", with.StatusCode, body)
	}

	// A read does not need it, or every page load would.
	read := c.do(t, "GET", "/2026-09-01/access-keys", "", false)
	defer read.Body.Close()
	if read.StatusCode != http.StatusOK {
		t.Errorf("a read with no CSRF token: status = %d, want 200", read.StatusCode)
	}
}

// Sign out has to actually sign out. A session that keeps working is a lie told to the person
// who clicked it, and is the reason sessions are server-side rather than self-contained.
func TestSignOutRevokesImmediately(t *testing.T) {
	rg := newRegion(t)
	_, cred := rg.admin(t)

	c, signIn := rg.console(t, cred.AccessKeyID, string(cred.Secret))
	signIn.Body.Close()

	ok := c.do(t, "GET", "/2026-09-01/account", "", false)
	ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("before sign-out: status = %d", ok.StatusCode)
	}

	out := c.do(t, "DELETE", "/2026-09-01/session", "", true)
	out.Body.Close()
	if out.StatusCode != http.StatusNoContent {
		t.Fatalf("sign-out status = %d, want 204", out.StatusCode)
	}

	// The cookie the browser still holds is now worthless, which is the property being tested —
	// not merely that the cookie was cleared.
	after := c.do(t, "GET", "/2026-09-01/account", "", false)
	defer after.Body.Close()
	if after.StatusCode != http.StatusUnauthorized {
		t.Errorf("after sign-out: status = %d, want 401", after.StatusCode)
	}
}

// An unknown key and a wrong secret answer identically, or sign-in becomes a key-id oracle.
func TestBadSignInIsIndistinguishable(t *testing.T) {
	rg := newRegion(t)
	_, cred := rg.admin(t)

	_, wrongSecret := rg.console(t, cred.AccessKeyID, "not-the-secret")
	defer wrongSecret.Body.Close()
	wrongBody, _ := io.ReadAll(wrongSecret.Body)

	_, unknownKey := rg.console(t, "DARIYAKEYDOESNOTEXISTAAAA", "whatever")
	defer unknownKey.Body.Close()
	unknownBody, _ := io.ReadAll(unknownKey.Body)

	if wrongSecret.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong secret: status = %d, want 401", wrongSecret.StatusCode)
	}
	if unknownKey.StatusCode != wrongSecret.StatusCode {
		t.Errorf("statuses differ: %d vs %d", unknownKey.StatusCode, wrongSecret.StatusCode)
	}
	if stripRequestID(t, string(wrongBody)) != stripRequestID(t, string(unknownBody)) {
		t.Errorf("responses differ:\n %s\n %s", wrongBody, unknownBody)
	}
}

// A session grants exactly what the principal already had, and nothing more. It is an envelope
// around a credential, not a new tier of one.
func TestSessionGrantsNoMoreThanTheKeyDid(t *testing.T) {
	rg := newRegion(t)

	// An account with credentials but no policy.
	acct, cred := rg.bare(t)
	_ = acct

	c, signIn := rg.console(t, cred.AccessKeyID, string(cred.Secret))
	signIn.Body.Close()
	if signIn.StatusCode != http.StatusOK {
		t.Fatalf("sign-in status = %d — a key with no policy must still be able to sign in",
			signIn.StatusCode)
	}

	resp := c.do(t, "GET", "/2026-09-01/account", "", false)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403: the session inherited permissions the key did not have",
			resp.StatusCode)
	}
}

func stripRequestID(t *testing.T, body string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("not JSON: %s", body)
	}
	delete(m, "request_id")
	out, _ := json.Marshal(m)
	return string(out)
}
