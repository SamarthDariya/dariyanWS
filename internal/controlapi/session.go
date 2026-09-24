package controlapi

import (
	"encoding/json"
	"net/http"
	"time"

	commonv1 "dariyanws/gen/dariya/common/v1"
	"dariyanws/internal/apierr"
	"dariyanws/internal/httpx"
	"dariyanws/internal/router"
	"dariyanws/internal/session"
)

// Console sign-in (DESIGN.md decision 12).
//
// SignInHandler is the only unauthenticated route in the system, and that is a hole rather than
// an exemption. It is mounted by the front door at an exact path, outside the authenticated
// chain, and it is the one place a secret arrives in a request body instead of being used to
// sign one. Before this is exposed beyond localhost it needs a rate limit; unit 7 is where that
// arrives, and until then the gap is written down rather than forgotten.

type signInRequest struct {
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
}

type signInResponse struct {
	AccountID    string `json:"accountId"`
	PrincipalARN string `json:"principalArn"`
	CSRFToken    string `json:"csrfToken"`
	ExpiresAt    int64  `json:"expiresAtUnixMs"`
}

// SignInHandler exchanges an access key pair for a session cookie.
func (a *API) SignInHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpx.WriteError(w, r, apierr.Validation("sign-in is a POST"), a.Dev)
			return
		}

		var req signInRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
			httpx.WriteError(w, r, apierr.Validation("the request body is not valid JSON"), a.Dev)
			return
		}

		token, s, err := a.Sessions.SignIn(r.Context(), session.Credentials{
			AccessKeyID:     req.AccessKeyID,
			SecretAccessKey: req.SecretAccessKey,
		})
		if err != nil {
			// One answer for an unknown key and a wrong secret, matching what the manager
			// already does in constant time. Anything else makes sign-in a key-id oracle.
			httpx.WriteError(w, r, &apierr.Error{
				Code:    apierr.CodeInvalidSig,
				Message: "the access key id or secret access key is incorrect",
			}, a.Dev)
			return
		}

		http.SetCookie(w, a.sessionCookie(token, s.ExpiresAt))

		// The CSRF token comes back in the body, not a cookie. A cookie would be sent
		// automatically by a forged request, which is the thing it exists to prevent; the
		// console holds this in memory and echoes it in a header.
		writeJSONValue(w, r, http.StatusOK, signInResponse{
			AccountID:    s.AccountID,
			PrincipalARN: s.PrincipalARN,
			CSRFToken:    s.CSRFToken,
			ExpiresAt:    s.ExpiresAt.UnixMilli(),
		})
	})
}

// sessionCookie builds the cookie.
//
// Secure is off in dev because local development is http and a Secure cookie would simply never
// be sent, presenting as "sign-in works and then nothing is authenticated". It is on everywhere
// else, and the flag that turns it off is the same one that already loosens error detail, so
// there is one switch to get wrong rather than two.
func (a *API) sessionCookie(token string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     session.CookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true, // script cannot read it, so an XSS cannot exfiltrate it
		Secure:   !a.Dev,
		SameSite: http.SameSiteStrictMode, // the primary CSRF defence
	}
}

func (a *API) clearedCookie() *http.Cookie {
	c := a.sessionCookie("", time.Unix(0, 0))
	c.MaxAge = -1
	return c
}

// SessionRoutes are the authenticated half: who am I, and sign me out.
func (a *API) sessionRoutes() []router.Route {
	self := func(_ *http.Request, p *commonv1.Principal) (string, error) {
		return "arn:dariya:iam:" + a.Region + ":" + p.GetAccountId() + ":account/" + p.GetAccountId(), nil
	}

	return []router.Route{
		{
			Service: Service, Method: "GET", Prefix: prefix("/session"),
			Action: "iam:GetSession", Resource: self,
			Handler: http.HandlerFunc(a.getSession),
		},
		{
			Service: Service, Method: "DELETE", Prefix: prefix("/session"),
			Action: "iam:DeleteSession", Resource: self,
			Handler: http.HandlerFunc(a.signOut),
		},
	}
}

// getSession is the console's "who am I". It works under either authentication scheme, which is
// the point of decision 12: the console and a signed API client see the same principal.
func (a *API) getSession(w http.ResponseWriter, r *http.Request) {
	p, err := principal(r)
	if err != nil {
		httpx.WriteError(w, r, err, a.Dev)
		return
	}

	writeJSONValue(w, r, http.StatusOK, map[string]string{
		"accountId":    p.GetAccountId(),
		"principalArn": p.GetPrincipalArn(),
	})
}

func (a *API) signOut(w http.ResponseWriter, r *http.Request) {
	// Whatever cookie was presented is destroyed, and the cookie is cleared regardless. A sign
	// out that leaves a working credential in the browser is a lie told to the person clicking
	// it — which is also why sessions are server-side rather than self-contained tokens.
	if cookie, err := r.Cookie(session.CookieName); err == nil {
		if err := a.Sessions.SignOut(r.Context(), cookie.Value); err != nil {
			httpx.WriteError(w, r, err, a.Dev)
			return
		}
	}

	http.SetCookie(w, a.clearedCookie())
	w.WriteHeader(http.StatusNoContent)
}

func writeJSONValue(w http.ResponseWriter, r *http.Request, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		_ = err // the status line is already out; nothing better is available
	}
}
