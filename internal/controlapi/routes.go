package controlapi

import (
	"fmt"
	"net/http"

	commonv1 "dariyanws/gen/dariya/common/v1"
	controlv1 "dariyanws/gen/dariya/control/v1"
	iamv1 "dariyanws/gen/dariya/iam/v1"
	"dariyanws/internal/apierr"
	"dariyanws/internal/httpx"
	"dariyanws/internal/iam"
	"dariyanws/internal/router"
)

// APIVersion dates the API surface, as AWS does.
//
// In the path rather than a header so a breaking change is visible in a log line and in a curl
// command, and so two versions can be served side by side by two routes rather than by branching
// inside a handler.
const APIVersion = "2026-09-01"

// Service is the ARN service segment these routes belong to, and therefore what a signature must
// be scoped to in order to reach them.
const Service = "iam"

func prefix(suffix string) string { return "/" + APIVersion + suffix }

// Routes returns the control plane's own routes, for the front door's table.
//
// Every route names its action here, beside the handler that serves it, so the permission and the
// implementation cannot drift apart into two lists.
func (a *API) Routes() []router.Route {
	region := a.Region

	// selfAccount is the resource for operations on the caller's own account. The id comes from
	// the principal, so there is no path that could name another.
	selfAccount := func(_ *http.Request, p *commonv1.Principal) (string, error) {
		return fmt.Sprintf("arn:dariya:iam:%s:%s:account/%s",
			region, p.GetAccountId(), p.GetAccountId()), nil
	}

	routes := []router.Route{
		{
			Service: Service, Method: "GET", Prefix: prefix("/account"),
			Action: "iam:GetAccount", Resource: selfAccount,
			Handler: http.HandlerFunc(a.getAccount),
		},

		// Access keys.
		{
			Service: Service, Method: "POST", Prefix: prefix("/access-keys"),
			// Creating a key acts on the account, because there is no key yet to name.
			Action: "iam:CreateAccessKey", Resource: selfAccount,
			Handler: http.HandlerFunc(a.createAccessKey),
		},
		{
			Service: Service, Method: "GET", Prefix: prefix("/access-keys"),
			Action: "iam:ListAccessKeys", Resource: selfAccount,
			Handler: http.HandlerFunc(a.listAccessKeys),
		},
		{
			// The trailing slash is what distinguishes this from the collection above; longest
			// prefix wins, so ordering in this slice does not matter.
			Service: Service, Method: "DELETE", Prefix: prefix("/access-keys/"),
			Action:   "iam:DeleteAccessKey",
			Resource: router.PathResource(region, "iam", "access-key", prefix("/access-keys/")),
			Handler:  http.HandlerFunc(a.deleteAccessKey),
		},

		// Policies.
		{
			Service: Service, Method: "GET", Prefix: prefix("/policies"),
			Action: "iam:ListPolicies", Resource: selfAccount,
			Handler: http.HandlerFunc(a.listPolicies),
		},
		{
			// PUT rather than POST, with the name in the path, because the router builds the
			// resource ARN from the path. A name that arrived in the body could not be
			// authorized before being read, which would mean authorizing against a resource the
			// handler had not yet decided on.
			Service: Service, Method: "PUT", Prefix: prefix("/policies/"),
			Action:   "iam:CreatePolicy",
			Resource: router.PathResource(region, "iam", "policy", prefix("/policies/")),
			Handler:  http.HandlerFunc(a.createPolicy),
		},
		{
			Service: Service, Method: "GET", Prefix: prefix("/policies/"),
			Action:   "iam:GetPolicy",
			Resource: router.PathResource(region, "iam", "policy", prefix("/policies/")),
			Handler:  http.HandlerFunc(a.getPolicy),
		},
		{
			Service: Service, Method: "DELETE", Prefix: prefix("/policies/"),
			Action:   "iam:DeletePolicy",
			Resource: router.PathResource(region, "iam", "policy", prefix("/policies/")),
			Handler:  http.HandlerFunc(a.deletePolicy),
		},
		{
			// Attach and detach are POSTs to sub-collections rather than PUT/DELETE on a
			// membership URL, because the membership is identified by a principal ARN and
			// putting an ARN in a path means encoding colons and slashes into it.
			Service: Service, Method: "POST", Prefix: prefix("/policies/"),
			Action:   "iam:AttachPolicy",
			Resource: router.PathResource(region, "iam", "policy", prefix("/policies/")),
			Handler:  http.HandlerFunc(a.attachOrDetach),
		},
	}

	return append(routes, a.sessionRoutes()...)
}

// ---------------------------------------------------------------------------
// Accounts and access keys
// ---------------------------------------------------------------------------

func (a *API) getAccount(w http.ResponseWriter, r *http.Request) {
	p, err := principal(r)
	if err != nil {
		httpx.WriteError(w, r, err, a.Dev)
		return
	}

	resp, err := a.Accounts.GetAccount(r.Context(),
		&controlv1.GetAccountRequest{AccountId: p.GetAccountId()})
	if err != nil {
		httpx.WriteError(w, r, err, a.Dev)
		return
	}
	writeProto(w, r, http.StatusOK, resp.GetAccount())
}

func (a *API) createAccessKey(w http.ResponseWriter, r *http.Request) {
	p, err := principal(r)
	if err != nil {
		httpx.WriteError(w, r, err, a.Dev)
		return
	}

	var req controlv1.CreateAccessKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err, a.Dev)
		return
	}

	// The account is overwritten, not validated. A client that sent one is ignored rather than
	// rejected, because there is no legitimate reason to send it and no harm in the field
	// existing — but there must be no path by which it is honoured.
	req.AccountId = p.GetAccountId()

	resp, err := a.Accounts.CreateAccessKey(r.Context(), &req)
	if err != nil {
		httpx.WriteError(w, r, err, a.Dev)
		return
	}

	// 201, and the only response in the whole API that contains a secret.
	writeProto(w, r, http.StatusCreated, resp.GetAccessKey())
}

func (a *API) listAccessKeys(w http.ResponseWriter, r *http.Request) {
	p, err := principal(r)
	if err != nil {
		httpx.WriteError(w, r, err, a.Dev)
		return
	}
	page, err := pageParams(r)
	if err != nil {
		httpx.WriteError(w, r, err, a.Dev)
		return
	}

	resp, err := a.Accounts.ListAccessKeys(r.Context(), &controlv1.ListAccessKeysRequest{
		AccountId: p.GetAccountId(),
		Page:      page,
	})
	if err != nil {
		httpx.WriteError(w, r, err, a.Dev)
		return
	}
	writeProto(w, r, http.StatusOK, resp)
}

func (a *API) deleteAccessKey(w http.ResponseWriter, r *http.Request) {
	keyID := pathSegment(r.URL.Path, prefix("/access-keys/"), 0)
	if keyID == "" {
		httpx.WriteError(w, r, apierr.Validation("the path does not name an access key"), a.Dev)
		return
	}

	// Authorization already confirmed the caller may act on this access key id, because the
	// router built the resource ARN from this same path segment. The handler does not re-check
	// ownership: doing so would be a second, subtly different rule, and the one that disagreed
	// would be the one nobody noticed.
	if _, err := a.Accounts.DeleteAccessKey(r.Context(),
		&controlv1.DeleteAccessKeyRequest{AccessKeyId: keyID}); err != nil {
		httpx.WriteError(w, r, err, a.Dev)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

func (a *API) createPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := principal(r)
	if err != nil {
		httpx.WriteError(w, r, err, a.Dev)
		return
	}
	name := pathSegment(r.URL.Path, prefix("/policies/"), 0)
	if name == "" {
		httpx.WriteError(w, r, apierr.Validation("the path does not name a policy"), a.Dev)
		return
	}

	var req iamv1.CreatePolicyRequest
	if err := decodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err, a.Dev)
		return
	}
	req.AccountId = p.GetAccountId()
	req.Name = name // the path is authoritative; it is what was authorized

	resp, err := a.Policies.CreatePolicy(r.Context(), &req)
	if err != nil {
		httpx.WriteError(w, r, err, a.Dev)
		return
	}
	writeProto(w, r, http.StatusCreated, resp.GetPolicy())
}

func (a *API) getPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := principal(r)
	if err != nil {
		httpx.WriteError(w, r, err, a.Dev)
		return
	}
	name := pathSegment(r.URL.Path, prefix("/policies/"), 0)

	resp, err := a.Policies.GetPolicy(r.Context(), &iamv1.GetPolicyRequest{
		PolicyArn: iam.PolicyARN(a.Region, p.GetAccountId(), name),
	})
	if err != nil {
		httpx.WriteError(w, r, err, a.Dev)
		return
	}
	writeProto(w, r, http.StatusOK, resp.GetPolicy())
}

func (a *API) listPolicies(w http.ResponseWriter, r *http.Request) {
	p, err := principal(r)
	if err != nil {
		httpx.WriteError(w, r, err, a.Dev)
		return
	}
	page, err := pageParams(r)
	if err != nil {
		httpx.WriteError(w, r, err, a.Dev)
		return
	}

	resp, err := a.Policies.ListPolicies(r.Context(), &iamv1.ListPoliciesRequest{
		AccountId: p.GetAccountId(),
		Page:      page,
	})
	if err != nil {
		httpx.WriteError(w, r, err, a.Dev)
		return
	}
	writeProto(w, r, http.StatusOK, resp)
}

func (a *API) deletePolicy(w http.ResponseWriter, r *http.Request) {
	p, err := principal(r)
	if err != nil {
		httpx.WriteError(w, r, err, a.Dev)
		return
	}
	name := pathSegment(r.URL.Path, prefix("/policies/"), 0)

	if _, err := a.Policies.DeletePolicy(r.Context(), &iamv1.DeletePolicyRequest{
		PolicyArn: iam.PolicyARN(a.Region, p.GetAccountId(), name),
	}); err != nil {
		httpx.WriteError(w, r, err, a.Dev)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// attachOrDetach serves both /policies/{name}/attachments and /detachments.
//
// One route and one handler because the router authorizes on the policy, which is the same
// resource for both — and because iam:AttachPolicy and iam:DetachPolicy differing by sub-path
// would mean the route table said one thing and the handler did another.
func (a *API) attachOrDetach(w http.ResponseWriter, r *http.Request) {
	p, err := principal(r)
	if err != nil {
		httpx.WriteError(w, r, err, a.Dev)
		return
	}

	name := pathSegment(r.URL.Path, prefix("/policies/"), 0)
	action := pathSegment(r.URL.Path, prefix("/policies/"), 1)
	policyARN := iam.PolicyARN(a.Region, p.GetAccountId(), name)

	var body iamv1.AttachPolicyRequest
	if err := decodeJSON(r, &body); err != nil {
		httpx.WriteError(w, r, err, a.Dev)
		return
	}
	if body.GetPrincipalArn() == "" {
		httpx.WriteError(w, r, apierr.Validation("principal_arn is required"), a.Dev)
		return
	}

	switch action {
	case "attachments":
		_, err = a.Policies.AttachPolicy(r.Context(), &iamv1.AttachPolicyRequest{
			PolicyArn: policyARN, PrincipalArn: body.GetPrincipalArn(),
		})
	case "detachments":
		_, err = a.Policies.DetachPolicy(r.Context(), &iamv1.DetachPolicyRequest{
			PolicyArn: policyARN, PrincipalArn: body.GetPrincipalArn(),
		})
	default:
		httpx.WriteError(w, r,
			apierr.NotFound("no such operation on a policy: %q", action), a.Dev)
		return
	}

	if err != nil {
		httpx.WriteError(w, r, err, a.Dev)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
