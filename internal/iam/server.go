package iam

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/protobuf/encoding/protojson"

	commonv1 "dariyanws/gen/dariya/common/v1"
	iamv1 "dariyanws/gen/dariya/iam/v1"
	"dariyanws/internal/apierr"
	"dariyanws/internal/arn"
	"dariyanws/internal/page"
	"dariyanws/internal/store"
)

const pgUniqueViolation = "23505"

// DocumentVersion is stamped on policies that arrive without one.
//
// Dated, as AWS does it, so the evaluation rules themselves can change later without silently
// reinterpreting policies written against the old ones.
const DocumentVersion = "2026-09-01"

// Server implements iamv1.IamServiceServer.
type Server struct {
	iamv1.UnimplementedIamServiceServer

	store  *store.Store
	region string
	now    func() time.Time

	// onPrincipalChanged lets a policy cache drop a principal the moment its permissions change.
	// Without it an attach would take up to the cache TTL to have any effect, which makes
	// granting access feel broken and revoking it dangerous.
	onPrincipalChanged func(principalARN string)
}

func NewServer(st *store.Store, region string, now func() time.Time) *Server {
	if now == nil {
		now = time.Now
	}
	return &Server{store: st, region: region, now: now}
}

// PolicyARN builds the deterministic name for a policy.
// OnPrincipalChanged registers a callback fired after any change to what a principal may do.
func (s *Server) OnPrincipalChanged(fn func(principalARN string)) { s.onPrincipalChanged = fn }

func (s *Server) principalChanged(principalARN string) {
	if s.onPrincipalChanged != nil {
		s.onPrincipalChanged(principalARN)
	}
}

func PolicyARN(region, accountID, name string) string {
	return fmt.Sprintf("arn:dariya:iam:%s:%s:policy/%s", region, accountID, name)
}

func (s *Server) CreatePolicy(ctx context.Context, req *iamv1.CreatePolicyRequest) (*iamv1.CreatePolicyResponse, error) {
	if err := arn.ValidateAccountID(req.GetAccountId()); err != nil {
		return nil, apierr.Validation("account_id must be 12 digits")
	}
	if err := validateName(req.GetName()); err != nil {
		return nil, err
	}

	doc := req.GetDocument()
	if err := ValidateDocument(doc); err != nil {
		// Rejected at write time rather than at evaluation time: a statement that can never match
		// reads like a grant, and is found during an incident by someone who believes it is
		// doing something.
		return nil, apierr.Validation("%v", err)
	}
	if doc.GetVersion() == "" {
		doc.Version = DocumentVersion
	}

	encoded, err := protojson.Marshal(doc)
	if err != nil {
		return nil, apierr.Internal(err, "could not encode the policy document")
	}

	policyARN := PolicyARN(s.region, req.GetAccountId(), req.GetName())
	nowMS := s.now().UnixMilli()

	tx, err := s.store.Pool().Begin(ctx)
	if err != nil {
		return nil, apierr.Internal(err, "could not begin transaction")
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// The idempotency token is claimed BEFORE the policy is inserted, and the order is not
	// cosmetic. A policy ARN is derived from its name, so a retry collides on the name; if the
	// insert went first, every retry would surface as AlreadyExists and the token would never be
	// consulted. Claiming the token first makes a retry a replay and a genuine duplicate name a
	// conflict, which are different things that otherwise look identical.
	if token := req.GetClientToken(); token != "" {
		tag, err := tx.Exec(ctx,
			`INSERT INTO idempotency (operation, client_token, result_id, created_at_ms)
			 VALUES ('CreatePolicy', $1, $2, $3) ON CONFLICT DO NOTHING`,
			token, policyARN, nowMS)
		if err != nil {
			return nil, apierr.Internal(err, "could not record idempotency token")
		}
		if tag.RowsAffected() == 0 {
			// A retry. Unlike a created access key there is no secret involved, so the original
			// can simply be returned.
			_ = tx.Rollback(ctx)

			var priorARN string
			if err := s.store.Pool().QueryRow(ctx,
				`SELECT result_id FROM idempotency WHERE operation='CreatePolicy' AND client_token=$1`,
				token).Scan(&priorARN); err != nil {
				return nil, apierr.Internal(err, "could not read idempotency token")
			}
			prior, err := s.getPolicy(ctx, priorARN)
			if err != nil {
				return nil, err
			}
			return &iamv1.CreatePolicyResponse{Policy: prior}, nil
		}
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO policies (policy_arn, account_id, name, document, created_at_ms)
		 VALUES ($1,$2,$3,$4,$5)`,
		policyARN, req.GetAccountId(), req.GetName(), encoded, nowMS); err != nil {
		if isUniqueViolation(err) {
			// A duplicate name is a duplicate ARN. Reported as a conflict rather than silently
			// updating: an upsert here would let a retry carrying a different document quietly
			// replace a policy somebody else wrote.
			return nil, apierr.AlreadyExists("account %s already has a policy named %q",
				req.GetAccountId(), req.GetName())
		}
		return nil, apierr.Internal(err, "could not store the policy")
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, apierr.Internal(err, "could not commit the policy")
	}

	return &iamv1.CreatePolicyResponse{Policy: &iamv1.Policy{
		PolicyArn:       policyARN,
		AccountId:       req.GetAccountId(),
		Name:            req.GetName(),
		Document:        doc,
		CreatedAtUnixMs: nowMS,
	}}, nil
}

func (s *Server) GetPolicy(ctx context.Context, req *iamv1.GetPolicyRequest) (*iamv1.GetPolicyResponse, error) {
	p, err := s.getPolicy(ctx, req.GetPolicyArn())
	if err != nil {
		return nil, err
	}
	return &iamv1.GetPolicyResponse{Policy: p}, nil
}

func (s *Server) ListPolicies(ctx context.Context, req *iamv1.ListPoliciesRequest) (*iamv1.ListPoliciesResponse, error) {
	if err := arn.ValidateAccountID(req.GetAccountId()); err != nil {
		return nil, apierr.Validation("account_id must be 12 digits")
	}
	limit, err := page.Limit(req.GetPage().GetMaxResults())
	if err != nil {
		return nil, err
	}
	after, err := page.Decode(req.GetPage().GetNextToken())
	if err != nil {
		return nil, err
	}

	rows, err := s.store.Pool().Query(ctx,
		`SELECT policy_arn, account_id, name, document, created_at_ms
		   FROM policies
		  WHERE account_id = $1 AND policy_arn > $2
		  ORDER BY policy_arn
		  LIMIT $3`, req.GetAccountId(), after, limit+1)
	if err != nil {
		return nil, apierr.Internal(err, "could not list policies")
	}
	defer rows.Close()

	resp := &iamv1.ListPoliciesResponse{Page: &commonv1.PageResponse{}}
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		resp.Policies = append(resp.Policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.Internal(err, "could not read policies")
	}

	if len(resp.Policies) > limit {
		resp.Policies = resp.Policies[:limit]
		resp.Page.NextToken = page.Encode(resp.Policies[limit-1].GetPolicyArn())
	}
	return resp, nil
}

// DeletePolicy removes the policy and, by cascade, every attachment of it.
//
// The cascade is the point: a policy deleted while still attached must not leave rows that grant
// nothing but look like they grant something, and must not require the caller to detach first —
// a two-step revocation is a revocation that gets half done.
func (s *Server) DeletePolicy(ctx context.Context, req *iamv1.DeletePolicyRequest) (*iamv1.DeletePolicyResponse, error) {
	// Who is affected has to be read BEFORE the delete, because the cascade destroys the evidence.
	// Reading it afterwards would find nothing and leave every affected principal holding cached
	// permissions from a policy that no longer exists — the exact case where a stale cache is
	// most dangerous.
	affected, err := s.principalsAttachedTo(ctx, req.GetPolicyArn())
	if err != nil {
		return nil, err
	}

	tag, err := s.store.Pool().Exec(ctx, `DELETE FROM policies WHERE policy_arn = $1`, req.GetPolicyArn())
	if err != nil {
		return nil, apierr.Internal(err, "could not delete the policy")
	}
	if tag.RowsAffected() == 0 {
		return nil, apierr.NotFound("no policy %s", req.GetPolicyArn())
	}

	for _, principalARN := range affected {
		s.principalChanged(principalARN)
	}
	return &iamv1.DeletePolicyResponse{}, nil
}

func (s *Server) principalsAttachedTo(ctx context.Context, policyARN string) ([]string, error) {
	rows, err := s.store.Pool().Query(ctx,
		`SELECT principal_arn FROM policy_attachments WHERE policy_arn = $1`, policyARN)
	if err != nil {
		return nil, apierr.Internal(err, "could not read policy attachments")
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var principalARN string
		if err := rows.Scan(&principalARN); err != nil {
			return nil, apierr.Internal(err, "could not scan a policy attachment")
		}
		out = append(out, principalARN)
	}
	return out, rows.Err()
}

// AttachPolicy binds a policy to a principal.
//
// Both must belong to the same account. Without that check a policy in account A could be
// attached to a principal in account B, which is a cross-tenant privilege grant performed by an
// API that looks like bookkeeping.
func (s *Server) AttachPolicy(ctx context.Context, req *iamv1.AttachPolicyRequest) (*iamv1.AttachPolicyResponse, error) {
	policy, err := s.getPolicy(ctx, req.GetPolicyArn())
	if err != nil {
		return nil, err
	}

	principal, err := arn.Parse(req.GetPrincipalArn())
	if err != nil {
		return nil, apierr.Validation("principal_arn is not a valid ARN: %v", err)
	}
	if principal.Service != "iam" || (principal.Type != "user" && principal.Type != "role") {
		return nil, apierr.Validation("principal_arn must name an iam user or role")
	}
	if principal.Account != policy.GetAccountId() {
		return nil, apierr.Validation(
			"policy belongs to account %s and principal to account %s; a policy cannot be "+
				"attached across accounts", policy.GetAccountId(), principal.Account)
	}

	// Idempotent by nature: attaching twice is the same state as attaching once, so a retry is
	// not an error.
	if _, err := s.store.Pool().Exec(ctx,
		`INSERT INTO policy_attachments (policy_arn, principal_arn, attached_at_ms)
		 VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
		req.GetPolicyArn(), req.GetPrincipalArn(), s.now().UnixMilli()); err != nil {
		return nil, apierr.Internal(err, "could not attach the policy")
	}
	s.principalChanged(req.GetPrincipalArn())
	return &iamv1.AttachPolicyResponse{}, nil
}

// DetachPolicy is a NotFound when there was nothing attached.
//
// Deliberately not silently successful: someone detaching a policy is usually revoking access,
// and "it was already gone" and "you detached the wrong thing" must not look identical.
func (s *Server) DetachPolicy(ctx context.Context, req *iamv1.DetachPolicyRequest) (*iamv1.DetachPolicyResponse, error) {
	tag, err := s.store.Pool().Exec(ctx,
		`DELETE FROM policy_attachments WHERE policy_arn = $1 AND principal_arn = $2`,
		req.GetPolicyArn(), req.GetPrincipalArn())
	if err != nil {
		return nil, apierr.Internal(err, "could not detach the policy")
	}
	if tag.RowsAffected() == 0 {
		return nil, apierr.NotFound("policy %s is not attached to %s",
			req.GetPolicyArn(), req.GetPrincipalArn())
	}
	s.principalChanged(req.GetPrincipalArn())
	return &iamv1.DetachPolicyResponse{}, nil
}

// PoliciesFor returns every policy attached to a principal, which is the authorisation hot path.
func (s *Server) PoliciesFor(ctx context.Context, principalARN string) ([]AttachedPolicy, error) {
	rows, err := s.store.Pool().Query(ctx,
		`SELECT p.policy_arn, p.document
		   FROM policy_attachments a
		   JOIN policies p ON p.policy_arn = a.policy_arn
		  WHERE a.principal_arn = $1
		  ORDER BY p.policy_arn`, principalARN)
	if err != nil {
		return nil, apierr.Internal(err, "could not read attached policies")
	}
	defer rows.Close()

	var out []AttachedPolicy
	for rows.Next() {
		var policyARN string
		var encoded []byte
		if err := rows.Scan(&policyARN, &encoded); err != nil {
			return nil, apierr.Internal(err, "could not scan an attached policy")
		}
		doc := &iamv1.PolicyDocument{}
		if err := protojson.Unmarshal(encoded, doc); err != nil {
			// A policy that will not decode must not be skipped quietly. Skipping it would
			// silently drop a Deny, which turns a corrupt row into an authorisation bypass.
			return nil, apierr.Internal(err, "policy %s could not be decoded", policyARN)
		}
		out = append(out, AttachedPolicy{PolicyARN: policyARN, Document: doc})
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.Internal(err, "could not read attached policies")
	}
	return out, nil
}

func (s *Server) getPolicy(ctx context.Context, policyARN string) (*iamv1.Policy, error) {
	row := s.store.Pool().QueryRow(ctx,
		`SELECT policy_arn, account_id, name, document, created_at_ms
		   FROM policies WHERE policy_arn = $1`, policyARN)

	p, err := scanPolicy(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apierr.NotFound("no policy %s", policyARN)
	}
	return p, err
}

type scannable interface {
	Scan(dest ...any) error
}

func scanPolicy(row scannable) (*iamv1.Policy, error) {
	var p iamv1.Policy
	var encoded []byte

	if err := row.Scan(&p.PolicyArn, &p.AccountId, &p.Name, &encoded, &p.CreatedAtUnixMs); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		return nil, apierr.Internal(err, "could not scan a policy")
	}

	doc := &iamv1.PolicyDocument{}
	if err := protojson.Unmarshal(encoded, doc); err != nil {
		return nil, apierr.Internal(err, "policy %s could not be decoded", p.PolicyArn)
	}
	p.Document = doc
	return &p, nil
}

func validateName(name string) error {
	switch {
	case name == "":
		return apierr.Validation("name is required")
	case len(name) > 64:
		return apierr.Validation("name must be at most 64 characters, got %d", len(name))
	default:
		return nil
	}
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation
}
