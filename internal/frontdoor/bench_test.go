package frontdoor

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	commonv1 "dariyanws/gen/dariya/common/v1"
	controlv1 "dariyanws/gen/dariya/control/v1"
	iamv1 "dariyanws/gen/dariya/iam/v1"
	"dariyanws/internal/authn"
	"dariyanws/internal/authz"
	"dariyanws/internal/control"
	"dariyanws/internal/httpx"
	"dariyanws/internal/iam"
	"dariyanws/internal/signing"
)

// E2's decomposition. The network sweep says what the front door costs in total; these say where
// it goes, by removing one term at a time from the same handler:
//
//	BenchmarkBareHandler      no middleware at all — the floor
//	BenchmarkPlumbingOnly     request id, recovery, access log; no authentication
//	BenchmarkAuthnMemoryKeys  full authentication, key resolved from memory — no database
//	BenchmarkAuthnRealKeys    full authentication, key resolved from Postgres
//
// The gap between the last two is the database. The gap between the middle two is signature
// verification. In-process on purpose: no sockets, so nothing here is measuring loopback.

// memoryResolver answers from memory, so the database can be subtracted from the measurement.
type memoryResolver struct{ key *control.SigningKey }

func (m memoryResolver) ResolveSigningKey(context.Context, string) (*control.SigningKey, error) {
	return m.key, nil
}

func benchHandler(b *testing.B, mw ...httpx.Middleware) http.Handler {
	b.Helper()
	return httpx.Chain(http.HandlerFunc(handlePing), mw...)
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// benchCredentials mints a real account and key, and returns a signed request factory.
func benchCredentials(b *testing.B) (*control.AccountsServer, signing.Credentials) {
	b.Helper()

	st := openBenchStore(b)
	kr := benchKeyring(b)
	accounts := control.NewAccountsServer(st, kr, testRegion, time.Now)

	ctx := context.Background()
	acct, err := accounts.CreateAccount(ctx, &controlv1.CreateAccountRequest{Name: "bench"})
	if err != nil {
		b.Fatalf("CreateAccount: %v", err)
	}
	key, err := accounts.CreateAccessKey(ctx, &controlv1.CreateAccessKeyRequest{
		AccountId: acct.GetAccount().GetAccountId(),
	})
	if err != nil {
		b.Fatalf("CreateAccessKey: %v", err)
	}

	return accounts, signing.Credentials{
		AccessKeyID: key.GetAccessKey().GetAccessKeyId(),
		Secret:      []byte(key.GetAccessKey().GetSecretAccessKey()),
	}
}

func signedBenchRequest(b *testing.B, cred signing.Credentials) *http.Request {
	b.Helper()
	req := httptest.NewRequest("GET", "/ping", nil)
	auth, headers := signing.Sign(
		signing.Request{Method: "GET", Path: "/ping"},
		cred, testRegion, ServiceName, time.Now())
	req.Header.Set("Authorization", auth)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func runBench(b *testing.B, h http.Handler, req *http.Request) {
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req.Clone(req.Context()))
			if rec.Code != http.StatusOK {
				b.Fatalf("status %d: %s", rec.Code, rec.Body.String())
			}
		}
	})
}

// The floor: what the handler costs with nothing wrapped around it. It needs a principal, so one
// is attached directly rather than authenticated.
func BenchmarkBareHandler(b *testing.B) {
	_, cred := benchCredentials(b)
	principal := fixedPrincipal()

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlePing(w, r.WithContext(httpx.WithPrincipal(r.Context(), principal)))
	})
	runBench(b, h, signedBenchRequest(b, cred))
}

func BenchmarkPlumbingOnly(b *testing.B) {
	_, cred := benchCredentials(b)
	principal := fixedPrincipal()

	h := httpx.Chain(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlePing(w, r.WithContext(httpx.WithPrincipal(r.Context(), principal)))
		}),
		httpx.WithRequestID, httpx.Recover(false), httpx.AccessLog(discard()),
	)
	runBench(b, h, signedBenchRequest(b, cred))
}

func BenchmarkAuthnMemoryKeys(b *testing.B) {
	accounts, cred := benchCredentials(b)

	key, err := accounts.ResolveSigningKey(context.Background(), cred.AccessKeyID)
	if err != nil {
		b.Fatalf("ResolveSigningKey: %v", err)
	}

	h := benchHandler(b,
		httpx.WithRequestID, httpx.Recover(false), httpx.AccessLog(discard()),
		authn.Middleware(authn.Config{
			Keys:    memoryResolver{key: key},
			Region:  testRegion,
			Service: func(*http.Request) string { return ServiceName },
			Log:     discard(),
		}),
	)
	runBench(b, h, signedBenchRequest(b, cred))
}

func BenchmarkAuthnRealKeys(b *testing.B) {
	accounts, cred := benchCredentials(b)

	h := benchHandler(b,
		httpx.WithRequestID, httpx.Recover(false), httpx.AccessLog(discard()),
		authn.Middleware(authn.Config{
			Keys:    accounts,
			Region:  testRegion,
			Service: func(*http.Request) string { return ServiceName },
			Log:     discard(),
		}),
	)
	runBench(b, h, signedBenchRequest(b, cred))
}

// The two primitives on their own, to settle whether the HMAC is ever worth talking about.
func BenchmarkSignatureVerifyOnly(b *testing.B) {
	cred := signing.Credentials{AccessKeyID: "DARIYAKEYABCDEFGHIJKLMNO", Secret: []byte("secret")}
	req := signing.Request{Method: "GET", Path: "/ping"}
	now := time.Now()

	auth, headers := signing.Sign(req, cred, testRegion, ServiceName, now)
	sig, err := signing.ParseAuthorization(auth)
	if err != nil {
		b.Fatal(err)
	}
	in := signing.VerifyInput{
		Request: req, Signature: sig,
		DateHeaderValue:     headers[signing.DateHeader],
		ContentSHA256Header: headers[signing.ContentSHA256Header],
		Secret:              cred.Secret, Region: testRegion, Service: ServiceName, Now: now,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := signing.Verify(in); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkResolveSigningKeyOnly(b *testing.B) {
	accounts, cred := benchCredentials(b)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := accounts.ResolveSigningKey(ctx, cred.AccessKeyID); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// Reported so the numbers can be read months later without guessing what they ran on.
func BenchmarkReportEnvironment(b *testing.B) {
	b.Logf("GOMAXPROCS=%d NumCPU=%d", runtime.GOMAXPROCS(0), runtime.NumCPU())
	st := openBenchStore(b)
	b.Logf("pgx pool max conns=%d", st.Pool().Config().MaxConns)
}

// E2c: what authorization adds on top of authentication.
//
// Measured in-process and in the same run as the layers below it, because BREAK.md's caveat from
// E2b applies — the bare handler measured 9,849 rps in one run and 17,820 in the next, so a
// number compared against a remembered one is not a measurement.
//
//	BenchmarkAuthnCachedKeys   authentication only, credential cache warm
//	BenchmarkAuthnAuthzCached  authentication and authorization, both caches warm
//	BenchmarkAuthorizeOnly     the decision on its own, cache warm
//	BenchmarkEvaluateOnly      the pure policy evaluation, no cache, no database

func benchIAM(b *testing.B, accountID string) (*iam.Server, *iam.Authorizer) {
	b.Helper()

	st := openBenchStore(b)
	policies := iam.NewServer(st, testRegion, time.Now)

	created, err := policies.CreatePolicy(context.Background(), &iamv1.CreatePolicyRequest{
		AccountId: accountID,
		Name:      "bench-ping",
		Document: &iamv1.PolicyDocument{Statements: []*iamv1.Statement{{
			Sid: "ping", Effect: iamv1.Effect_EFFECT_ALLOW,
			Actions: []string{ActionPing}, Resources: []string{PingResourceARN(testRegion, accountID)},
		}}},
	})
	if err != nil {
		b.Fatalf("CreatePolicy: %v", err)
	}
	if _, err := policies.AttachPolicy(context.Background(), &iamv1.AttachPolicyRequest{
		PolicyArn:    created.GetPolicy().GetPolicyArn(),
		PrincipalArn: "arn:dariya:iam:" + testRegion + ":" + accountID + ":user/root",
	}); err != nil {
		b.Fatalf("AttachPolicy: %v", err)
	}

	authorizer := iam.NewAuthorizer(policies, iam.AuthorizerOptions{})
	return policies, authorizer
}

func BenchmarkAuthnCachedKeys(b *testing.B) {
	accounts, cred := benchCredentials(b)
	cached := control.NewCachingResolver(accounts, control.CacheOptions{})

	h := benchHandler(b,
		httpx.WithRequestID, httpx.Recover(false), httpx.AccessLog(discard()),
		authn.Middleware(authn.Config{
			Keys:    cached,
			Region:  testRegion,
			Service: func(*http.Request) string { return ServiceName },
			Log:     discard(),
		}),
	)
	runBench(b, h, signedBenchRequest(b, cred))
}

func BenchmarkAuthnAuthzCached(b *testing.B) {
	accounts, cred := benchCredentials(b)

	key, err := accounts.ResolveSigningKey(context.Background(), cred.AccessKeyID)
	if err != nil {
		b.Fatalf("ResolveSigningKey: %v", err)
	}
	_, authorizer := benchIAM(b, key.AccountID)

	cached := control.NewCachingResolver(accounts, control.CacheOptions{})

	h := benchHandler(b,
		httpx.WithRequestID, httpx.Recover(false), httpx.AccessLog(discard()),
		authn.Middleware(authn.Config{
			Keys:    cached,
			Region:  testRegion,
			Service: func(*http.Request) string { return ServiceName },
			Log:     discard(),
		}),
		authz.Middleware(authz.Config{
			Decide: authorizer,
			Target: func(_ *http.Request, p *commonv1.Principal) (authz.Target, error) {
				return authz.Target{
					Action:      ActionPing,
					ResourceARN: PingResourceARN(testRegion, p.GetAccountId()),
				}, nil
			},
			Log: discard(),
		}),
	)
	runBench(b, h, signedBenchRequest(b, cred))
}

func BenchmarkAuthorizeOnly(b *testing.B) {
	accounts, cred := benchCredentials(b)
	key, err := accounts.ResolveSigningKey(context.Background(), cred.AccessKeyID)
	if err != nil {
		b.Fatalf("ResolveSigningKey: %v", err)
	}
	_, authorizer := benchIAM(b, key.AccountID)

	req := &iamv1.AuthorizeRequest{
		Principal:   &commonv1.Principal{AccountId: key.AccountID, PrincipalArn: key.PrincipalARN},
		Action:      ActionPing,
		ResourceArn: PingResourceARN(testRegion, key.AccountID),
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := authorizer.Authorize(ctx, req)
			if err != nil {
				b.Fatal(err)
			}
			if resp.GetDecision() != iamv1.Decision_DECISION_ALLOW {
				b.Fatalf("decision = %v", resp.GetDecision())
			}
		}
	})
}

// The floor for authorization: matching, with nothing around it.
func BenchmarkEvaluateOnly(b *testing.B) {
	const account = "000000000001"
	resource := PingResourceARN(testRegion, account)

	policies := []iam.AttachedPolicy{{
		PolicyARN: "arn:dariya:iam:hind-1:" + account + ":policy/p",
		Document: &iamv1.PolicyDocument{Statements: []*iamv1.Statement{{
			Sid: "ping", Effect: iamv1.Effect_EFFECT_ALLOW,
			Actions: []string{ActionPing}, Resources: []string{resource},
		}}},
	}}
	req := iam.Request{Action: ActionPing, ResourceARN: resource}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !iam.Evaluate(policies, req).Allowed() {
			b.Fatal("denied")
		}
	}
}
