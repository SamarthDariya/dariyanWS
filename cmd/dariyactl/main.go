// Command dariyactl is the operator CLI for the dariyanWS control plane.
//
// At M1 it talks to Postgres in-process rather than over the wire, because nothing serves yet —
// the front door does not listen until M2 and there is no gRPC endpoint until M5. That is a
// deliberate, temporary shortcut: an operator tool that keeps direct database access after there
// is an API is an operator tool that quietly becomes the second way to do everything, with none of
// the authorisation the first way has. It moves onto the API at M5.
//
//	dariyactl bootstrap                    seed a dev account and mint credentials
//	dariyactl account create --name NAME
//	dariyactl account list
//	dariyactl key create --account ID [--principal ARN]
//	dariyactl key list --account ID
//	dariyactl key delete --id KEYID
//	dariyactl sign --key ... --secret ... --method POST --path /x   emit a signed curl command
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	commonv1 "dariyanws/gen/dariya/common/v1"
	controlv1 "dariyanws/gen/dariya/control/v1"
	iamv1 "dariyanws/gen/dariya/iam/v1"
	"dariyanws/internal/capability"
	"dariyanws/internal/control"
	"dariyanws/internal/iam"
	"dariyanws/internal/secrets"
	"dariyanws/internal/signing"
	"dariyanws/internal/store"
)

const (
	defaultRegion = "hind-1"

	// bootstrapToken makes `dariyactl bootstrap` idempotent in its account creation: running it
	// twice gives the same dev account rather than a second one. It deliberately does not make key
	// creation idempotent — each run mints a fresh key, because a secret is shown once and a
	// replayed create cannot produce it again.
	bootstrapToken = "dariyactl-bootstrap-dev"

	envDSN = "DARIYA_DSN"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	// keygen and sign are pure and need no database, so they are handled before anything
	// connects — keygen in particular has to work on a machine where nothing is running yet,
	// since its output is what makes the rest runnable.
	if os.Args[1] == "keygen" {
		if err := cmdKeygen(); err != nil {
			fatal(err)
		}
		return
	}

	// `sign` is pure and needs no database, so it is handled before anything connects. It exists
	// so M2 can be exercised with curl before there is any client library.
	if os.Args[1] == "sign" {
		if err := cmdSign(os.Args[2:]); err != nil {
			fatal(err)
		}
		return
	}

	ctx := context.Background()
	srv, closeFn, err := dial(ctx)
	if err != nil {
		fatal(err)
	}
	defer closeFn()

	switch os.Args[1] {
	case "bootstrap":
		err = cmdBootstrap(ctx, srv)
	case "account":
		err = cmdAccount(ctx, srv, os.Args[2:])
	case "key":
		err = cmdKey(ctx, srv, os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fatal(err)
	}
}

type plane struct {
	accounts *control.AccountsServer
	policies *iam.Server
}

func dial(ctx context.Context) (*plane, func(), error) {
	dsn := os.Getenv(envDSN)
	if dsn == "" {
		dsn = store.DefaultTestDSN
	}
	st, err := store.Open(ctx, dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("%w\n\nIs the region up? Try `make region-up`.", err)
	}
	if err := st.Migrate(ctx); err != nil {
		st.Close()
		return nil, nil, err
	}

	kr, err := secrets.NewKeyringFromEnv()
	if err != nil {
		st.Close()
		return nil, nil, fmt.Errorf("%w\n\nGenerate one with `make dev-keys` and export it.", err)
	}

	return &plane{
		accounts: control.NewAccountsServer(st, kr, defaultRegion, time.Now),
		policies: iam.NewServer(st, defaultRegion, time.Now),
	}, st.Close, nil
}

// cmdBootstrap is what `make dev-token` runs: one command from empty database to usable
// credentials, because DESIGN.md decision 4 means nothing at all works without a principal and a
// painful local setup is how that decision starts getting worked around.
func cmdBootstrap(ctx context.Context, srv *plane) error {
	acct, err := srv.accounts.CreateAccount(ctx, &controlv1.CreateAccountRequest{
		Name:        "dev",
		ClientToken: bootstrapToken,
	})
	if err != nil {
		return err
	}
	id := acct.GetAccount().GetAccountId()

	key, err := srv.accounts.CreateAccessKey(ctx, &controlv1.CreateAccessKeyRequest{AccountId: id})
	if err != nil {
		return err
	}
	k := key.GetAccessKey()

	// A credential with no policy can do nothing at all — decision 6 means the front door
	// authorizes every route, and M3.4 exempted none. Bootstrap therefore grants the dev
	// account's root user everything inside its own account, which is safe because the
	// cross-account check in Authorize does not depend on the policy being narrow.
	if err := grantAdmin(ctx, srv, id); err != nil {
		return err
	}

	fmt.Printf(`# dev account %s (%s)
# Credentials are shown once. Re-run `+"`make dev-token`"+` to mint another key.
export DARIYA_ACCOUNT_ID=%s
export DARIYA_ACCESS_KEY_ID=%s
export DARIYA_SECRET_ACCESS_KEY=%s
export DARIYA_REGION=%s
export DARIYA_PRINCIPAL_ARN=%s
`, id, acct.GetAccount().GetName(), id, k.GetAccessKeyId(), k.GetSecretAccessKey(), defaultRegion, k.GetPrincipalArn())
	return nil
}

func cmdAccount(ctx context.Context, srv *plane, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("account: want `create` or `list`")
	}
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("account create", flag.ExitOnError)
		name := fs.String("name", "", "account name")
		_ = fs.Parse(args[1:])

		resp, err := srv.accounts.CreateAccount(ctx, &controlv1.CreateAccountRequest{Name: *name})
		if err != nil {
			return err
		}
		a := resp.GetAccount()
		fmt.Printf("%s\t%s\t%s\n", a.GetAccountId(), a.GetName(), a.GetState())
		return nil

	case "list":
		token := ""
		for {
			resp, err := srv.accounts.ListAccounts(ctx, &controlv1.ListAccountsRequest{
				Page: &commonv1.PageRequest{NextToken: token},
			})
			if err != nil {
				return err
			}
			for _, a := range resp.GetAccounts() {
				fmt.Printf("%s\t%s\t%s\n", a.GetAccountId(), a.GetName(), a.GetState())
			}
			if token = resp.GetPage().GetNextToken(); token == "" {
				return nil
			}
		}

	default:
		return fmt.Errorf("account: unknown subcommand %q", args[0])
	}
}

func cmdKey(ctx context.Context, srv *plane, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("key: want `create`, `list` or `delete`")
	}
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("key create", flag.ExitOnError)
		account := fs.String("account", "", "account id")
		principal := fs.String("principal", "", "principal ARN (default: the account's root user)")
		_ = fs.Parse(args[1:])

		resp, err := srv.accounts.CreateAccessKey(ctx, &controlv1.CreateAccessKeyRequest{
			AccountId:    *account,
			PrincipalArn: *principal,
		})
		if err != nil {
			return err
		}
		k := resp.GetAccessKey()
		fmt.Printf("access key id:     %s\nsecret access key: %s\nprincipal:         %s\n\n",
			k.GetAccessKeyId(), k.GetSecretAccessKey(), k.GetPrincipalArn())
		fmt.Fprintln(os.Stderr, "The secret is shown once and is not recoverable. Save it now.")
		return nil

	case "list":
		fs := flag.NewFlagSet("key list", flag.ExitOnError)
		account := fs.String("account", "", "account id")
		_ = fs.Parse(args[1:])

		token := ""
		for {
			resp, err := srv.accounts.ListAccessKeys(ctx, &controlv1.ListAccessKeysRequest{
				AccountId: *account,
				Page:      &commonv1.PageRequest{NextToken: token},
			})
			if err != nil {
				return err
			}
			for _, k := range resp.GetAccessKeys() {
				fmt.Printf("%s\t%s\t%s\n", k.GetAccessKeyId(), k.GetPrincipalArn(), k.GetState())
			}
			if token = resp.GetPage().GetNextToken(); token == "" {
				return nil
			}
		}

	case "delete":
		fs := flag.NewFlagSet("key delete", flag.ExitOnError)
		id := fs.String("id", "", "access key id")
		_ = fs.Parse(args[1:])

		if _, err := srv.accounts.DeleteAccessKey(ctx, &controlv1.DeleteAccessKeyRequest{AccessKeyId: *id}); err != nil {
			return err
		}
		fmt.Printf("deleted %s\n", *id)
		return nil

	default:
		return fmt.Errorf("key: unknown subcommand %q", args[0])
	}
}

// cmdSign prints a curl command carrying a valid signature.
//
// This is the development affordance decision 4 asks for: multi-account from day one means there
// is no "just curl it", so the tooling has to make the signed equivalent one command away.
func cmdSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyID := fs.String("key", os.Getenv("DARIYA_ACCESS_KEY_ID"), "access key id")
	secret := fs.String("secret", os.Getenv("DARIYA_SECRET_ACCESS_KEY"), "secret access key")
	region := fs.String("region", envOr("DARIYA_REGION", defaultRegion), "region")
	service := fs.String("service", "", "service the request is scoped to, e.g. func")
	method := fs.String("method", "GET", "HTTP method")
	rawURL := fs.String("url", "http://localhost:8080/", "full request URL")
	body := fs.String("body", "", "request body")
	_ = fs.Parse(args)

	if *keyID == "" || *secret == "" {
		return fmt.Errorf("sign: --key and --secret are required (or run `make dev-token`)")
	}
	if *service == "" {
		return fmt.Errorf("sign: --service is required — it is part of the signature, not a hint")
	}

	u, err := url.Parse(*rawURL)
	if err != nil {
		return fmt.Errorf("sign: --url: %w", err)
	}

	req := signing.Request{
		Method: *method,
		Path:   u.Path,
		Query:  u.Query(),
		Body:   []byte(*body),
	}
	auth, headers := signing.Sign(req,
		signing.Credentials{AccessKeyID: *keyID, Secret: []byte(*secret)},
		*region, *service, time.Now())

	var b strings.Builder
	fmt.Fprintf(&b, "curl -sS -X %s \\\n", strings.ToUpper(*method))
	fmt.Fprintf(&b, "  -H 'Authorization: %s' \\\n", auth)
	for _, h := range []string{signing.DateHeader, signing.ContentSHA256Header} {
		fmt.Fprintf(&b, "  -H '%s: %s' \\\n", h, headers[h])
	}
	if *body != "" {
		fmt.Fprintf(&b, "  --data-raw '%s' \\\n", *body)
	}
	fmt.Fprintf(&b, "  '%s'\n", u.String())

	// The signature is valid for MaxSkew; say so, because a command pasted into a notes file and
	// run tomorrow fails in a way that looks like a bug in the front door.
	fmt.Fprintf(os.Stderr, "# valid for %s\n", signing.MaxSkew)
	fmt.Print(b.String())
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func usage() {
	fmt.Fprint(os.Stderr, `dariyactl — operator CLI for the dariyanWS control plane

  dariyactl bootstrap
  dariyactl account create --name NAME
  dariyactl account list
  dariyactl key create --account ID [--principal ARN]
  dariyactl key list --account ID
  dariyactl key delete --id KEYID
  dariyactl sign --service SVC --url URL [--method M] [--body B]
  dariyactl keygen

Environment:
  DARIYA_DSN            Postgres DSN (default: the local region)
  DARIYA_MASTER_KEYS    master keys for credential encryption (see `+"`make dev-keys`"+`)
`)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "dariyactl: %v\n", err)
	os.Exit(1)
}

// grantAdmin attaches an allow-everything policy to an account's root user.
//
// Idempotent through the client token, because bootstrap is expected to be re-run — each run
// mints a new access key, and re-granting must not be the thing that fails.
func grantAdmin(ctx context.Context, srv *plane, accountID string) error {
	created, err := srv.policies.CreatePolicy(ctx, &iamv1.CreatePolicyRequest{
		AccountId: accountID,
		Name:      "root-admin",
		Document: &iamv1.PolicyDocument{Statements: []*iamv1.Statement{{
			Sid:       "everything-in-this-account",
			Effect:    iamv1.Effect_EFFECT_ALLOW,
			Actions:   []string{"*"},
			Resources: []string{"*"},
		}}},
		ClientToken: bootstrapToken + "-policy",
	})
	if err != nil {
		return err
	}

	// Attaching is idempotent by nature, so a re-run needs no special case.
	_, err = srv.policies.AttachPolicy(ctx, &iamv1.AttachPolicyRequest{
		PolicyArn:    created.GetPolicy().GetPolicyArn(),
		PrincipalArn: fmt.Sprintf("arn:dariya:iam:%s:%s:user/root", defaultRegion, accountID),
	})
	return err
}

// cmdKeygen prints every key the region needs, in one place.
//
// One command rather than three, because these keys have to agree with each other: the front
// door's token signing key and the public key every service verifies with are two halves of one
// pair, and generating them separately is how a region ends up minting tokens nothing accepts.
func cmdKeygen() error {
	master, err := secrets.GenerateKey()
	if err != nil {
		return err
	}
	seed, pub, err := capability.GenerateKey()
	if err != nil {
		return err
	}

	fmt.Printf("export %s=dev1:%s\n", secrets.EnvVar, base64.StdEncoding.EncodeToString(master))
	fmt.Printf("export %s=dev1:%s\n", capability.EnvSigningKey, base64.StdEncoding.EncodeToString(seed))
	fmt.Printf("export %s=dev1:%s\n", capability.EnvPublicKeys, base64.StdEncoding.EncodeToString(pub))
	fmt.Fprintln(os.Stderr,
		"# Keep these. Credentials encrypted under a previous master key stop decrypting, and "+
			"tokens signed by a previous key stop verifying.")
	return nil
}
