// Command frontdoor is the single endpoint every request to this cloud enters through
// (DESIGN.md decision 2).
//
// It verifies a signature, and from M3 it will ask IAM for a decision, mint a capability token,
// and proxy to the service that owns the resource. At M2 it authenticates and answers /ping.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dariyanws/internal/capability"
	"dariyanws/internal/control"
	"dariyanws/internal/frontdoor"
	"dariyanws/internal/iam"
	"dariyanws/internal/router"
	"dariyanws/internal/secrets"
	"dariyanws/internal/store"
)

func main() {
	var (
		addr   = flag.String("addr", envOr("DARIYA_ADDR", ":8080"), "listen address")
		region = flag.String("region", envOr("DARIYA_REGION", "hind-1"), "region this front door serves")
		dsn    = flag.String("dsn", envOr("DARIYA_DSN", store.DefaultTestDSN), "control-plane Postgres DSN")
		dev    = flag.Bool("dev", os.Getenv("DARIYA_DEV") == "1",
			"development mode: error responses name the check that rejected a request")
		nocache = flag.Bool("no-key-cache", false,
			"resolve every access key from Postgres — E2's control, see BREAK.md")

		// One service, one flag, for as long as there is one service. A registry that services
		// self-register into is the obvious next step and is deliberately not taken yet: it
		// would be a discovery mechanism with a single participant, and its failure modes could
		// not be exercised.
		funcUpstream = flag.String("func-upstream", envOr("DARIYA_FUNC_UPSTREAM", ""),
			"base URL of the func data plane, e.g. http://127.0.0.1:8081")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Signals are wired before anything is opened, so a Ctrl-C during a slow database connect
	// still exits instead of requiring a second, less patient one.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, *addr, *region, *dsn, *dev, *nocache, *funcUpstream, log); err != nil {
		log.Error("front door stopped", "error", err)
		os.Exit(1)
	}
	log.Info("front door stopped")
}

func run(ctx context.Context, addr, region, dsn string, dev, nocache bool, funcUpstream string, log *slog.Logger) error {
	st, err := store.Open(ctx, dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	if err := st.Migrate(ctx); err != nil {
		return err
	}

	// A missing master key is fatal at boot rather than at the first request. Every signed request
	// needs to decrypt an access key secret, so a front door without one can authenticate nobody —
	// better to fail to start than to serve a wall of 403s that look like a signing bug.
	kr, err := secrets.NewKeyringFromEnv()
	if err != nil {
		return err
	}

	// A front door that cannot mint capabilities cannot authorize anything a service will
	// honour, so a missing token key is fatal at boot rather than at the first allow.
	minter, err := capability.NewMinterFromEnv(0)
	if err != nil {
		return err
	}

	accounts := control.NewAccountsServer(st, kr, region, time.Now)
	policies := iam.NewServer(st, region, time.Now)

	// The routes this front door proxies. Empty is legal and means a control plane with no data
	// planes behind it, which is what every milestone before this one was.
	var routes []router.Route
	if funcUpstream != "" {
		routes = append(routes, router.Route{
			Service:  "func",
			Prefix:   "/f/",
			Action:   "func:Invoke",
			Resource: router.PathResource(region, "func", "function", "/f/"),
			Upstream: funcUpstream,
		})
	}

	handler, _, err := frontdoor.NewHandler(accounts, policies, st, frontdoor.Options{
		Region:          region,
		Dev:             dev,
		Log:             log,
		Mint:            minter,
		DisableKeyCache: nocache,
		Routes:          routes,
	})
	if err != nil {
		return err
	}

	if dev {
		log.Warn("development mode: error responses will name the check that rejected a request")
	}
	return frontdoor.Serve(ctx, addr, handler, log)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
