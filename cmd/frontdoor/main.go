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

	"dariyanws/internal/control"
	"dariyanws/internal/frontdoor"
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
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Signals are wired before anything is opened, so a Ctrl-C during a slow database connect
	// still exits instead of requiring a second, less patient one.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, *addr, *region, *dsn, *dev, *nocache, log); err != nil {
		log.Error("front door stopped", "error", err)
		os.Exit(1)
	}
	log.Info("front door stopped")
}

func run(ctx context.Context, addr, region, dsn string, dev, nocache bool, log *slog.Logger) error {
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

	accounts := control.NewAccountsServer(st, kr, region, time.Now)
	handler, _ := frontdoor.NewHandler(accounts, st, frontdoor.Options{
		Region:          region,
		Dev:             dev,
		Log:             log,
		DisableKeyCache: nocache,
	})

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
