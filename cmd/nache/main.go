// Command nache is the managed cache's control plane (DESIGN.md decision 13): the API customers
// call through the front door, and the reconciler that makes their clusters real on chala.
//
// One process, two halves that share only the store. The API never waits on chala; the
// reconciler never answers a customer. Killing either half's dependency — chala, or the front
// door the reconciler calls chala through — stops convergence and nothing else.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dariyanws/internal/capability"
	"dariyanws/internal/nache"
	"dariyanws/internal/nache/store"
	"dariyanws/internal/servicekit"
	"dariyanws/internal/signing"
)

func main() {
	var (
		addr      = flag.String("addr", envOr("NACHE_ADDR", "127.0.0.1:8083"), "listen address")
		region    = flag.String("region", envOr("DARIYA_REGION", "hind-1"), "region")
		dsn       = flag.String("dsn", envOr("NACHE_DSN", store.DefaultDSN), "nache's own Postgres database")
		frontDoor = flag.String("front-door", envOr("DARIYA_FRONT_DOOR", "http://127.0.0.1:8080"),
			"where nache calls chala through")
		period = flag.Duration("period", 2*time.Second, "reconciler period — the worst-case detection latency")
		max    = flag.Int("max-clusters", 5, "cache clusters one account may have")
		dev    = flag.Bool("dev", os.Getenv("DARIYA_DEV") == "1", "development mode")

		// BREAK.md E5 only. A planted fault, like E4's planted bug, and just as clearly labelled.
		e5Crash = flag.Bool("e5-crash-after-run", false,
			"E5: exit immediately after the first RunNode, before its observation is written")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, *addr, *region, *dsn, *frontDoor, *period, *max, *dev, *e5Crash, log); err != nil {
		log.Error("nache stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, addr, region, dsn, frontDoor string, period time.Duration, max int, dev, e5Crash bool, log *slog.Logger) error {
	// nache's service-account credentials, from `dariyactl service-account --service nache`.
	keyID, secret := os.Getenv("NACHE_ACCESS_KEY_ID"), os.Getenv("NACHE_SECRET_ACCESS_KEY")
	if keyID == "" || secret == "" {
		return errors.New("NACHE_ACCESS_KEY_ID and NACHE_SECRET_ACCESS_KEY are not set — " +
			"eval \"$(go run ./cmd/dariyactl service-account --service nache)\"")
	}

	verifier, err := capability.NewVerifierFromEnv()
	if err != nil {
		return err
	}

	st, err := store.Open(ctx, dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	rec := &nache.Reconciler{
		Store: st,
		Compute: &nache.ChalaClient{
			FrontDoor:   frontDoor,
			Region:      region,
			Credentials: signing.Credentials{AccessKeyID: keyID, Secret: []byte(secret)},
			HTTP:        &http.Client{Timeout: 20 * time.Second},
		},
		Period: period,
		Log:    log.With("component", "reconciler"),
	}
	if e5Crash {
		// os.Exit runs no deferred function and flushes nothing, so as far as the store and chala
		// can tell this is kill -9 at the worst possible instant. The difference from a real
		// SIGKILL — it can only happen here, never mid-write — is E5's stated fidelity gap.
		rec.AfterRunNode = func(c *store.Cluster) {
			log.Warn("E5: exiting between RunNode and the row update", "cluster", c.Name)
			os.Exit(137)
		}
	}
	go rec.Run(ctx)

	api := nache.NewAPI(st, servicekit.NewGuard(verifier, nache.Service, region), nache.APIConfig{
		Region: region, MaxClustersPerAccount: max, Dev: dev, Log: log,
	})
	srv := &http.Server{
		Addr:              addr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	log.Info("nache listening", "addr", addr, "front_door", frontDoor, "period", period)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
