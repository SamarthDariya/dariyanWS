// Command chala is dariyachala, the compute service (DESIGN.md decision 13b).
//
// It is the only process in the region that holds the Docker socket, and it sits behind the front
// door like any data plane: public keys only, a capability on every request, no database. It runs
// on the host rather than in the region's compose file because it needs the socket, and mounting
// the socket into a container would hand root to whatever else can reach that container.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"dariyanws/internal/capability"
	"dariyanws/internal/chala"
	"dariyanws/internal/chala/docker"
	"dariyanws/internal/servicekit"
)

func main() {
	var (
		addr   = flag.String("addr", envOr("CHALA_ADDR", "127.0.0.1:8082"), "listen address")
		region = flag.String("region", envOr("DARIYA_REGION", "hind-1"), "region")
		socket = flag.String("socket", docker.DefaultSocket(), "Docker daemon socket")
		max    = flag.Int("max-instances", 20, "instances one account may have at once")
		dev    = flag.Bool("dev", os.Getenv("DARIYA_DEV") == "1", "development mode")

		// Which control planes the region trusts to attach instances to other accounts' networks
		// (DESIGN.md decision 13i). Printed by `dariyactl service-account`.
		services = flag.String("service-accounts", os.Getenv("DARIYA_SERVICE_ACCOUNTS"),
			"comma-separated ACCOUNT=SERVICE pairs, e.g. 123456789012=nache")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serviceAccounts, err := parseServiceAccounts(*services)
	if err != nil {
		log.Error("cannot start", "error", err)
		os.Exit(2)
	}

	if err := run(ctx, *addr, *region, *socket, *max, serviceAccounts, *dev, log); err != nil {
		log.Error("chala stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, addr, region, socket string, max int, serviceAccounts map[string]string, dev bool, log *slog.Logger) error {
	// Public keys only. chala verifies capabilities and cannot mint them (decision 6).
	verifier, err := capability.NewVerifierFromEnv()
	if err != nil {
		return err
	}

	d := docker.New(socket)
	bootCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := d.Ping(bootCtx); err != nil {
		return errors.Join(err, errors.New("is Docker running? `open -a Docker`"))
	}

	s, err := chala.New(d, servicekit.NewGuard(verifier, chala.Service, region), chala.Config{
		Region: region, Catalog: chala.DefaultCatalog(), MaxInstancesPerAccount: max,
		ServiceAccounts: serviceAccounts, Dev: dev, Log: log,
	})
	if err != nil {
		return err
	}
	// Before listening, so a RunInstance can never be the thing that waits on a registry.
	if err := s.PrepareImages(bootCtx, log); err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		// Longer than the front door's 15s proxy timeout, so it is the front door that gives up
		// first and the caller gets a contract-shaped error rather than a reset connection.
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	log.Info("chala listening", "addr", addr, "socket", socket, "max_instances", max,
		"service_accounts", len(serviceAccounts))
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// parseServiceAccounts reads ACCOUNT=SERVICE pairs. chala.New validates the values; this only
// refuses what cannot be split.
func parseServiceAccounts(raw string) (map[string]string, error) {
	out := map[string]string{}
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		acct, svc, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, fmt.Errorf("--service-accounts: %q is not ACCOUNT=SERVICE", pair)
		}
		if _, dup := out[acct]; dup {
			return nil, fmt.Errorf("--service-accounts: %s appears twice", acct)
		}
		out[acct] = svc
	}
	return out, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
