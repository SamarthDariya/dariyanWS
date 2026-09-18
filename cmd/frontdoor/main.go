// Command frontdoor is the single endpoint every request to this cloud enters through
// (DESIGN.md decision 2).
//
// M0 ships the skeleton and nothing else: there is no listener, because a front door that accepts
// connections before it can verify a signature is a front door that is briefly an open proxy, and
// the tempting shortcut is to leave it that way "just for local dev". It starts listening at M2,
// when signature verification lands with it.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
)

// Region is pinned (DESIGN.md decision 4). It is a variable rather than a constant so the second
// region, when it exists, is a flag and not a rebuild.
var region = flag.String("region", "hind-1", "region this front door serves")

func main() {
	dev := flag.Bool("dev", os.Getenv("DARIYA_DEV") == "1",
		"development mode: error responses say which check rejected a request")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	log.Info("dariyanWS front door", "region", *region, "dev", *dev, "milestone", "M0")

	fmt.Fprintln(os.Stderr, "M0: contract only — no listener until M2. See DESIGN.md.")
}
