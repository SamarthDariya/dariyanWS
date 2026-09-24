// Command echo is two things, which is why it has a mode flag.
//
// **--mode bare** is E2's control: the same response the front door produces, with none of the
// work it does to produce it. It must not grow features — a control that drifts toward the thing
// it controls for stops being a control — and it is what `--no-key-cache` comparisons are
// measured against.
//
// **--mode guarded** is a data plane. It sits behind the front door, verifies the capability on
// each request offline with servicekit, and refuses anything the capability does not authorise.
// It is the smallest possible service that is honest about decision 6, and it is what E1 kills
// the control plane in front of.
//
// It stands in for dariyafunc until dariyafunc exists. What it proves is not that invoking a
// function works — it does not invoke anything — but that the authorization decision survives
// the hop, and keeps being honoured when the thing that made it is gone.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"dariyanws/internal/capability"
	"dariyanws/internal/httpx"
	"dariyanws/internal/servicekit"
)

const invokePrefix = "/f/"

func main() {
	var (
		addr    = flag.String("addr", ":8081", "listen address")
		mode    = flag.String("mode", "guarded", "bare (E2's control) or guarded (a real data plane)")
		service = flag.String("service", "func", "the ARN service segment this process serves")
		region  = flag.String("region", "hind-1", "region")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	mux := http.NewServeMux()
	switch *mode {
	case "bare":
		mux.HandleFunc("/ping", bareHandler())
		mux.HandleFunc(invokePrefix, bareHandler())

	case "guarded":
		// Public keys only. A data plane that held a signing key could mint its own permissions,
		// which is the property decision 6 chose Ed25519 for.
		verifier, err := capability.NewVerifierFromEnv()
		if err != nil {
			log.Error("cannot start", "error", err)
			os.Exit(1)
		}
		mux.Handle(invokePrefix, guardedHandler(
			servicekit.NewGuard(verifier, *service, *region), *service, log))

	default:
		log.Error("unknown mode", "mode", *mode)
		os.Exit(2)
	}

	// Unauthenticated, and deliberately so: this is what E1 polls to tell "the data plane is
	// alive" apart from "the data plane is refusing requests", which are the two outcomes the
	// experiment has to distinguish.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Info("echo listening", "addr", *addr, "mode", *mode, "service", *service)
	if err := srv.ListenAndServe(); err != nil {
		log.Error("stopped", "error", err)
		os.Exit(1)
	}
}

// bareHandler writes a fixed body with a hand-rolled encoder, so the control does not pay for a
// reflection-based encoder either. The comparison is about middleware, and leaving JSON encoding
// in both sides would hide a term rather than isolate one.
func bareHandler() http.HandlerFunc {
	body := []byte(`{"account_id":"000000000000","principal_arn":"arn:dariya:iam:hind-1:000000000000:user/root","request_id":"00000000000000000000000000000000"}`)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
}

// guardedHandler is the shortest correct data plane, and after M4.4 the only one the API allows.
//
// Note what it does not do: it never calls IAM, never calls the front door, and never reads a
// database. Everything it needs to decide whether to serve this request is in the request, and
// that is the whole of decision 6.
func guardedHandler(guard *servicekit.Guard, service string, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := functionName(r.URL.Path)
		if name == "" {
			writeJSON(w, http.StatusNotFound, map[string]string{
				"code": "ResourceNotFound", "message": "the path does not name a function",
			})
			return
		}

		// The service states what it is about to do before it is permitted to do it. It names
		// the resource by type and id; the account comes from the verified token, because a
		// data plane cannot know whose resource it is serving until the token is checked.
		cap, err := guard.Authorize(r, servicekit.Intent{
			Action:       service + ":Invoke",
			ResourceType: "function",
			ResourceID:   name,
		})
		if err != nil {
			log.Warn("refused",
				"request_id", r.Header.Get(httpx.RequestIDHeader),
				"path", r.URL.Path, "error", err)
			writeJSON(w, http.StatusForbidden, map[string]string{
				"code": "AccessDenied", "message": "the capability does not authorise this request",
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"served":        name,
			"account_id":    cap.GetAccountId(),
			"principal_arn": cap.GetPrincipalArn(),
			"action":        cap.GetAction(),
			"resource_arn":  cap.GetResourceArn(),
			"request_id":    r.Header.Get(httpx.RequestIDHeader),
		})
	})
}

func functionName(path string) string {
	rest := strings.TrimPrefix(path, invokePrefix)
	name, _, _ := strings.Cut(rest, "/")
	return name
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
