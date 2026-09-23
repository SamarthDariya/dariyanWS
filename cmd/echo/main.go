// Command echo is the control in E2: the same response the front door produces, with none of the
// work it does to produce it.
//
// No authentication, no request id, no access log, no database. Whatever it is slower than is the
// cost of the front door, and nothing else — which is why it must keep answering on the same path
// with the same body shape, and why it must NOT grow features. A control that drifts toward the
// thing it controls for stops being a control.
//
// It is also, early, the echo service M5 needs to prove routing through a real proxy hop. When
// that arrives it moves behind the front door instead of beside it.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"
)

func main() {
	addr := flag.String("addr", ":8081", "listen address")
	flag.Parse()

	mux := http.NewServeMux()

	// Hand-written rather than encoding/json, so the control does not pay for a reflection-based
	// encoder the front door also pays for. The comparison is about middleware, and leaving JSON
	// encoding in both sides would hide a term rather than isolate one.
	body := []byte(`{"account_id":"000000000000","principal_arn":"arn:dariya:iam:hind-1:000000000000:user/root","request_id":"00000000000000000000000000000000"}`)

	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	srv := &http.Server{
		Addr:    *addr,
		Handler: mux,

		// Matched to the front door's, so the control differs in what it does per request and not
		// in how its server is configured.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("echo listening on %s", *addr)
	log.Fatal(srv.ListenAndServe())
}
