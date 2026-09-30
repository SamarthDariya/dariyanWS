package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdoptRequestID(t *testing.T) {
	var seen string
	h := AdoptRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestID(r.Context())
	}))

	for name, c := range map[string]struct {
		header string
		kept   bool
	}{
		"the front door's id":     {"0123456789abcdef0123456789abcdef", true},
		"none":                    {"", false},
		"not hex":                 {"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", false},
		"log injection":           {"abc\nlevel=ERROR msg=forged", false},
		"right charset, too long": {"0123456789abcdef0123456789abcdef00", false},
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			if c.header != "" {
				r.Header.Set(RequestIDHeader, c.header)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)

			if c.kept && seen != c.header {
				t.Fatalf("id = %q, want the front door's %q", seen, c.header)
			}
			if !c.kept && (seen == c.header || !isRequestID(seen)) {
				t.Fatalf("id = %q, want a freshly minted one", seen)
			}
			if w.Header().Get(RequestIDHeader) != seen {
				t.Fatalf("response header %q disagrees with context %q", w.Header().Get(RequestIDHeader), seen)
			}
		})
	}
}
