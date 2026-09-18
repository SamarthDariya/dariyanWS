// Package signing implements the edge auth scheme: SigV4-shaped, one HMAC round
// (DESIGN.md decision 5).
//
// What survives from SigV4, because it is what actually matters:
//
//   - the secret never crosses the wire — only a MAC over the request does;
//   - the body hash makes the payload tamper-evident;
//   - the timestamp bounds replay;
//   - the credential scope names which key to look up and which region and service the signature
//     is good for.
//
// What is dropped: the four-round derived-key chain (key → date → region → service → request). It
// exists so AWS can hand a regional service a scoped signing key without sharing the root secret.
// One region and one front door means it buys nothing but debugging.
//
// # The canonical string
//
//	DARIYA1-HMAC-SHA256
//	<method>
//	<canonical path>
//	<canonical query>
//	<timestamp>
//	<hex sha256(body)>
//	<credential scope>
//
// # A known gap, stated rather than hidden
//
// The Host header is NOT signed. A signature is therefore valid against any endpoint that shares
// the credential scope's region and service — with one front door there is nowhere else to replay
// it to, which is why decision 5 left it out. It becomes a real gap the moment a second endpoint
// serves the same scope, and the fix is one more line in the canonical string plus the operational
// cost that made AWS invent SignedHeaders: every proxy that rewrites Host breaks every signature.
//
// # Debuggability
//
// Every failure mode here surfaces to a caller as one opaque 403, which is correct in production
// and miserable during development. Verify returns a typed *Error naming the check that failed; the
// front door renders the detail only under DARIYA_DEV=1.
package signing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	// Algorithm is the scheme name, first token of the Authorization header and first line of the
	// canonical string. Versioned so a future scheme can coexist during a migration.
	Algorithm = "DARIYA1-HMAC-SHA256"

	// TimeFormat is compact ISO 8601, as AWS uses. Second precision; no sub-second field, because
	// the skew window is minutes wide and false precision invites canonicalisation mismatches.
	TimeFormat = "20060102T150405Z"

	// DateHeader carries the signing timestamp.
	DateHeader = "X-Dariya-Date"

	// ContentSHA256Header lets a caller state the body hash it signed, so a proxy that re-chunks
	// or re-encodes the body cannot silently invalidate a signature without it being obvious which
	// side changed.
	ContentSHA256Header = "X-Dariya-Content-Sha256"

	// MaxSkew bounds replay and tolerates unsynchronised clocks. Five minutes matches AWS.
	//
	// It is symmetric on purpose: a request timestamped in the future is just as much a sign of a
	// wrong clock as one in the past, and rejecting only the past means a client whose clock runs
	// fast fails every request with no useful error.
	MaxSkew = 5 * time.Minute
)

// Failure names which check rejected a request. It is the difference between an afternoon and a
// minute when a signature stops matching.
type Failure string

const (
	FailMalformedHeader Failure = "malformed_authorization_header"
	FailUnknownAlgo     Failure = "unknown_algorithm"
	FailMalformedCred   Failure = "malformed_credential_scope"
	FailMissingDate     Failure = "missing_date_header"
	FailMalformedDate   Failure = "malformed_date_header"
	FailDateMismatch    Failure = "date_header_disagrees_with_credential_scope"
	FailSkew            Failure = "timestamp_outside_skew_window"
	FailScopeMismatch   Failure = "credential_scope_is_for_a_different_region_or_service"
	FailBodyHash        Failure = "body_hash_does_not_match_body"
	FailSignature       Failure = "signature_does_not_match"
)

// Error is a verification failure. Message is safe to log; Failure is safe to return to a caller
// only in development.
type Error struct {
	Failure Failure
	Detail  string
}

func (e *Error) Error() string { return fmt.Sprintf("signing: %s: %s", e.Failure, e.Detail) }

func failf(f Failure, format string, args ...any) *Error {
	return &Error{Failure: f, Detail: fmt.Sprintf(format, args...)}
}

// Credentials are what a client signs with.
type Credentials struct {
	AccessKeyID string
	Secret      []byte
}

// Scope is the part of the credential that says which key, when, where and for what.
type Scope struct {
	AccessKeyID string
	Date        string // yyyymmdd, must agree with the timestamp
	Region      string
	Service     string
}

func (s Scope) String() string {
	return strings.Join([]string{s.AccessKeyID, s.Date, s.Region, s.Service}, "/")
}

// scopeSuffix is everything after the access key id — the part that binds a signature to a region
// and a service.
func (s Scope) scopeSuffix() string {
	return strings.Join([]string{s.Date, s.Region, s.Service}, "/")
}

// Request is the subset of an HTTP request that gets signed. It is a plain struct rather than an
// *http.Request so that signing is testable without a server and identical on both sides.
type Request struct {
	Method string
	Path   string
	Query  url.Values
	Body   []byte
}

// RequestFromHTTP builds a Request from a server-side *http.Request. The body must already be read
// — the caller owns that, because it also has to hand the same bytes to the handler.
func RequestFromHTTP(r *http.Request, body []byte) Request {
	return Request{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Body: body}
}

// Signature is a parsed Authorization header.
type Signature struct {
	Scope     Scope
	Signature string // lowercase hex
}

// ---------------------------------------------------------------------------
// Canonicalisation
// ---------------------------------------------------------------------------

// CanonicalString builds the exact bytes both sides MAC over.
//
// Both sides must produce this identically or nothing works, which is why it is one function used
// by the signer and the verifier rather than two implementations that agree until they do not.
func CanonicalString(req Request, scope Scope, timestamp string) string {
	var b strings.Builder
	b.WriteString(Algorithm)
	b.WriteByte('\n')
	b.WriteString(strings.ToUpper(req.Method))
	b.WriteByte('\n')
	b.WriteString(canonicalPath(req.Path))
	b.WriteByte('\n')
	b.WriteString(canonicalQuery(req.Query))
	b.WriteByte('\n')
	b.WriteString(timestamp)
	b.WriteByte('\n')
	b.WriteString(HashBody(req.Body))
	b.WriteByte('\n')
	b.WriteString(scope.String())
	return b.String()
}

// canonicalPath normalises the path. An empty path is "/", and each segment is escaped so that a
// path differing only in encoding produces one canonical form — otherwise "/a b" and "/a%20b" sign
// differently and the caller gets an unexplained 403.
func canonicalPath(p string) string {
	if p == "" {
		return "/"
	}
	segments := strings.Split(p, "/")
	for i, s := range segments {
		segments[i] = uriEncode(s)
	}
	return strings.Join(segments, "/")
}

// canonicalQuery sorts by key and then by value, so parameter order on the wire cannot change the
// signature. Go's url.Values is a map and has no order of its own; relying on one is a bug that
// appears roughly one request in a hundred.
func canonicalQuery(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	pairs := make([]string, 0, len(q))
	for key, values := range q {
		sorted := append([]string(nil), values...)
		sort.Strings(sorted)
		for _, v := range sorted {
			pairs = append(pairs, uriEncode(key)+"="+uriEncode(v))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// uriEncode is RFC 3986 unreserved-set encoding: everything except A-Z a-z 0-9 - _ . ~ is
// percent-encoded with uppercase hex. Notably this encodes "+" and " " the same way rather than
// treating "+" as a space, which is where url.QueryEscape would disagree with every other
// implementation.
func uriEncode(s string) string {
	const upperhex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(upperhex[c>>4])
			b.WriteByte(upperhex[c&15])
		}
	}
	return b.String()
}

// HashBody is the hex sha256 of a payload. An empty body hashes to the sha256 of the empty string
// rather than to a sentinel, so there is one rule instead of two.
func HashBody(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

// Sign returns the Authorization header value and the headers a client must send with it.
func Sign(req Request, cred Credentials, region, service string, now time.Time) (auth string, headers map[string]string) {
	ts := now.UTC().Format(TimeFormat)
	scope := Scope{
		AccessKeyID: cred.AccessKeyID,
		Date:        ts[:8],
		Region:      region,
		Service:     service,
	}

	sig := mac(cred.Secret, CanonicalString(req, scope, ts))

	auth = fmt.Sprintf("%s Credential=%s, Signature=%s", Algorithm, scope.String(), sig)
	headers = map[string]string{
		DateHeader:          ts,
		ContentSHA256Header: HashBody(req.Body),
	}
	return auth, headers
}

func mac(secret []byte, message string) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

// ParseAuthorization reads the header without needing a secret, because the front door has to know
// which access key id to look up before it can verify anything.
func ParseAuthorization(header string) (Signature, error) {
	algo, rest, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok {
		return Signature{}, failf(FailMalformedHeader, "expected %q followed by parameters", Algorithm)
	}
	if algo != Algorithm {
		return Signature{}, failf(FailUnknownAlgo, "got %q, want %q", algo, Algorithm)
	}

	var sig Signature
	var credSeen, sigSeen bool
	for _, part := range strings.Split(rest, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return Signature{}, failf(FailMalformedHeader, "parameter %q is not key=value", part)
		}
		switch key {
		case "Credential":
			fields := strings.Split(value, "/")
			if len(fields) != 4 {
				return Signature{}, failf(FailMalformedCred,
					"expected <key>/<yyyymmdd>/<region>/<service>, got %q", value)
			}
			sig.Scope = Scope{AccessKeyID: fields[0], Date: fields[1], Region: fields[2], Service: fields[3]}
			credSeen = true
		case "Signature":
			sig.Signature = value
			sigSeen = true
		default:
			// Unknown parameters are ignored rather than rejected, so a later scheme can add one
			// without every existing verifier failing closed on it.
		}
	}
	if !credSeen || !sigSeen {
		return Signature{}, failf(FailMalformedHeader, "both Credential and Signature are required")
	}
	return sig, nil
}

// VerifyInput is everything Verify needs that does not come from the request body itself.
type VerifyInput struct {
	Request   Request
	Signature Signature

	// DateHeaderValue is the X-Dariya-Date the client sent.
	DateHeaderValue string

	// ContentSHA256Header is optional. When present it must match the body, which turns a body
	// mangled in transit into a specific error instead of a generic signature mismatch.
	ContentSHA256Header string

	Secret  []byte
	Region  string
	Service string
	Now     time.Time
}

// Verify checks a signed request. It returns nil or an *Error naming the failed check.
//
// Order matters: everything cheap and unambiguous is checked before the MAC, so that a clock skew
// or a mangled body is reported as itself rather than as "signature does not match" — the error
// that sends people looking in the wrong place for an afternoon.
func Verify(in VerifyInput) error {
	if in.DateHeaderValue == "" {
		return failf(FailMissingDate, "%s is required", DateHeader)
	}
	ts, err := time.Parse(TimeFormat, in.DateHeaderValue)
	if err != nil {
		return failf(FailMalformedDate, "%s=%q is not %s", DateHeader, in.DateHeaderValue, TimeFormat)
	}

	// The date inside the credential scope is part of the signed string, so a mismatch would fail
	// the MAC anyway — reported here to say which of the two the client got wrong.
	if got, want := in.Signature.Scope.Date, in.DateHeaderValue[:8]; got != want {
		return failf(FailDateMismatch, "credential scope date is %s, %s says %s", got, DateHeader, want)
	}

	if skew := in.Now.UTC().Sub(ts); skew > MaxSkew || skew < -MaxSkew {
		return failf(FailSkew, "request is %s away from server time, limit is %s",
			skew.Round(time.Second), MaxSkew)
	}

	if in.Signature.Scope.Region != in.Region || in.Signature.Scope.Service != in.Service {
		return failf(FailScopeMismatch, "signed for %s/%s, this endpoint is %s/%s",
			in.Signature.Scope.Region, in.Signature.Scope.Service, in.Region, in.Service)
	}

	if in.ContentSHA256Header != "" {
		if got := HashBody(in.Request.Body); got != in.ContentSHA256Header {
			return failf(FailBodyHash, "%s says %s, body hashes to %s",
				ContentSHA256Header, in.ContentSHA256Header, got)
		}
	}

	expected := mac(in.Secret, CanonicalString(in.Request, in.Signature.Scope, in.DateHeaderValue))

	// Constant time: a byte-by-byte comparison leaks how much of a guessed signature was right,
	// which is enough to forge one given enough attempts.
	if !hmac.Equal([]byte(expected), []byte(in.Signature.Signature)) {
		return failf(FailSignature, "computed %s…", expected[:8])
	}
	return nil
}
