// Package page encodes and decodes the opaque pagination cursors in common.proto.
//
// Opaque means the client cannot read it, which means the client cannot depend on it, which means
// the encoding can change later without a contract break. Today a cursor is the last key seen;
// tomorrow it may carry a snapshot id or an expiry.
package page

import (
	"encoding/base64"
	"strings"

	"dariyanws/internal/apierr"
)

// DefaultLimit applies when a request asks for zero. MaxLimit caps what a caller can ask for, so a
// single List cannot be turned into a full table scan by setting max_results to a million.
const (
	DefaultLimit = 50
	MaxLimit     = 500
)

const prefix = "v1:"

// Encode makes a cursor from the last key of the page just returned. An empty key means the listing
// is exhausted and yields an empty token.
func Encode(lastKey string) string {
	if lastKey == "" {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(prefix + lastKey))
}

// Decode reads a cursor. A token that does not decode is a ValidationException rather than a silent
// restart from the beginning: a caller looping until the token is empty would otherwise loop
// forever on a corrupted one.
func Decode(token string) (string, error) {
	if token == "" {
		return "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", apierr.Validation("next_token is not a valid pagination token")
	}
	s := string(raw)
	if !strings.HasPrefix(s, prefix) {
		return "", apierr.Validation("next_token is not a valid pagination token")
	}
	return strings.TrimPrefix(s, prefix), nil
}

// Limit clamps a requested page size.
func Limit(requested int32) (int, error) {
	switch {
	case requested < 0:
		return 0, apierr.Validation("max_results must not be negative, got %d", requested)
	case requested == 0:
		return DefaultLimit, nil
	case requested > MaxLimit:
		return 0, apierr.Validation("max_results must be at most %d, got %d", MaxLimit, requested)
	default:
		return int(requested), nil
	}
}
