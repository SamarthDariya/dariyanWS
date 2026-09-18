package arn

import (
	"errors"
	"testing"
)

func TestParseRoundTrip(t *testing.T) {
	for _, s := range []string{
		"arn:dariya:kyu:hind-1:000000000001:queue/orders",
		"arn:dariya:func:hind-1:000000000001:function/resize-image",
		"arn:dariya:iam:hind-1:000000000001:user/samarth",
		// An id containing a slash is legal — only the first slash separates type from id.
		"arn:dariya:func:hind-1:000000000001:function/resize-image/v2",
	} {
		a, err := Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		if got := a.String(); got != s {
			t.Errorf("round trip: got %q, want %q", got, s)
		}
	}
}

func TestParseFields(t *testing.T) {
	a := MustParse("arn:dariya:kyu:hind-1:000000000001:queue/orders")
	if a.Service != "kyu" || a.Region != "hind-1" || a.Account != "000000000001" ||
		a.Type != "queue" || a.ID != "orders" {
		t.Fatalf("unexpected fields: %+v", a)
	}
}

func TestParseRejects(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want error
	}{
		{"too few segments", "arn:dariya:kyu:hind-1:000000000001", ErrMalformed},
		{"no arn prefix", "urn:dariya:kyu:hind-1:000000000001:queue/orders", ErrMalformed},
		{"wrong partition", "arn:aws:kyu:hind-1:000000000001:queue/orders", ErrPartition},
		{"empty service", "arn:dariya::hind-1:000000000001:queue/orders", ErrEmptyField},
		{"empty region", "arn:dariya:kyu::000000000001:queue/orders", ErrEmptyField},
		// The case this parser exists for: a short account id must not be accepted, or storage key
		// prefixes stop being a tenant boundary.
		{"short account", "arn:dariya:kyu:hind-1:1:queue/orders", ErrAccountID},
		{"non-digit account", "arn:dariya:kyu:hind-1:00000000000x:queue/orders", ErrAccountID},
		{"no resource type", "arn:dariya:kyu:hind-1:000000000001:orders", ErrNoResource},
		{"empty resource id", "arn:dariya:kyu:hind-1:000000000001:queue/", ErrNoResource},
		{"empty resource type", "arn:dariya:kyu:hind-1:000000000001:/orders", ErrNoResource},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse(c.in); !errors.Is(err, c.want) {
				t.Errorf("Parse(%q) = %v, want %v", c.in, err, c.want)
			}
		})
	}
}

func TestSameAccount(t *testing.T) {
	a := MustParse("arn:dariya:kyu:hind-1:000000000001:queue/orders")
	b := MustParse("arn:dariya:func:hind-1:000000000001:function/f")
	c := MustParse("arn:dariya:func:hind-1:000000000002:function/f")
	if !a.SameAccount(b) {
		t.Error("same account reported different")
	}
	if a.SameAccount(c) {
		t.Error("different accounts reported same")
	}
}
