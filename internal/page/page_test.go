package page

import "testing"

func TestRoundTrip(t *testing.T) {
	for _, key := range []string{"000000000001", "arn:dariya:iam:hind-1:000000000001:user/x"} {
		got, err := Decode(Encode(key))
		if err != nil {
			t.Fatalf("Decode(Encode(%q)): %v", key, err)
		}
		if got != key {
			t.Errorf("got %q, want %q", got, key)
		}
	}
}

func TestEmptyMeansExhausted(t *testing.T) {
	if Encode("") != "" {
		t.Error("empty key should encode to empty token")
	}
	got, err := Decode("")
	if err != nil || got != "" {
		t.Errorf("Decode(\"\") = %q, %v", got, err)
	}
}

// A caller loops until the token comes back empty. A garbage token that silently decoded to "start
// from the beginning" would turn that loop into an infinite one.
func TestBadTokenIsAnError(t *testing.T) {
	for _, bad := range []string{"!!!not base64!!!", "aGVsbG8"} { // second decodes, wrong prefix
		if _, err := Decode(bad); err == nil {
			t.Errorf("Decode(%q) succeeded, want error", bad)
		}
	}
}

func TestLimitClamps(t *testing.T) {
	if n, _ := Limit(0); n != DefaultLimit {
		t.Errorf("Limit(0) = %d, want %d", n, DefaultLimit)
	}
	if n, _ := Limit(10); n != 10 {
		t.Errorf("Limit(10) = %d", n)
	}
	if _, err := Limit(MaxLimit + 1); err == nil {
		t.Error("over-max limit accepted")
	}
	if _, err := Limit(-1); err == nil {
		t.Error("negative limit accepted")
	}
}
