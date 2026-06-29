package auth

import (
	"testing"
	"time"
)

func TestTOTPRoundTrip(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	code, err := totpAt(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != totpDigits {
		t.Fatalf("code length = %d, want %d", len(code), totpDigits)
	}
	if !ValidateTOTP(secret, code) {
		t.Error("freshly generated code should validate")
	}
}

func TestTOTPRejectsWrongCode(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	if ValidateTOTP(secret, "000000") && func() bool { c, _ := totpAt(secret, time.Now()); return c != "000000" }() {
		t.Error("a wrong code should not validate")
	}
	if ValidateTOTP(secret, "12345") {
		t.Error("malformed (5-digit) code must be rejected")
	}
}

func TestTOTPSkewWindow(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	// Code from the previous step must still validate (±1 window).
	prev, _ := totpAt(secret, time.Now().Add(-totpPeriod))
	if !ValidateTOTP(secret, prev) {
		t.Error("previous-step code should validate within skew window")
	}
	// A code two steps old should not.
	old, _ := totpAt(secret, time.Now().Add(-3*totpPeriod))
	cur, _ := totpAt(secret, time.Now())
	if old != cur && ValidateTOTP(secret, old) {
		t.Error("code outside the skew window must be rejected")
	}
}

func TestOtpauthURL(t *testing.T) {
	u := OtpauthURL("ABCD", "admin", "LinkGuard FW")
	for _, want := range []string{"otpauth://totp/", "secret=ABCD", "issuer=LinkGuard", "digits=6", "period=30"} {
		if !contains(u, want) {
			t.Errorf("otpauth URL missing %q: %s", want, u)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
