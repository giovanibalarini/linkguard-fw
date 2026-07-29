package handlers

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteInternalErrorNeverLeaksRawErrorText(t *testing.T) {
	w := httptest.NewRecorder()
	writeInternalError(w, errors.New("stat /var/lib/linkguard-fw/linkguard.db: permission denied"))
	if w.Code != 500 {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "permission denied") || strings.Contains(body, "/var/lib") {
		t.Fatalf("response leaked internal error detail: %s", body)
	}
}

func TestClampLimitUsesDefaultWhenEmpty(t *testing.T) {
	if got := clampLimit("", 100, 1000); got != 100 {
		t.Fatalf("clampLimit(\"\", 100, 1000) = %d, want 100", got)
	}
}

func TestClampLimitUsesDefaultWhenInvalid(t *testing.T) {
	if got := clampLimit("not-a-number", 100, 1000); got != 100 {
		t.Fatalf("clampLimit invalid input = %d, want default 100", got)
	}
}

func TestClampLimitUsesDefaultWhenZeroOrNegative(t *testing.T) {
	if got := clampLimit("0", 100, 1000); got != 100 {
		t.Fatalf("clampLimit(\"0\", ...) = %d, want default 100", got)
	}
	if got := clampLimit("-5", 100, 1000); got != 100 {
		t.Fatalf("clampLimit(\"-5\", ...) = %d, want default 100", got)
	}
}

func TestClampLimitPassesThroughValidValue(t *testing.T) {
	if got := clampLimit("250", 100, 1000); got != 250 {
		t.Fatalf("clampLimit(\"250\", ...) = %d, want 250", got)
	}
}

func TestClampLimitCapsAtCeiling(t *testing.T) {
	if got := clampLimit("999999999", 100, 1000); got != 1000 {
		t.Fatalf("clampLimit(\"999999999\", 100, 1000) = %d, want capped at 1000", got)
	}
}
