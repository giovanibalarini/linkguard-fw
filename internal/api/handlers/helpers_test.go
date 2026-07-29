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
