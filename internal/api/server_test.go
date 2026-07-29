package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestMaxBodySizeSkipsBackupRestorePath proves the global maxBodySize
// middleware does not wrap the body for /api/backup/restore, so a body
// between the global default (2MB) and BackupHandler.Restore's own limit
// (32MB) still reaches the handler intact. http.MaxBytesReader nests rather
// than replaces: calling it a second time on an already-wrapped r.Body
// enforces the *smaller* of the two limits, regardless of which was applied
// most recently. If the global middleware wrapped this route too, a body
// like this (well under 32MB, over 2MB) would be rejected — which is
// exactly what this test guards against.
func TestMaxBodySizeSkipsBackupRestorePath(t *testing.T) {
	const globalLimit = 2 << 20   // 2MB, same as the production default
	const handlerLimit = 32 << 20 // 32MB, same as BackupHandler.Restore

	payload := bytes.Repeat([]byte("x"), 5<<20) // 5MB: over global, under handler

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, handlerLimit)
		got, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(got) != len(payload) {
			http.Error(w, "short read", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := maxBodySize(globalLimit)(inner)

	req := httptest.NewRequest(http.MethodPost, backupRestorePath, bytes.NewReader(payload))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for a %d-byte restore body (over the 2MB global cap, under the 32MB handler cap), got %d: %s", len(payload), w.Code, w.Body.String())
	}
}

// TestMaxBodySizeRejectsOverGlobalLimitForOtherPaths confirms the global
// middleware still enforces its cap for every route that doesn't manage its
// own, larger limit.
func TestMaxBodySizeRejectsOverGlobalLimitForOtherPaths(t *testing.T) {
	const globalLimit = 2 << 20
	payload := bytes.Repeat([]byte("x"), 3<<20) // 3MB, over the 2MB global cap

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := maxBodySize(globalLimit)(inner)

	req := httptest.NewRequest(http.MethodPost, "/api/whatever", bytes.NewReader(payload))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a body over the global 2MB cap, got %d", w.Code)
	}
}
