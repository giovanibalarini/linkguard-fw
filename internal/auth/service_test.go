package auth

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func TestLoginPaysBcryptCostEvenForNonexistentUser(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	svc := NewService(db, "test-secret-at-least-32-bytes-long-xxxx", nil)

	start := time.Now()
	_, _, _ = svc.Login("usuario-que-nao-existe", "qualquer-senha", "")
	elapsed := time.Since(start)

	// bcrypt.DefaultCost typically costs on the order of tens of milliseconds;
	// a nonexistent-user short-circuit before the fix returns in microseconds.
	// This is a coarse check, not a precise timing-attack proof — it just
	// confirms the dummy-hash comparison actually runs.
	if elapsed < 10*time.Millisecond {
		t.Fatalf("Login for a nonexistent user returned too fast (%v) — looks like it's still short-circuiting before paying bcrypt cost", elapsed)
	}
}
