# Cofre de segredos — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the three secrets currently living in the `settings` table (GitHub PAT, notification channel credentials, per-user TOTP secrets) into a separate, encrypted `secrets` table, so a future secret can never leak through `ExportSettings()` by omission — the guarantee is structural, not a maintained exclusion list.

**Architecture:** `internal/secrets` owns a new `secrets` table and an AES-256-GCM cipher keyed by a 32-byte file (`/etc/linkguard-fw/secret.key`, generated on first boot, never derived from another secret). A `Secrets` interface (`Set`/`Get`/`Status`/`Delete`) is the only way in or out. Migration is automatic and idempotent, moving the three existing secrets on boot and deleting them from `settings`.

**Tech Stack:** Go 1.25 stdlib only (`crypto/aes`, `crypto/cipher`, `crypto/rand`) — no new dependency.

## Global Constraints

- The key file is generated with `crypto/rand`, written with mode `0600`, and the service refuses to start if it exists but is unreadable — never silently treat unreadable secrets as "not configured".
- The key is never derived from `jwt_secret` or any other existing value — independent lifecycle (see spec §4).
- Migration runs once per boot, is idempotent, and moves data (copy to `secrets`, delete from `settings`) rather than merely reading it — a second boot must find nothing left to migrate.
- `internal/secrets` must not import any package that could create a cycle with `internal/storage` (it depends on `storage.DB`, storage must not depend on it).
- gofmt must pass on every Go file touched.

---

### Task 1: Schema — `secrets` table

**Files:**
- Modify: `internal/storage/storage.go`
- Test: `internal/storage/storage_test.go`

**Interfaces:**
- Produces: table `secrets(name TEXT PRIMARY KEY, nonce BLOB, ciphertext BLOB, updated_at DATETIME)`, queryable via `db.Conn()`.

- [ ] **Step 1: Add the schema constant**

In `internal/storage/storage.go`, add near `createSettingsTable`:

```go
const createSecretsTable = `
CREATE TABLE IF NOT EXISTS secrets (
    name       TEXT PRIMARY KEY,
    nonce      BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    updated_at DATETIME NOT NULL
);`
```

- [ ] **Step 2: Register the migration**

In `migrate()`, add `createSecretsTable` to the `migrations` slice, after `createSettingsTable`:

```go
	migrations := []string{
		createUsersTable,
		createRolesTable,
		createRolePermissionsTable,
		createUserRolesTable,
		createLinksTable,
		createAlertsTable,
		createAuditLogsTable,
		createFailoverEventsTable,
		createRoutingPoliciesTable,
		createIptablesBackupsTable,
		createSettingsTable,
		createSecretsTable,
		createTrafficSamplesTable,
		createHostMetadataTable,
		createDHCPReservationsTable,
		createDNSBlocklistTable,
		insertDefaultAdmin,
	}
```

(If Project 1's plan already ran and added `createMetricSamplesTable`/`createStateIntervalsTable`/`createStateIntervalsOpenIndex` to this same slice, insert `createSecretsTable` alongside them in whatever order — table creation order among independent tables does not matter.)

- [ ] **Step 3: Write the failing test**

Add to `internal/storage/storage_test.go`:

```go
func TestSecretsTableExists(t *testing.T) {
	db := newTestDB(t)

	_, err := db.Conn().Exec(`INSERT INTO secrets (name, nonce, ciphertext, updated_at)
		VALUES (?, ?, ?, ?)`, "test_key", []byte("012345678901"), []byte("ciphertext"), time.Now())
	if err != nil {
		t.Fatalf("insert secrets: %v", err)
	}
}
```

- [ ] **Step 4: Run test to verify it fails, then passes**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/storage/... -run TestSecretsTableExists -v
```

Expected before Steps 1–2: FAIL with `no such table: secrets`. After: PASS.

- [ ] **Step 5: gofmt and commit**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
gofmt -w internal/storage/storage.go internal/storage/storage_test.go
git add internal/storage/storage.go internal/storage/storage_test.go
git commit -m "feat(storage): add secrets table"
```

---

### Task 2: `internal/secrets` — key file, cipher, `Secrets` interface

**Files:**
- Create: `internal/secrets/keyfile.go`
- Create: `internal/secrets/service.go`
- Test: `internal/secrets/service_test.go`

**Interfaces:**
- Consumes: `*storage.DB` with raw `db.Conn()` access (no repository functions needed — this package owns its table directly, same pattern as `internal/monitoring` owning its config in `settings`).
- Produces:
  - `type Secrets interface { Set(name, plaintext string) error; Get(name string) (string, error); Status(name string) (configured bool, hint string); Delete(name string) error }`
  - `func LoadOrGenerateKey(path string) ([]byte, error)`
  - `func NewService(db *storage.DB, key []byte) *Service` (implements `Secrets`)

- [ ] **Step 1: Write the failing key-file test**

Create `internal/secrets/keyfile_test.go`:

```go
package secrets_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
)

func TestLoadOrGenerateKeyCreatesOnFirstCall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")

	key1, err := secrets.LoadOrGenerateKey(path)
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	if len(key1) != 32 {
		t.Fatalf("expected 32-byte key, got %d bytes", len(key1))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected mode 0600, got %v", info.Mode().Perm())
	}
}

func TestLoadOrGenerateKeyReturnsExistingKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")

	key1, err := secrets.LoadOrGenerateKey(path)
	if err != nil {
		t.Fatalf("first LoadOrGenerateKey: %v", err)
	}
	key2, err := secrets.LoadOrGenerateKey(path)
	if err != nil {
		t.Fatalf("second LoadOrGenerateKey: %v", err)
	}
	if string(key1) != string(key2) {
		t.Fatal("expected the second call to return the same key, not regenerate")
	}
}

func TestLoadOrGenerateKeyRejectsWrongSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(path, []byte("too-short"), 0600); err != nil {
		t.Fatalf("seed bad key file: %v", err)
	}

	if _, err := secrets.LoadOrGenerateKey(path); err == nil {
		t.Fatal("expected an error for a key file of the wrong size")
	}
}
```

- [ ] **Step 2: Implement the key file**

Create `internal/secrets/keyfile.go`:

```go
// Package secrets stores credentials separately from configuration. The
// separation is the guarantee: internal/storage's ExportSettings() only ever
// reads the settings table, so a value stored here structurally cannot leak
// through a backup export, no matter what future feature adds a new secret.
//
// This does not protect against root on the machine — the service runs as
// root and can read both the key file and the database. It protects against
// the real vectors for this installation: a shared backup file, a copied
// .db, a decommissioned disk.
package secrets

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

const keySize = 32 // AES-256

// LoadOrGenerateKey reads the encryption key from path, generating and
// writing a new random one on first run. The key is never derived from any
// other secret (e.g. jwt_secret) — rotating one must never invalidate the
// other. A key file that exists but is unreadable or the wrong size is a
// fatal error: the service must not start and silently treat every secret as
// "not configured".
func LoadOrGenerateKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if len(data) != keySize {
			return nil, fmt.Errorf("secret key file %s is %d bytes, expected %d", path, len(data), keySize)
		}
		return data, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read secret key file %s: %w", path, err)
	}

	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate secret key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create secret key directory: %w", err)
	}
	if err := os.WriteFile(path, key, 0600); err != nil {
		return nil, fmt.Errorf("write secret key file %s: %w", path, err)
	}
	return key, nil
}
```

- [ ] **Step 3: Run the key-file tests to verify they fail, then pass**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/secrets/... -run TestLoadOrGenerateKey -v
```

Expected before Step 2: FAIL (package does not exist). After: PASS.

- [ ] **Step 4: Write the failing service tests**

Create `internal/secrets/service_test.go`:

```go
package secrets_test

import (
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func newTestSvc(t *testing.T) *secrets.Service {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	key, err := secrets.LoadOrGenerateKey(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	return secrets.NewService(db, key)
}

func TestSetThenGetRoundTrips(t *testing.T) {
	svc := newTestSvc(t)

	if err := svc.Set("github_update_token", "ghp_realvalue"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := svc.Get("github_update_token")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "ghp_realvalue" {
		t.Fatalf("expected round-trip value, got %q", got)
	}
}

func TestGetUnsetReturnsEmpty(t *testing.T) {
	svc := newTestSvc(t)

	got, err := svc.Get("never_set")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty string for unset secret, got %q", got)
	}
}

func TestStatusReflectsConfiguredAndHint(t *testing.T) {
	svc := newTestSvc(t)

	configured, hint := svc.Status("ai_api_token")
	if configured {
		t.Fatal("expected not configured before Set")
	}
	if hint != "" {
		t.Fatalf("expected empty hint before Set, got %q", hint)
	}

	if err := svc.Set("ai_api_token", "sk-ant-abcd1234wxyz7f2a"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	configured, hint = svc.Status("ai_api_token")
	if !configured {
		t.Fatal("expected configured after Set")
	}
	if hint != "sk-ant-…7f2a" {
		t.Fatalf("expected hint to show only a suffix, got %q", hint)
	}
}

func TestDeleteRemovesSecret(t *testing.T) {
	svc := newTestSvc(t)

	_ = svc.Set("notifications", `{"webhook":{"url":"https://x"}}`)
	if err := svc.Delete("notifications"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	configured, _ := svc.Status("notifications")
	if configured {
		t.Fatal("expected not configured after Delete")
	}
}

func TestEachSetUsesAFreshNonce(t *testing.T) {
	svc := newTestSvc(t)

	_ = svc.Set("k", "value-one")
	nonce1 := svc.NonceForTest("k")
	_ = svc.Set("k", "value-two")
	nonce2 := svc.NonceForTest("k")

	if string(nonce1) == string(nonce2) {
		t.Fatal("expected a fresh nonce on every Set — reusing a GCM nonce breaks its authentication guarantee")
	}
}

func TestTamperedCiphertextFailsToDecrypt(t *testing.T) {
	svc := newTestSvc(t)

	_ = svc.Set("k", "original")
	svc.CorruptCiphertextForTest("k")

	if _, err := svc.Get("k"); err == nil {
		t.Fatal("expected Get to fail on tampered ciphertext, not silently return corrupted data")
	}
}
```

- [ ] **Step 5: Implement the service**

Create `internal/secrets/service.go`:

```go
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"fmt"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// Secrets is the only way credentials enter or leave storage. There is
// deliberately no "list all" or "export" method — callers must know the exact
// name they want, which keeps a future accidental dump structurally hard.
type Secrets interface {
	Set(name, plaintext string) error
	Get(name string) (string, error)
	Status(name string) (configured bool, hint string)
	Delete(name string) error
}

// Service is the AES-256-GCM-backed implementation, storing ciphertext in the
// secrets table.
type Service struct {
	db  *storage.DB
	gcm cipher.AEAD
}

// NewService creates a secrets Service. key must be exactly 32 bytes (see
// LoadOrGenerateKey).
func NewService(db *storage.DB, key []byte) *Service {
	block, err := aes.NewCipher(key)
	if err != nil {
		// key is always 32 bytes from LoadOrGenerateKey; a bad key here is a
		// programming error, not a runtime condition to recover from.
		panic(fmt.Sprintf("secrets: invalid key: %v", err))
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(fmt.Sprintf("secrets: create GCM: %v", err))
	}
	return &Service{db: db, gcm: gcm}
}

// Set encrypts plaintext with a fresh random nonce and upserts it.
func (s *Service) Set(name, plaintext string) error {
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := s.gcm.Seal(nil, nonce, []byte(plaintext), nil)

	_, err := s.db.Conn().Exec(`
		INSERT INTO secrets (name, nonce, ciphertext, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET nonce=excluded.nonce, ciphertext=excluded.ciphertext, updated_at=excluded.updated_at`,
		name, nonce, ciphertext, time.Now())
	return err
}

// Get decrypts and returns the plaintext, or "" if name was never set. A
// tampered or corrupted ciphertext returns an error rather than garbage —
// GCM is authenticated, so decryption failure is detectable, and this
// function never masks that as "not configured".
func (s *Service) Get(name string) (string, error) {
	var nonce, ciphertext []byte
	err := s.db.Conn().QueryRow(`SELECT nonce, ciphertext FROM secrets WHERE name = ?`, name).
		Scan(&nonce, &ciphertext)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	plaintext, err := s.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt secret %q: %w", name, err)
	}
	return string(plaintext), nil
}

// Status reports whether name is configured and, if so, a display hint
// (the last 4 characters, prefixed with an ellipsis) — never the full value.
func (s *Service) Status(name string) (configured bool, hint string) {
	val, err := s.Get(name)
	if err != nil || val == "" {
		return false, ""
	}
	if len(val) <= 4 {
		return true, "…" + val
	}
	return true, "…" + val[len(val)-4:]
}

// Delete removes a secret. No-op if it was never set.
func (s *Service) Delete(name string) error {
	_, err := s.db.Conn().Exec(`DELETE FROM secrets WHERE name = ?`, name)
	return err
}

// NonceForTest exposes the stored nonce for a name, for testing nonce
// uniqueness across Set calls. Test-only.
func (s *Service) NonceForTest(name string) []byte {
	var nonce []byte
	_ = s.db.Conn().QueryRow(`SELECT nonce FROM secrets WHERE name = ?`, name).Scan(&nonce)
	return nonce
}

// CorruptCiphertextForTest flips a byte of the stored ciphertext, simulating
// tampering or disk corruption, so tests can verify Get fails loudly instead
// of returning garbage. Test-only.
func (s *Service) CorruptCiphertextForTest(name string) {
	var ciphertext []byte
	_ = s.db.Conn().QueryRow(`SELECT ciphertext FROM secrets WHERE name = ?`, name).Scan(&ciphertext)
	if len(ciphertext) == 0 {
		return
	}
	ciphertext[0] ^= 0xFF
	_, _ = s.db.Conn().Exec(`UPDATE secrets SET ciphertext = ? WHERE name = ?`, ciphertext, name)
}
```

- [ ] **Step 6: Run tests to verify they fail, then pass**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/secrets/... -v
```

Expected before Step 5: FAIL (`secrets.Service` undefined). After: all PASS, including Step 3's key-file tests (no regression).

- [ ] **Step 7: Fix the hint format bug you'll hit in Step 6**

The test `TestStatusReflectsConfiguredAndHint` expects `hint == "sk-ant-…7f2a"` (prefix preserved, suffix shown), but the implementation in Step 5 produces `"…7f2a"` (no prefix). Reconcile by using the exact hint format the spec calls for — prefix up to a separator plus the last 4 characters. Replace `Status` in `internal/secrets/service.go`:

```go
// Status reports whether name is configured and, if so, a display hint. The
// hint keeps everything up to and including the first "-" (e.g. "sk-ant-"),
// replaces the middle with "…", and shows the last 4 characters — enough for
// the admin to recognize which token it is without ever seeing the value.
func (s *Service) Status(name string) (configured bool, hint string) {
	val, err := s.Get(name)
	if err != nil || val == "" {
		return false, ""
	}
	prefix := ""
	if idx := strings.Index(val, "-"); idx > 0 && idx < 12 {
		prefix = val[:idx+1]
	}
	suffix := val
	if len(val) > 4 {
		suffix = val[len(val)-4:]
	}
	return true, prefix + "…" + suffix
}
```

Add `"strings"` to the imports in `internal/secrets/service.go`.

- [ ] **Step 8: Re-run tests to confirm the fix**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/secrets/... -v
```

Expected: all PASS, including `TestStatusReflectsConfiguredAndHint` now matching `"sk-ant-…7f2a"` exactly.

- [ ] **Step 9: gofmt, vet, commit**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
gofmt -w internal/secrets/
go vet ./internal/secrets/...
git add internal/secrets/
git commit -m "feat(secrets): AES-256-GCM vault with Set/Get/Status/Delete"
```

---

### Task 3: Migration — move the 3 existing secrets out of `settings`

**Files:**
- Modify: `internal/storage/storage.go`
- Test: `internal/storage/storage_test.go`

**Interfaces:**
- Consumes: `secrets.Secrets` (Task 2), `db.conn *sql.DB`.
- Produces: `func MigrateSettingsToSecrets(db *DB, sec SecretsSetter) error` — a package-level function (not a `*DB` method, since it needs the `secrets.Service`, which would create an import cycle if `internal/storage` imported `internal/secrets`). `SecretsSetter` is a minimal local interface so `internal/storage` does not need to import `internal/secrets` at all.

- [ ] **Step 1: Add the migration function with a local interface (no import cycle)**

In `internal/storage/repository.go`, add near `ExportSettings` (which Task 4 will also touch):

```go
// SecretsSetter is the minimal write surface MigrateSettingsToSecrets needs.
// Defined here (not imported from internal/secrets) so internal/storage never
// depends on internal/secrets — the dependency runs the other way (secrets
// depends on storage.DB), and this keeps it that way.
type SecretsSetter interface {
	Set(name, plaintext string) error
}

// MigrateSettingsToSecrets moves the legacy secret-shaped settings rows
// (github_update_token, notifications, and every totp_<userID>) into sec,
// then deletes them from settings. Idempotent: a key already absent from
// settings (already migrated on a prior boot) is silently skipped.
func MigrateSettingsToSecrets(db *DB, sec SecretsSetter) error {
	exact := []string{"github_update_token", "notifications"}
	for _, key := range exact {
		if err := migrateOneSetting(db, sec, key); err != nil {
			return err
		}
	}

	rows, err := db.conn.Query(`SELECT key FROM settings WHERE key LIKE 'totp_%'`)
	if err != nil {
		return err
	}
	var totpKeys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			rows.Close()
			return err
		}
		totpKeys = append(totpKeys, k)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, key := range totpKeys {
		if err := migrateOneSetting(db, sec, key); err != nil {
			return err
		}
	}
	return nil
}

func migrateOneSetting(db *DB, sec SecretsSetter, key string) error {
	value, err := db.GetSetting(key)
	if err != nil {
		return err
	}
	if value == "" {
		return nil // never set, or already migrated
	}
	if err := sec.Set(key, value); err != nil {
		return fmt.Errorf("migrate secret %q: %w", key, err)
	}
	_, err = db.conn.Exec(`DELETE FROM settings WHERE key = ?`, key)
	return err
}
```

- [ ] **Step 2: Write the failing test**

Add to `internal/storage/storage_test.go`:

```go
type fakeSecretsSetter struct {
	stored map[string]string
}

func (f *fakeSecretsSetter) Set(name, plaintext string) error {
	if f.stored == nil {
		f.stored = map[string]string{}
	}
	f.stored[name] = plaintext
	return nil
}

func TestMigrateSettingsToSecretsMovesKnownKeys(t *testing.T) {
	db := newTestDB(t)

	_ = db.SetSetting("github_update_token", "ghp_abc")
	_ = db.SetSetting("notifications", `{"webhook":{"url":"https://x"}}`)
	_ = db.SetSetting("totp_user-1", `{"secret":"AAA","enabled":true}`)
	_ = db.SetSetting("totp_user-2", `{"secret":"BBB","enabled":true}`)
	_ = db.SetSetting("monitoring", `{"enabled":true}`) // must NOT be migrated

	fake := &fakeSecretsSetter{}
	if err := storage.MigrateSettingsToSecrets(db, fake); err != nil {
		t.Fatalf("MigrateSettingsToSecrets: %v", err)
	}

	want := map[string]string{
		"github_update_token": "ghp_abc",
		"notifications":       `{"webhook":{"url":"https://x"}}`,
		"totp_user-1":         `{"secret":"AAA","enabled":true}`,
		"totp_user-2":         `{"secret":"BBB","enabled":true}`,
	}
	for k, v := range want {
		if fake.stored[k] != v {
			t.Fatalf("expected %q migrated with value %q, got %q", k, v, fake.stored[k])
		}
	}

	settings, err := db.ExportSettings()
	if err != nil {
		t.Fatalf("ExportSettings: %v", err)
	}
	for k := range want {
		if _, present := settings[k]; present {
			t.Fatalf("expected %q removed from settings after migration, still present", k)
		}
	}
	if settings["monitoring"] != `{"enabled":true}` {
		t.Fatalf("expected non-secret key 'monitoring' untouched, got %q", settings["monitoring"])
	}
}

func TestMigrateSettingsToSecretsIsIdempotent(t *testing.T) {
	db := newTestDB(t)
	_ = db.SetSetting("github_update_token", "ghp_abc")

	fake := &fakeSecretsSetter{}
	if err := storage.MigrateSettingsToSecrets(db, fake); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if err := storage.MigrateSettingsToSecrets(db, fake); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if fake.stored["github_update_token"] != "ghp_abc" {
		t.Fatalf("expected value to survive two migrate calls unchanged, got %q", fake.stored["github_update_token"])
	}
}
```

- [ ] **Step 3: Run tests to verify they fail, then pass**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/storage/... -run TestMigrateSettingsToSecrets -v
```

Expected before Step 1: FAIL (`storage.MigrateSettingsToSecrets` undefined). After: PASS.

- [ ] **Step 4: gofmt and commit**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
gofmt -w internal/storage/repository.go internal/storage/storage_test.go
git add internal/storage/repository.go internal/storage/storage_test.go
git commit -m "feat(storage): migrate legacy settings-table secrets into the vault"
```

---

### Task 4: Simplify `ExportSettings` back to unfiltered (the vault makes the filter obsolete)

**Files:**
- Modify: `internal/storage/repository.go`
- Test: `internal/storage/storage_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: `ExportSettings()` keeps its existing signature; behavior changes because `secrets` is a different table, not because of new filter logic.

- [ ] **Step 1: Remove the interim filter added by the emergency fix**

The emergency fix (commit `188c486`) added `secretSettingKeys`/`secretSettingPrefixes`/`isSecretSettingKey` to `internal/storage/repository.go` as a stopgap. Once Task 3's migration has moved every secret out of `settings` and into `secrets`, that filter has nothing left to catch — remove it so there is exactly one mechanism (table separation), not two overlapping ones. Replace the current `ExportSettings` and the three helpers above it:

```go
// ExportSettings returns every key/value in the settings table (for backups).
// Secrets are never in this table — see internal/secrets — so no filtering is
// needed here; the guarantee is structural, not a maintained exclusion list.
func (db *DB) ExportSettings() (map[string]string, error) {
	rows, err := db.conn.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}
```

Delete the `secretSettingKeys` map, `secretSettingPrefixes` slice, and `isSecretSettingKey` function entirely.

- [ ] **Step 2: Update the existing regression test**

The test `TestExportSettingsExcludesSecrets` (added by the emergency fix) inserted secret-shaped keys directly into `settings` via `db.SetSetting` and asserted they don't appear in the export. That test is now testing the wrong layer — with the vault in place, a secret is never written to `settings` in the first place, so the meaningful test is at the `secrets` package boundary (already covered by Task 2's tests) plus the migration boundary (already covered by Task 3's `TestMigrateSettingsToSecretsMovesKnownKeys`, which asserts the migrated keys are gone from `ExportSettings()`'s output).

Delete `TestExportSettingsExcludesSecrets` from `internal/storage/storage_test.go` — keeping it would require `settings` to keep accepting secret-shaped keys, which contradicts the whole point of this project.

- [ ] **Step 3: Run the full storage suite**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/storage/... -v
```

Expected: all PASS. `TestMigrateSettingsToSecretsMovesKnownKeys` (Task 3) now carries the assertion that used to live in the deleted test.

- [ ] **Step 4: gofmt and commit**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
gofmt -w internal/storage/repository.go internal/storage/storage_test.go
git add internal/storage/repository.go internal/storage/storage_test.go
git commit -m "refactor(storage): drop the interim secret-key filter now the vault owns separation"
```

---

### Task 5: Wire the vault into `main.go` and update the 3 call sites

**Files:**
- Modify: `cmd/linkguard-fw/main.go`
- Modify: `internal/auth/twofa.go`
- Modify: `internal/auth/service.go` (add a `secrets.Secrets` field)
- Modify: `internal/notify/notify.go`
- Modify: `internal/api/handlers/update.go`
- Modify: `internal/api/server.go`
- Test: `internal/auth/twofa_test.go` (extend if present, else note coverage relies on existing 2FA tests still passing), `internal/notify/notify_test.go` (extend if present)

**Interfaces:**
- Consumes: `secrets.Secrets` (Task 2), `secrets.LoadOrGenerateKey` (Task 2), `storage.MigrateSettingsToSecrets` (Task 3).
- Produces: nothing new publicly — every call site keeps its existing exported signature; only the storage backing changes.

- [ ] **Step 1: Load the key and run the migration in `main.go`**

In `cmd/linkguard-fw/main.go`, add the import:

```go
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
```

After `seedDefaultRoles(db)` (around line 115–118), add:

```go
	secretKey, err := secrets.LoadOrGenerateKey("/etc/linkguard-fw/secret.key")
	if err != nil {
		slog.Error("failed to load or generate secret key", "err", err)
		return 1
	}
	secretsSvc := secrets.NewService(db, secretKey)
	if err := storage.MigrateSettingsToSecrets(db, secretsSvc); err != nil {
		slog.Error("failed to migrate legacy secrets", "err", err)
		return 1
	}
```

- [ ] **Step 2: Thread `secretsSvc` into `auth.NewService`**

In `internal/auth/service.go`, add a `secrets.Secrets` field and constructor parameter:

```go
import (
	// ... existing imports ...
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
)

type Service struct {
	db        *storage.DB
	jwtSecret []byte
	sec       secrets.Secrets

	mu       sync.Mutex
	attempts map[string]*attemptInfo
}

// NewService creates an auth Service. sec is where 2FA secrets are stored.
func NewService(db *storage.DB, jwtSecret string, sec secrets.Secrets) *Service {
	return &Service{db: db, jwtSecret: []byte(jwtSecret), sec: sec, attempts: map[string]*attemptInfo{}}
}
```

(The prior body was `return &Service{db: db, jwtSecret: []byte(jwtSecret), attempts: map[string]*attemptInfo{}}` — this adds only `sec: sec`.)

- [ ] **Step 3: Rewrite `twofa.go` to use the vault**

Replace `internal/auth/twofa.go` in full:

```go
package auth

import "encoding/json"

// Two-factor (TOTP) state is stored per user in the secrets vault: key
// "totp_<userID>" → {secret, enabled}. A pending setup is stored with
// enabled=false until the user proves possession with a valid code.

type twoFAState struct {
	Secret  string `json:"secret"`
	Enabled bool   `json:"enabled"`
}

func twoFAKey(userID string) string { return "totp_" + userID }

func (s *Service) getTwoFA(userID string) twoFAState {
	var st twoFAState
	if raw, _ := s.sec.Get(twoFAKey(userID)); raw != "" {
		_ = json.Unmarshal([]byte(raw), &st)
	}
	return st
}

func (s *Service) saveTwoFA(userID string, st twoFAState) error {
	out, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.sec.Set(twoFAKey(userID), string(out))
}

// TwoFAEnabled reports whether the user has activated 2FA.
func (s *Service) TwoFAEnabled(userID string) bool {
	return s.getTwoFA(userID).Enabled
}

// BeginTwoFASetup creates (or replaces) a pending secret and returns the secret
// and otpauth URL for the authenticator app. It does not enable 2FA yet.
func (s *Service) BeginTwoFASetup(userID, username string) (secret, otpauth string, err error) {
	secret, err = GenerateTOTPSecret()
	if err != nil {
		return "", "", err
	}
	if err := s.saveTwoFA(userID, twoFAState{Secret: secret, Enabled: false}); err != nil {
		return "", "", err
	}
	return secret, OtpauthURL(secret, username, "LinkGuard FW"), nil
}

// ActivateTwoFA enables 2FA once the user proves possession with a valid code.
func (s *Service) ActivateTwoFA(userID, code string) error {
	st := s.getTwoFA(userID)
	if st.Secret == "" {
		return errors.New("inicie a configuração de 2FA primeiro")
	}
	if !ValidateTOTP(st.Secret, code) {
		return errors.New("código inválido")
	}
	st.Enabled = true
	return s.saveTwoFA(userID, st)
}

// DisableTwoFA turns off 2FA, requiring a valid current code to do so.
func (s *Service) DisableTwoFA(userID, code string) error {
	st := s.getTwoFA(userID)
	if !st.Enabled {
		return nil
	}
	if !ValidateTOTP(st.Secret, code) {
		return errors.New("código inválido")
	}
	return s.saveTwoFA(userID, twoFAState{})
}
```

This drops the `"errors"` import unless the four functions using `errors.New` are kept — they are, so add `"errors"` back to the import block (it was in the original file; only `getTwoFA`/`saveTwoFA` changed their storage backend, the rest is unchanged):

```go
import (
	"encoding/json"
	"errors"
)
```

- [ ] **Step 4: Rewrite `notify.go`'s settings access**

In `internal/notify/notify.go`, add a `sec secrets.Secrets` field to `Service` and update the constructor:

```go
import (
	// ... existing imports ...
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
)

type Service struct {
	db     *storage.DB
	sec    secrets.Secrets
	client *http.Client
}

// NewService creates a notify Service. sec is where channel credentials
// (SMTP password, Telegram/WhatsApp tokens) are stored.
func NewService(db *storage.DB, sec secrets.Secrets) *Service {
	return &Service{db: db, sec: sec, client: &http.Client{Timeout: 10 * time.Second}}
}
```

(The prior body was `return &Service{db: db, client: &http.Client{Timeout: 10 * time.Second}}` — this adds only `sec: sec`.)

Update `LoadConfig`/`SaveConfig` to use `s.sec` instead of `s.db`:

```go
// LoadConfig reads the persisted configuration (with defaults).
func (s *Service) LoadConfig() Config {
	c := Config{MinSeverity: "warning"}
	if raw, _ := s.sec.Get(settingKey); raw != "" {
		_ = json.Unmarshal([]byte(raw), &c)
	}
	if c.MinSeverity == "" {
		c.MinSeverity = "warning"
	}
	if c.WhatsApp.URL == "" {
		c.WhatsApp.URL = defaultWhatsAppURL
	}
	return c
}

// SaveConfig persists the configuration.
func (s *Service) SaveConfig(c Config) error {
	out, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return s.sec.Set(settingKey, string(out))
}
```

- [ ] **Step 5: Rewrite `update.go`'s token access**

In `internal/api/handlers/update.go`, add a `sec secrets.Secrets` field:

```go
import (
	// ... existing imports ...
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
)

const githubTokenKey = "github_update_token"

// UpdateHandler checks for and installs new releases.
type UpdateHandler struct {
	db  *storage.DB
	sec secrets.Secrets
	svc *updater.Service
}

// NewUpdateHandler creates an UpdateHandler.
func NewUpdateHandler(db *storage.DB, sec secrets.Secrets, svc *updater.Service) *UpdateHandler {
	return &UpdateHandler{db: db, sec: sec, svc: svc}
}

// TokenStatus reports whether a GitHub token is configured (never returns it).
func (h *UpdateHandler) TokenStatus(w http.ResponseWriter, r *http.Request) {
	configured, _ := h.sec.Status(githubTokenKey)
	writeJSON(w, http.StatusOK, map[string]bool{"configured": configured})
}

// SetToken stores (or clears, if empty) the GitHub token used to reach the
// private repo's releases. Required because the repo is private — without it the
// GitHub API answers 404.
func (h *UpdateHandler) SetToken(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	tok := strings.TrimSpace(b.Token)
	if err := h.sec.Set(githubTokenKey, tok); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	auditAction(h.db, r, "update.token.set", "system", "")
	writeJSON(w, http.StatusOK, map[string]bool{"configured": tok != ""})
}
```

`Check` and `Apply` (the rest of the file) are unchanged.

- [ ] **Step 6: Update `server.go`'s inline closure and constructor calls**

In `internal/api/server.go`, `buildRouter` currently builds the updater closure inline:

```go
		updateH := handlers.NewUpdateHandler(s.db, updater.NewService(s.exec, cfg.Version,
			func() string { tok, _ := s.db.GetSetting("github_update_token"); return tok }))
```

`Server` needs a `sec secrets.Secrets` field to make this available. Add the field to the `Server` struct and to `New(...)`'s parameter list and body, following the exact same pattern as every other service field (`db`, `exec`, `linkSvc`, etc. — see the struct and `New` function read at the top of this file). Add the import:

```go
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
```

Add to the `Server` struct:

```go
	sec secrets.Secrets
```

Add `sec secrets.Secrets` as a new parameter to `New(...)` (append it after `mon *monitoring.Collector` in the signature) and set `sec: sec` in the struct literal.

Then replace the closure in `buildRouter`:

```go
		updateH := handlers.NewUpdateHandler(s.db, s.sec, updater.NewService(s.exec, cfg.Version,
			func() string { tok, _ := s.sec.Get("github_update_token"); return tok }))
```

- [ ] **Step 7: Update `main.go`'s call sites for the changed constructors**

In `cmd/linkguard-fw/main.go`:

Replace:
```go
	authSvc := auth.NewService(db, cfg.JWTSecret)
```
with:
```go
	authSvc := auth.NewService(db, cfg.JWTSecret, secretsSvc)
```

Replace:
```go
	notifySvc := notify.NewService(db)
```
with:
```go
	notifySvc := notify.NewService(db, secretsSvc)
```

Also update the `--notify-down` early-exit path (around line 94–106), which constructs its own short-lived `notify.NewService(db)`:

```go
	if *notifyDown {
		db, err := storage.Open(cfg.DBPath)
		if err == nil {
			defer db.Close()
			key, keyErr := secrets.LoadOrGenerateKey("/etc/linkguard-fw/secret.key")
			if keyErr != nil {
				slog.Warn("notify-down: failed to load secret key", "err", keyErr)
				return 1
			}
			sec := secrets.NewService(db, key)
			for _, e := range notify.NewService(db, sec).SendNow("critical",
				"LinkGuard caiu", "O serviço linkguard-fw parou inesperadamente no firewall.") {
				if e != nil {
					slog.Warn("notify-down send failed", "err", e)
				}
			}
		}
		return 0
	}
```

Finally, add `secretsSvc` to the `api.New(...)` call (append after `metricsCollector` in the argument list, matching the new parameter added to `server.go`'s `New` in Step 6):

```go
	server := api.New(api.Config{
		Addr:    cfg.Addr(),
		DryRun:  cfg.DryRun,
		WebFS:   linkguardfw.WebFS,
		PromReg: promReg,
		Version: version,
	}, db, exec, linkSvc, iptSvc, routeSvc, failoverSvc, balancerSvc, alertSvc, authSvc, hostSvc, nftSvc, netSvc, vpnSvc, notifySvc, trafficSvc, sysCollector, rrdSvc, promReg, metricsCollector, secretsSvc)
```

- [ ] **Step 8: Build and fix any remaining call sites**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go build ./... 2>&1
```

Expected: the compiler will point at any test file or additional call site this plan didn't enumerate (e.g. `internal/auth/*_test.go` calling the old 2-argument `auth.NewService`, or `internal/notify/*_test.go` calling the old 1-argument `notify.NewService`). For each one reported: update the call to pass a `secrets.Service` built the same way as `newTestSvc` in `internal/secrets/service_test.go` (Task 2) — open a temp DB, `secrets.LoadOrGenerateKey` into a temp dir, `secrets.NewService(db, key)`. Repeat `go build ./...` until it is clean.

- [ ] **Step 9: Run the full test suite**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./... 2>&1
```

Expected: every package `ok`.

- [ ] **Step 10: Manual verification — 2FA and notifications survive a restart**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
rm -f /tmp/lg-secrets-check.db
LINKGUARD_TEST_DB=/tmp/lg-secrets-check.db go run ./cmd/linkguard-fw/ --dry-run --debug --addr 127.0.0.1 --port 9998 --config /dev/null &
sleep 2
ls -la /etc/linkguard-fw/secret.key 2>&1 || echo "note: needs write access to /etc/linkguard-fw — run as a user that can create it, or adjust the path for local testing"
kill %1
```

If `/etc/linkguard-fw` is not writable in the local dev environment, this step is informational only — the real verification is the automated test suite from Step 9 plus a deploy-time check once this ships (deployment is out of scope for this plan; see the roadmap doc for the staged-deploy decision).

- [ ] **Step 11: gofmt, vet, commit**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
gofmt -w internal/auth/ internal/notify/ internal/api/handlers/update.go internal/api/server.go cmd/linkguard-fw/main.go
go vet ./...
git add internal/auth/ internal/notify/ internal/api/handlers/update.go internal/api/server.go cmd/linkguard-fw/main.go
git commit -m "feat(secrets): wire the vault into auth, notify, and the updater"
```

---

### Task 6: Backup restore — tell the admin what to reconfigure

**Files:**
- Modify: `internal/api/handlers/backup.go`
- Test: `internal/api/handlers/backup_test.go` (create if it does not exist)

**Interfaces:**
- Consumes: `secrets.Secrets.Status` (Task 2) — to check, at restore time, whether the *destination* box already had secrets configured before the restore (they are never touched by restore, since they were never in the backup file).
- Produces: `restoreResult` gains a field `SecretsToReconfigure []string`.

- [ ] **Step 1: Write the failing test**

Create `internal/api/handlers/backup_test.go` (check first with `ls internal/api/handlers/backup_test.go` — if it exists, add to it instead of overwriting):

```go
package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func TestRestoreReportsMissingSecretsToReconfigure(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	key, err := secrets.LoadOrGenerateKey(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	sec := secrets.NewService(db, key)

	h := handlers.NewBackupHandler(db, sec, "test-version")

	body, _ := json.Marshal(map[string]interface{}{
		"version":  "test-version",
		"kind":     "linkguard-fw-backup",
		"settings": map[string]string{},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/backup/restore", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.Restore(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		SecretsToReconfigure []string `json:"secrets_to_reconfigure"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	want := map[string]bool{"github_update_token": true, "notifications": true}
	got := map[string]bool{}
	for _, k := range resp.SecretsToReconfigure {
		got[k] = true
	}
	for k := range want {
		if !got[k] {
			t.Fatalf("expected %q in secrets_to_reconfigure (never configured on this box), got %v", k, resp.SecretsToReconfigure)
		}
	}
}
```

- [ ] **Step 2: Update the handler**

In `internal/api/handlers/backup.go`, add a `sec secrets.Secrets` field:

```go
import (
	// ... existing imports ...
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
)

// BackupHandler exports and restores LinkGuard configuration.
type BackupHandler struct {
	db      *storage.DB
	sec     secrets.Secrets
	version string
}

// NewBackupHandler creates a BackupHandler.
func NewBackupHandler(db *storage.DB, sec secrets.Secrets, version string) *BackupHandler {
	return &BackupHandler{db: db, sec: sec, version: version}
}
```

Update the `restoreResult` type to add the new field:

```go
// restoreResult reports what the restore applied.
type restoreResult struct {
	Settings             int      `json:"settings"`
	Reservations         int      `json:"reservations"`
	Blocklist            int      `json:"blocklist"`
	SecretsToReconfigure []string `json:"secrets_to_reconfigure"`
}
```

At the end of `Restore` (find the point where `restoreResult` is built and written — check the current implementation with `grep -n "restoreResult{" internal/api/handlers/backup.go` first), add the check before writing the response:

```go
	knownSecrets := []string{"github_update_token", "notifications"}
	var missing []string
	for _, name := range knownSecrets {
		if configured, _ := h.sec.Status(name); !configured {
			missing = append(missing, name)
		}
	}
	if missing == nil {
		missing = []string{}
	}
```

Then set `SecretsToReconfigure: missing` on the `restoreResult` value already being constructed, and use `missing` in place of a hardcoded empty value in whatever `writeJSON` call already sends the response.

Note: per-user `totp_*` secrets are deliberately **not** included in `knownSecrets` — 2FA is per-user state, not a single "is it configured" toggle, and a fresh install has no users to compare against yet. Reconfiguring 2FA after a restore is inherently a per-user action (each admin re-does their own setup), not something a single line in this list can represent.

- [ ] **Step 3: Update `server.go`'s constructor call**

In `internal/api/server.go`, find `backupH := handlers.NewBackupHandler(s.db, cfg.Version)` and update to:

```go
		backupH := handlers.NewBackupHandler(s.db, s.sec, cfg.Version)
```

- [ ] **Step 4: Run tests to verify they fail, then pass**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/api/handlers/... -run TestRestoreReportsMissingSecretsToReconfigure -v
```

Expected before Step 2: FAIL (compile error, `NewBackupHandler` argument count). After: PASS.

- [ ] **Step 5: Build, full suite, gofmt, commit**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go build ./... 2>&1
go test ./... 2>&1
gofmt -w internal/api/handlers/backup.go internal/api/handlers/backup_test.go internal/api/server.go
git add internal/api/handlers/backup.go internal/api/handlers/backup_test.go internal/api/server.go
git commit -m "feat(backup): tell the admin which secrets need reconfiguring after restore"
```

---

### Task 7: Frontend — surface `secrets_to_reconfigure` after restore

**Files:**
- Modify: `web/src/components/BackupRestore.tsx`
- Modify: `web/src/types/index.ts`

**Interfaces:**
- Consumes: the `secrets_to_reconfigure` field added to the restore response (Task 6).

- [ ] **Step 1: Read the current component**

```bash
grep -n "restoreResult\|RestoreResult\|handleRestore\|secrets_to_reconfigure" web/src/components/BackupRestore.tsx
```

Use the output to find exactly where the restore response is parsed and rendered — the component already shows a summary (settings/reservations/blocklist counts) after a successful restore; this task adds one more line to that summary.

- [ ] **Step 2: Add the type**

In `web/src/types/index.ts`, find the existing restore-result type (search for `Settings: number` or similar) and add:

```typescript
export interface RestoreResult {
  settings: number;
  reservations: number;
  blocklist: number;
  secrets_to_reconfigure: string[];
}
```

If a type with a different name already covers this shape, extend it in place rather than creating a duplicate.

- [ ] **Step 3: Render the warning**

In `web/src/components/BackupRestore.tsx`, in the success block that already renders the restore summary, add a conditional warning when `secrets_to_reconfigure.length > 0`:

```tsx
{result.secrets_to_reconfigure && result.secrets_to_reconfigure.length > 0 && (
  <div className="mt-3 p-3 rounded bg-yellow-500/10 border border-yellow-500/30 text-yellow-300 text-sm">
    <p className="font-medium mb-1">Reconfigure estas credenciais:</p>
    <ul className="list-disc list-inside space-y-0.5">
      {result.secrets_to_reconfigure.map(name => (
        <li key={name}>
          {name === 'github_update_token' ? 'Token do GitHub (Configurações → Atualizações)' :
           name === 'notifications' ? 'Notificações (Configurações → Notificações)' :
           name}
        </li>
      ))}
    </ul>
    <p className="text-yellow-400/70 text-xs mt-1">
      Segredos nunca fazem parte do arquivo de backup — precisam ser reinformados manualmente.
    </p>
  </div>
)}
```

Adjust the exact JSX container/class names to match the surrounding markup style in the file (read the file's existing success-state block first and mirror its conventions).

- [ ] **Step 4: Build and verify**

```bash
cd web && npm run build 2>&1 | tail -30
```

Expected: clean build.

- [ ] **Step 5: Commit**

```bash
git add web/src/components/BackupRestore.tsx web/src/types/index.ts
git commit -m "feat(web): show which credentials need reconfiguring after a restore"
```
</content>
