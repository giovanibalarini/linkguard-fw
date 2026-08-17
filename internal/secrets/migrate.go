package secrets

import (
	"fmt"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// legacySecretKeys are the settings keys whose value is a credential and
// belongs in the secrets table. This list is policy, not persistence: it says
// what counts as a secret in this product, which is precisely what this
// package is for. It lived in internal/storage until issue #25.
var legacySecretKeys = []string{"github_update_token", "notifications", "wireguard"}

// legacyTOTPPrefix is the literal prefix of the per-user TOTP rows
// ("totp_<userID>"). Matching is done in Go with strings.HasPrefix rather
// than in SQL on purpose: SQLite's LIKE treats "_" as a single-character
// wildcard, so `LIKE 'totp_%'` also matches "totpXfoo" — a key nothing reads
// back once moved. GLOB does not have that trap, but Go's HasPrefix has no
// metacharacters at all, so the trap cannot be reintroduced by someone
// editing the pattern later. The settings table holds tens of rows, so
// reading the key list and filtering in memory costs nothing.
const legacyTOTPPrefix = "totp_"

// Setter is the write half of Secrets, and the only thing MigrateFromSettings
// needs. It is a separate interface so a test can inject a Set that fails —
// the case that decides whether a TOTP seed survives, see MigrateFromSettings.
type Setter interface {
	Set(name, plaintext string) error
}

// settingsStore is the settings-table surface the migration needs.
// *storage.DB satisfies it; it exists so the dependency reads as three named
// operations instead of "the whole database".
type settingsStore interface {
	GetSetting(key string) (string, error)
	SettingKeys() ([]string, error)
	DeleteSetting(key string) error
}

// MigrateFromSettings moves the legacy credential-shaped settings rows
// (github_update_token, notifications, wireguard and every totp_<userID>)
// into sec, then deletes them from settings.
//
// It is idempotent: a key already absent from settings (migrated on a prior
// boot) is skipped, so a value written straight to secrets afterwards — an
// admin re-enrolling TOTP, say — is never overwritten by the stale plaintext.
//
// This runs at boot, before the server listens, and a returned error aborts
// startup. That is deliberate: the alternative is serving with credentials in
// an unknown state. But it means every error here is an appliance that comes
// up with no service, so nothing in this file should fail for a reason other
// than "the write really did not happen".
func MigrateFromSettings(store settingsStore, sec Setter) error {
	keys := append([]string(nil), legacySecretKeys...)

	all, err := store.SettingKeys()
	if err != nil {
		return err
	}
	for _, k := range all {
		if strings.HasPrefix(k, legacyTOTPPrefix) && len(k) > len(legacyTOTPPrefix) {
			keys = append(keys, k)
		}
	}

	for _, key := range keys {
		if err := migrateOne(store, sec, key); err != nil {
			return err
		}
	}
	return nil
}

// migrateOne moves a single settings row into sec, then deletes it.
//
// The order is load-bearing and there is no transaction spanning the two
// stores. If sec.Set fails, the row is left untouched, so the plaintext still
// in settings is re-attempted on the next boot rather than lost. The reverse
// order — or a rollback that deleted first — would destroy a TOTP seed on any
// write failure and lock that admin out of the UI permanently, since the
// seed exists nowhere else.
//
// The window that remains is Set succeeding and DeleteSetting failing: the
// value is then in both tables, and the next boot re-Sets the identical
// value and retries the delete. Duplicated, never lost. Closing even that
// would need a transaction across two stores, which SQLite gives us (same
// connection) but which would also have to be plumbed through the Secrets
// interface; the failure it prevents is strictly less bad than the one the
// current order already prevents, so it is not worth the surface.
func migrateOne(store settingsStore, sec Setter, key string) error {
	value, err := store.GetSetting(key)
	if err != nil {
		return err
	}
	if value == "" {
		return nil // never set, or already migrated
	}
	if err := sec.Set(key, value); err != nil {
		return fmt.Errorf("migrate secret %q: %w", key, err)
	}
	return store.DeleteSetting(key)
}

// compile-time proof that the concrete store used at boot satisfies the
// interface above, so a rename in storage breaks the build here rather than
// at the single call site in main.go.
var _ settingsStore = (*storage.DB)(nil)
