package secrets_test

import (
	"errors"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func newMigrateTestDB(t *testing.T) *storage.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// fakeSecretsSetter stands in for *Service so a test can make the write fail.
// The real Service can only fail if sqlite or the key does, neither of which
// a test can arrange — and "the write failed" is exactly the branch that
// decides whether a TOTP seed survives.
type fakeSecretsSetter struct {
	stored map[string]string
	failOn map[string]bool
}

func (f *fakeSecretsSetter) Set(name, plaintext string) error {
	if f.failOn[name] {
		return errors.New("boom: secrets write failed")
	}
	if f.stored == nil {
		f.stored = map[string]string{}
	}
	f.stored[name] = plaintext
	return nil
}

func TestMigrateFromSettingsMovesKnownKeys(t *testing.T) {
	db := newMigrateTestDB(t)

	_ = db.SetSetting("github_update_token", "ghp_abc")
	_ = db.SetSetting("notifications", `{"webhook":{"url":"https://x"}}`)
	_ = db.SetSetting("wireguard", `{"private_key":"wgpriv123","peers":[]}`)
	_ = db.SetSetting("totp_user-1", `{"secret":"AAA","enabled":true}`)
	_ = db.SetSetting("totp_user-2", `{"secret":"BBB","enabled":true}`)
	_ = db.SetSetting("monitoring", `{"enabled":true}`) // must NOT be migrated

	fake := &fakeSecretsSetter{}
	if err := secrets.MigrateFromSettings(db, fake); err != nil {
		t.Fatalf("MigrateFromSettings: %v", err)
	}

	want := map[string]string{
		"github_update_token": "ghp_abc",
		"notifications":       `{"webhook":{"url":"https://x"}}`,
		"wireguard":           `{"private_key":"wgpriv123","peers":[]}`,
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

func TestMigrateFromSettingsIsIdempotent(t *testing.T) {
	db := newMigrateTestDB(t)
	_ = db.SetSetting("github_update_token", "ghp_abc")

	fake := &fakeSecretsSetter{}
	if err := secrets.MigrateFromSettings(db, fake); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if err := secrets.MigrateFromSettings(db, fake); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if fake.stored["github_update_token"] != "ghp_abc" {
		t.Fatalf("expected value to survive two migrate calls unchanged, got %q", fake.stored["github_update_token"])
	}
}

// TestMigrateFromSettingsKeepsRowWhenSetFails is the "never lose a secret"
// guarantee. If the secrets write fails, the plaintext in settings is the ONLY
// remaining copy — deleting it before the write is confirmed would destroy a
// TOTP seed and lock the admin out of the UI permanently. The row must still
// be there so the next boot re-attempts the same key.
func TestMigrateFromSettingsKeepsRowWhenSetFails(t *testing.T) {
	db := newMigrateTestDB(t)
	_ = db.SetSetting("totp_user-1", `{"secret":"AAA","enabled":true}`)
	_ = db.SetSetting("github_update_token", "ghp_abc")

	fake := &fakeSecretsSetter{failOn: map[string]bool{"totp_user-1": true}}
	err := secrets.MigrateFromSettings(db, fake)
	if err == nil {
		t.Fatal("expected an error when the secrets write fails, got nil")
	}

	settings, exportErr := db.ExportSettings()
	if exportErr != nil {
		t.Fatalf("ExportSettings: %v", exportErr)
	}
	if settings["totp_user-1"] != `{"secret":"AAA","enabled":true}` {
		t.Fatalf("secret lost: settings row must survive a failed secrets write, got %q", settings["totp_user-1"])
	}
	if _, present := fake.stored["totp_user-1"]; present {
		t.Fatal("failing Set must not have stored anything")
	}
}

// TestMigrateFromSettingsPrefixIsExact pins the "_" precision of the match.
// SQLite's LIKE treats "_" as a single-character wildcard, so `LIKE 'totp_%'`
// would also drag "totpXfoo" into the secrets table, where nothing reads it
// back — a silent data move. Only the literal "totp_<userID>" prefix migrates.
func TestMigrateFromSettingsPrefixIsExact(t *testing.T) {
	db := newMigrateTestDB(t)
	_ = db.SetSetting("totp_user-1", `{"secret":"AAA"}`)
	_ = db.SetSetting("totpXfoo", "not-a-secret")
	_ = db.SetSetting("totp", "also-not-a-secret")
	_ = db.SetSetting("totp_", "empty-user-id")
	_ = db.SetSetting("xtotp_user-9", "not-a-secret-either")

	fake := &fakeSecretsSetter{}
	if err := secrets.MigrateFromSettings(db, fake); err != nil {
		t.Fatalf("MigrateFromSettings: %v", err)
	}

	if fake.stored["totp_user-1"] != `{"secret":"AAA"}` {
		t.Fatalf("expected totp_user-1 migrated, got %q", fake.stored["totp_user-1"])
	}
	for _, key := range []string{"totpXfoo", "totp", "totp_", "xtotp_user-9"} {
		if _, migrated := fake.stored[key]; migrated {
			t.Fatalf("key %q must NOT be migrated: it is not totp_<userID>", key)
		}
	}

	settings, err := db.ExportSettings()
	if err != nil {
		t.Fatalf("ExportSettings: %v", err)
	}
	for k, v := range map[string]string{
		"totpXfoo":     "not-a-secret",
		"totp":         "also-not-a-secret",
		"totp_":        "empty-user-id",
		"xtotp_user-9": "not-a-secret-either",
	} {
		if settings[k] != v {
			t.Fatalf("expected %q left in settings with %q, got %q", k, v, settings[k])
		}
	}
}

// TestMigrateFromSettingsDoesNotClobberNewerValue covers the boot after the
// boot after the migration: the DB is already migrated and the admin has since
// rotated the TOTP seed through the app, which writes straight to secrets.
// Re-running the migration must not resurrect the stale plaintext, which would
// silently invalidate the authenticator the admin just enrolled.
func TestMigrateFromSettingsDoesNotClobberNewerValue(t *testing.T) {
	db := newMigrateTestDB(t)
	_ = db.SetSetting("totp_user-1", `{"secret":"OLD","enabled":true}`)
	_ = db.SetSetting("github_update_token", "ghp_old")

	fake := &fakeSecretsSetter{}
	if err := secrets.MigrateFromSettings(db, fake); err != nil {
		t.Fatalf("first migrate: %v", err)
	}

	// The admin re-enrolls TOTP and rotates the token; both writes land in
	// secrets only, since settings no longer holds these keys.
	_ = fake.Set("totp_user-1", `{"secret":"NEW","enabled":true}`)
	_ = fake.Set("github_update_token", "ghp_new")

	if err := secrets.MigrateFromSettings(db, fake); err != nil {
		t.Fatalf("second migrate: %v", err)
	}

	if fake.stored["totp_user-1"] != `{"secret":"NEW","enabled":true}` {
		t.Fatalf("migration overwrote a newer TOTP seed, got %q", fake.stored["totp_user-1"])
	}
	if fake.stored["github_update_token"] != "ghp_new" {
		t.Fatalf("migration overwrote a newer token, got %q", fake.stored["github_update_token"])
	}
}

// TestMigrateFromSettingsThroughTheRealService is the round trip the fake
// cannot prove: after the migration the value must come back out of the real
// AES-GCM Service, decrypted and identical. A TOTP seed that migrates but
// does not decrypt is the same lockout as one that was lost.
func TestMigrateFromSettingsThroughTheRealService(t *testing.T) {
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
	svc := secrets.NewService(db, key)

	_ = db.SetSetting("totp_user-1", `{"secret":"JBSWY3DPEHPK3PXP","enabled":true}`)
	_ = db.SetSetting("github_update_token", "ghp_realvalue")

	if err := secrets.MigrateFromSettings(db, svc); err != nil {
		t.Fatalf("MigrateFromSettings: %v", err)
	}

	got, err := svc.Get("totp_user-1")
	if err != nil {
		t.Fatalf("Get totp_user-1: %v", err)
	}
	if got != `{"secret":"JBSWY3DPEHPK3PXP","enabled":true}` {
		t.Fatalf("TOTP seed did not survive the round trip, got %q", got)
	}
	if got, err := svc.Get("github_update_token"); err != nil || got != "ghp_realvalue" {
		t.Fatalf("token round trip: got %q, err %v", got, err)
	}

	settings, err := db.ExportSettings()
	if err != nil {
		t.Fatalf("ExportSettings: %v", err)
	}
	if _, present := settings["totp_user-1"]; present {
		t.Fatal("plaintext TOTP seed still in settings after a successful migration")
	}
}
