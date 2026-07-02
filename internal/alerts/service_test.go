package alerts

import (
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func openTestDB(t *testing.T) *storage.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

type fakeNotifier struct {
	normal   []string
	recovery []string
}

func (f *fakeNotifier) Notify(severity, title, message string) {
	f.normal = append(f.normal, severity+"|"+title)
}
func (f *fakeNotifier) NotifyRecovery(title, message string) {
	f.recovery = append(f.recovery, title)
}

func TestServiceOfflineIsCriticalNormal(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)
	fn := &fakeNotifier{}
	s.SetNotifier(fn)

	if err := s.ServiceOffline("unbound"); err != nil {
		t.Fatal(err)
	}
	if len(fn.normal) != 1 || fn.normal[0] != "critical|Serviço offline: unbound" {
		t.Errorf("normal notifies = %v", fn.normal)
	}
	if len(fn.recovery) != 0 {
		t.Errorf("unexpected recovery notify: %v", fn.recovery)
	}
}

func TestServiceOnlineDeliversViaRecovery(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)
	fn := &fakeNotifier{}
	s.SetNotifier(fn)

	if err := s.ServiceOnline("unbound"); err != nil {
		t.Fatal(err)
	}
	if len(fn.recovery) != 1 {
		t.Errorf("recovery notifies = %v, want 1", fn.recovery)
	}
}
