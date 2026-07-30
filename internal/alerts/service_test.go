package alerts

import (
	"path/filepath"
	"strings"
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

func TestLinkDegradedMessageIncludesMeasuredValues(t *testing.T) {
	db := openTestDB(t)
	svc := NewService(db)

	if err := svc.LinkDegraded("WAN SUMICITY", "link-1", 842.5, 33.3); err != nil {
		t.Fatalf("LinkDegraded: %v", err)
	}

	alerts, err := svc.List(false, 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	msg := alerts[0].Message
	if !strings.Contains(msg, "842.5") {
		t.Errorf("expected message to include the measured latency, got: %q", msg)
	}
	if !strings.Contains(msg, "33.3") {
		t.Errorf("expected message to include the measured packet loss, got: %q", msg)
	}
}

func TestBackupFailedIsWarningNormal(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)
	fn := &fakeNotifier{}
	s.SetNotifier(fn)

	if err := s.BackupFailed("smtp indisponível"); err != nil {
		t.Fatal(err)
	}
	if len(fn.normal) != 1 || fn.normal[0] != "warning|Falha ao enviar backup" {
		t.Errorf("normal notifies = %v", fn.normal)
	}
	if len(fn.recovery) != 0 {
		t.Errorf("unexpected recovery notify: %v", fn.recovery)
	}
}

func TestBackupSucceededDeliversViaRecovery(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)
	fn := &fakeNotifier{}
	s.SetNotifier(fn)

	if err := s.BackupSucceeded(); err != nil {
		t.Fatal(err)
	}
	if len(fn.recovery) != 1 {
		t.Errorf("recovery notifies = %v, want 1", fn.recovery)
	}
}

func TestNTPUnsyncedIsWarning(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)
	fn := &fakeNotifier{}
	s.SetNotifier(fn)

	if err := s.NTPUnsynced(); err != nil {
		t.Fatal(err)
	}
	if len(fn.normal) != 1 || fn.normal[0] != "warning|Relógio dessincronizado" {
		t.Errorf("normal notifies = %v", fn.normal)
	}
}

func TestNTPSyncedDeliversViaRecovery(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)
	fn := &fakeNotifier{}
	s.SetNotifier(fn)

	if err := s.NTPSynced(); err != nil {
		t.Fatal(err)
	}
	if len(fn.recovery) != 1 {
		t.Errorf("expected 1 recovery notify, got %v", fn.recovery)
	}
}

func TestDiskSMARTFailIsCritical(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)
	fn := &fakeNotifier{}
	s.SetNotifier(fn)

	if err := s.DiskSMARTFail(); err != nil {
		t.Fatal(err)
	}
	if len(fn.normal) != 1 || fn.normal[0] != "critical|Disco: falha no SMART" {
		t.Errorf("normal notifies = %v", fn.normal)
	}
}

func TestDiskSMARTDegradedCitesCount(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)

	if err := s.DiskSMARTDegraded(3); err != nil {
		t.Fatal(err)
	}
	alertsList, _ := db.GetAlerts(false, 0)
	if len(alertsList) != 1 || !strings.Contains(alertsList[0].Message, "3") {
		t.Errorf("expected message to cite the count, got %+v", alertsList)
	}
}

func TestDiskSMARTHotCitesTemp(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)

	if err := s.DiskSMARTHot(60); err != nil {
		t.Fatal(err)
	}
	alertsList, _ := db.GetAlerts(false, 0)
	if len(alertsList) != 1 || !strings.Contains(alertsList[0].Message, "60") {
		t.Errorf("expected message to cite the temperature, got %+v", alertsList)
	}
}

func TestSlowBootCitesSeconds(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)

	if err := s.SlowBoot(245); err != nil {
		t.Fatal(err)
	}
	alertsList, _ := db.GetAlerts(false, 0)
	if len(alertsList) != 1 || alertsList[0].Severity != SeverityWarning || !strings.Contains(alertsList[0].Message, "245") {
		t.Errorf("expected a warning citing the duration, got %+v", alertsList)
	}
}

func TestJournalCorruptCitesDetail(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)

	if err := s.JournalCorrupt("system@abc.journal~ invalid object"); err != nil {
		t.Fatal(err)
	}
	alertsList, _ := db.GetAlerts(false, 0)
	if len(alertsList) != 1 || !strings.Contains(alertsList[0].Message, "system@abc.journal~") {
		t.Errorf("expected message to cite the detail, got %+v", alertsList)
	}
}

func TestJournalOKDeliversViaRecovery(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)
	fn := &fakeNotifier{}
	s.SetNotifier(fn)

	if err := s.JournalOK(); err != nil {
		t.Fatal(err)
	}
	if len(fn.recovery) != 1 {
		t.Errorf("expected 1 recovery notify, got %v", fn.recovery)
	}
}
