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

// TestConfigDriftAlertPairsResolveEachOther guards the contract every
// paired alert in this package follows: the recovery side must auto-resolve
// its problem counterpart, otherwise a fixed problem stays red forever on
// the panel — which would defeat the whole point of these watchers.
func TestConfigDriftAlertPairsResolveEachOther(t *testing.T) {
	cases := []struct {
		name        string
		problemType string
		raise       func(*Service) error
		recover     func(*Service) error
	}{
		{"firewall-nat", TypeFirewallNATDrift,
			func(s *Service) error { return s.FirewallNATDrift("enp4s0 não existe") },
			func(s *Service) error { return s.FirewallNATOK() }},
		{"wan-interface", TypeWANInterfaceMissing,
			func(s *Service) error { return s.WANInterfaceMissing("WAN VIVO -> enp4s0") },
			func(s *Service) error { return s.WANInterfaceOK() }},
		{"dns-resolver", TypeDNSResolverDrift,
			func(s *Service) error { return s.DNSResolverDrift("189.40.0.1") },
			func(s *Service) error { return s.DNSResolverOK() }},
		{"security-updates", TypeSecurityUpdatesPending,
			func(s *Service) error { return s.SecurityUpdatesPending("2 pacotes") },
			func(s *Service) error { return s.SecurityUpdatesNone() }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := openTestDB(t)
			s := NewService(db)

			if err := tc.raise(s); err != nil {
				t.Fatalf("raise: %v", err)
			}
			open, err := db.GetAlerts(false, 50)
			if err != nil {
				t.Fatalf("GetAlerts: %v", err)
			}
			if !hasOpenAlertOfType(open, tc.problemType) {
				t.Fatalf("expected an open %s alert, got %+v", tc.problemType, open)
			}

			if err := tc.recover(s); err != nil {
				t.Fatalf("recover: %v", err)
			}
			open, err = db.GetAlerts(false, 50)
			if err != nil {
				t.Fatalf("GetAlerts: %v", err)
			}
			if hasOpenAlertOfType(open, tc.problemType) {
				t.Errorf("%s should have been auto-resolved by its recovery call", tc.problemType)
			}
		})
	}
}

func hasOpenAlertOfType(alerts []storage.Alert, alertType string) bool {
	for _, a := range alerts {
		if a.Type == alertType && !a.Resolved {
			return true
		}
	}
	return false
}

// TestCreateDoesNotDuplicateAnAlreadyOpenAlert guards the root cause of most
// of the 135-alert pileup on the production panel: the same (type, linkID)
// problem re-firing (e.g. on every service restart, since the debounce state
// is in-memory) must not open a second unresolved row or notify a second time.
func TestCreateDoesNotDuplicateAnAlreadyOpenAlert(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)
	fn := &fakeNotifier{}
	s.SetNotifier(fn)

	if err := s.HighCPU(95); err != nil {
		t.Fatalf("HighCPU (1st): %v", err)
	}
	if err := s.HighCPU(97); err != nil {
		t.Fatalf("HighCPU (2nd): %v", err)
	}

	open, err := db.GetAlerts(true, 0)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	n := 0
	for _, a := range open {
		if a.Type == TypeHighCPU {
			n++
		}
	}
	if n != 1 {
		t.Errorf("expected exactly 1 unresolved high_cpu alert, got %d (%+v)", n, open)
	}
	if len(fn.normal) != 1 {
		t.Errorf("expected notifier to fire exactly once, got %d: %v", len(fn.normal), fn.normal)
	}
}

// TestCreateOpensAgainAfterTheEarlierAlertResolved guards against the dedupe
// in Create over-suppressing a genuine recurrence: once the earlier alert for
// the same (type, linkID) has been resolved, a fresh occurrence must open a
// new row.
func TestCreateOpensAgainAfterTheEarlierAlertResolved(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)

	if err := s.HighCPU(95); err != nil {
		t.Fatalf("HighCPU (1st): %v", err)
	}
	s.AutoResolve(TypeHighCPU, "")

	if err := s.HighCPU(96); err != nil {
		t.Fatalf("HighCPU (2nd): %v", err)
	}

	open, err := db.GetAlerts(true, 0)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	n := 0
	for _, a := range open {
		if a.Type == TypeHighCPU {
			n++
		}
	}
	if n != 1 {
		t.Errorf("expected exactly 1 unresolved high_cpu alert after resolve+re-raise, got %d (%+v)", n, open)
	}

	all, err := db.GetAlerts(false, 0)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	total := 0
	for _, a := range all {
		if a.Type == TypeHighCPU {
			total++
		}
	}
	if total != 2 {
		t.Errorf("expected 2 total high_cpu rows (1 resolved + 1 open), got %d (%+v)", total, all)
	}
}

// TestRecoveryAlertIsStoredResolved guards Fix A: a recovery alert announces
// a condition that already ended, so it must land in the DB already
// resolved — it is history, not an open item — while still notifying via the
// recovery path.
func TestRecoveryAlertIsStoredResolved(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)
	fn := &fakeNotifier{}
	s.SetNotifier(fn)

	if err := s.NTPSynced(); err != nil {
		t.Fatalf("NTPSynced: %v", err)
	}

	unresolved, err := db.GetAlerts(true, 0)
	if err != nil {
		t.Fatalf("GetAlerts(true): %v", err)
	}
	for _, a := range unresolved {
		if a.Type == TypeNTPSynced {
			t.Errorf("recovery alert %q should not appear in unresolved list", a.Type)
		}
	}

	all, err := db.GetAlerts(false, 0)
	if err != nil {
		t.Fatalf("GetAlerts(false): %v", err)
	}
	found := false
	for _, a := range all {
		if a.Type == TypeNTPSynced {
			found = true
			if !a.Resolved {
				t.Errorf("expected recovery alert to be stored resolved, got Resolved=false")
			}
		}
	}
	if !found {
		t.Fatal("expected the ntp_synced recovery alert to be stored in history")
	}

	if len(fn.recovery) != 1 {
		t.Errorf("expected NotifyRecovery to fire exactly once, got %v", fn.recovery)
	}
}

// TestRecoveryStillResolvesItsProblemCounterpart guards against Fix A
// accidentally breaking AutoResolve: the recovery call must still clear the
// open problem alert it pairs with.
func TestRecoveryStillResolvesItsProblemCounterpart(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)

	if err := s.NTPUnsynced(); err != nil {
		t.Fatalf("NTPUnsynced: %v", err)
	}
	if err := s.NTPSynced(); err != nil {
		t.Fatalf("NTPSynced: %v", err)
	}

	open, err := db.GetAlerts(true, 0)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	for _, a := range open {
		if a.Type == TypeNTPUnsynced {
			t.Errorf("expected ntp_unsynced to have been auto-resolved, but it is still open: %+v", a)
		}
	}
}

// TestSecurityUpdatesPendingIsWarningNotCritical: a pending update is a
// maintenance signal, not an outage — raising it as Critical would train the
// operator to ignore Critical alerts.
func TestSecurityUpdatesPendingIsWarningNotCritical(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)

	if err := s.SecurityUpdatesPending("2 pacotes"); err != nil {
		t.Fatalf("SecurityUpdatesPending: %v", err)
	}
	open, err := db.GetAlerts(false, 50)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	for _, a := range open {
		if a.Type == TypeSecurityUpdatesPending && a.Severity != SeverityWarning {
			t.Errorf("severity = %q, want %q", a.Severity, SeverityWarning)
		}
	}
}
