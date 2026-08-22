package alerts

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
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
		{"base-deps", TypeBaseDepsMissing,
			func(s *Service) error { return s.BaseDepsMissing("nftables — sem filtro de pacote") },
			func(s *Service) error { return s.BaseDepsOK("nftables") }},
		{"netsvc-deps", TypeNetsvcDepsMissing,
			func(s *Service) error { return s.NetsvcDepsMissing("kea-dhcp4-server — sem servidor DHCP") },
			func(s *Service) error { return s.NetsvcDepsOK("kea-dhcp4-server") }},
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

// TestResolveStaleOnStartupClearsStateDerivedAlert guards the fix for the
// 2026-08-11 aftermath: three alerts had to be resolved by hand because the
// conditions they described were fixed by a service restart, but nothing
// ever observed the transition (health state lives only in memory) to close
// them. A state-derived type left open by a previous process must be
// resolved at startup.
func TestResolveStaleOnStartupClearsStateDerivedAlert(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)

	if err := s.HighCPU(95); err != nil {
		t.Fatalf("HighCPU: %v", err)
	}

	s.ResolveStaleOnStartup()

	open, err := db.GetAlerts(true, 0)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	for _, a := range open {
		if a.Type == TypeHighCPU {
			t.Errorf("expected the stale high_cpu alert to be resolved at startup, still open: %+v", a)
		}
	}
}

// TestResolveStaleOnStartupPreservesRuleError guards the deliberate
// exemption: rule_error has no recovery counterpart, so clearing it at
// startup would silently discard a genuine unacknowledged failure that
// nothing else will ever re-raise.
func TestResolveStaleOnStartupPreservesRuleError(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)

	if err := s.RuleError("Failover for WAN VIVO failed: X"); err != nil {
		t.Fatalf("RuleError: %v", err)
	}

	s.ResolveStaleOnStartup()

	open, err := db.GetAlerts(true, 0)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	found := false
	for _, a := range open {
		if a.Type == TypeRuleError {
			found = true
		}
	}
	if !found {
		t.Error("expected an open rule_error alert to survive ResolveStaleOnStartup, but it was resolved")
	}
}

// TestResolveStaleOnStartupIsSilentBookkeeping guards that the cleanup is
// pure bookkeeping: it must not create any new alert row (recovery or
// otherwise) and must not notify — the operator does not need to be told
// about a condition that already went away while the service was down.
func TestResolveStaleOnStartupIsSilentBookkeeping(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)
	fn := &fakeNotifier{}
	s.SetNotifier(fn)

	if err := s.HighCPU(95); err != nil {
		t.Fatalf("HighCPU: %v", err)
	}
	if err := s.NTPUnsynced(); err != nil {
		t.Fatalf("NTPUnsynced: %v", err)
	}
	fn.normal, fn.recovery = nil, nil // ignore the notifications from raising them above

	before, err := db.GetAlerts(false, 0)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}

	s.ResolveStaleOnStartup()

	if len(fn.normal) != 0 || len(fn.recovery) != 0 {
		t.Errorf("expected no notifications from ResolveStaleOnStartup, got normal=%v recovery=%v", fn.normal, fn.recovery)
	}

	after, err := db.GetAlerts(false, 0)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	if len(after) != len(before) {
		t.Errorf("expected ResolveStaleOnStartup to create no new alert rows: before=%d after=%d", len(before), len(after))
	}
}

// TestStateAlertTypesMatchAutoResolveCallSites is a drift guard: it parses
// this package's own service.go and checks that the set of alert-type
// identifiers passed as ResolveStaleOnStartup's raw material — every type
// some method here actually resolves via s.AutoResolve(Type..., ...) —
// matches stateAlertTypes exactly. If a future problem/recovery pair is
// added (a new AutoResolve call site) without updating stateAlertTypes, or
// vice versa, this test fails instead of the mismatch going unnoticed.
func TestStateAlertTypesMatchAutoResolveCallSites(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine this test file's location")
	}
	srcPath := filepath.Join(filepath.Dir(thisFile), "service.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, srcPath, nil, 0)
	if err != nil {
		t.Fatalf("parse service.go: %v", err)
	}

	autoResolved := map[string]bool{}
	var declaredList []string

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if ok && sel.Sel.Name == "AutoResolve" && len(node.Args) > 0 {
				if ident, ok := node.Args[0].(*ast.Ident); ok {
					autoResolved[ident.Name] = true
				}
			}
		case *ast.ValueSpec:
			for _, name := range node.Names {
				if name.Name != "stateAlertTypes" || len(node.Values) == 0 {
					continue
				}
				lit, ok := node.Values[0].(*ast.CompositeLit)
				if !ok {
					continue
				}
				for _, el := range lit.Elts {
					if ident, ok := el.(*ast.Ident); ok {
						declaredList = append(declaredList, ident.Name)
					}
				}
			}
		}
		return true
	})

	if len(autoResolved) == 0 {
		t.Fatal("found no s.AutoResolve(Type..., ...) call sites while parsing service.go — parser problem?")
	}
	if len(declaredList) == 0 {
		t.Fatal("found no identifiers in the stateAlertTypes declaration while parsing service.go — parser problem?")
	}

	declared := map[string]bool{}
	for _, name := range declaredList {
		if declared[name] {
			t.Errorf("stateAlertTypes lists %s more than once", name)
		}
		declared[name] = true
	}

	for name := range autoResolved {
		if !declared[name] {
			t.Errorf("%s has a recovery method that calls AutoResolve but is missing from stateAlertTypes", name)
		}
	}
	for name := range declared {
		if !autoResolved[name] {
			t.Errorf("stateAlertTypes lists %s but no method resolves it via AutoResolve — is this stale?", name)
		}
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

// TestBaseDepsMissingIsCriticalAndKeepsTheDetail: an appliance running
// without nftables has no packet filter at all, so this is Critical — and the
// row has to carry the detail (which packages, what breaks, how to fix), or
// the operator has to go read the journal to find out how bad it is.
func TestBaseDepsMissingIsCriticalAndKeepsTheDetail(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)

	detail := "nftables — sem ele não existe filtro de pacote nenhum. instale à mão: apt-get install -y nftables"
	if err := s.BaseDepsMissing(detail); err != nil {
		t.Fatalf("BaseDepsMissing: %v", err)
	}
	open, err := db.GetAlerts(true, 50)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	found := false
	for _, a := range open {
		if a.Type != TypeBaseDepsMissing {
			continue
		}
		found = true
		if a.Severity != SeverityCritical {
			t.Errorf("severity = %q, want %q", a.Severity, SeverityCritical)
		}
		if !strings.Contains(a.Message, detail) {
			t.Errorf("message = %q, want it to carry the detail", a.Message)
		}
	}
	if !found {
		t.Fatalf("expected an open %s alert, got %+v", TypeBaseDepsMissing, open)
	}
}

// TestRuleErrorKeepsDistinctFailuresVisible is the regression guard for the
// rule_error catch-all: rule_error is raised from seven unrelated call sites
// (failover, NTP apply, DHCP/DNS apply, and four in the balancer) and has no
// recovery counterpart, so under the plain (type, linkID) dedupe the first
// failure ever recorded opens a row that never resolves — and every
// subsequent, completely unrelated Critical failure from any other
// subsystem is silently swallowed forever. Two failures with different
// messages must both surface as separate unresolved rows.
func TestRuleErrorKeepsDistinctFailuresVisible(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)

	if err := s.RuleError("Falha ao aplicar DHCP/DNS: X"); err != nil {
		t.Fatalf("RuleError (1st): %v", err)
	}
	if err := s.RuleError("Failover for WAN VIVO failed: Y"); err != nil {
		t.Fatalf("RuleError (2nd): %v", err)
	}

	open, err := db.GetAlerts(true, 0)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	n := 0
	for _, a := range open {
		if a.Type == TypeRuleError {
			n++
		}
	}
	if n != 2 {
		t.Errorf("expected 2 unresolved rule_error alerts (distinct failures), got %d (%+v)", n, open)
	}
}

// TestRuleErrorStillCollapsesIdenticalRepeats confirms the message-keyed
// exception for rule_error doesn't throw away dedupe entirely: the exact
// same failure repeated (e.g. on every service restart, same as the
// (type, linkID) case) must still collapse into a single open row.
func TestRuleErrorStillCollapsesIdenticalRepeats(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)

	for i := 0; i < 3; i++ {
		if err := s.RuleError("Falha ao aplicar DHCP/DNS: X"); err != nil {
			t.Fatalf("RuleError (%d): %v", i, err)
		}
	}

	open, err := db.GetAlerts(true, 0)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	n := 0
	for _, a := range open {
		if a.Type == TypeRuleError {
			n++
		}
	}
	if n != 1 {
		t.Errorf("expected exactly 1 unresolved rule_error alert for 3 identical repeats, got %d (%+v)", n, open)
	}
}

// TestHighCPUDedupeIgnoresPercentVariance guards the default (type, linkID)
// path against the message-variance leaking in: HighCPU embeds the live
// percentage in its message, so if dedupe ever keyed on message by default,
// every restart-driven re-raise with a slightly different reading would
// duplicate the alert again — exactly the pileup the (type, linkID) dedupe
// was introduced to fix.
func TestHighCPUDedupeIgnoresPercentVariance(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)

	if err := s.HighCPU(91.2); err != nil {
		t.Fatalf("HighCPU (1st): %v", err)
	}
	if err := s.HighCPU(93.5); err != nil {
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
		t.Errorf("expected exactly 1 unresolved high_cpu alert despite differing percentages, got %d (%+v)", n, open)
	}
}

// openServiceOfflineFor conta os alertas service_offline abertos daquele
// serviço — a identidade que a correção introduziu é (tipo, nome do serviço).
func openServiceOfflineFor(t *testing.T, db *storage.DB, name string) int {
	t.Helper()
	open, err := db.GetAlerts(true, 0)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	n := 0
	for _, a := range open {
		if a.Type == TypeServiceOffline && a.LinkID == name {
			n++
		}
	}
	return n
}

// TestTwoServicesDownRaiseTwoAlerts é o defeito medido na VM (§14 da
// validação final): com um service_offline aberto para o nftables, o
// kea-dhcp4-server caiu de verdade e nenhum alerta foi criado, porque Create
// deduplica por (tipo, identificador) e todo serviço dividia o identificador
// vazio. Duas quedas reais precisam de dois alertas — colapsar em um faz o
// operador consertar um serviço e ir embora sem saber do outro.
func TestTwoServicesDownRaiseTwoAlerts(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)
	fn := &fakeNotifier{}
	s.SetNotifier(fn)

	if err := s.ServiceOffline("nftables"); err != nil {
		t.Fatalf("ServiceOffline(nftables): %v", err)
	}
	if err := s.ServiceOffline("kea-dhcp4-server"); err != nil {
		t.Fatalf("ServiceOffline(kea-dhcp4-server): %v", err)
	}

	if n := openServiceOfflineFor(t, db, "nftables"); n != 1 {
		t.Errorf("service_offline aberto para nftables = %d, quero 1", n)
	}
	if n := openServiceOfflineFor(t, db, "kea-dhcp4-server"); n != 1 {
		t.Errorf("service_offline aberto para kea-dhcp4-server = %d, quero 1 (a queda do segundo serviço foi engolida pela do primeiro)", n)
	}
	if len(fn.normal) != 2 {
		t.Errorf("notificações = %v, quero uma por serviço caído", fn.normal)
	}
}

// TestServiceOnlineResolvesOnlyItsOwnService: a volta de um serviço não pode
// fechar o alerta de outro que continua caído — era assim que a tela passava a
// dizer que estava tudo bem com um serviço parado, o dado falso que este
// projeto não admite.
func TestServiceOnlineResolvesOnlyItsOwnService(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)

	if err := s.ServiceOffline("nftables"); err != nil {
		t.Fatalf("ServiceOffline(nftables): %v", err)
	}
	if err := s.ServiceOffline("kea-dhcp4-server"); err != nil {
		t.Fatalf("ServiceOffline(kea-dhcp4-server): %v", err)
	}

	if err := s.ServiceOnline("nftables"); err != nil {
		t.Fatalf("ServiceOnline(nftables): %v", err)
	}

	if n := openServiceOfflineFor(t, db, "nftables"); n != 0 {
		t.Errorf("service_offline do nftables continua aberto depois da recuperação (%d abertos)", n)
	}
	if n := openServiceOfflineFor(t, db, "kea-dhcp4-server"); n != 1 {
		t.Errorf("service_offline do kea-dhcp4-server = %d, quero 1 — a recuperação do nftables fechou o alerta do serviço errado", n)
	}
}

// TestServiceOfflineStillDedupesPerService: a deduplicação continua valendo,
// só que por serviço. O estado que decide se a condição é "nova" mora na
// memória do processo (internal/monitoring), então cada reinício reavalia a
// queda ainda verdadeira — e ela não pode virar uma linha nova a cada vez.
// Depois de resolvido, porém, cair de novo é um problema genuinamente novo e
// abre linha nova.
func TestServiceOfflineStillDedupesPerService(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)
	fn := &fakeNotifier{}
	s.SetNotifier(fn)

	if err := s.ServiceOffline("unbound"); err != nil {
		t.Fatalf("ServiceOffline (1ª): %v", err)
	}
	if err := s.ServiceOffline("unbound"); err != nil {
		t.Fatalf("ServiceOffline (2ª): %v", err)
	}
	if n := openServiceOfflineFor(t, db, "unbound"); n != 1 {
		t.Errorf("service_offline aberto para unbound = %d, quero 1 (a mesma queda repetida não pode empilhar)", n)
	}
	if len(fn.normal) != 1 {
		t.Errorf("notificações = %v, quero exatamente 1 para a mesma queda repetida", fn.normal)
	}

	if err := s.ServiceOnline("unbound"); err != nil {
		t.Fatalf("ServiceOnline: %v", err)
	}
	if err := s.ServiceOffline("unbound"); err != nil {
		t.Fatalf("ServiceOffline (3ª, depois da recuperação): %v", err)
	}
	if n := openServiceOfflineFor(t, db, "unbound"); n != 1 {
		t.Errorf("service_offline aberto para unbound depois de cair de novo = %d, quero 1", n)
	}

	all, err := db.GetAlerts(false, 0)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	total := 0
	for _, a := range all {
		if a.Type == TypeServiceOffline {
			total++
		}
	}
	if total != 2 {
		t.Errorf("linhas service_offline no total = %d, quero 2 (a primeira queda resolvida + a nova)", total)
	}
}

// TestResolveStaleOnStartupClosesPreFixServiceAlert cobre o que já está
// gravado nas máquinas em produção: alertas service_offline com o
// identificador VAZIO, que o código novo nunca mais casaria. Eles não podem
// ficar órfãos e eternamente vermelhos. Quem os fecha é o
// ResolveStaleOnStartup do primeiro boot depois do upgrade (o postinst
// reinicia o serviço) — ele lê o identificador da própria linha, então fecha
// tanto as antigas quanto as novas. O que ainda estiver caído volta a ser
// levantado pelo vigia no ciclo seguinte, agora por serviço.
func TestResolveStaleOnStartupClosesPreFixServiceAlert(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)

	legacy := &storage.Alert{
		Type:     TypeServiceOffline,
		Severity: SeverityCritical,
		Title:    "Serviço offline: kea-dhcp4-server",
		Message:  "O serviço kea-dhcp4-server parou de responder.",
		LinkID:   "", // como a versão anterior gravava
	}
	if err := db.CreateAlert(legacy); err != nil {
		t.Fatalf("CreateAlert (linha antiga): %v", err)
	}
	if err := s.ServiceOffline("unbound"); err != nil {
		t.Fatalf("ServiceOffline(unbound): %v", err)
	}

	s.ResolveStaleOnStartup()

	open, err := db.GetAlerts(true, 0)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	for _, a := range open {
		if a.Type == TypeServiceOffline {
			t.Errorf("service_offline continua aberto depois do ResolveStaleOnStartup (órfão): %+v", a)
		}
	}

	// E o vigia consegue reabrir por serviço logo depois — a limpeza não deixa
	// a vaga travada.
	if err := s.ServiceOffline("kea-dhcp4-server"); err != nil {
		t.Fatalf("ServiceOffline(kea-dhcp4-server) depois da limpeza: %v", err)
	}
	if n := openServiceOfflineFor(t, db, "kea-dhcp4-server"); n != 1 {
		t.Errorf("service_offline reaberto para kea-dhcp4-server = %d, quero 1", n)
	}
}

// TestBalancerNoWANEhEstadoENaoPegaTudo é a regressão da issue #147.
//
// Em produção um `rule_error` com a mensagem "Balanceamento: nenhuma interface
// WAN ativa" ficou SEIS DIAS vermelho numa caixa saudável — a condição durou
// minutos, o alerta não. rule_error é um pega-tudo levantado de sete lugares
// sem nada que observe a transição "resolvido", e o código já documentava isso.
//
// Um vermelho que nunca apaga ensina quem opera a ignorar vermelho.
func TestBalancerNoWANEhEstadoENaoPegaTudo(t *testing.T) {
	var achou bool
	for _, tipo := range stateAlertTypes {
		if tipo == TypeBalancerNoWAN {
			achou = true
		}
		if tipo == TypeRuleError {
			t.Error("rule_error entrou em stateAlertTypes: ele não tem quem o feche")
		}
	}
	if !achou {
		t.Error("balancer_no_wan não está em stateAlertTypes: ficaria vermelho para sempre")
	}
}

// TestAlertaQueNomeiaAparelhoNaoSaiSemEscolha é a rede que a regra escrita em
// internal/metrics/exposicao.go exige.
//
// O padrão de severidade mínima das notificações é "warning". Sem este portão,
// um alerta de comportamento por aparelho — que nomeia o apelido, o nome de host
// ou o endereço físico — sairia por Telegram, WhatsApp ou e-mail SEM NINGUÉM
// TER DECIDIDO ISSO. Identidade de aparelho é inventário da rede do cliente.
func TestAlertaQueNomeiaAparelhoNaoSaiSemEscolha(t *testing.T) {
	db := openTestDB(t)
	svc := NewService(db)
	n := &fakeNotifier{}
	svc.SetNotifier(n)

	// Fonte não ligada = ninguém escolheu = não sai.
	if err := svc.HostAcimaDoNormal("aa:bb:cc:dd:ee:ff", "Notebook da Ana", 9e6, 1e6); err != nil {
		t.Fatalf("HostAcimaDoNormal: %v", err)
	}
	if len(n.normal) != 0 {
		t.Errorf("o alerta saiu da caixa sem escolha explícita (%d notificações)", len(n.normal))
	}

	// Escolhido explicitamente: sai.
	svc.SetNotificarAparelho(func() (bool, error) { return true, nil })
	if err := svc.HostNovoNaRede("aa:bb:cc:dd:ee:aa", "Celular novo"); err != nil {
		t.Fatalf("HostNovoNaRede: %v", err)
	}
	if len(n.normal) != 1 {
		t.Errorf("com a escolha feita, o alerta não saiu (%d notificações)", len(n.normal))
	}

	// E um alerta que NÃO nomeia aparelho continua saindo como sempre.
	svc.SetNotificarAparelho(func() (bool, error) { return false, nil })
	if err := svc.HighCPU(97); err != nil {
		t.Fatalf("HighCPU: %v", err)
	}
	if len(n.normal) != 2 {
		t.Errorf("um alerta de sistema deixou de sair por causa do portão (%d)", len(n.normal))
	}
}

// TestErroAoLerAEscolhaNaoNotifica: não conseguir ler a escolha não pode
// significar "pode publicar identidade de aparelho para fora".
func TestErroAoLerAEscolhaNaoNotifica(t *testing.T) {
	db := openTestDB(t)
	svc := NewService(db)
	n := &fakeNotifier{}
	svc.SetNotifier(n)
	svc.SetNotificarAparelho(func() (bool, error) { return false, errTeste })

	_ = svc.HostNovoNaRede("aa:bb:cc:dd:ee:bb", "Aparelho")
	if len(n.normal) != 0 {
		t.Errorf("erro de leitura virou autorização (%d notificações)", len(n.normal))
	}
}

type notificadorEspiao struct{ chamadas int }

func (n *notificadorEspiao) Notify(string, string, string) { n.chamadas++ }
func (n *notificadorEspiao) NotifyRecovery(string, string) { n.chamadas++ }

var errTeste = errTipo("banco fora")

type errTipo string

func (e errTipo) Error() string { return string(e) }
