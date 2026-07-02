package stresstest

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func TestFinalizeSummary(t *testing.T) {
	s := &Service{nowFn: func() string { return "00:00:00" }}
	test := &Test{
		Samples: []Sample{
			{Phase: "baseline", Ping: true, DNS: true}, // excluded from summary
			{Phase: "fault", Ping: true, DNS: true},
			{Phase: "fault", Ping: false, DNS: true},    // 1 ping loss
			{Phase: "recovery", Ping: true, DNS: false}, // 1 dns loss
			{Phase: "recovery", Ping: true, DNS: true},
		},
	}
	s.finalize(test, false)

	// 4 non-baseline samples; 1 ping fail = 25%, 1 dns fail = 25%.
	if test.PingLossPct != 25 {
		t.Errorf("ping loss = %.0f, want 25", test.PingLossPct)
	}
	if test.DNSLossPct != 25 {
		t.Errorf("dns loss = %.0f, want 25", test.DNSLossPct)
	}
	if test.State != "done" || !test.Restored {
		t.Errorf("state=%q restored=%v, want done/true", test.State, test.Restored)
	}
}

func TestFinalizeAborted(t *testing.T) {
	s := &Service{nowFn: func() string { return "00:00:00" }}
	test := &Test{Samples: []Sample{{Phase: "fault", Ping: true, DNS: true}}}
	s.finalize(test, true)
	if test.State != "aborted" {
		t.Errorf("state=%q, want aborted", test.State)
	}
}

// TestSnapshotEmptySamplesNotNil guards the black-screen regression: snapshot of
// a freshly-started test (empty Samples) must marshal to "samples":[] not null,
// or the frontend crashes dereferencing test.samples.
func TestSnapshotEmptySamplesNotNil(t *testing.T) {
	cp := snapshot(&Test{State: "running", Samples: []Sample{}})
	if cp.Samples == nil {
		t.Fatal("snapshot nil-ed an empty Samples slice (JSON would be null)")
	}
	b, err := json.Marshal(cp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"samples":[]`) {
		t.Errorf(`expected "samples":[] in JSON, got: %s`, b)
	}
}

func newTestServiceWithAlerts(t *testing.T) (*Service, *storage.DB) {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := &Service{exec: firewall.NewDryRunExecutor(), alertSvc: alerts.NewService(db)}
	return s, db
}

func countAlertsOfType(alerts []storage.Alert, typ string) int {
	n := 0
	for _, a := range alerts {
		if a.Type == typ {
			n++
		}
	}
	return n
}

func TestApplyFaultRaisesOutageAlert(t *testing.T) {
	s, db := newTestServiceWithAlerts(t)
	t2 := &Test{Mode: ModeOutage, LinkName: "WAN VIVO", LinkID: "id1", Interface: "eth0"}

	s.applyFault(t2)

	got, err := db.GetAlerts(false, 0)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	if n := countAlertsOfType(got, alerts.TypeLinkOffline); n != 1 {
		t.Errorf("link_offline alerts = %d, want 1 (all: %+v)", n, got)
	}

	s.restore(t2, "")

	got, err = db.GetAlerts(false, 0)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	if n := countAlertsOfType(got, alerts.TypeLinkOnline); n != 1 {
		t.Errorf("link_online alerts = %d, want 1 (all: %+v)", n, got)
	}
}

func TestApplyFaultDegradeRaisesDegradedAlert(t *testing.T) {
	s, db := newTestServiceWithAlerts(t)
	t2 := &Test{Mode: ModeDegrade, LinkName: "WAN Claro", LinkID: "id2", Interface: "eth1"}

	s.applyFault(t2)

	got, err := db.GetAlerts(false, 0)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	if n := countAlertsOfType(got, alerts.TypeLinkDegraded); n != 1 {
		t.Errorf("link_degraded alerts = %d, want 1 (all: %+v)", n, got)
	}
}
