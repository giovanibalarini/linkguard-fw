package monitoring

import (
	"context"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
)

type updatesExec struct{ out string }

func (e *updatesExec) Execute(_ context.Context, _ string, _ ...string) (string, error) {
	return "", nil
}
func (e *updatesExec) ExecuteRead(_ context.Context, _ string, _ ...string) (string, error) {
	return e.out, nil
}
func (e *updatesExec) IsDryRun() bool { return false }

const securitySample = "Inst linux-image-amd64 [6.12.94-1] (6.12.101-1 Debian-Security:13/stable-security [amd64])\n"
const plainSample = "Inst curl [8.14.1-1] (8.14.2-1 Debian:13/stable [amd64])\n"

// The panel must light up for ANY pending update — that is the operator's
// stated need ("eu deveria só olhar para ele") — so the health item goes
// down on a plain update too.
func TestUpdatesSchedulerPanelReflectsAnyPendingUpdate(t *testing.T) {
	c := newDriftTestCollector(t)
	c.exec = &updatesExec{out: plainSample}
	u := NewUpdatesScheduler(c)

	u.RunOnce(context.Background())
	u.RunOnce(context.Background())

	if up := c.healthUp("system:updates"); up {
		t.Error("system:updates should be down while any update is pending")
	}
}

// But a push notification only fires for SECURITY updates — routine
// packages would spam the operator into ignoring the channel.
func TestUpdatesSchedulerAlertsOnlyForSecurityUpdates(t *testing.T) {
	c := newDriftTestCollector(t)
	c.exec = &updatesExec{out: plainSample}
	u := NewUpdatesScheduler(c)

	u.RunOnce(context.Background())
	u.RunOnce(context.Background())

	open, err := c.db.GetAlerts(false, 50)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	for _, a := range open {
		if a.Type == alerts.TypeSecurityUpdatesPending {
			t.Error("a non-security update must not raise the security alert")
		}
	}
}

func TestUpdatesSchedulerAlertsOnSecurityUpdate(t *testing.T) {
	c := newDriftTestCollector(t)
	c.exec = &updatesExec{out: securitySample}
	u := NewUpdatesScheduler(c)

	u.RunOnce(context.Background())
	u.RunOnce(context.Background())

	open, err := c.db.GetAlerts(false, 50)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	found := false
	for _, a := range open {
		if a.Type == alerts.TypeSecurityUpdatesPending {
			found = true
			if !strings.Contains(a.Message, "linux-image-amd64") {
				t.Errorf("alert should name the pending package, got: %q", a.Message)
			}
		}
	}
	if !found {
		t.Error("expected a pending-security-update alert")
	}
}

// TestUpdatesSchedulerClearsSecurityAlertWhenOnlyRoutineUpdatesRemain guards
// against the alert being stranded open forever: once the operator installs
// the security package, the alert must clear even if a routine (non-security)
// package is still pending — it must NOT depend on the panel's rep.Total==0
// transition, which won't fire while any routine update remains.
func TestUpdatesSchedulerClearsSecurityAlertWhenOnlyRoutineUpdatesRemain(t *testing.T) {
	c := newDriftTestCollector(t)
	exec := &updatesExec{out: securitySample}
	c.exec = exec
	u := NewUpdatesScheduler(c)

	u.RunOnce(context.Background())
	u.RunOnce(context.Background())

	exec.out = plainSample
	u.RunOnce(context.Background())

	open, err := c.db.GetAlerts(false, 50)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	for _, a := range open {
		if a.Type == alerts.TypeSecurityUpdatesPending && !a.Resolved {
			t.Errorf("security alert should have cleared once the security update was installed, got open alert: %+v", a)
		}
	}
}

// TestUpdatesSchedulerAlertsSecurityEvenWhenPanelAlreadyDown guards against
// the alert silently never firing: if the panel is already down for a
// routine package, a newly-appeared security update must still raise the
// alert — it must NOT depend on the panel's transDown transition, which
// won't fire again while the panel is already down.
func TestUpdatesSchedulerAlertsSecurityEvenWhenPanelAlreadyDown(t *testing.T) {
	c := newDriftTestCollector(t)
	exec := &updatesExec{out: plainSample}
	c.exec = exec
	u := NewUpdatesScheduler(c)

	u.RunOnce(context.Background())
	u.RunOnce(context.Background())

	exec.out = securitySample
	u.RunOnce(context.Background())

	open, err := c.db.GetAlerts(false, 50)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	found := false
	for _, a := range open {
		if a.Type == alerts.TypeSecurityUpdatesPending && !a.Resolved {
			found = true
		}
	}
	if !found {
		t.Error("expected an open security-updates alert once a security update appeared, even though the panel was already down")
	}
}

// TestUpdatesSchedulerDoesNotRepeatSecurityAlertOnEveryRun guards against the
// fix regressing into alert spam: repeated runs that keep observing the same
// security-pending state must not create a new alert row every time.
func TestUpdatesSchedulerDoesNotRepeatSecurityAlertOnEveryRun(t *testing.T) {
	c := newDriftTestCollector(t)
	c.exec = &updatesExec{out: securitySample}
	u := NewUpdatesScheduler(c)

	u.RunOnce(context.Background())
	u.RunOnce(context.Background())
	u.RunOnce(context.Background())

	all, err := c.db.GetAlerts(false, 50)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	count := 0
	for _, a := range all {
		if a.Type == alerts.TypeSecurityUpdatesPending {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 security-updates alert row, got %d", count)
	}
}

// The last report is cached so the UI can list the packages without paying
// for an apt call on every page load.
func TestUpdatesSchedulerCachesTheReportForTheUI(t *testing.T) {
	c := newDriftTestCollector(t)
	c.exec = &updatesExec{out: securitySample}
	u := NewUpdatesScheduler(c)

	u.RunOnce(context.Background())

	rep := c.LastUpdatesReport()
	if rep.Total != 1 || rep.Security != 1 {
		t.Fatalf("cached report = %+v, want Total=1 Security=1", rep)
	}
	if len(rep.Packages) != 1 || rep.Packages[0].Name != "linux-image-amd64" {
		t.Errorf("cached packages = %+v", rep.Packages)
	}
}
