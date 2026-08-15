package monitoring

import (
	"context"
	"os"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func newTestCollector() *Collector {
	return &Collector{health: map[string]*itemState{}}
}

func TestObserveAntiFlapRequiresTwoDowns(t *testing.T) {
	c := newTestCollector()
	// first sighting: up, no transition
	if tr := c.observe("svc:unbound", true, 100); tr != transNone {
		t.Fatalf("first up should be transNone, got %v", tr)
	}
	// one down: NOT yet a transition (anti-flap needs 2 consecutive)
	if tr := c.observe("svc:unbound", false, 101); tr != transNone {
		t.Fatalf("single down should be suppressed (anti-flap), got %v", tr)
	}
	// second consecutive down: now it's a real outage
	if tr := c.observe("svc:unbound", false, 102); tr != transDown {
		t.Fatalf("second down should be transDown, got %v", tr)
	}
	// stays down: no repeat
	if tr := c.observe("svc:unbound", false, 103); tr != transNone {
		t.Fatalf("staying down should be transNone, got %v", tr)
	}
	// recovery is immediate (no debounce on the way up)
	if tr := c.observe("svc:unbound", true, 104); tr != transUp {
		t.Fatalf("recovery should be transUp, got %v", tr)
	}
}

func TestObserveFlapDoesNotAlert(t *testing.T) {
	c := newTestCollector()
	c.observe("link:wan1", true, 1)  // up
	c.observe("link:wan1", false, 2) // one down (suppressed)
	if tr := c.observe("link:wan1", true, 3); tr != transNone {
		t.Fatalf("a single-cycle blip must not alert, got %v", tr)
	}
}

func TestObserveDownAtStartupAlertsOnConfirm(t *testing.T) {
	c := newTestCollector()
	if tr := c.observe("svc:x", false, 1); tr != transNone {
		t.Fatalf("first down (startup) should be transNone, got %v", tr)
	}
	if tr := c.observe("svc:x", false, 2); tr != transDown {
		t.Fatalf("second consecutive down should fire transDown, got %v", tr)
	}
	if tr := c.observe("svc:x", true, 3); tr != transUp {
		t.Fatalf("recovery should fire transUp, got %v", tr)
	}
}

// unitShape é o que o `systemctl show` responderia sobre uma unidade.
type unitShape struct {
	loadState   string // loaded / not-found / masked
	activeState string // active / inactive / failed / activating
	unitType    string // simple / notify / oneshot
}

// daemon e oneshot são atalhos para as duas formas que existem na lista de
// serviços vigiados: kea/unbound são daemons, nftables é oneshot.
func daemon(activeState string) unitShape {
	return unitShape{loadState: "loaded", activeState: activeState, unitType: "notify"}
}

func oneshot(activeState string) unitShape {
	return unitShape{loadState: "loaded", activeState: activeState, unitType: "oneshot"}
}

type fakeExec struct {
	active      map[string]bool
	units       map[string]unitShape
	showErr     error
	ntpSynced   string // valor de retorno de `timedatectl show ...` ("yes"/"no")
	findmntOut  string
	lsblkOut    string
	smartctlOut string
	smartctlErr error
	journalOut  string
	journalErr  error
}

func (f *fakeExec) Execute(_ context.Context, _ string, _ ...string) (string, error) { return "", nil }
func (f *fakeExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	switch cmd {
	case "systemctl":
		if len(args) > 1 && args[0] == "show" {
			if f.showErr != nil {
				return "", f.showErr
			}
			u, ok := f.units[args[1]]
			if !ok {
				// O que o systemd real responde para uma unidade que não
				// existe: exit 0 e LoadState=not-found. Quando o teste só
				// declarou `active`, traduz para a forma de um daemon.
				if f.active != nil {
					if f.active[args[1]] {
						u = daemon("active")
					} else {
						u = daemon("inactive")
					}
				} else {
					u = unitShape{loadState: "not-found", activeState: "inactive"}
				}
			}
			return "Type=" + u.unitType + "\nLoadState=" + u.loadState + "\nActiveState=" + u.activeState + "\n", nil
		}
		if len(args) == 2 && args[0] == "is-active" {
			if f.active[args[1]] {
				return "active\n", nil
			}
			return "inactive\n", assertErr{}
		}
	case "timedatectl":
		return f.ntpSynced, nil
	case "findmnt":
		return f.findmntOut, nil
	case "lsblk":
		return f.lsblkOut, nil
	case "smartctl":
		return f.smartctlOut, f.smartctlErr
	case "journalctl":
		return f.journalOut, f.journalErr
	}
	return "", nil
}
func (f *fakeExec) IsDryRun() bool                              { return false }
func (_ *fakeExec) WriteFile(string, []byte, os.FileMode) error { return nil }

type assertErr struct{}

func (assertErr) Error() string { return "inactive" }

func TestCheckServicesRaisesOnSecondDown(t *testing.T) {
	fe := &fakeExec{active: map[string]bool{"unbound": true}}
	db := openTestDB(t)
	as := alerts.NewService(db)
	c := &Collector{db: db, alertSvc: as, exec: fe, health: map[string]*itemState{}, nowFn: seqClock()}

	cfg := Config{Enabled: true, Services: []string{"unbound"}, DiskThresholdPct: 90}
	c.checkServices(cfg) // up → no alert
	fe.active["unbound"] = false
	c.checkServices(cfg) // 1st down → suppressed
	c.checkServices(cfg) // 2nd down → alert

	alertsList, _ := db.GetAlerts(false, 0)
	var offline int
	for _, a := range alertsList {
		if a.Type == alerts.TypeServiceOffline {
			offline++
		}
	}
	if offline != 1 {
		t.Fatalf("expected exactly 1 service_offline alert, got %d", offline)
	}
}

// newServiceCollector monta um Collector de verdade para os testes de
// checkServices, com o banco e o serviço de alertas reais.
func newServiceCollector(t *testing.T, fe *fakeExec) (*Collector, *storage.DB) {
	t.Helper()
	db := openTestDB(t)
	return &Collector{db: db, alertSvc: alerts.NewService(db), exec: fe,
		health: map[string]*itemState{}, nowFn: seqClock()}, db
}

func countOffline(t *testing.T, db *storage.DB) int {
	t.Helper()
	all, _ := db.GetAlerts(false, 0)
	n := 0
	for _, a := range all {
		if a.Type == alerts.TypeServiceOffline {
			n++
		}
	}
	return n
}

// O alerta crítico falso da validação em VM, em forma de teste.
//
// `nftables.service` é Type=oneshot: carrega o /etc/nftables.conf no boot e
// termina. E quem o deixa parado é o próprio LinkGuard — ele habilita a
// unidade e NUNCA a inicia (bootstrapdeps.EnsureNftablesUnitEnabled). Com
// `systemctl is-active` respondendo "inactive", o vigia levantava
// "Serviço offline: nftables" com severidade CRITICAL numa máquina onde nada
// estava errado. Alerta crítico falso treina o operador a ignorar a tela.
func TestOneshotParadaNaoEQuedaMasFalhaE(t *testing.T) {
	fe := &fakeExec{units: map[string]unitShape{"nftables": oneshot("inactive")}}
	c, db := newServiceCollector(t, fe)
	cfg := Config{Enabled: true, Services: []string{"nftables"}}

	// Muitas passadas: se "inactive" fosse tratado como queda, o anti-flap
	// (duas leituras) já teria disparado na segunda.
	for i := 0; i < 5; i++ {
		c.checkServices(cfg)
	}
	if n := countOffline(t, db); n != 0 {
		t.Fatalf("unidade oneshot parada gerou %d alerta(s) service_offline; "+
			"ela carrega o arquivo e termina — parada é o repouso normal dela, e é o "+
			"próprio LinkGuard que a deixa assim de propósito", n)
	}

	// E o caso que importa de verdade continua alertando: `nft -f` recusado
	// no boot deixa a unidade em `failed`, e aí as regras NÃO foram
	// carregadas.
	fe.units["nftables"] = oneshot("failed")
	c.checkServices(cfg)
	c.checkServices(cfg)
	if n := countOffline(t, db); n != 1 {
		t.Fatalf("unidade oneshot em `failed` gerou %d alerta(s), esperava 1: "+
			"esse é o caso em que o ruleset não foi carregado", n)
	}
}

// Daemon de verdade parado continua sendo queda — o conserto acima não pode
// ter emudecido o vigia inteiro.
func TestDaemonParadoContinuaSendoQueda(t *testing.T) {
	fe := &fakeExec{units: map[string]unitShape{"unbound": daemon("active")}}
	c, db := newServiceCollector(t, fe)
	cfg := Config{Enabled: true, Services: []string{"unbound"}}

	c.checkServices(cfg)
	fe.units["unbound"] = daemon("inactive")
	c.checkServices(cfg) // 1ª queda: anti-flap segura
	if n := countOffline(t, db); n != 0 {
		t.Fatalf("uma leitura só já alertou (%d): o anti-flap sumiu", n)
	}
	c.checkServices(cfg) // 2ª queda: alerta
	if n := countOffline(t, db); n != 1 {
		t.Fatalf("daemon parado gerou %d alerta(s), esperava 1", n)
	}
}

// Os outros dois vigiados (kea-dhcp4-server, unbound) são instalados SOB
// DEMANDA, quando o admin liga DHCP/DNS no painel. Numa máquina onde ele
// nunca ligou, a unidade não existe. Ausência não é queda — e um item
// vermelho no painel para um serviço que ninguém pediu é dado falso.
func TestUnidadeAusenteOuMascaradaNaoEQuedaENaoVaiParaOPainel(t *testing.T) {
	for nome, forma := range map[string]unitShape{
		"não instalada": {loadState: "not-found", activeState: "inactive"},
		"mascarada":     {loadState: "masked", activeState: "inactive"},
	} {
		t.Run(nome, func(t *testing.T) {
			fe := &fakeExec{units: map[string]unitShape{"kea-dhcp4-server": forma}}
			c, db := newServiceCollector(t, fe)
			cfg := Config{Enabled: true, Services: []string{"kea-dhcp4-server"}}
			for i := 0; i < 5; i++ {
				c.checkServices(cfg)
			}
			if n := countOffline(t, db); n != 0 {
				t.Errorf("unidade %s gerou %d alerta(s) service_offline", nome, n)
			}
			for _, it := range c.Snapshot() {
				if it.Name == "kea-dhcp4-server" {
					t.Errorf("unidade %s apareceu no painel (Up=%v): dado falso", nome, it.Up)
				}
			}
		})
	}
}

// "Não consegui perguntar" (sem systemd, timeout, binário ausente) não pode
// virar "caiu".
func TestFalhaAoConsultarOSystemdNaoViraQueda(t *testing.T) {
	fe := &fakeExec{showErr: assertErr{}}
	c, db := newServiceCollector(t, fe)
	cfg := Config{Enabled: true, Services: []string{"unbound"}}
	for i := 0; i < 5; i++ {
		c.checkServices(cfg)
	}
	if n := countOffline(t, db); n != 0 {
		t.Fatalf("systemctl indisponível gerou %d alerta(s) service_offline", n)
	}
}

func seqClock() func() int64 {
	var n int64
	return func() int64 { n++; return n }
}

func TestCheckResourceTransitionAlertsOnce(t *testing.T) {
	db := openTestDB(t)
	as := alerts.NewService(db)
	c := &Collector{db: db, alertSvc: as, health: map[string]*itemState{}, nowFn: seqClock()}

	c.checkResource("resource:cpu", "CPU", 10, 90, as.HighCPU, as.CPUNormal) // healthy (first sighting)
	c.checkResource("resource:cpu", "CPU", 95, 90, as.HighCPU, as.CPUNormal) // 1st over -> suppressed
	c.checkResource("resource:cpu", "CPU", 95, 90, as.HighCPU, as.CPUNormal) // 2nd over -> alert
	c.checkResource("resource:cpu", "CPU", 95, 90, as.HighCPU, as.CPUNormal) // still over -> no repeat

	al, _ := db.GetAlerts(false, 0)
	n := 0
	for _, a := range al {
		if a.Type == alerts.TypeHighCPU && a.Severity == alerts.SeverityWarning {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 high_cpu warning alert, got %d", n)
	}
}

func TestCheckResourceBootSpikeSuppressed(t *testing.T) {
	db := openTestDB(t)
	as := alerts.NewService(db)
	c := &Collector{db: db, alertSvc: as, health: map[string]*itemState{}, nowFn: seqClock()}

	c.checkResource("resource:cpu", "CPU", 10, 90, as.HighCPU, as.CPUNormal) // healthy
	c.checkResource("resource:cpu", "CPU", 99, 90, as.HighCPU, as.CPUNormal) // one-tick spike
	c.checkResource("resource:cpu", "CPU", 10, 90, as.HighCPU, as.CPUNormal) // back to healthy

	al, _ := db.GetAlerts(false, 0)
	if len(al) != 0 {
		t.Fatalf("a one-tick boot spike must not alert, got %d alerts", len(al))
	}
}

func TestCheckResourceDiskPolarity(t *testing.T) {
	db := openTestDB(t)
	as := alerts.NewService(db)
	c := &Collector{db: db, alertSvc: as, health: map[string]*itemState{}, nowFn: seqClock()}

	c.checkResource("resource:disk", "Disco", 50, 90, as.DiskFull, as.DiskCleared) // healthy
	c.checkResource("resource:disk", "Disco", 95, 90, as.DiskFull, as.DiskCleared) // 1st over -> suppressed
	c.checkResource("resource:disk", "Disco", 95, 90, as.DiskFull, as.DiskCleared) // 2nd over -> disk_full

	al, _ := db.GetAlerts(false, 0)
	full := 0
	for _, a := range al {
		if a.Type == alerts.TypeDiskFull && a.Severity == alerts.SeverityCritical {
			full++
		}
	}
	if full != 1 {
		t.Fatalf("expected 1 disk_full critical alert, got %d", full)
	}
}

func TestCheckNTPRaisesOnSecondUnsynced(t *testing.T) {
	fe := &fakeExec{ntpSynced: "yes\n"}
	db := openTestDB(t)
	as := alerts.NewService(db)
	c := &Collector{db: db, alertSvc: as, exec: fe, health: map[string]*itemState{}, nowFn: seqClock()}

	c.checkNTP() // synced -> no alert
	fe.ntpSynced = "no\n"
	c.checkNTP() // 1st unsynced -> suppressed
	c.checkNTP() // 2nd unsynced -> alert

	al, _ := db.GetAlerts(false, 0)
	n := 0
	for _, a := range al {
		if a.Type == alerts.TypeNTPUnsynced {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 ntp_unsynced alert, got %d", n)
	}
}

const passingSmartJSON = `{"smart_status":{"passed":true},"ata_smart_attributes":{"table":[{"id":5,"raw":{"value":0,"string":"0"}},{"id":194,"raw":{"value":35,"string":"35"}}]}}`
const failingSmartJSON = `{"smart_status":{"passed":false},"ata_smart_attributes":{"table":[{"id":5,"raw":{"value":9,"string":"9"}},{"id":194,"raw":{"value":60,"string":"60"}}]}}`

func TestCheckSMARTRaisesHealthFailOnSecondReading(t *testing.T) {
	fe := &fakeExec{findmntOut: "/dev/sda2\n", lsblkOut: "sda\n", smartctlOut: passingSmartJSON}
	db := openTestDB(t)
	as := alerts.NewService(db)
	c := &Collector{db: db, alertSvc: as, exec: fe, health: map[string]*itemState{}, nowFn: seqClock()}
	cfg := Config{SMARTReallocatedThreshold: 0, SMARTTempThresholdC: 55}

	c.checkSMART(cfg) // passed -> no alert
	fe.smartctlOut = failingSmartJSON
	c.checkSMART(cfg) // 1st fail -> suppressed
	c.checkSMART(cfg) // 2nd fail -> alert

	al, _ := db.GetAlerts(false, 0)
	var health, realloc, hot int
	for _, a := range al {
		switch a.Type {
		case alerts.TypeDiskSMARTFail:
			health++
		case alerts.TypeDiskSMARTDegraded:
			realloc++
		case alerts.TypeDiskSMARTHot:
			hot++
		}
	}
	if health != 1 {
		t.Errorf("expected exactly 1 disk_smart_fail alert, got %d", health)
	}
	if realloc != 1 {
		t.Errorf("expected exactly 1 disk_smart_degraded alert (9 > 0 threshold), got %d", realloc)
	}
	if hot != 1 {
		t.Errorf("expected exactly 1 disk_smart_hot alert (60 >= 55 threshold), got %d", hot)
	}
}

func TestCheckSMARTReadErrorSkipsTickWithoutAlert(t *testing.T) {
	fe := &fakeExec{findmntOut: "/dev/sda2\n", lsblkOut: "sda\n", smartctlErr: assertErr{}}
	db := openTestDB(t)
	as := alerts.NewService(db)
	c := &Collector{db: db, alertSvc: as, exec: fe, health: map[string]*itemState{}, nowFn: seqClock()}

	c.checkSMART(Config{SMARTReallocatedThreshold: 0, SMARTTempThresholdC: 55})

	al, _ := db.GetAlerts(false, 0)
	if len(al) != 0 {
		t.Fatalf("a read error should not raise a false SMART-fail alert, got %d alerts", len(al))
	}
}

// TestCheckSMARTReallocatedPolarity locks down the +1 polarity trick in
// checkSMART's call to checkResource: with threshold=0, a reallocated-sector
// count of exactly 0 must stay healthy (0 <= 0 is fine), while a count of 1
// must already alert (any reallocated sector at all is a problem when the
// threshold is 0). checkResource's own comparison is strict "<", so
// checkSMART must pass threshold+1, not threshold, or this polarity flips.
func TestCheckSMARTReallocatedPolarity(t *testing.T) {
	healthyJSON := `{"smart_status":{"passed":true},"ata_smart_attributes":{"table":[{"id":5,"raw":{"value":0,"string":"0"}},{"id":194,"raw":{"value":30,"string":"30"}}]}}`
	oneReallocatedJSON := `{"smart_status":{"passed":true},"ata_smart_attributes":{"table":[{"id":5,"raw":{"value":1,"string":"1"}},{"id":194,"raw":{"value":30,"string":"30"}}]}}`

	fe := &fakeExec{findmntOut: "/dev/sda2\n", lsblkOut: "sda\n", smartctlOut: healthyJSON}
	db := openTestDB(t)
	as := alerts.NewService(db)
	c := &Collector{db: db, alertSvc: as, exec: fe, health: map[string]*itemState{}, nowFn: seqClock()}
	cfg := Config{SMARTReallocatedThreshold: 0, SMARTTempThresholdC: 55}

	c.checkSMART(cfg) // count=0, threshold=0 -> healthy, no alert
	fe.smartctlOut = oneReallocatedJSON
	c.checkSMART(cfg) // count=1, threshold=0 -> 1st over -> suppressed
	c.checkSMART(cfg) // count=1, threshold=0 -> 2nd over -> alert

	al, _ := db.GetAlerts(false, 0)
	n := 0
	for _, a := range al {
		if a.Type == alerts.TypeDiskSMARTDegraded {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 disk_smart_degraded alert (count=1 > threshold=0), got %d", n)
	}
}

func TestCheckBootTimeOnlyRunsOnce(t *testing.T) {
	db := openTestDB(t)
	as := alerts.NewService(db)
	c := &Collector{db: db, alertSvc: as, health: map[string]*itemState{}, nowFn: seqClock(), bootIDFn: fakeBootID("boot-new")}
	cfg := Config{Enabled: true, BootTimeThresholdSec: 180}

	c.checkBootTime(200, cfg) // slow boot -> alert
	c.checkBootTime(5, cfg)   // second call must be a no-op (bootChecked guard)

	al, _ := db.GetAlerts(false, 0)
	n := 0
	for _, a := range al {
		if a.Type == alerts.TypeSlowBoot {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 slow_boot alert (second call must be ignored), got %d", n)
	}
}

func TestCheckBootTimeFastBootNoAlert(t *testing.T) {
	db := openTestDB(t)
	as := alerts.NewService(db)
	c := &Collector{db: db, alertSvc: as, health: map[string]*itemState{}, nowFn: seqClock(), bootIDFn: fakeBootID("boot-new")}

	c.checkBootTime(20, Config{Enabled: true, BootTimeThresholdSec: 180})

	al, _ := db.GetAlerts(false, 0)
	if len(al) != 0 {
		t.Fatalf("a fast boot must not alert, got %d alerts", len(al))
	}
}

func TestCheckBootTimeRespectsDisabledToggle(t *testing.T) {
	db := openTestDB(t)
	as := alerts.NewService(db)
	c := &Collector{db: db, alertSvc: as, health: map[string]*itemState{}, nowFn: seqClock(), bootIDFn: fakeBootID("boot-new")}

	c.checkBootTime(300, Config{Enabled: false, BootTimeThresholdSec: 180})

	al, _ := db.GetAlerts(false, 0)
	if len(al) != 0 {
		t.Fatalf("cfg.Enabled=false must suppress the alert even on a slow boot, got %d alerts", len(al))
	}
}

// fakeBootID returns a bootIDFn stub that always reports the given id.
func fakeBootID(id string) func() (string, error) {
	return func() (string, error) { return id, nil }
}

// TestCheckBootTimeSkipsWhenSameBootID reproduces the production bug this
// fix targets: a `systemctl restart linkguard-fw` (e.g. from every package
// deploy's postinst) does NOT reboot the machine, so the kernel's boot_id
// is unchanged from the last time checkBootTime persisted it. In that case
// the process must not measure/alert on the kernel's (large, stale-looking)
// uptime, and the boot-time item must not appear in Snapshot at all.
func TestCheckBootTimeSkipsWhenSameBootID(t *testing.T) {
	db := openTestDB(t)
	as := alerts.NewService(db)
	if err := db.SetSetting(bootLastKnownIDSettingKey, "boot-same"); err != nil {
		t.Fatal(err)
	}
	c := &Collector{db: db, alertSvc: as, health: map[string]*itemState{}, nowFn: seqClock(), bootIDFn: fakeBootID("boot-same")}

	// Simulate exactly the production scenario: kernel uptime of hours
	// (well over BootTimeThresholdSec) at the first tick after a plain
	// service restart.
	c.checkBootTime(14400, Config{Enabled: true, BootTimeThresholdSec: 180})

	al, _ := db.GetAlerts(false, 0)
	n := 0
	for _, a := range al {
		if a.Type == alerts.TypeSlowBoot {
			n++
		}
	}
	if n != 0 {
		t.Fatalf("a same-boot_id restart must not alert slow_boot, got %d", n)
	}

	for _, item := range c.Snapshot() {
		if item.Name == "boot-time" {
			t.Fatalf("boot-time must not appear in Snapshot when boot_id is unchanged (same service restart, not a real boot), got %+v", item)
		}
	}
}

// TestCheckBootTimeDifferentBootIDMeasuresAndPersists confirms the "real
// boot" path: a boot_id different from the last known one (or none saved
// yet) measures/alerts as before AND persists the new boot_id, so that a
// subsequent same-session service restart can recognize it.
func TestCheckBootTimeDifferentBootIDMeasuresAndPersists(t *testing.T) {
	db := openTestDB(t)
	as := alerts.NewService(db)
	if err := db.SetSetting(bootLastKnownIDSettingKey, "boot-old"); err != nil {
		t.Fatal(err)
	}
	c := &Collector{db: db, alertSvc: as, health: map[string]*itemState{}, nowFn: seqClock(), bootIDFn: fakeBootID("boot-new")}

	c.checkBootTime(200, Config{Enabled: true, BootTimeThresholdSec: 180})

	al, _ := db.GetAlerts(false, 0)
	n := 0
	for _, a := range al {
		if a.Type == alerts.TypeSlowBoot {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("a genuinely new boot_id over threshold should alert slow_boot, got %d", n)
	}

	found := false
	for _, item := range c.Snapshot() {
		if item.Name == "boot-time" {
			found = true
		}
	}
	if !found {
		t.Fatal("boot-time should appear in Snapshot for a real boot")
	}

	saved, err := db.GetSetting(bootLastKnownIDSettingKey)
	if err != nil {
		t.Fatal(err)
	}
	if saved != "boot-new" {
		t.Fatalf("expected the new boot_id to be persisted, got %q", saved)
	}
}
