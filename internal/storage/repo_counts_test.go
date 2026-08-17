package storage_test

import (
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// Rede de segurança para o recorte da issue #26: CountLinks e CountAlerts
// estavam encalhados a ~900 linhas dos seus domínios e não tinham teste, embora
// alimentem o /health (CountLinks) e o coletor de monitoramento (CountAlerts).

func TestCountLinks(t *testing.T) {
	db := newTestDB(t)

	n, err := db.CountLinks()
	if err != nil {
		t.Fatalf("CountLinks: %v", err)
	}
	if n != 0 {
		t.Fatalf("esperava 0 links, veio %d", n)
	}

	for _, name := range []string{"WAN1", "WAN2"} {
		l := &storage.Link{Name: name, Interface: "eth0", IPAddress: "192.168.1.1",
			Gateway: "192.168.1.254", Weight: 100, TableID: 100, Enabled: true}
		if err := db.CreateLink(l); err != nil {
			t.Fatalf("CreateLink(%s): %v", name, err)
		}
	}

	n, err = db.CountLinks()
	if err != nil {
		t.Fatalf("CountLinks: %v", err)
	}
	if n != 2 {
		t.Fatalf("esperava 2 links, veio %d", n)
	}
}

func TestCountLinksCountsDisabledLinksToo(t *testing.T) {
	db := newTestDB(t)

	l := &storage.Link{Name: "WAN desligada", Interface: "eth1", IPAddress: "192.168.2.1",
		Gateway: "192.168.2.254", Weight: 100, TableID: 101, Enabled: false}
	if err := db.CreateLink(l); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	n, err := db.CountLinks()
	if err != nil {
		t.Fatalf("CountLinks: %v", err)
	}
	// É COUNT(*) da tabela: link desligado continua sendo um link configurado, e
	// o /health conta configuração, não link no ar.
	if n != 1 {
		t.Fatalf("esperava 1 link, veio %d", n)
	}
}

func TestCountAlertsCountsOnlyTheUnresolvedOnes(t *testing.T) {
	db := newTestDB(t)

	n, err := db.CountAlerts()
	if err != nil {
		t.Fatalf("CountAlerts: %v", err)
	}
	if n != 0 {
		t.Fatalf("esperava 0 alertas, veio %d", n)
	}

	aberto := &storage.Alert{Type: "link_down", Severity: "critical", Title: "WAN1 caiu", Message: "sem resposta"}
	if err := db.CreateAlert(aberto); err != nil {
		t.Fatalf("CreateAlert: %v", err)
	}
	jaFechado := &storage.Alert{Type: "link_up", Severity: "info", Title: "WAN1 voltou", Message: "ok", Resolved: true}
	if err := db.CreateAlert(jaFechado); err != nil {
		t.Fatalf("CreateAlert: %v", err)
	}

	n, err = db.CountAlerts()
	if err != nil {
		t.Fatalf("CountAlerts: %v", err)
	}
	if n != 1 {
		t.Fatalf("esperava 1 alerta em aberto, veio %d", n)
	}

	if err := db.ResolveAlert(aberto.ID); err != nil {
		t.Fatalf("ResolveAlert: %v", err)
	}
	n, err = db.CountAlerts()
	if err != nil {
		t.Fatalf("CountAlerts: %v", err)
	}
	if n != 0 {
		t.Fatalf("esperava 0 alertas depois de resolver, veio %d", n)
	}
}
