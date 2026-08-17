package storage_test

import (
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// Rede de segurança para o recorte da issue #26: os eventos de failover são o
// histórico de por que a máquina trocou de link, e não tinham nenhum teste.

func TestCreateFailoverEventRoundTrip(t *testing.T) {
	db := newTestDB(t)

	e := &storage.FailoverEvent{
		LinkID:     "link-giga",
		LinkName:   "WAN1 Giga",
		FromStatus: "up",
		ToStatus:   "down",
		Reason:     "3 sondas perdidas seguidas",
		Commands:   "ip route replace default via 192.168.1.254",
		DryRun:     true,
	}
	if err := db.CreateFailoverEvent(e); err != nil {
		t.Fatalf("CreateFailoverEvent: %v", err)
	}
	if e.ID == "" {
		t.Error("esperava ID gerado")
	}
	if e.CreatedAt.IsZero() {
		t.Error("esperava created_at preenchido")
	}

	got, err := db.GetFailoverEvents(10)
	if err != nil {
		t.Fatalf("GetFailoverEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("esperava 1 evento, veio %d", len(got))
	}
	g := got[0]
	if g.ID != e.ID || g.LinkID != e.LinkID || g.LinkName != e.LinkName ||
		g.FromStatus != "up" || g.ToStatus != "down" ||
		g.Reason != e.Reason || g.Commands != e.Commands {
		t.Errorf("evento voltou diferente: %+v", g)
	}
	// dry_run é INTEGER no banco: o round-trip do bool precisa valer, senão um
	// ensaio vira um failover de verdade no histórico.
	if !g.DryRun {
		t.Error("esperava DryRun=true")
	}
}

func TestCreateFailoverEventKeepsTheGivenID(t *testing.T) {
	db := newTestDB(t)

	e := &storage.FailoverEvent{ID: "id-escolhido", LinkID: "l", LinkName: "n"}
	if err := db.CreateFailoverEvent(e); err != nil {
		t.Fatalf("CreateFailoverEvent: %v", err)
	}
	if e.ID != "id-escolhido" {
		t.Errorf("esperava o ID informado, veio %s", e.ID)
	}
}

func TestGetFailoverEventsRespectsTheLimit(t *testing.T) {
	db := newTestDB(t)

	for i := 0; i < 5; i++ {
		e := &storage.FailoverEvent{LinkID: "l", LinkName: "n", FromStatus: "up", ToStatus: "down"}
		if err := db.CreateFailoverEvent(e); err != nil {
			t.Fatalf("CreateFailoverEvent: %v", err)
		}
	}

	got, err := db.GetFailoverEvents(3)
	if err != nil {
		t.Fatalf("GetFailoverEvents(3): %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("esperava 3 eventos, veio %d", len(got))
	}

	// limit <= 0 cai no padrão de 100, não em "nenhum".
	got, err = db.GetFailoverEvents(0)
	if err != nil {
		t.Fatalf("GetFailoverEvents(0): %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("esperava os 5 eventos com limit=0, veio %d", len(got))
	}

	got, err = db.GetFailoverEvents(-1)
	if err != nil {
		t.Fatalf("GetFailoverEvents(-1): %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("esperava os 5 eventos com limit=-1, veio %d", len(got))
	}
}

func TestGetFailoverEventsIsNilWhenEmpty(t *testing.T) {
	db := newTestDB(t)

	got, err := db.GetFailoverEvents(10)
	if err != nil {
		t.Fatalf("GetFailoverEvents: %v", err)
	}
	if got != nil {
		t.Fatalf("esperava nil, veio %#v", got)
	}
}
