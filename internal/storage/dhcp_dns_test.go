package storage_test

import (
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// Esta máquina serve DHCP e DNS para a LAN inteira: uma reserva perdida tira um
// host do ar com IP trocado, e um domínio que fica na blocklist depois de
// removido derruba um serviço legítimo. Os testes abaixo olham só o que dá para
// observar de fora (o que a listagem devolve depois de cada escrita).

// ─── DHCP reservations ───────────────────────────────────────────────────────

// reservationByMAC procura uma reserva na listagem; devolve nil se não achar.
func reservationByMAC(t *testing.T, db *storage.DB, mac string) *storage.DHCPReservation {
	t.Helper()
	list, err := db.ListDHCPReservations()
	if err != nil {
		t.Fatalf("ListDHCPReservations: %v", err)
	}
	for i := range list {
		if list[i].MAC == mac {
			return &list[i]
		}
	}
	return nil
}

func TestUpsertDHCPReservationCreatesTheReservation(t *testing.T) {
	db := newTestDB(t)

	if err := db.UpsertDHCPReservation("aa:bb:cc:dd:ee:01", "192.168.3.50", "impressora"); err != nil {
		t.Fatalf("UpsertDHCPReservation: %v", err)
	}

	got := reservationByMAC(t, db, "aa:bb:cc:dd:ee:01")
	if got == nil {
		t.Fatal("esperava a reserva na listagem, não veio nada")
	}
	if got.IP != "192.168.3.50" {
		t.Errorf("esperava IP=192.168.3.50, veio %s", got.IP)
	}
	if got.Hostname != "impressora" {
		t.Errorf("esperava Hostname=impressora, veio %s", got.Hostname)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Errorf("esperava created_at/updated_at preenchidos, veio %v / %v", got.CreatedAt, got.UpdatedAt)
	}
}

func TestUpsertDHCPReservationUpdatesTheSameMACInPlace(t *testing.T) {
	db := newTestDB(t)

	if err := db.UpsertDHCPReservation("aa:bb:cc:dd:ee:02", "192.168.3.51", "notebook"); err != nil {
		t.Fatalf("UpsertDHCPReservation (1): %v", err)
	}
	first := reservationByMAC(t, db, "aa:bb:cc:dd:ee:02")
	if first == nil {
		t.Fatal("esperava a reserva depois do primeiro upsert")
	}

	// Mesmo MAC, IP e hostname novos: tem que sobrescrever, não duplicar.
	if err := db.UpsertDHCPReservation("aa:bb:cc:dd:ee:02", "192.168.3.99", "notebook-novo"); err != nil {
		t.Fatalf("UpsertDHCPReservation (2): %v", err)
	}

	list, err := db.ListDHCPReservations()
	if err != nil {
		t.Fatalf("ListDHCPReservations: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("esperava 1 reserva depois do upsert, veio %d", len(list))
	}
	got := list[0]
	if got.IP != "192.168.3.99" {
		t.Errorf("esperava IP=192.168.3.99, veio %s", got.IP)
	}
	if got.Hostname != "notebook-novo" {
		t.Errorf("esperava Hostname=notebook-novo, veio %s", got.Hostname)
	}
	if !got.CreatedAt.Equal(first.CreatedAt) {
		t.Errorf("created_at deveria ser preservado no upsert: era %v, virou %v", first.CreatedAt, got.CreatedAt)
	}
	if !got.UpdatedAt.After(first.UpdatedAt) {
		t.Errorf("updated_at deveria avançar no upsert: era %v, virou %v", first.UpdatedAt, got.UpdatedAt)
	}
}

func TestUpsertDHCPReservationAcceptsEmptyHostname(t *testing.T) {
	db := newTestDB(t)

	if err := db.UpsertDHCPReservation("aa:bb:cc:dd:ee:03", "192.168.3.52", ""); err != nil {
		t.Fatalf("UpsertDHCPReservation: %v", err)
	}
	got := reservationByMAC(t, db, "aa:bb:cc:dd:ee:03")
	if got == nil {
		t.Fatal("esperava a reserva mesmo sem hostname")
	}
	if got.Hostname != "" {
		t.Errorf("esperava hostname vazio, veio %q", got.Hostname)
	}
}

// A chave é o MAC, então dois MACs diferentes podem reivindicar o mesmo IP.
// O banco não impede — quem chama é que precisa validar (aqui só fixamos o
// contrato para que uma mudança de comportamento apareça).
func TestUpsertDHCPReservationDoesNotPreventDuplicateIP(t *testing.T) {
	db := newTestDB(t)

	if err := db.UpsertDHCPReservation("aa:bb:cc:dd:ee:04", "192.168.3.60", "host-a"); err != nil {
		t.Fatalf("UpsertDHCPReservation a: %v", err)
	}
	if err := db.UpsertDHCPReservation("aa:bb:cc:dd:ee:05", "192.168.3.60", "host-b"); err != nil {
		t.Fatalf("UpsertDHCPReservation b: %v", err)
	}

	list, err := db.ListDHCPReservations()
	if err != nil {
		t.Fatalf("ListDHCPReservations: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("esperava 2 reservas (o storage não desduplica IP), veio %d", len(list))
	}
}

// O MAC é usado cru como chave primária: maiúsculas e minúsculas viram linhas
// distintas. Quem chama precisa normalizar antes (o handler HTTP faz isso).
func TestUpsertDHCPReservationIsCaseSensitiveOnMAC(t *testing.T) {
	db := newTestDB(t)

	if err := db.UpsertDHCPReservation("aa:bb:cc:dd:ee:06", "192.168.3.61", "minusculo"); err != nil {
		t.Fatalf("UpsertDHCPReservation minúsculo: %v", err)
	}
	if err := db.UpsertDHCPReservation("AA:BB:CC:DD:EE:06", "192.168.3.62", "maiusculo"); err != nil {
		t.Fatalf("UpsertDHCPReservation maiúsculo: %v", err)
	}

	list, err := db.ListDHCPReservations()
	if err != nil {
		t.Fatalf("ListDHCPReservations: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("esperava 2 linhas (MAC é case-sensitive no storage), veio %d", len(list))
	}
}

func TestListDHCPReservationsIsOrderedByIP(t *testing.T) {
	db := newTestDB(t)

	// IPs escolhidos para que a ordem seja a mesma em texto e numericamente.
	for _, r := range []struct{ mac, ip string }{
		{"aa:bb:cc:dd:ee:30", "192.168.3.30"},
		{"aa:bb:cc:dd:ee:10", "192.168.3.10"},
		{"aa:bb:cc:dd:ee:20", "192.168.3.20"},
	} {
		if err := db.UpsertDHCPReservation(r.mac, r.ip, ""); err != nil {
			t.Fatalf("UpsertDHCPReservation %s: %v", r.mac, err)
		}
	}

	list, err := db.ListDHCPReservations()
	if err != nil {
		t.Fatalf("ListDHCPReservations: %v", err)
	}
	want := []string{"192.168.3.10", "192.168.3.20", "192.168.3.30"}
	if len(list) != len(want) {
		t.Fatalf("esperava %d reservas, veio %d", len(want), len(list))
	}
	for i, ip := range want {
		if list[i].IP != ip {
			t.Errorf("posição %d: esperava %s, veio %s", i, ip, list[i].IP)
		}
	}
}

func TestUpsertDHCPReservationFailsOnClosedDB(t *testing.T) {
	db := newTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := db.UpsertDHCPReservation("aa:bb:cc:dd:ee:07", "192.168.3.70", "x"); err == nil {
		t.Fatal("esperava erro ao gravar reserva com o banco fechado, veio nil")
	}
}

func TestDeleteDHCPReservationRemovesOnlyTheGivenMAC(t *testing.T) {
	db := newTestDB(t)

	if err := db.UpsertDHCPReservation("aa:bb:cc:dd:ee:08", "192.168.3.80", "vai"); err != nil {
		t.Fatalf("UpsertDHCPReservation 1: %v", err)
	}
	if err := db.UpsertDHCPReservation("aa:bb:cc:dd:ee:09", "192.168.3.81", "fica"); err != nil {
		t.Fatalf("UpsertDHCPReservation 2: %v", err)
	}

	if err := db.DeleteDHCPReservation("aa:bb:cc:dd:ee:08"); err != nil {
		t.Fatalf("DeleteDHCPReservation: %v", err)
	}

	list, err := db.ListDHCPReservations()
	if err != nil {
		t.Fatalf("ListDHCPReservations: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("esperava 1 reserva restante, veio %d", len(list))
	}
	if list[0].MAC != "aa:bb:cc:dd:ee:09" {
		t.Errorf("apagou a reserva errada: sobrou %s", list[0].MAC)
	}
}

// Apagar um MAC que não existe não é erro (é um no-op silencioso), e não pode
// levar junto nenhuma outra reserva.
func TestDeleteDHCPReservationUnknownMACIsANoOp(t *testing.T) {
	db := newTestDB(t)

	if err := db.UpsertDHCPReservation("aa:bb:cc:dd:ee:0a", "192.168.3.90", "fica"); err != nil {
		t.Fatalf("UpsertDHCPReservation: %v", err)
	}

	if err := db.DeleteDHCPReservation("ff:ff:ff:ff:ff:ff"); err != nil {
		t.Fatalf("DeleteDHCPReservation (MAC inexistente): %v", err)
	}

	list, err := db.ListDHCPReservations()
	if err != nil {
		t.Fatalf("ListDHCPReservations: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("esperava a reserva existente intacta, veio %d linhas", len(list))
	}
}

func TestDeleteDHCPReservationFailsOnClosedDB(t *testing.T) {
	db := newTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := db.DeleteDHCPReservation("aa:bb:cc:dd:ee:0b"); err == nil {
		t.Fatal("esperava erro ao apagar reserva com o banco fechado, veio nil")
	}
}

// ─── DNS blocklist ───────────────────────────────────────────────────────────

func TestAddDNSBlocklistStoresTheDomain(t *testing.T) {
	db := newTestDB(t)

	if err := db.AddDNSBlocklist("ads.example.com"); err != nil {
		t.Fatalf("AddDNSBlocklist: %v", err)
	}

	list, err := db.ListDNSBlocklist()
	if err != nil {
		t.Fatalf("ListDNSBlocklist: %v", err)
	}
	if len(list) != 1 || list[0] != "ads.example.com" {
		t.Fatalf("esperava [ads.example.com], veio %v", list)
	}
}

// Bloquear o mesmo domínio duas vezes é operação corriqueira (dois cliques no
// painel): não pode explodir nem duplicar a linha.
func TestAddDNSBlocklistTwiceIsIdempotent(t *testing.T) {
	db := newTestDB(t)

	if err := db.AddDNSBlocklist("tracker.example.com"); err != nil {
		t.Fatalf("AddDNSBlocklist (1): %v", err)
	}
	if err := db.AddDNSBlocklist("tracker.example.com"); err != nil {
		t.Fatalf("AddDNSBlocklist (2) deveria ser no-op, veio erro: %v", err)
	}

	list, err := db.ListDNSBlocklist()
	if err != nil {
		t.Fatalf("ListDNSBlocklist: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("esperava 1 domínio, veio %d: %v", len(list), list)
	}
}

func TestAddDNSBlocklistKeepsTheListSortedAndAccumulates(t *testing.T) {
	db := newTestDB(t)

	for _, d := range []string{"zeta.example.com", "alfa.example.com", "meio.example.com"} {
		if err := db.AddDNSBlocklist(d); err != nil {
			t.Fatalf("AddDNSBlocklist %s: %v", d, err)
		}
	}

	list, err := db.ListDNSBlocklist()
	if err != nil {
		t.Fatalf("ListDNSBlocklist: %v", err)
	}
	want := []string{"alfa.example.com", "meio.example.com", "zeta.example.com"}
	if len(list) != len(want) {
		t.Fatalf("esperava %d domínios, veio %d: %v", len(want), len(list), list)
	}
	for i := range want {
		if list[i] != want[i] {
			t.Errorf("posição %d: esperava %s, veio %s", i, want[i], list[i])
		}
	}
}

// O storage guarda o domínio como veio: "Example.com" e "example.com" são duas
// linhas. Quem chama normaliza (o handler HTTP aplica ToLower antes de gravar).
func TestAddDNSBlocklistIsCaseSensitive(t *testing.T) {
	db := newTestDB(t)

	if err := db.AddDNSBlocklist("example.com"); err != nil {
		t.Fatalf("AddDNSBlocklist minúsculo: %v", err)
	}
	if err := db.AddDNSBlocklist("Example.com"); err != nil {
		t.Fatalf("AddDNSBlocklist capitalizado: %v", err)
	}

	list, err := db.ListDNSBlocklist()
	if err != nil {
		t.Fatalf("ListDNSBlocklist: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("esperava 2 linhas (domínio é case-sensitive no storage), veio %d: %v", len(list), list)
	}
}

func TestAddDNSBlocklistFailsOnClosedDB(t *testing.T) {
	db := newTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := db.AddDNSBlocklist("ads.example.com"); err == nil {
		t.Fatal("esperava erro ao bloquear domínio com o banco fechado, veio nil")
	}
}

func TestDeleteDNSBlocklistRemovesOnlyTheGivenDomain(t *testing.T) {
	db := newTestDB(t)

	for _, d := range []string{"vai.example.com", "fica.example.com"} {
		if err := db.AddDNSBlocklist(d); err != nil {
			t.Fatalf("AddDNSBlocklist %s: %v", d, err)
		}
	}

	if err := db.DeleteDNSBlocklist("vai.example.com"); err != nil {
		t.Fatalf("DeleteDNSBlocklist: %v", err)
	}

	list, err := db.ListDNSBlocklist()
	if err != nil {
		t.Fatalf("ListDNSBlocklist: %v", err)
	}
	if len(list) != 1 || list[0] != "fica.example.com" {
		t.Fatalf("esperava [fica.example.com], veio %v", list)
	}
}

// Desbloquear um domínio que não está na lista não é erro — o desbloqueio é
// idempotente do ponto de vista de quem chama.
func TestDeleteDNSBlocklistUnknownDomainIsANoOp(t *testing.T) {
	db := newTestDB(t)

	if err := db.AddDNSBlocklist("fica.example.com"); err != nil {
		t.Fatalf("AddDNSBlocklist: %v", err)
	}
	if err := db.DeleteDNSBlocklist("nunca-bloqueado.example.com"); err != nil {
		t.Fatalf("DeleteDNSBlocklist (domínio ausente): %v", err)
	}

	list, err := db.ListDNSBlocklist()
	if err != nil {
		t.Fatalf("ListDNSBlocklist: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("esperava a lista intacta com 1 domínio, veio %v", list)
	}
}

// Bloquear de novo depois de desbloquear tem que voltar a valer — se o INSERT
// OR IGNORE deixasse resíduo, o domínio nunca mais entraria na lista.
func TestDNSBlocklistAddDeleteAddRoundTrip(t *testing.T) {
	db := newTestDB(t)

	if err := db.AddDNSBlocklist("volta.example.com"); err != nil {
		t.Fatalf("AddDNSBlocklist (1): %v", err)
	}
	if err := db.DeleteDNSBlocklist("volta.example.com"); err != nil {
		t.Fatalf("DeleteDNSBlocklist: %v", err)
	}
	if err := db.AddDNSBlocklist("volta.example.com"); err != nil {
		t.Fatalf("AddDNSBlocklist (2): %v", err)
	}

	list, err := db.ListDNSBlocklist()
	if err != nil {
		t.Fatalf("ListDNSBlocklist: %v", err)
	}
	if len(list) != 1 || list[0] != "volta.example.com" {
		t.Fatalf("esperava [volta.example.com] depois do ciclo, veio %v", list)
	}
}

func TestDeleteDNSBlocklistFailsOnClosedDB(t *testing.T) {
	db := newTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := db.DeleteDNSBlocklist("ads.example.com"); err == nil {
		t.Fatal("esperava erro ao desbloquear domínio com o banco fechado, veio nil")
	}
}
