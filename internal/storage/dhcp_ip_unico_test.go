package storage_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// Issue #59: a tabela dhcp_reservations tinha PK só em `mac`, e o handler só
// validava que MAC e IP parseavam. Dois MACs podiam reivindicar o mesmo
// endereço; o kea aceitava a configuração gerada e entregava o IP aos dois.
//
// O que chega ao admin não é "reserva duplicada" — é conflito de endereço
// intermitente, que só aparece com os dois aparelhos ligados ao mesmo tempo.

func TestUpsertDHCPReservationRecusaIPDeOutroMAC(t *testing.T) {
	db := newTestDB(t)

	if err := db.UpsertDHCPReservation("aa:bb:cc:00:00:01", "192.168.1.50", "impressora"); err != nil {
		t.Fatalf("primeira reserva: %v", err)
	}

	err := db.UpsertDHCPReservation("aa:bb:cc:00:00:02", "192.168.1.50", "nvr")
	if err == nil {
		t.Fatal("a segunda reserva com o mesmo IP foi aceita — dois aparelhos na LAN com o mesmo endereço")
	}

	var taken *storage.ErrDHCPIPTaken
	if !errors.As(err, &taken) {
		t.Fatalf("erro = %v, esperado *ErrDHCPIPTaken", err)
	}
	// O MAC dono é o conteúdo útil: sem ele o admin não sabe qual reserva
	// remover, e a tela lista por MAC, não por IP.
	if taken.OwnerMAC != "aa:bb:cc:00:00:01" {
		t.Errorf("OwnerMAC = %q, esperado o MAC da primeira reserva", taken.OwnerMAC)
	}
	if taken.IP != "192.168.1.50" {
		t.Errorf("IP = %q, esperado 192.168.1.50", taken.IP)
	}

	// E a recusa não pode ter deixado a segunda reserva pela metade.
	list, err := db.ListDHCPReservations()
	if err != nil {
		t.Fatalf("ListDHCPReservations: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("esperava 1 reserva depois da recusa, veio %d", len(list))
	}
}

// TestUpsertDHCPReservationDeixaOMesmoMACReeditarOProprioIP é o contraponto, e
// é ele que impede a correção de virar um bloqueio bobo: a checagem tem um
// `mac != ?` justamente para que reeditar o hostname de um host — sem trocar o
// IP — continue funcionando. Sem essa cláusula, a reserva colidiria consigo
// mesma e nenhum host poderia mais ser editado.
func TestUpsertDHCPReservationDeixaOMesmoMACReeditarOProprioIP(t *testing.T) {
	db := newTestDB(t)

	if err := db.UpsertDHCPReservation("aa:bb:cc:00:00:01", "192.168.1.50", "impressora"); err != nil {
		t.Fatalf("primeira: %v", err)
	}
	if err := db.UpsertDHCPReservation("aa:bb:cc:00:00:01", "192.168.1.50", "impressora do 2o andar"); err != nil {
		t.Fatalf("reeditar o hostname mantendo o IP foi recusado: %v", err)
	}

	list, err := db.ListDHCPReservations()
	if err != nil {
		t.Fatalf("ListDHCPReservations: %v", err)
	}
	if len(list) != 1 || list[0].Hostname != "impressora do 2o andar" {
		t.Fatalf("esperava 1 reserva com o hostname novo, veio %+v", list)
	}
}

// TestUpsertDHCPReservationLiberaOIPDepoisDeApagarADono: o IP volta a ficar
// disponível quando a reserva que o segurava sai. Óbvio, e é o caminho que o
// admin percorre para resolver um conflito — se ele não funcionasse, a
// correção teria criado um beco sem saída.
func TestUpsertDHCPReservationLiberaOIPDepoisDeApagarADono(t *testing.T) {
	db := newTestDB(t)

	if err := db.UpsertDHCPReservation("aa:bb:cc:00:00:01", "192.168.1.50", ""); err != nil {
		t.Fatalf("primeira: %v", err)
	}
	if err := db.DeleteDHCPReservation("aa:bb:cc:00:00:01"); err != nil {
		t.Fatalf("DeleteDHCPReservation: %v", err)
	}
	if err := db.UpsertDHCPReservation("aa:bb:cc:00:00:02", "192.168.1.50", ""); err != nil {
		t.Fatalf("o IP não foi liberado depois de apagar a reserva dona: %v", err)
	}
}

// TestBootComReservasDuplicadasNaoQuebra é a parte da #59 que a issue mandou
// decidir de propósito, e é a mais importante deste arquivo.
//
// `CREATE UNIQUE INDEX` sobre uma tabela que já tem duplicata FALHA. Se isso
// acontecesse dentro do boot, o resultado não seria um erro de índice: seria o
// firewall não subir por causa de dado que já estava lá — a classe do incidente
// de 2026-07-24, em que uma migração travada deixou a máquina mais de 50
// minutos fora do ar.
//
// O teste simula a base "suja" escrevendo a duplicata por SQL cru (é o único
// jeito: a partir desta correção o caminho normal recusa), fecha, e reabre.
// Reabrir é o que o boot faz.
func TestBootComReservasDuplicadasNaoQuebra(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sujo.db")

	db, err := storage.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Um Open sobre base limpa já cria o índice, então para simular a base
	// LEGADA — a gravada por uma versão anterior a esta correção, que é o
	// cenário que importa — é preciso derrubá-lo antes de semear.
	if _, err := db.Conn().Exec(`DROP INDEX IF EXISTS idx_dhcp_reservations_ip`); err != nil {
		t.Fatalf("derrubar o índice para simular a base legada: %v", err)
	}

	// Por fora do Upsert, de propósito: o caminho normal agora recusa, e o que
	// se quer aqui é a linha que já está no banco de alguém.
	for _, mac := range []string{"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"} {
		_, err := db.Conn().Exec(`
			INSERT INTO dhcp_reservations (mac, ip, hostname, created_at, updated_at)
			VALUES (?, '192.168.1.50', '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`, mac)
		if err != nil {
			t.Fatalf("semear duplicata (%s): %v", mac, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// O boot. Não pode falhar.
	db2, err := storage.Open(path)
	if err != nil {
		t.Fatalf("o boot falhou numa base com reserva duplicada — "+
			"o firewall não subiria por causa de dado que já estava lá: %v", err)
	}
	defer db2.Close() //nolint:errcheck // teste

	// E as duas reservas continuam lá: apagar uma por conta própria decidiria
	// pelo admin qual aparelho perde o endereço fixo.
	list, err := db2.ListDHCPReservations()
	if err != nil {
		t.Fatalf("ListDHCPReservations: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("o boot mexeu nas reservas do admin: esperava as 2, veio %d", len(list))
	}
}

// TestIndiceUnicoNasceDepoisQueOAdminResolveOConflito prova que a espera
// anunciada no log é real.
//
// É por isto que a criação do índice NÃO é uma migração versionada: o runner
// registra a migração como aplicada assim que ela retorna sem erro, então uma
// migração que "pulasse" o índice nunca mais seria tentada — o índice não
// existiria para sempre, em silêncio. Rodando a cada boot, ele nasce sozinho
// quando a base fica limpa.
func TestIndiceUnicoNasceDepoisQueOAdminResolveOConflito(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolve.db")

	db, err := storage.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Mesma simulação de base legada do teste acima.
	if _, err := db.Conn().Exec(`DROP INDEX IF EXISTS idx_dhcp_reservations_ip`); err != nil {
		t.Fatalf("derrubar o índice para simular a base legada: %v", err)
	}
	for _, mac := range []string{"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"} {
		if _, err := db.Conn().Exec(`
			INSERT INTO dhcp_reservations (mac, ip, hostname, created_at, updated_at)
			VALUES (?, '192.168.1.50', '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`, mac); err != nil {
			t.Fatalf("semear duplicata: %v", err)
		}
	}
	db.Close() //nolint:errcheck // teste

	// Boot com a base suja: o índice não pode existir ainda.
	db2, err := storage.Open(path)
	if err != nil {
		t.Fatalf("Open (base suja): %v", err)
	}
	if indiceExiste(t, db2) {
		t.Fatal("o índice único foi criado sobre uma base com duplicata")
	}

	// O admin resolve o conflito pela tela.
	if err := db2.DeleteDHCPReservation("aa:bb:cc:00:00:02"); err != nil {
		t.Fatalf("DeleteDHCPReservation: %v", err)
	}
	db2.Close() //nolint:errcheck // teste

	// Boot seguinte: agora o índice nasce, sem ninguém pedir.
	db3, err := storage.Open(path)
	if err != nil {
		t.Fatalf("Open (base limpa): %v", err)
	}
	defer db3.Close() //nolint:errcheck // teste
	if !indiceExiste(t, db3) {
		t.Error("o índice único não foi criado depois de a base ficar limpa — " +
			"a rede de baixo nunca chegaria a existir")
	}
}

func indiceExiste(t *testing.T, db *storage.DB) bool {
	t.Helper()
	var n int
	err := db.Conn().QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_dhcp_reservations_ip'`,
	).Scan(&n)
	if err != nil {
		t.Fatalf("consultar sqlite_master: %v", err)
	}
	return n > 0
}
