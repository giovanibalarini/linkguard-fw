package handlers

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// A #59 tem duas metades, e esta é a que o admin encontra: a recusa precisa
// NOMEAR o MAC dono do IP.
//
// Sem isso ele descobre que não pode usar aquele endereço e não descobre qual
// reserva remover para poder — e a tela lista as reservas por MAC, não por IP,
// então nem procurando ele acha. Uma recusa que não diz o caminho de saída é só
// um obstáculo.

func newDHCPConflitoHandler(t *testing.T) *NetsvcHandler {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() }) //nolint:errcheck // teste
	return NewNetsvcHandler(db, fakeNetsvcProvider{}, nil, nil)
}

func upsertReserva(t *testing.T, h *NetsvcHandler, mac, ip, hostname string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"MAC": mac, "IP": ip, "Hostname": hostname})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	rec := httptest.NewRecorder()
	h.UpsertReservation(rec, httptest.NewRequest("POST", "/api/dhcp/reservations", strings.NewReader(string(body))))
	return rec
}

func TestUpsertReservationRecusaIPJaReservadoENomeiaOMACDono(t *testing.T) {
	h := newDHCPConflitoHandler(t)

	if rec := upsertReserva(t, h, "AA:BB:CC:00:00:01", "192.168.3.50", "impressora"); rec.Code != 200 {
		t.Fatalf("primeira reserva: status %d, corpo %s", rec.Code, rec.Body.String())
	}

	rec := upsertReserva(t, h, "AA:BB:CC:00:00:02", "192.168.3.50", "nvr")

	// 409 e não 400: o pedido está bem formado; o que conflita é o estado.
	if rec.Code != 409 {
		t.Fatalf("status = %d, esperado 409 — corpo: %s", rec.Code, rec.Body.String())
	}

	corpo := rec.Body.String()
	// O MAC vem normalizado em minúsculas pelo handler, que é como ele aparece
	// na listagem da tela — é esse texto que o admin vai procurar.
	if !strings.Contains(corpo, "aa:bb:cc:00:00:01") {
		t.Errorf("a recusa não nomeia o MAC dono do IP; o admin não saberia qual reserva remover. Corpo: %s", corpo)
	}
	if !strings.Contains(corpo, "192.168.3.50") {
		t.Errorf("a recusa não nomeia o IP em conflito. Corpo: %s", corpo)
	}
}

// TestUpsertReservationDeixaOMesmoMACSalvarDeNovo impede que a correção vire um
// bloqueio bobo: reeditar o hostname de um host, sem trocar o IP, é a operação
// mais comum desta tela. Se a checagem não excluísse a própria reserva, nenhum
// host poderia mais ser editado.
func TestUpsertReservationDeixaOMesmoMACSalvarDeNovo(t *testing.T) {
	h := newDHCPConflitoHandler(t)

	if rec := upsertReserva(t, h, "AA:BB:CC:00:00:01", "192.168.3.50", "impressora"); rec.Code != 200 {
		t.Fatalf("primeira: status %d", rec.Code)
	}
	rec := upsertReserva(t, h, "AA:BB:CC:00:00:01", "192.168.3.50", "impressora do 2o andar")
	if rec.Code != 200 {
		t.Fatalf("reeditar a própria reserva foi recusado: status %d, corpo %s", rec.Code, rec.Body.String())
	}
}
