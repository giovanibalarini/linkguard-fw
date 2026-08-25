package storage_test

import (
	"sync"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// ─── Cota por aparelho (issue #126) ──────────────────────────────────────────

func TestAddHostUsageSomaNoSQLENaoEmGo(t *testing.T) {
	db := newTestDB(t)
	const mac = "aa:bb:cc:dd:ee:ff"
	const ciclo = int64(1_750_000_000)

	// Cem somas concorrentes. Com read-modify-write em Go, parte delas se
	// perderia e o consumo exibido seria menor que o real — o modo de falha que
	// o ON CONFLICT ... rx_bytes + excluded.rx_bytes existe para impedir.
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := db.AddHostUsage(mac, storage.HostPeriodMonthly, ciclo, 1000, 500); err != nil {
				t.Errorf("AddHostUsage: %v", err)
			}
		}()
	}
	wg.Wait()

	u, err := db.GetHostUsage(mac, storage.HostPeriodMonthly, ciclo)
	if err != nil {
		t.Fatalf("GetHostUsage: %v", err)
	}
	if u.RxBytes != 100_000 || u.TxBytes != 50_000 {
		t.Errorf("rx=%d tx=%d, queria 100000/50000 — alguma soma se perdeu", u.RxBytes, u.TxBytes)
	}
}

func TestGetHostUsageDeCicloSemTrafegoNaoEhErro(t *testing.T) {
	db := newTestDB(t)
	// Ciclo novo, ainda sem tráfego medido: zero é a resposta certa, e não erro.
	// Se fosse erro, o Flush pararia de avaliar a cota no primeiro minuto de
	// cada ciclo.
	u, err := db.GetHostUsage("aa:bb:cc:dd:ee:ff", storage.HostPeriodMonthly, 1)
	if err != nil {
		t.Fatalf("GetHostUsage: %v", err)
	}
	if u.RxBytes != 0 || u.TxBytes != 0 {
		t.Errorf("ciclo vazio veio com %d/%d", u.RxBytes, u.TxBytes)
	}
}

func TestGetHostUsageAllTrazSoOCicloPedido(t *testing.T) {
	db := newTestDB(t)
	const a = "aa:bb:cc:dd:ee:ff"
	const b = "11:22:33:44:55:66"
	if err := db.AddHostUsage(a, storage.HostPeriodMonthly, 100, 10, 0); err != nil {
		t.Fatal(err)
	}
	if err := db.AddHostUsage(b, storage.HostPeriodMonthly, 100, 20, 0); err != nil {
		t.Fatal(err)
	}
	// Mesmo aparelho, ciclo anterior: não pode entrar na leitura do ciclo atual,
	// senão a tela somaria mês passado com este.
	if err := db.AddHostUsage(a, storage.HostPeriodMonthly, 50, 999, 0); err != nil {
		t.Fatal(err)
	}

	got, err := db.GetHostUsageAll(storage.HostPeriodMonthly, 100)
	if err != nil {
		t.Fatalf("GetHostUsageAll: %v", err)
	}
	if len(got) != 2 || got[a].RxBytes != 10 || got[b].RxBytes != 20 {
		t.Errorf("GetHostUsageAll(monthly, 100) = %+v", got)
	}
}

func TestSaveHostQuotaSubstituiSemDuplicar(t *testing.T) {
	db := newTestDB(t)
	const mac = "aa:bb:cc:dd:ee:ff"
	q := storage.HostQuota{MAC: mac, LimitGB: 5, Period: storage.HostPeriodMonthly, CycleDay: 10, AlertPct: 80, AlertEnabled: true}
	if err := db.SaveHostQuota(q); err != nil {
		t.Fatal(err)
	}
	q.LimitGB = 0
	q.AlertEnabled = false
	if err := db.SaveHostQuota(q); err != nil {
		t.Fatal(err)
	}
	quotas, err := db.GetHostQuotas()
	if err != nil {
		t.Fatal(err)
	}
	if len(quotas) != 1 {
		t.Fatalf("gravou %d linhas para o mesmo aparelho", len(quotas))
	}
	// O dia de fechamento SOBREVIVE à remoção da cota: é ele que decide qual
	// ciclo a tela lê, e perdê-lo esconderia o consumo já medido.
	if quotas[mac].CycleDay != 10 {
		t.Errorf("cycle_day = %d depois de zerar a cota, queria 10", quotas[mac].CycleDay)
	}
}
