package tsdb_test

import (
	"context"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

// O defeito: Run saía no ctx.Done() sem gravar nada, e o balde da janela
// corrente ia embora. Como o auto-update reinicia o serviço, cada atualização
// abria um buraco nas séries de tráfego, latência e perda — as mesmas que o
// vigia usa depois para dizer se um link estava ruim.
//
// A sutileza que este teste guarda: um `tick` no desligamento NÃO resolveria.
// O tick só fecha balde cuja janela já virou; o que estava em curso continuaria
// perdido. Por isso Flush() fecha tudo, inclusive o balde corrente.
func TestFlushWritesTheInProgressBucket(t *testing.T) {
	db := newTestDB(t)
	svc := tsdb.NewService(db)

	// Uma amostra agora: cai no balde da janela corrente, que ainda não virou.
	now := time.Now().Unix()
	svc.GaugeForTest("if.rx_bps", "enp0s3", 12345, now)

	// Antes do flush, nada no banco: o balde está só em memória.
	before, err := db.GetMetricSamples("if.rx_bps", "enp0s3", 1, now-60, now+60)
	if err != nil {
		t.Fatalf("GetMetricSamples: %v", err)
	}
	if len(before) != 0 {
		t.Fatalf("esperava nada gravado antes do flush, veio %d", len(before))
	}

	svc.Flush()

	after, err := db.GetMetricSamples("if.rx_bps", "enp0s3", 1, now-60, now+60)
	if err != nil {
		t.Fatalf("GetMetricSamples: %v", err)
	}
	if len(after) == 0 {
		t.Fatal("o balde em curso não foi gravado pelo Flush — é o dado que se perdia a cada reinício")
	}
	if after[0].VMax != 12345 {
		t.Errorf("valor gravado errado: %v", after[0].VMax)
	}
}

// E o caminho de verdade: Run, cancelamento do contexto, dado no banco.
func TestRunFlushesOnContextCancel(t *testing.T) {
	db := newTestDB(t)
	svc := tsdb.NewService(db)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { svc.Run(ctx); close(done) }()

	now := time.Now().Unix()
	svc.GaugeForTest("if.tx_bps", "enp0s4", 999, now)

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run não retornou depois do cancelamento")
	}

	got, err := db.GetMetricSamples("if.tx_bps", "enp0s4", 1, now-60, now+60)
	if err != nil {
		t.Fatalf("GetMetricSamples: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("o desligamento do Run não gravou o balde em curso")
	}
}
