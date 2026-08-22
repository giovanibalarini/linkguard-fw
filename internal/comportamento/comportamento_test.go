package comportamento

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

func novoServico(t *testing.T) (*Servico, *storage.DB) {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NovoServico(db, alerts.NewService(db)), db
}

func alertasAbertos(t *testing.T, db *storage.DB, tipo string) int {
	t.Helper()
	as, err := db.GetAlerts(true, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, a := range as {
		if a.Type == tipo {
			n++
		}
	}
	return n
}

func TestAparelhoNovoAvisaUmaVezSo(t *testing.T) {
	// A issue é explícita: alerta de comportamento que dispara demais é pior
	// que nenhum — vira ruído e some no meio dos outros.
	s, db := novoServico(t)
	if err := db.UpsertHostSighting("aa:bb:cc:dd:ee:01", "192.168.3.50"); err != nil {
		t.Fatal(err)
	}

	s.Verificar()
	if n := alertasAbertos(t, db, alerts.TypeHostNovoNaRede); n != 1 {
		t.Fatalf("primeiro aviso: %d alertas, queria 1", n)
	}
	// Segunda passada, minutos depois: nada de novo.
	s.agora = func() time.Time { return time.Now().Add(2 * time.Minute) }
	s.Verificar()
	if n := alertasAbertos(t, db, alerts.TypeHostNovoNaRede); n != 1 {
		t.Errorf("o mesmo aparelho gerou %d alertas", n)
	}
}

func TestAparelhoVelhoNaoEhNovo(t *testing.T) {
	s, db := novoServico(t)
	if err := db.UpsertHostSighting("aa:bb:cc:dd:ee:02", "192.168.3.51"); err != nil {
		t.Fatal(err)
	}
	// Uma hora depois, ele já não é novidade.
	s.agora = func() time.Time { return time.Now().Add(time.Hour) }
	s.Verificar()
	if n := alertasAbertos(t, db, alerts.TypeHostNovoNaRede); n != 0 {
		t.Errorf("aparelho de uma hora atrás foi anunciado como novo (%d)", n)
	}
}

func TestSemHistoricoNaoInventaNormal(t *testing.T) {
	// Duas amostras não definem o normal de ninguém. Alertar aqui seria
	// inventar um baseline — e o alerta que nasce de um baseline inventado é
	// exatamente o que ensina o admin a ignorar a tela.
	s, db := novoServico(t)
	if err := db.UpsertHostSighting("aa:bb:cc:dd:ee:03", "192.168.3.52"); err != nil {
		t.Fatal(err)
	}
	agora := time.Now()
	for i := 0; i < 3; i++ {
		_ = db.UpsertMetricSample(storage.MetricSample{
			Series: SerieConsumo, Label: "aa:bb:cc:dd:ee:03", StepSeconds: PassoBaseline,
			TsUnix: agora.Add(-time.Duration(i) * 5 * time.Minute).Unix(),
			VAvg:   500 * 1024 * 1024,
		})
	}
	s.agora = func() time.Time { return agora.Add(time.Hour) }
	s.Verificar()
	if n := alertasAbertos(t, db, alerts.TypeHostAcimaDoNormal); n != 0 {
		t.Errorf("alertou sobre consumo com três amostras de histórico (%d)", n)
	}
}

func TestPisoAbsolutoImpedeRuidoDeAparelhoQuieto(t *testing.T) {
	// SEM O PISO O DETECTOR SERIA INÚTIL E BARULHENTO AO MESMO TEMPO: um
	// aparelho que faz 1 KB/s e passa a fazer 4 KB/s excedeu o triplo, e não
	// aconteceu nada. É a divisão por um normal pequeno que faz detector de
	// desvio virar gerador de ruído.
	s, db := novoServico(t)
	mac := "aa:bb:cc:dd:ee:04"
	if err := db.UpsertHostSighting(mac, "192.168.3.53"); err != nil {
		t.Fatal(err)
	}
	agora := time.Now()
	// Histórico farto na mesma hora, com valores minúsculos.
	for i := 1; i <= 40; i++ {
		_ = db.UpsertMetricSample(storage.MetricSample{
			Series: SerieConsumo, Label: mac, StepSeconds: PassoBaseline,
			TsUnix: agora.Add(-time.Duration(i) * 24 * time.Hour).Unix(),
			VAvg:   1024,
		})
	}
	// E agora "dez vezes mais": 10 KB/s. Dez vezes o normal, e irrelevante.
	_ = db.UpsertMetricSample(storage.MetricSample{
		Series: SerieConsumo, Label: mac, StepSeconds: PassoBaseline,
		TsUnix: agora.Unix(), VAvg: 10 * 1024,
	})
	s.agora = func() time.Time { return agora }
	s.Verificar()
	if n := alertasAbertos(t, db, alerts.TypeHostAcimaDoNormal); n != 0 {
		t.Errorf("alertou sobre 10 KB/s por ser dez vezes o normal (%d)", n)
	}
}

func TestFormatarTaxaEhLegivel(t *testing.T) {
	for _, c := range []struct {
		bps  float64
		quer string
	}{
		{5 * 1024 * 1024, "5.0 MB/s"},
		{200 * 1024, "200 KB/s"},
		{300, "300 B/s"},
	} {
		if got := FormatarTaxa(c.bps); got != c.quer {
			t.Errorf("FormatarTaxa(%v) = %q, queria %q", c.bps, got, c.quer)
		}
	}
}

// TestPassoBaselineExisteNoTSDB amarra o passo que o detector CONSULTA ao
// conjunto de passos que o tsdb realmente GRAVA para esta série.
//
// POR QUE ESTE TESTE EXISTE. O detector pedia o passo 300, que o produto nunca
// gravou. GetMetricSamples casa o passo por igualdade exata, então a consulta
// voltava vazia para todo aparelho, consumo() desistia por falta de histórico e
// o alerta de "acima do normal" nunca pôde disparar. Medido em produção antes
// do conserto: a série existia nos passos 10, 60, 900 e 3600, com zero linhas
// no 300 e zero alertas emitidos desde a entrega.
//
// Os outros testes deste arquivo não pegavam isso porque INSEREM as amostras
// com o passo que eles mesmos escolhem — provam a aritmética da mediana num
// histórico que o produto não é capaz de produzir. Um teste que semeia o dado
// que testa concorda com qualquer número; este pergunta ao produtor.
func TestPassoBaselineExisteNoTSDB(t *testing.T) {
	passos := tsdb.StepsFor(SerieConsumo)
	for _, p := range passos {
		if p == PassoBaseline {
			return
		}
	}
	t.Fatalf("o detector consulta %s no passo %d, e o tsdb só grava esta série nos passos %v: "+
		"a consulta volta vazia para todo aparelho e o alerta nunca dispara",
		SerieConsumo, PassoBaseline, passos)
}

// TestJanelaDoBaselineCabeNaRetencao garante que a janela de sete dias não peça
// justamente a borda que a limpeza apaga. É o motivo de o passo ser 900 e não
// 60: o passo 60 é mantido por exatamente sete dias no perfil padrão.
func TestJanelaDoBaselineCabeNaRetencao(t *testing.T) {
	for _, perfil := range []string{tsdb.Profile30d, tsdb.Profile1y, tsdb.Profile5y} {
		guardado, ok := tsdb.RetentionFor(perfil, PassoBaseline)
		if !ok {
			t.Fatalf("perfil %s não guarda o passo %d", perfil, PassoBaseline)
		}
		if guardado <= JanelaBaseline {
			t.Errorf("perfil %s guarda o passo %d por %v, e o baseline pede %v: a borda da janela é apagada enquanto a consulta a pede",
				perfil, PassoBaseline, guardado, JanelaBaseline)
		}
	}
}
