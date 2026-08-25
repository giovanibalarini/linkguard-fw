package hostquota

import (
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// ─── 1. O último minuto do ciclo pertence ao ciclo QUE ACABOU ────────────────
//
// O amostrador entrega deltas a cada dez segundos; o flush roda a cada minuto.
// Com o ciclo decidido no instante do FLUSH, tudo o que foi medido nos ~60 s
// antes da virada era gravado na chave do ciclo NOVO: o dia que acabou fechava
// com zero e o dia seguinte nascia estourado, com alerta crítico sobre tráfego
// que o aparelho não fez naquele dia.
//
// No mensal é um minuto por mês; no diário é um minuto por DIA, e um minuto a
// 300 Mbit/s são 2,25 GB — mais que a cota diária inteira de um tablet.
func TestOQueFoiMedidoAntesDaViradaFicaNoCicloQueAcabou(t *testing.T) {
	db := newTestDB(t)
	al := &alerterFalso{}
	svc := NewService(db, al)
	aparelho(t, db, macA, "192.168.3.50", "notebook")
	if err := svc.Save(storage.HostQuota{MAC: macA, LimitGB: 1, Period: storage.HostPeriodDaily, CycleDay: 1, AlertPct: 80}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loc := time.UTC
	ontem := time.Date(2026, 8, 25, 23, 59, 55, 0, loc)
	svc.nowFn = func() time.Time { return ontem }
	medir(svc, macA, 2_000_000_000, 0) // 2 GB às 23:59:55

	// O flush só acontece depois da meia-noite.
	hoje := time.Date(2026, 8, 26, 0, 0, 20, 0, loc)
	svc.nowFn = func() time.Time { return hoje }
	svc.Flush()

	inicioDeOntem := CycleStart(ontem, storage.HostPeriodDaily, 1).Unix()
	inicioDeHoje := CycleStart(hoje, storage.HostPeriodDaily, 1).Unix()

	uOntem, err := db.GetHostUsage(macA, storage.HostPeriodDaily, inicioDeOntem)
	if err != nil {
		t.Fatal(err)
	}
	uHoje, err := db.GetHostUsage(macA, storage.HostPeriodDaily, inicioDeHoje)
	if err != nil {
		t.Fatal(err)
	}
	if uOntem.RxBytes != 2_000_000_000 {
		t.Errorf("o dia 25 fechou com %d bytes: o consumo dele foi parar noutro ciclo", uOntem.RxBytes)
	}
	if uHoje.RxBytes != 0 {
		t.Errorf("o dia 26 nasceu com %d bytes que o aparelho não gastou nele", uHoje.RxBytes)
	}
	if al.temCriado(TypeQuotaExceeded + "|" + macA) {
		t.Errorf("o ciclo novo nasceu estourado: %v", al.criados)
	}
}

// ─── 2. Reinício ATRAVÉS da virada não pode deixar o alerta preso ────────────
//
// lastCycle é memória e nasce vazio a cada processo. Se o daemon reinicia
// DEPOIS da virada — upgrade noturno, reboot, crash —, o primeiro flush só
// semeava o mapa e nunca resolvia nada: o alerta do ciclo anterior ficava
// aberto para sempre e, como alerts.Create deduplica por (tipo, chave), o aviso
// do ciclo seguinte, e do seguinte, nunca era criado. A feature morre em
// silêncio, com a suíte verde.
func TestReinicioDepoisDaViradaResolveOAlertaDoCicloAnterior(t *testing.T) {
	db := newTestDB(t)
	aparelho(t, db, macA, "192.168.3.50", "notebook")

	loc := time.UTC
	ontem := time.Date(2026, 8, 25, 20, 0, 0, 0, loc)

	// Processo 1: estoura a cota no dia 25.
	al1 := &alerterFalso{}
	svc1 := NewService(db, al1)
	svc1.nowFn = func() time.Time { return ontem }
	if err := svc1.Save(storage.HostQuota{MAC: macA, LimitGB: 0.001, Period: storage.HostPeriodDaily, CycleDay: 1, AlertPct: 80, AlertEnabled: true}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	medir(svc1, macA, 2_000_000, 0)
	svc1.Flush()
	if !al1.temCriado(TypeQuotaExceeded + "|" + macA) {
		t.Fatalf("não estourou no dia 25: %v", al1.criados)
	}

	// Processo 2: serviço NOVO sobre o MESMO banco, já no dia 26. É o upgrade
	// noturno, e lastCycle está vazio.
	hoje := time.Date(2026, 8, 26, 9, 0, 0, 0, loc)
	al2 := &alerterFalso{}
	svc2 := NewService(db, al2)
	svc2.nowFn = func() time.Time { return hoje }
	svc2.Flush()

	if !al2.temResolvido(TypeQuotaExceeded + "|" + macA) {
		t.Errorf("o estouro do dia 25 ficou preso depois do reinício: %v", al2.resolvidos)
	}
	if !al2.temResolvido(TypeQuotaWarning + "|" + macA) {
		t.Errorf("o aviso do dia 25 ficou preso depois do reinício: %v", al2.resolvidos)
	}
}

// ─── 3. Trocar período/dia não pode zerar a barra com o alerta aberto ────────
//
// Delete foi escrito para não mover a chave do ciclo. Save cometia exatamente o
// defeito que Delete evita: o consumo ficava sob a chave antiga, a tela passava
// a ler a nova, a barra voltava para 0% — e o alerta de "cota em 95%"
// continuava no painel. Tela e alerta discordando sobre o mesmo aparelho.
func TestTrocarODiaDeFechamentoNaoZeraOConsumoNemDeixaOAlertaAberto(t *testing.T) {
	db := newTestDB(t)
	al := &alerterFalso{}
	svc := NewService(db, al)
	aparelho(t, db, macA, "192.168.3.50", "notebook")

	loc := time.UTC
	agora := time.Date(2026, 8, 10, 12, 0, 0, 0, loc)
	svc.nowFn = func() time.Time { return agora }

	if err := svc.Save(storage.HostQuota{MAC: macA, LimitGB: 0.001, Period: storage.HostPeriodMonthly, CycleDay: 1, AlertPct: 80, AlertEnabled: true}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	medir(svc, macA, 950_000, 0) // 95%
	svc.Flush()
	antes, err := svc.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if antes[0].UsedBytes == 0 {
		t.Fatal("nada foi medido antes da troca")
	}
	if !al.temCriado(TypeQuotaWarning + "|" + macA) {
		t.Fatalf("não avisou em 95%%: %v", al.criados)
	}

	// O admin muda o fechamento para o dia 28. A chave do ciclo vigente muda.
	al.resolvidos = nil
	if err := svc.Save(storage.HostQuota{MAC: macA, LimitGB: 0.001, Period: storage.HostPeriodMonthly, CycleDay: 28, AlertPct: 80, AlertEnabled: true}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	depois, err := svc.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if depois[0].CycleStart == antes[0].CycleStart {
		t.Fatal("o ciclo não mudou: o teste deixou de exercitar o defeito")
	}
	if depois[0].UsedBytes != antes[0].UsedBytes {
		t.Errorf("o consumo caiu de %d para %d ao trocar o dia de fechamento",
			antes[0].UsedBytes, depois[0].UsedBytes)
	}
	if !al.temResolvido(TypeQuotaWarning + "|" + macA) {
		t.Errorf("o ciclo foi redefinido e o aviso antigo continuou aberto: %v", al.resolvidos)
	}
}

// Trocar mensal→diário é o mesmo defeito com um salto maior: o acumulado do mês
// passaria a ser lido na chave da meia-noite de hoje.
func TestTrocarMensalParaDiarioLevaOConsumoJunto(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(db, &alerterFalso{})
	aparelho(t, db, macA, "192.168.3.50", "tv")

	agora := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	svc.nowFn = func() time.Time { return agora }
	if err := svc.Save(storage.HostQuota{MAC: macA, LimitGB: 5, Period: storage.HostPeriodMonthly, CycleDay: 1, AlertPct: 80}); err != nil {
		t.Fatal(err)
	}
	medir(svc, macA, 3_000_000, 0)
	svc.Flush()

	if err := svc.Save(storage.HostQuota{MAC: macA, LimitGB: 5, Period: storage.HostPeriodDaily, CycleDay: 1, AlertPct: 80}); err != nil {
		t.Fatal(err)
	}
	st, err := svc.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if st[0].UsedBytes != 3_000_000 {
		t.Errorf("depois de trocar para diário o consumo virou %d, queria 3000000", st[0].UsedBytes)
	}
	if st[0].Period != storage.HostPeriodDaily {
		t.Errorf("o período gravado foi %q", st[0].Period)
	}
}

// ─── 4. O aviso é decidido no Save, não herdado do corpo do PUT ──────────────
//
// O campo vinha do JSON decodificado cru. Um PUT sem ele gravava false por
// zero-value: a tela desenhava a cota, a barra enchia, cruzava 100% — e o flush
// pulava aquele aparelho para sempre. Uma cota ativa aos olhos e morta na
// prática, sem nada na interface que permitisse perceber.
func TestCotaSalvaSemOCampoDoAvisoAindaAvisa(t *testing.T) {
	db := newTestDB(t)
	al := &alerterFalso{}
	svc := NewService(db, al)
	aparelho(t, db, macA, "192.168.3.50", "câmera")

	// Exatamente o que chega de um PUT que não mandou o campo.
	if err := svc.Save(storage.HostQuota{MAC: macA, LimitGB: 0.001, Period: storage.HostPeriodMonthly, CycleDay: 1, AlertPct: 80}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	quotas, err := db.GetHostQuotas()
	if err != nil {
		t.Fatal(err)
	}
	if !quotas[macA].AlertEnabled {
		t.Fatal("a cota foi gravada com o aviso desligado por zero-value do JSON")
	}

	medir(svc, macA, 2_000_000, 0)
	svc.Flush()
	if !al.temCriado(TypeQuotaExceeded + "|" + macA) {
		t.Errorf("a cota encheu e nenhum alerta nasceu: %v", al.criados)
	}
	st, err := svc.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !st[0].AlertEnabled {
		t.Error("a tela mostraria uma cota desenhada e muda")
	}
}

// ─── 5. Erro do banco não pode comer o minuto que já saiu da fila ────────────
//
// Flush drena pending ANTES de falar com o banco. Sem devolver o que não foi
// gravado, um "database is locked" — que não é hipótese remota, porque o
// mesmo SQLite recebe as escritas de metric_samples — apaga permanentemente o
// minuto medido.
func TestErroDoBancoDevolveOMinutoParaAFila(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(db, nil)
	medir(svc, macA, 1_234_000, 5_000)
	db.Close() // qualquer consulta a partir daqui falha

	svc.Flush()

	svc.mu.Lock()
	porInstante := svc.pending[macA]
	svc.mu.Unlock()
	var rx, tx uint64
	for _, d := range porInstante {
		rx += d.rx
		tx += d.tx
	}
	if rx != 1_234_000 || tx != 5_000 {
		t.Errorf("a fila ficou com %d/%d depois do erro: o minuto medido evaporou", rx, tx)
	}
}

// ─── 6. Falha ao gravar não pode tirar o aparelho do controle de ciclo ──────
//
// O continue depois do erro de AddHostUsage pulava novoLastCycle. Na rodada
// seguinte o aparelho aparecia como desconhecido, e a virada de ciclo dele não
// resolvia alerta nenhum — que é justamente a diferença entre a feature
// funcionar e não funcionar no ciclo diário.
func TestFalhaAoGravarNaoTiraOAparelhoDoControleDeCiclo(t *testing.T) {
	db := newTestDB(t)
	al := &alerterFalso{}
	svc := NewService(db, al)
	aparelho(t, db, macA, "192.168.3.50", "notebook")
	if err := svc.Save(storage.HostQuota{MAC: macA, LimitGB: 1, Period: storage.HostPeriodDaily, CycleDay: 1, AlertPct: 80, AlertEnabled: true}); err != nil {
		t.Fatal(err)
	}

	loc := time.UTC
	ontem := time.Date(2026, 8, 25, 20, 0, 0, 0, loc)
	svc.nowFn = func() time.Time { return ontem }

	// A tabela some debaixo do flush: AddHostUsage falha, GetHostQuotas não.
	if _, err := db.Conn().Exec(derrubaHostUsage); err != nil {
		t.Fatalf("derrubar host_usage: %v", err)
	}
	medir(svc, macA, 1_000, 0)
	svc.Flush()
	if _, visto := svc.lastCycle[macA]; !visto {
		t.Fatal("o aparelho saiu do controle de ciclo por causa de um erro de gravação")
	}
	if _, err := db.Conn().Exec(recriaHostUsage); err != nil {
		t.Fatalf("recriar host_usage: %v", err)
	}

	// Virada do dia: com o aparelho ainda no mapa, os alertas de ontem fecham.
	hoje := ontem.AddDate(0, 0, 1)
	svc.nowFn = func() time.Time { return hoje }
	al.resolvidos = nil
	svc.Flush()
	if !al.temResolvido(TypeQuotaExceeded + "|" + macA) {
		t.Errorf("a virada do dia não fechou os alertas de ontem: %v", al.resolvidos)
	}
}

// SQL de teste com aspas simples fica em constante, pelo mesmo motivo do resto:
// legibilidade do corpo do teste.
const (
	derrubaHostUsage = `ALTER TABLE host_usage RENAME TO host_usage_escondida`
	recriaHostUsage  = `ALTER TABLE host_usage_escondida RENAME TO host_usage`
)

// ─── 7. A tela precisa distinguir aparelho comportado de medição morta ──────
//
// host_metadata guarda a linha para sempre depois do primeiro avistamento,
// então Present continua verdadeiro para o MAC de privacidade que um celular
// rotacionou ontem: 0% consumido, barra verde, para sempre — a cota-fantasma.
// LastSeen e MeasuredAt são o que permite à tela dizer "sem medição neste
// ciclo" em vez de desenhar saúde.
func TestSnapshotDizQuandoOAparelhoFoiVistoEQuandoFoiMedido(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(db, nil)
	aparelho(t, db, macA, "192.168.3.50", "tablet")
	if err := svc.Save(storage.HostQuota{MAC: macA, LimitGB: 1, Period: storage.HostPeriodMonthly, CycleDay: 1, AlertPct: 80}); err != nil {
		t.Fatal(err)
	}

	// Cota declarada, nada medido ainda: a barra verde seria uma mentira.
	st, err := svc.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if st[0].MeasuredAt != 0 {
		t.Errorf("measured_at = %d sem nada medido", st[0].MeasuredAt)
	}
	if st[0].LastSeen == 0 {
		t.Error("last_seen veio zerado para um aparelho que está no inventário")
	}

	medir(svc, macA, 1_000, 0)
	svc.Flush()
	st, err = svc.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if st[0].MeasuredAt == 0 {
		t.Error("o ciclo foi medido e measured_at continuou zero: a tela não distingue medição viva de morta")
	}
}

// ─── 8. A poda roda no máximo uma vez por dia ───────────────────────────────
func TestAPodaNaoRodaAcadaMinuto(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(db, nil)
	agora := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	svc.nowFn = func() time.Time { return agora }

	svc.Flush()
	primeira := svc.ultimaPoda
	if primeira.IsZero() {
		t.Fatal("a poda nunca rodou")
	}
	svc.nowFn = func() time.Time { return agora.Add(time.Minute) }
	svc.Flush()
	if !svc.ultimaPoda.Equal(primeira) {
		t.Error("a poda rodou de novo um minuto depois: é um DELETE com subconsulta a cada flush")
	}
	svc.nowFn = func() time.Time { return agora.Add(25 * time.Hour) }
	svc.Flush()
	if svc.ultimaPoda.Equal(primeira) {
		t.Error("a poda não voltou a rodar depois de 25 h")
	}
}
