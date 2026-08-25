package storage

import (
	"path/filepath"
	"strings"
	"testing"
)

func abrirCota(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "cota.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// O ciclo DIÁRIO do dia 1 e o ciclo MENSAL que fecha no dia 1 têm o MESMO
// cycle_start. Sem period na chave primária, o ON CONFLICT de AddHostUsage soma
// os dois na mesma linha: o consumo de um dia vira o consumo do mês, e o
// histórico devolve linhas de dia ao lado de linhas de mês sem nada que as
// distinga.
func TestConsumoDiarioENaoSeMisturaComOMensalNoMesmoInstante(t *testing.T) {
	db := abrirCota(t)
	const mac = "aa:bb:cc:dd:ee:ff"
	const inicio = int64(1_754_006_400) // 1 de agosto

	if err := db.AddHostUsage(mac, HostPeriodMonthly, inicio, 1000, 0); err != nil {
		t.Fatal(err)
	}
	if err := db.AddHostUsage(mac, HostPeriodDaily, inicio, 7, 0); err != nil {
		t.Fatal(err)
	}

	mensal, err := db.GetHostUsage(mac, HostPeriodMonthly, inicio)
	if err != nil {
		t.Fatal(err)
	}
	diario, err := db.GetHostUsage(mac, HostPeriodDaily, inicio)
	if err != nil {
		t.Fatal(err)
	}
	if mensal.RxBytes != 1000 {
		t.Errorf("o ciclo mensal ficou com %d bytes: o diário do mesmo instante foi somado nele", mensal.RxBytes)
	}
	if diario.RxBytes != 7 {
		t.Errorf("o ciclo diário ficou com %d bytes", diario.RxBytes)
	}

	// E o histórico tem de dizer QUAL dos dois é cada linha.
	hist, err := db.GetHostUsageHistory(mac, 12)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 2 {
		t.Fatalf("histórico com %d linha(s), queria 2 (uma por período)", len(hist))
	}
	periodos := map[string]bool{}
	for _, h := range hist {
		periodos[h.Period] = true
	}
	if !periodos[HostPeriodMonthly] || !periodos[HostPeriodDaily] {
		t.Errorf("o histórico não distingue os períodos: %+v", hist)
	}
}

// GetHostUsageAll filtra por (period, cycle_start) e a chave primária começa
// por mac: sem o índice, é varredura da tabela inteira. Com ciclo diário a
// tabela cresce uma linha por aparelho por dia, e o Snapshot roda a cada minuto
// por aba aberta.
func TestGetHostUsageAllUsaIndiceENaoVarreATabela(t *testing.T) {
	db := abrirCota(t)
	rows, err := db.Conn().Query(
		`EXPLAIN QUERY PLAN SELECT mac, period, cycle_start, rx_bytes, tx_bytes, updated_at FROM host_usage WHERE period = ? AND cycle_start = ?`,
		HostPeriodMonthly, int64(1))
	if err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN: %v", err)
	}
	defer rows.Close()
	var plano strings.Builder
	for rows.Next() {
		var id, parent, notused int
		var detalhe string
		if err := rows.Scan(&id, &parent, &notused, &detalhe); err != nil {
			t.Fatalf("scan: %v", err)
		}
		plano.WriteString(detalhe)
		plano.WriteString(" ")
	}
	p := plano.String()
	if !strings.Contains(p, "idx_host_usage_cycle") {
		t.Errorf("o plano não usa idx_host_usage_cycle: %q", p)
	}
	if strings.Contains(p, "SCAN host_usage") {
		t.Errorf("a leitura do ciclo varre host_usage inteira: %q", p)
	}
}

// MoveHostUsage é o que impede o Save de esconder o consumo já medido ao trocar
// o período ou o dia de fechamento — o defeito de 2026-08-20 entrando pela
// porta que o Delete foi escrito para trancar.
func TestMoveHostUsageLevaOConsumoParaAChaveNova(t *testing.T) {
	db := abrirCota(t)
	const mac = "aa:bb:cc:dd:ee:ff"
	if err := db.AddHostUsage(mac, HostPeriodMonthly, 100, 950, 50); err != nil {
		t.Fatal(err)
	}
	// A chave nova já tem consumo: o move SOMA, não substitui.
	if err := db.AddHostUsage(mac, HostPeriodMonthly, 200, 1, 0); err != nil {
		t.Fatal(err)
	}
	if err := db.MoveHostUsage(mac, HostPeriodMonthly, 100, HostPeriodMonthly, 200); err != nil {
		t.Fatalf("MoveHostUsage: %v", err)
	}
	novo, err := db.GetHostUsage(mac, HostPeriodMonthly, 200)
	if err != nil {
		t.Fatal(err)
	}
	if novo.RxBytes != 951 || novo.TxBytes != 50 {
		t.Errorf("chave nova = %d/%d, queria 951/50", novo.RxBytes, novo.TxBytes)
	}
	velho, err := db.GetHostUsage(mac, HostPeriodMonthly, 100)
	if err != nil {
		t.Fatal(err)
	}
	if velho.RxBytes != 0 || velho.TxBytes != 0 {
		t.Errorf("a chave antiga sobreviveu com %d/%d: o consumo ficou contado duas vezes", velho.RxBytes, velho.TxBytes)
	}
}

// host_usage não tinha poda nenhuma. Com telefone rotacionando endereço físico
// e ciclo diário, cada MAC transitório deixa uma linha por dia, invisível na
// tela (o Snapshot só itera inventário mais cotas) e imortal no banco.
func TestPurgeHostUsagePodaOTransitorioEPreservaQuemTemCota(t *testing.T) {
	db := abrirCota(t)
	const comCota = "aa:bb:cc:dd:ee:ff"
	const transitorio = "11:22:33:44:55:66"
	const zerada = "99:88:77:66:55:44"

	if err := db.SaveHostQuota(HostQuota{MAC: comCota, LimitGB: 5, Period: HostPeriodMonthly, CycleDay: 1, AlertPct: 80, AlertEnabled: true}); err != nil {
		t.Fatal(err)
	}
	// Linha preservada pelo Delete: limite zero. Ela existe para guardar o
	// ciclo, e não para imunizar o histórico contra a retenção.
	if err := db.SaveHostQuota(HostQuota{MAC: zerada, LimitGB: 0, Period: HostPeriodMonthly, CycleDay: 1, AlertPct: 80}); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{comCota, transitorio, zerada} {
		if err := db.AddHostUsage(m, HostPeriodDaily, 100, 10, 0); err != nil {
			t.Fatal(err)
		}
		if err := db.AddHostUsage(m, HostPeriodDaily, 5000, 10, 0); err != nil {
			t.Fatal(err)
		}
	}

	n, err := db.PurgeHostUsage(1000)
	if err != nil {
		t.Fatalf("PurgeHostUsage: %v", err)
	}
	if n != 2 {
		t.Errorf("podou %d linha(s), queria 2", n)
	}
	if u, _ := db.GetHostUsage(comCota, HostPeriodDaily, 100); u.RxBytes != 10 {
		t.Error("a retenção apagou o histórico de um aparelho COM cota declarada")
	}
	if u, _ := db.GetHostUsage(transitorio, HostPeriodDaily, 100); u.RxBytes != 0 {
		t.Error("o ciclo antigo do MAC transitório sobreviveu: a tabela cresce para sempre")
	}
	if u, _ := db.GetHostUsage(transitorio, HostPeriodDaily, 5000); u.RxBytes != 10 {
		t.Error("a retenção comeu o ciclo RECENTE")
	}
}

// SQL com aspas simples fica em constante, para o corpo dos testes continuar
// legível.
const (
	limpaMarcadorCota = `DELETE FROM settings WHERE key = 'migration_hosts_quota_granted'`
	revogaCota        = `DELETE FROM role_permissions WHERE role_id = ? AND permission = 'hosts.quota'`
)

// A cota nasceu gateada por hosts.block — a permissão de TRANCAR aparelho.
// Papéis embutidos não são re-semeados, então sem esta migração quem declarava
// cota ontem perderia a tela no upgrade.
func TestMigracaoConcedeHostsQuotaAQuemJaBloqueava(t *testing.T) {
	db := abrirCota(t)
	if _, err := db.conn.Exec(limpaMarcadorCota); err != nil {
		t.Fatalf("limpar o marcador: %v", err)
	}
	podeBloquear := []string{"hosts.read", "hosts.block"}
	soLe := []string{"hosts.read"}
	operador := &Role{Name: "Operador", Permissions: podeBloquear}
	visualizador := &Role{Name: "Visualizador", Permissions: soLe}
	for _, r := range []*Role{operador, visualizador} {
		if err := db.CreateRole(r); err != nil {
			t.Fatalf("CreateRole %s: %v", r.Name, err)
		}
	}
	if err := db.runOneMigrationForTest(upGrantHostsQuota); err != nil {
		t.Fatalf("upGrantHostsQuota: %v", err)
	}
	if !rolePerms(t, db, operador.ID)["hosts.quota"] {
		t.Error("quem podia declarar cota via hosts.block perdeu a tela no upgrade")
	}
	if rolePerms(t, db, visualizador.ID)["hosts.quota"] {
		t.Error("papel de leitura ganhou hosts.quota: permissão nova não se distribui sozinha")
	}

	// Revogar e rodar de novo não pode devolver: migração que desfaz decisão do
	// operador é pior que migração que falta.
	if _, err := db.conn.Exec(revogaCota, operador.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.runOneMigrationForTest(upGrantHostsQuota); err != nil {
		t.Fatal(err)
	}
	if rolePerms(t, db, operador.ID)["hosts.quota"] {
		t.Error("a migração devolveu uma permissão revogada pelo admin")
	}
}
