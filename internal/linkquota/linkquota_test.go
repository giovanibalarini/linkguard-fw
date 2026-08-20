package linkquota

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func newTestDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// alerterFalso registra o que teria sido alertado.
type alerterFalso struct {
	criados    []string // "tipo|linkID"
	resolvidos []string
	mensagens  []string // corpo do alerta, para conferir o texto que o admin lê
}

func (a *alerterFalso) Create(alertType, _, _, message, linkID string) error {
	a.criados = append(a.criados, alertType+"|"+linkID)
	a.mensagens = append(a.mensagens, message)
	return nil
}
func (a *alerterFalso) AutoResolve(alertType, linkID string) {
	a.resolvidos = append(a.resolvidos, alertType+"|"+linkID)
}

func linkDeTeste(t *testing.T, db *storage.DB, id, iface string) {
	t.Helper()
	l := &storage.Link{ID: id, Name: "WAN " + id, Interface: iface, Enabled: true, Weight: 1}
	if err := db.CreateLink(l); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
}

// ─── ciclo ───────────────────────────────────────────────────────────────────

func TestCycleStart(t *testing.T) {
	loc := time.UTC
	casos := []struct {
		nome  string
		agora time.Time
		dia   int
		want  time.Time
	}{
		{
			"depois do fechamento, o ciclo é deste mês",
			time.Date(2026, 8, 20, 15, 0, 0, 0, loc), 10,
			time.Date(2026, 8, 10, 0, 0, 0, 0, loc),
		},
		{
			"antes do fechamento, o ciclo ainda é o do mês passado",
			time.Date(2026, 8, 5, 15, 0, 0, 0, loc), 10,
			time.Date(2026, 7, 10, 0, 0, 0, 0, loc),
		},
		{
			"no próprio dia do fechamento, à meia-noite, o ciclo novo já começou",
			time.Date(2026, 8, 10, 0, 0, 0, 0, loc), 10,
			time.Date(2026, 8, 10, 0, 0, 0, 0, loc),
		},
		{
			"virada de ano: janeiro antes do fechamento cai em dezembro",
			time.Date(2026, 1, 3, 12, 0, 0, 0, loc), 15,
			time.Date(2025, 12, 15, 0, 0, 0, 0, loc),
		},
		{
			"fevereiro com fechamento no 28 existe",
			time.Date(2026, 3, 1, 12, 0, 0, 0, loc), 28,
			time.Date(2026, 2, 28, 0, 0, 0, 0, loc),
		},
		{
			"dia acima do teto é limitado a 28, e não vira mês seguinte",
			time.Date(2026, 3, 30, 12, 0, 0, 0, loc), 31,
			time.Date(2026, 3, 28, 0, 0, 0, 0, loc),
		},
		{
			"dia zero é tratado como dia 1",
			time.Date(2026, 3, 30, 12, 0, 0, 0, loc), 0,
			time.Date(2026, 3, 1, 0, 0, 0, 0, loc),
		},
	}
	for _, c := range casos {
		if got := CycleStart(c.agora, c.dia); !got.Equal(c.want) {
			t.Errorf("%s: CycleStart(%v, %d) = %v, queria %v", c.nome, c.agora, c.dia, got, c.want)
		}
	}
}

func TestCycleEndEhUmMesDepois(t *testing.T) {
	start := time.Date(2026, 1, 31, 0, 0, 0, 0, time.UTC)
	// 31 de janeiro + 1 mês não existe em fevereiro; o Go normaliza para 3 de
	// março. É exatamente por isso que o dia de fechamento é limitado a 28 —
	// o teste registra o comportamento para quem for tentado a subir o teto.
	if got := CycleEnd(start); got.Month() != time.March {
		t.Logf("nota: 31/01 + 1 mês = %v (normalização do Go)", got)
	}
	normal := time.Date(2026, 2, 10, 0, 0, 0, 0, time.UTC)
	want := time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC)
	if got := CycleEnd(normal); !got.Equal(want) {
		t.Errorf("CycleEnd = %v, queria %v", got, want)
	}
}

// ─── acumulação ──────────────────────────────────────────────────────────────

func TestFlushAcumulaNoLinkCerto(t *testing.T) {
	db := newTestDB(t)
	linkDeTeste(t, db, "l1", "wan1")
	linkDeTeste(t, db, "l2", "wan2")
	s := NewService(db, nil)
	agora := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	s.nowFn = func() time.Time { return agora }

	s.AddInterfaceBytes("wan1", 1000, 500)
	s.AddInterfaceBytes("wan1", 200, 100)
	s.AddInterfaceBytes("wan2", 7, 7)
	s.AddInterfaceBytes("lan0", 999999, 999999) // não é link: tem de ser ignorado
	s.Flush()

	ciclo := CycleStart(agora, 1).Unix()
	u1, _ := db.GetLinkUsage("l1", ciclo)
	if u1.RxBytes != 1200 || u1.TxBytes != 600 {
		t.Errorf("l1: rx=%d tx=%d, queria 1200/600", u1.RxBytes, u1.TxBytes)
	}
	u2, _ := db.GetLinkUsage("l2", ciclo)
	if u2.RxBytes != 7 {
		t.Errorf("l2: rx=%d, queria 7", u2.RxBytes)
	}
}

func TestFlushSomaSobreOCicloEmVezDeSubstituir(t *testing.T) {
	db := newTestDB(t)
	linkDeTeste(t, db, "l1", "wan1")
	s := NewService(db, nil)
	agora := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	s.nowFn = func() time.Time { return agora }

	s.AddInterfaceBytes("wan1", 100, 0)
	s.Flush()
	s.AddInterfaceBytes("wan1", 50, 0)
	s.Flush()

	u, _ := db.GetLinkUsage("l1", CycleStart(agora, 1).Unix())
	if u.RxBytes != 150 {
		t.Errorf("rx = %d, queria 150 (o consumo do ciclo acumula entre flushes)", u.RxBytes)
	}
}

func TestFlushEsvaziaOAcumuladoEmMemoria(t *testing.T) {
	// Se o pendente não fosse limpo, o mesmo byte seria contado a cada minuto
	// para sempre — e a franquia estouraria sozinha em algumas horas.
	db := newTestDB(t)
	linkDeTeste(t, db, "l1", "wan1")
	s := NewService(db, nil)
	agora := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	s.nowFn = func() time.Time { return agora }

	s.AddInterfaceBytes("wan1", 100, 0)
	s.Flush()
	s.Flush()
	s.Flush()

	u, _ := db.GetLinkUsage("l1", CycleStart(agora, 1).Unix())
	if u.RxBytes != 100 {
		t.Errorf("rx = %d, queria 100 — flush sem tráfego novo não pode somar de novo", u.RxBytes)
	}
}

// ─── limiares ────────────────────────────────────────────────────────────────

func servicoComFranquia(t *testing.T, limitGB float64, alertPct int) (*Service, *storage.DB, *alerterFalso) {
	t.Helper()
	db := newTestDB(t)
	linkDeTeste(t, db, "l1", "wan1")
	if err := db.SaveLinkQuota(storage.LinkQuota{
		LinkID: "l1", LimitGB: limitGB, CycleDay: 1, AlertPct: alertPct, Enabled: true,
	}); err != nil {
		t.Fatalf("SaveLinkQuota: %v", err)
	}
	al := &alerterFalso{}
	s := NewService(db, al)
	s.nowFn = func() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) }
	return s, db, al
}

func TestAvisaAoCruzarOLimiar(t *testing.T) {
	s, _, al := servicoComFranquia(t, 10, 80) // 10 GB, avisa em 80%

	s.AddInterfaceBytes("wan1", 7_000_000_000, 0) // 70%
	s.Flush()
	if len(al.criados) != 0 {
		t.Fatalf("avisou cedo demais: %v", al.criados)
	}

	s.AddInterfaceBytes("wan1", 1_500_000_000, 0) // 85%
	s.Flush()
	if len(al.criados) != 1 || al.criados[0] != TypeQuotaWarning+"|l1" {
		t.Fatalf("queria um aviso de franquia, veio %v", al.criados)
	}
}

func TestFranquiaEstouradaEhCriticoENaoAviso(t *testing.T) {
	s, _, al := servicoComFranquia(t, 1, 80)
	s.AddInterfaceBytes("wan1", 1_100_000_000, 0) // 110%
	s.Flush()
	if len(al.criados) != 1 || al.criados[0] != TypeQuotaExceeded+"|l1" {
		t.Fatalf("queria só o alerta de esgotada, veio %v", al.criados)
	}
}

func TestSemFranquiaNaoAlertaMasContinuaMedindo(t *testing.T) {
	db := newTestDB(t)
	linkDeTeste(t, db, "l1", "wan1")
	al := &alerterFalso{}
	s := NewService(db, al)
	agora := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	s.nowFn = func() time.Time { return agora }

	s.AddInterfaceBytes("wan1", 50_000_000_000, 0)
	s.Flush()

	if len(al.criados) != 0 {
		t.Errorf("link sem franquia não pode gerar alerta: %v", al.criados)
	}
	u, _ := db.GetLinkUsage("l1", CycleStart(agora, 1).Unix())
	if u.RxBytes == 0 {
		t.Error("link sem franquia tem de continuar sendo medido — é o que permite declarar a franquia depois e já ter número")
	}
}

func TestFranquiaDesligadaNaoAlerta(t *testing.T) {
	s, db, al := servicoComFranquia(t, 1, 80)
	if err := db.SaveLinkQuota(storage.LinkQuota{
		LinkID: "l1", LimitGB: 1, CycleDay: 1, AlertPct: 80, Enabled: false,
	}); err != nil {
		t.Fatal(err)
	}
	s.AddInterfaceBytes("wan1", 2_000_000_000, 0)
	s.Flush()
	if len(al.criados) != 0 {
		t.Errorf("franquia desligada não alerta: %v", al.criados)
	}
}

func TestViradaDeCicloResolveOsAlertasDoCicloAnterior(t *testing.T) {
	// Sem isto, o alerta do ciclo passado continua aberto, o alerts.Service
	// suprime o novo por ser do mesmo (tipo, link), e o ciclo seguinte estoura
	// em silêncio. É o pior modo de falha possível para esta feature.
	s, _, al := servicoComFranquia(t, 1, 80)
	agosto := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	s.nowFn = func() time.Time { return agosto }
	s.AddInterfaceBytes("wan1", 2_000_000_000, 0)
	s.Flush()

	setembro := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	s.nowFn = func() time.Time { return setembro }
	s.Flush()

	var achou bool
	for _, r := range al.resolvidos {
		if r == TypeQuotaExceeded+"|l1" {
			achou = true
		}
	}
	if !achou {
		t.Errorf("a virada de ciclo tinha de resolver o alerta do ciclo anterior; resolvidos: %v", al.resolvidos)
	}
}

func TestCicloNovoComecaZerado(t *testing.T) {
	s, db, _ := servicoComFranquia(t, 10, 80)
	agosto := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	s.nowFn = func() time.Time { return agosto }
	s.AddInterfaceBytes("wan1", 5_000_000_000, 0)
	s.Flush()

	setembro := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	s.nowFn = func() time.Time { return setembro }
	u, _ := db.GetLinkUsage("l1", CycleStart(setembro, 1).Unix())
	if u.RxBytes != 0 {
		t.Errorf("ciclo novo trouxe %d bytes do anterior", u.RxBytes)
	}
	// E o anterior continua no banco: é o "quanto gastei no mês passado".
	antigo, _ := db.GetLinkUsage("l1", CycleStart(agosto, 1).Unix())
	if antigo.RxBytes != 5_000_000_000 {
		t.Errorf("o ciclo anterior foi perdido: %d", antigo.RxBytes)
	}
}

// ─── API do serviço ──────────────────────────────────────────────────────────

func TestSaveValida(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)
	casos := []struct {
		nome string
		q    storage.LinkQuota
	}{
		{"sem link", storage.LinkQuota{CycleDay: 1, AlertPct: 80}},
		{"franquia negativa", storage.LinkQuota{LinkID: "l1", LimitGB: -1, CycleDay: 1, AlertPct: 80}},
		{"dia 0", storage.LinkQuota{LinkID: "l1", LimitGB: 1, CycleDay: 0, AlertPct: 80}},
		{"dia 31 não existe todo mês", storage.LinkQuota{LinkID: "l1", LimitGB: 1, CycleDay: 31, AlertPct: 80}},
		{"aviso em 0%", storage.LinkQuota{LinkID: "l1", LimitGB: 1, CycleDay: 1, AlertPct: 0}},
		{"aviso acima de 100%", storage.LinkQuota{LinkID: "l1", LimitGB: 1, CycleDay: 1, AlertPct: 101}},
	}
	for _, c := range casos {
		if err := s.Save(c.q); err == nil {
			t.Errorf("%s: devia ter sido recusado", c.nome)
		}
	}
	if err := s.Save(storage.LinkQuota{LinkID: "l1", LimitGB: 50, CycleDay: 28, AlertPct: 90, Enabled: true}); err != nil {
		t.Errorf("franquia válida recusada: %v", err)
	}
}

func TestSnapshotCalculaPercentual(t *testing.T) {
	s, _, _ := servicoComFranquia(t, 10, 80)
	s.AddInterfaceBytes("wan1", 2_500_000_000, 0)
	s.Flush()

	sts, err := s.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(sts) != 1 {
		t.Fatalf("queria 1 link, veio %d", len(sts))
	}
	st := sts[0]
	if st.UsedPct < 24.9 || st.UsedPct > 25.1 {
		t.Errorf("percentual = %.2f, queria ~25", st.UsedPct)
	}
	if st.CycleEnd <= st.CycleStart {
		t.Errorf("fim do ciclo (%d) não é depois do começo (%d)", st.CycleEnd, st.CycleStart)
	}
	if !st.Configured || !st.Enabled {
		t.Errorf("franquia configurada não apareceu como tal: %+v", st)
	}
}

func TestSnapshotSemFranquiaNaoInventaPercentual(t *testing.T) {
	db := newTestDB(t)
	linkDeTeste(t, db, "l1", "wan1")
	s := NewService(db, nil)
	sts, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if sts[0].UsedPct != 0 || sts[0].Configured {
		t.Errorf("link sem franquia não pode ter percentual: %+v", sts[0])
	}
}

func TestDeleteResolveAlertasEMantemHistorico(t *testing.T) {
	s, db, al := servicoComFranquia(t, 1, 80)
	agora := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	s.nowFn = func() time.Time { return agora }
	s.AddInterfaceBytes("wan1", 2_000_000_000, 0)
	s.Flush()

	// Conta só o que o Delete acrescentou: o próprio Flush já resolve o aviso
	// quando o crítico o substitui, então comparar o total seria frágil.
	antes := len(al.resolvidos)
	if err := s.Delete("l1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	peloDelete := al.resolvidos[antes:]
	querendo := map[string]bool{TypeQuotaWarning + "|l1": false, TypeQuotaExceeded + "|l1": false}
	for _, r := range peloDelete {
		querendo[r] = true
	}
	for tipo, achou := range querendo {
		if !achou {
			t.Errorf("apagar a franquia tem de resolver %s; o Delete resolveu %v", tipo, peloDelete)
		}
	}
	u, _ := db.GetLinkUsage("l1", CycleStart(agora, 1).Unix())
	if u.RxBytes == 0 {
		t.Error("o consumo medido não pode ser apagado junto com a franquia")
	}
}

func TestHumanBytesAcompanhaAGrandeza(t *testing.T) {
	casos := []struct {
		in   float64
		want string
	}{
		{18_400_000, "18.4 MB"},
		{20_000_000, "20.0 MB"},
		{1_500_000_000, "1.5 GB"},
		{50_000_000_000, "50.0 GB"},
		{300_000, "300 KB"},
	}
	for _, c := range casos {
		if got := humanBytes(c.in); got != c.want {
			t.Errorf("humanBytes(%v) = %q, queria %q", c.in, got, c.want)
		}
	}
	if got := humanGB(0.5); got != "500.0 MB" {
		t.Errorf("humanGB(0.5) = %q, queria 500.0 MB — plano fracionário existe", got)
	}
}

func TestMensagemNaoZeraComFranquiaMenorQueUmGB(t *testing.T) {
	// Achado numa validação em máquina real: com franquia de 20 MB e 18 MB
	// consumidos, o alerta saía "consumiu 0.0 GB dos 0 GB do ciclo" — um aviso
	// que não avisa nada. Plano de backup móvel de 500 MB é exatamente o
	// público desta feature.
	s, _, al := servicoComFranquia(t, 0.02, 80) // 20 MB
	s.AddInterfaceBytes("wan1", 18_400_000, 0)
	s.Flush()

	if len(al.mensagens) == 0 {
		t.Fatal("nenhum alerta disparou")
	}
	msg := al.mensagens[0]
	if strings.Contains(msg, "0.0 GB") || strings.Contains(msg, "0 GB") {
		t.Errorf("a mensagem zerou os números: %q", msg)
	}
	if !strings.Contains(msg, "MB") {
		t.Errorf("franquia abaixo de 1 GB tem de ser dita em MB: %q", msg)
	}
}

func TestFranquiaEsgotadaResolveOAvisoAnterior(t *testing.T) {
	// Os dois abertos ao mesmo tempo põem dois alertas do mesmo link na tela
	// dizendo coisas diferentes sobre o mesmo fato. Visto na VM.
	s, _, al := servicoComFranquia(t, 0.02, 80)
	s.AddInterfaceBytes("wan1", 18_400_000, 0) // 92% → aviso
	s.Flush()
	s.AddInterfaceBytes("wan1", 10_000_000, 0) // passa de 100% → crítico
	s.Flush()

	var resolveuAviso bool
	for _, r := range al.resolvidos {
		if r == TypeQuotaWarning+"|l1" {
			resolveuAviso = true
		}
	}
	if !resolveuAviso {
		t.Errorf("o crítico não resolveu o aviso que ele substitui; resolvidos: %v", al.resolvidos)
	}
}
