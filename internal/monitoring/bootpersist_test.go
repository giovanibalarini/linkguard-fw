package monitoring

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

// O item "Regras no próximo boot" (§10 da validação em VM). O que estes testes
// guardam, nesta ordem de importância:
//
//  1. numa máquina SAUDÁVEL nada aparece de errado — um falso "as regras não
//     sobrevivem ao reboot" seria pior que o silêncio de hoje, porque treina o
//     operador a ignorar a tela;
//  2. quando o arquivo de boot realmente não reflete o firewall vivo, o item
//     acende e o alerta abre;
//  3. quando não dá para saber, ninguém inventa um veredito.

// fakeBootPersist é a fonte que o vigia lê, montada à mão para exercitar as
// combinações que um nft de verdade só produziria com /etc imutável.
type fakeBootPersist struct {
	state nftables.PersistState
	path  string
}

func (f *fakeBootPersist) PersistState() nftables.PersistState { return f.state }
func (f *fakeBootPersist) PersistPath() string                 { return f.path }

// healthyBootPersist devolve a fonte de uma máquina sem problema nenhum: a
// última gravação deu certo e o arquivo está lá.
func healthyBootPersist(t *testing.T) *fakeBootPersist {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nftables.conf")
	if err := os.WriteFile(path, []byte("#!/usr/sbin/nft -f\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return &fakeBootPersist{state: nftables.PersistState{Attempted: true, OK: true, At: 1}, path: path}
}

// TestBootPersistStaysSilentOnAHealthyBox é O teste do falso positivo. Dois
// ciclos completos do vigia — o mesmo número que a validação em VM rodou —
// numa máquina em que o Persist gravou e o arquivo existe: o item tem que
// existir e estar VERDE, e nenhum alerta pode ser aberto.
func TestBootPersistStaysSilentOnAHealthyBox(t *testing.T) {
	c := newDriftTestCollector(t)
	c.SetBootPersistSource(healthyBootPersist(t))

	c.checkBootPersist()
	c.checkBootPersist()

	up, known := c.healthState("firewall:bootpersist")
	if !known {
		t.Fatal("o item tem que existir numa máquina saudável — verde é informação, ausência não é")
	}
	if !up {
		t.Error("máquina saudável não pode acender o item de 'não sobrevive ao reboot'")
	}
	assertNoBootPersistAlert(t, c)
}

// TestBootPersistFlagsAFailedWrite é o caso medido na VM: /etc imutável, o
// os.WriteFile falha, as regras valem no kernel e não vão sobreviver ao
// reboot. O item acende e o alerta abre com o motivo dentro.
func TestBootPersistFlagsAFailedWrite(t *testing.T) {
	c := newDriftTestCollector(t)
	c.SetBootPersistSource(&fakeBootPersist{
		state: nftables.PersistState{
			Attempted: true,
			Err:       "open /etc/nftables.conf: read-only file system",
			At:        1,
		},
		path: "/etc/nftables.conf",
	})

	c.checkBootPersist()
	c.checkBootPersist() // downConfirm=2: a queda é declarada no tique confirmador

	if up, known := c.healthState("firewall:bootpersist"); !known || up {
		t.Fatalf("o item tinha que estar vermelho (known=%v up=%v)", known, up)
	}
	al := findBootPersistAlert(t, c)
	if al == nil {
		t.Fatal("um Persist que falhou tem que abrir o alerta")
	}
	if !strings.Contains(al.Message, "read-only file system") {
		t.Errorf("o alerta tem que carregar o motivo do journal, veio: %q", al.Message)
	}
}

// TestBootPersistFlagsAVanishedFile cobre a outra metade da pergunta "o
// arquivo de boot reflete o que está valendo?": o Persist gravou com sucesso e
// alguém apagou o arquivo depois. A gravação foi um sucesso e a máquina mesmo
// assim não volta com estas regras.
func TestBootPersistFlagsAVanishedFile(t *testing.T) {
	c := newDriftTestCollector(t)
	src := healthyBootPersist(t)
	if err := os.Remove(src.path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	c.SetBootPersistSource(src)

	c.checkBootPersist()
	c.checkBootPersist()

	if up, known := c.healthState("firewall:bootpersist"); !known || up {
		t.Fatalf("arquivo de boot ausente tinha que acender o item (known=%v up=%v)", known, up)
	}
}

// TestBootPersistSaysNothingBeforeTheFirstAttempt: "ainda não tentei" não é
// "está tudo bem" nem "está quebrado". Sem veredito, o item não existe — em
// vez de nascer verde por otimismo (dry-run, ou o boot antes da primeira
// reconciliação).
func TestBootPersistSaysNothingBeforeTheFirstAttempt(t *testing.T) {
	c := newDriftTestCollector(t)
	c.SetBootPersistSource(&fakeBootPersist{path: "/etc/nftables.conf"})

	c.checkBootPersist()
	c.checkBootPersist()

	if _, known := c.healthState("firewall:bootpersist"); known {
		t.Error("sem nenhuma tentativa de gravação não há veredito a dar")
	}
	assertNoBootPersistAlert(t, c)
}

// TestBootPersistSaysNothingWithoutASource: um Collector sem fonte ligada não
// sabe nada sobre o arquivo de boot. Nem item, nem alerta, nem pânico.
func TestBootPersistSaysNothingWithoutASource(t *testing.T) {
	c := newDriftTestCollector(t)

	c.checkBootPersist()
	c.checkBootPersist()

	if _, known := c.healthState("firewall:bootpersist"); known {
		t.Error("sem fonte ligada o vigia não pode afirmar nada sobre o arquivo de boot")
	}
}

// TestBootPersistSaysNothingWhenTheFileCannotBeInspected: um os.Stat que falha
// por algo que NÃO é "não existe" (permissão no diretório, IO) é "não consegui
// olhar", não "o arquivo está errado". Mesma escolha de todo early-return dos
// vigias de deriva.
func TestBootPersistSaysNothingWhenTheFileCannotBeInspected(t *testing.T) {
	dir := t.TempDir()
	blocked := filepath.Join(dir, "sem-permissao")
	if err := os.Mkdir(blocked, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	path := filepath.Join(blocked, "nftables.conf")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })
	if _, err := os.Stat(path); err == nil {
		t.Skip("rodando como root: o diretório sem permissão ainda é legível, nada a testar aqui")
	}

	c := newDriftTestCollector(t)
	c.SetBootPersistSource(&fakeBootPersist{
		state: nftables.PersistState{Attempted: true, OK: true, At: 1},
		path:  path,
	})

	c.checkBootPersist()
	c.checkBootPersist()

	if _, known := c.healthState("firewall:bootpersist"); known {
		t.Error("não conseguir olhar o arquivo não é veredito sobre ele")
	}
}

// TestBootPersistRecoversOnItsOwn: a condição é contínua, então o item tem que
// sumir sozinho quando o arquivo volta a ser gravado — sem ninguém "resolver" o
// alerta à mão. É a razão de isto ser item de saúde e não só alerta.
func TestBootPersistRecoversOnItsOwn(t *testing.T) {
	c := newDriftTestCollector(t)
	src := &fakeBootPersist{
		state: nftables.PersistState{Attempted: true, Err: "read-only file system", At: 1},
		path:  "/etc/nftables.conf",
	}
	c.SetBootPersistSource(src)
	c.checkBootPersist()
	c.checkBootPersist()
	if up, _ := c.healthState("firewall:bootpersist"); up {
		t.Fatal("pré-condição: o item tinha que estar vermelho")
	}

	healthy := healthyBootPersist(t)
	src.state, src.path = healthy.state, healthy.path
	c.checkBootPersist()

	if up, known := c.healthState("firewall:bootpersist"); !known || !up {
		t.Fatalf("o item tinha que voltar ao verde sozinho (known=%v up=%v)", known, up)
	}
	if findBootPersistAlert(t, c) != nil {
		t.Error("o alerta tinha que ter sido fechado sozinho quando a condição mudou")
	}
}

// ─── helpers ────────────────────────────────────────────────────────────────

func findBootPersistAlert(t *testing.T, c *Collector) *alertRow {
	t.Helper()
	list, err := c.alertSvc.List(true, 100)
	if err != nil {
		t.Fatalf("List alerts: %v", err)
	}
	for _, a := range list {
		if a.Type == alerts.TypeFirewallBootPersistFailed {
			return &alertRow{Message: a.Message, Severity: a.Severity}
		}
	}
	return nil
}

func assertNoBootPersistAlert(t *testing.T, c *Collector) {
	t.Helper()
	if al := findBootPersistAlert(t, c); al != nil {
		t.Errorf("nenhum alerta podia ter sido aberto, veio: %q", al.Message)
	}
}

type alertRow struct {
	Message  string
	Severity string
}

// TestBootPersistEndToEndWithARealUnwritableDir liga as pontas SEM fonte
// falsa: um *nftables.Service de verdade, um Persist de verdade, e um
// diretório REALMENTE não gravável — o os.WriteFile falha por permissão do
// sistema de arquivos, que é o que o /etc imutável da VM produziu ("operation
// not permitted"). É a prova de que o caminho inteiro (Persist → PersistState
// → item de saúde) funciona com o erro vindo do kernel, e não de um executor
// falso; e a segunda metade prova a recuperação com a mesma fidelidade,
// devolvendo a permissão de escrita ao diretório.
func TestBootPersistEndToEndWithARealUnwritableDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "etc")
	if err := os.Mkdir(dir, 0o555); err != nil { // r-xr-xr-x: dá para listar, não para criar
		t.Fatalf("Mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	path := filepath.Join(dir, "nftables.conf")
	if err := os.WriteFile(path, nil, 0o644); err == nil {
		t.Skip("rodando como root: o diretório sem permissão de escrita ainda aceita gravação, nada a reproduzir aqui")
	}

	nft := nftables.NewService(&driftExec{responses: map[string]string{}})
	nft.SetConfPath(path)
	if err := nft.Persist(context.Background()); err == nil {
		t.Fatal("pré-condição: o Persist tinha que falhar num diretório não gravável")
	}

	c := newDriftTestCollector(t)
	c.SetBootPersistSource(nft)
	c.checkBootPersist()
	c.checkBootPersist()

	if up, known := c.healthState("firewall:bootpersist"); !known || up {
		t.Fatalf("a falha real de gravação tinha que acender o item (known=%v up=%v)", known, up)
	}
	if al := findBootPersistAlert(t, c); al == nil {
		t.Fatal("a falha real de gravação tinha que abrir o alerta")
	} else if al.Severity != alerts.SeverityWarning {
		t.Errorf("severidade tem que ser warning (as regras VALEM agora), veio %q", al.Severity)
	}

	// O /etc volta ao normal; a próxima passada grava e o item some sozinho.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if err := nft.Persist(context.Background()); err != nil {
		t.Fatalf("Persist depois da recuperação: %v", err)
	}
	c.checkBootPersist()

	if up, known := c.healthState("firewall:bootpersist"); !known || !up {
		t.Fatalf("o item tinha que voltar ao verde sozinho (known=%v up=%v)", known, up)
	}
	if findBootPersistAlert(t, c) != nil {
		t.Error("o alerta tinha que ter sido fechado sozinho")
	}
}
