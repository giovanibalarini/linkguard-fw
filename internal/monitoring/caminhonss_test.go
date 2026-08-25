package monitoring

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
)

// hostsVM é a linha do /etc/nsswitch.conf da VM de validação: o `resolve`
// (systemd-resolved) vem antes do dns e o [!UNAVAIL=return] encerra a busca
// ali. Medido: o getent não incrementava o contador do unbound.
const hostsVM = "hosts: files myhostname resolve [!UNAVAIL=return] dns\n"

// coletorDeCaminho monta o Collector com o resolv.conf apontando para o
// resolver local (o portão da checagem) e o nsswitch.conf que o caso pede.
func coletorDeCaminho(t *testing.T, nsswitch string, resolvedAtivo bool) *Collector {
	t.Helper()
	c := newDriftTestCollector(t)
	c.resolvConfPath = writeTempFile(t, "# managed by linkguard\nnameserver 127.0.0.1\n")
	c.nsswitchPath = filepath.Join(t.TempDir(), "nsswitch.conf")
	escreverNsswitch(t, c, nsswitch)
	if resolvedAtivo {
		c.exec.(*driftExec).responses["systemctl is-active systemd-resolved"] = "active\n"
	}
	return c
}

func escreverNsswitch(t *testing.T, c *Collector, conteudo string) {
	t.Helper()
	if conteudo == "" {
		return
	}
	if err := os.WriteFile(c.nsswitchPath, []byte(conteudo), 0o644); err != nil {
		t.Fatalf("escrever nsswitch.conf: %v", err)
	}
}

func abertosDoTipo(t *testing.T, c *Collector, tipo string) int {
	t.Helper()
	todos, err := c.db.GetAlerts(true, 0)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	n := 0
	for _, a := range todos {
		if a.Type == tipo {
			n++
		}
	}
	return n
}

// todosDoTipo conta alertas do tipo INCLUSIVE os já resolvidos — a linha de
// recuperação nasce resolvida (createRecovery), então contá-la entre os abertos
// nunca acharia nada.
func todosDoTipo(t *testing.T, c *Collector, tipo string) int {
	t.Helper()
	todos, err := c.db.GetAlerts(false, 0)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	n := 0
	for _, a := range todos {
		if a.Type == tipo {
			n++
		}
	}
	return n
}

func mensagemDoTipo(t *testing.T, c *Collector, tipo string) string {
	t.Helper()
	todos, err := c.db.GetAlerts(false, 0)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	for _, a := range todos {
		if a.Type == tipo {
			return a.Message
		}
	}
	return ""
}

// TestCaminhoNSSAbreNaLinhaDaVM: o caso que abriu a issue #195. O produto
// escreve o resolv.conf, o painel mostra o resolver local no ar, e a resolução
// da caixa não passa por lá.
func TestCaminhoNSSAbreNaLinhaDaVM(t *testing.T) {
	c := coletorDeCaminho(t, hostsVM, true)

	c.checkCaminhoNSS()
	c.checkCaminhoNSS() // downConfirm=2: a queda é declarada no tique confirmador

	if n := abertosDoTipo(t, c, alerts.TypeCaminhoDNSForaDoLocal); n != 1 {
		t.Fatalf("alertas abertos = %d, queria 1", n)
	}
	msg := mensagemDoTipo(t, c, alerts.TypeCaminhoDNSForaDoLocal)
	if !strings.Contains(msg, "!UNAVAIL=return") || !strings.Contains(msg, "resolve") {
		t.Errorf("a mensagem não diz onde olhar: %q", msg)
	}
}

// TestCaminhoNSSFechaSozinhoNoTiqueSeguinteDepoisDoConserto é o defeito P4: o
// veredito nascia e morria dentro do EnsureResolvConf, que roda UMA VEZ por
// processo. O admin arrumava a linha hosts: e o painel ficava vermelho até o
// serviço reiniciar — a doença que esta issue existe para curar, do lado do
// alerta. Aqui a condição é medida por tique: sobe sozinha e desce sozinha.
func TestCaminhoNSSFechaSozinhoNoTiqueSeguinteDepoisDoConserto(t *testing.T) {
	c := coletorDeCaminho(t, hostsVM, true)

	c.checkCaminhoNSS()
	c.checkCaminhoNSS()
	if n := abertosDoTipo(t, c, alerts.TypeCaminhoDNSForaDoLocal); n != 1 {
		t.Fatalf("alertas abertos antes do conserto = %d, queria 1", n)
	}

	// O admin arruma o /etc/nsswitch.conf. Nada reinicia.
	escreverNsswitch(t, c, "hosts: files dns\n")
	c.checkCaminhoNSS()

	if n := abertosDoTipo(t, c, alerts.TypeCaminhoDNSForaDoLocal); n != 0 {
		t.Errorf("o alerta continuou aberto depois do conserto (%d abertos): so o reboot o apagaria", n)
	}
	if n := todosDoTipo(t, c, alerts.TypeCaminhoDNSNoLocal); n == 0 {
		t.Error("a volta ao normal não foi anunciada")
	}
}

// TestCaminhoNSSNaoFechaQuandoOutroModuloContinuaCortando é o defeito P1, o mais
// grave dos cinco: com o systemd-resolved parado, a análise retornava no
// primeiro módulo que corta (`resolve`) dizendo "alcança o dns", e o produto
// FECHAVA o alerta — enquanto o `nis [NOTFOUND=return]` logo adiante continua
// encerrando a busca. Alerta se auto-fechando numa caixa quebrada.
func TestCaminhoNSSNaoFechaQuandoOutroModuloContinuaCortando(t *testing.T) {
	const linha = "hosts: files myhostname resolve [!UNAVAIL=return] nis [NOTFOUND=return] dns\n"
	c := coletorDeCaminho(t, linha, false) // systemd-resolved parado

	c.checkCaminhoNSS()
	c.checkCaminhoNSS()

	if n := todosDoTipo(t, c, alerts.TypeCaminhoDNSNoLocal); n != 0 {
		t.Error("anunciou recuperação numa caixa em que o nis continua cortando a busca")
	}
	if n := abertosDoTipo(t, c, alerts.TypeCaminhoDNSForaDoLocal); n != 1 {
		t.Fatalf("alertas abertos = %d, queria 1", n)
	}
	if msg := mensagemDoTipo(t, c, alerts.TypeCaminhoDNSForaDoLocal); !strings.Contains(msg, "nis") {
		t.Errorf("o alerta não nomeia quem corta de verdade: %q", msg)
	}
}

// TestCaminhoNSSSemModuloDNSAbreCritico é o defeito P5: sem módulo `dns` na
// linha, a caixa não resolve nome externo NENHUM — mandar ali a frase do
// Warning ("a caixa continua resolvendo nomes") põe o operador a caçar um
// problema silencioso enquanto o barulhento está na cara.
func TestCaminhoNSSSemModuloDNSAbreCritico(t *testing.T) {
	// A linha da VM sem o dns no fim, com o resolved parado: o `resolve` não
	// corta (devolve UNAVAIL) e não sobra mais nada.
	c := coletorDeCaminho(t, "hosts: files myhostname resolve [!UNAVAIL=return]\n", false)

	c.checkCaminhoNSS()
	c.checkCaminhoNSS()

	if n := abertosDoTipo(t, c, alerts.TypeCaminhoDNSForaDoLocal); n != 0 {
		t.Error("abriu o aviso de 'continua resolvendo nomes' numa caixa que não resolve nome nenhum")
	}
	if n := abertosDoTipo(t, c, alerts.TypeResolucaoSemModuloDNS); n != 1 {
		t.Fatalf("alertas abertos do caso grave = %d, queria 1", n)
	}
}

// TestCaminhoNSSResolvedApenasParadoNaoFechaAlerta é o defeito P3. `is-active`
// responde sobre o processo AGORA, e o processo sobe de novo no próximo boot sem
// ninguém tocar neste produto. Fechar o alerta por causa disso anuncia um
// conserto que ninguém fez, e o vermelho volta a piscar no reboot seguinte.
// Abrir exige certeza; fechar também.
func TestCaminhoNSSResolvedApenasParadoNaoFechaAlerta(t *testing.T) {
	c := coletorDeCaminho(t, hostsVM, true)

	c.checkCaminhoNSS()
	c.checkCaminhoNSS()
	if n := abertosDoTipo(t, c, alerts.TypeCaminhoDNSForaDoLocal); n != 1 {
		t.Fatalf("alertas abertos = %d, queria 1", n)
	}

	// Alguém para o systemd-resolved. O arquivo continua o mesmo.
	delete(c.exec.(*driftExec).responses, "systemctl is-active systemd-resolved")
	c.checkCaminhoNSS()
	c.checkCaminhoNSS()

	if n := abertosDoTipo(t, c, alerts.TypeCaminhoDNSForaDoLocal); n != 1 {
		t.Errorf("alertas abertos = %d: o alerta foi fechado por um daemon que volta no próximo boot", n)
	}
	if n := todosDoTipo(t, c, alerts.TypeCaminhoDNSNoLocal); n != 0 {
		t.Error("anunciou recuperação sem que a linha hosts: tenha mudado")
	}
}

// TestCaminhoNSSResolvedParadoNaoAbreAlerta é a outra metade da mesma regra: se
// nem abrir nem fechar é o veredito, então também não se abre. A caixa em que o
// resolved está parado chega ao dns HOJE.
func TestCaminhoNSSResolvedParadoNaoAbreAlerta(t *testing.T) {
	c := coletorDeCaminho(t, hostsVM, false)

	c.checkCaminhoNSS()
	c.checkCaminhoNSS()

	if n := abertosDoTipo(t, c, alerts.TypeCaminhoDNSForaDoLocal); n != 0 {
		t.Errorf("abriu alerta (%d) numa caixa cuja busca chega ao dns agora", n)
	}
	if _, known := c.healthState("dns:caminho"); known {
		t.Error("um tique sem veredito registrou estado de saúde")
	}
}

// TestCaminhoNSSMalformadoNaoAbreNemFecha é o defeito P2 no nível da decisão:
// colchete sem fechar fazia o parser parar e o produto abrir alerta dizendo "a
// linha hosts: não lista o módulo dns" — sobre uma linha que lista.
func TestCaminhoNSSMalformadoNaoAbreNemFecha(t *testing.T) {
	c := coletorDeCaminho(t, "hosts: files resolve [!UNAVAIL=return dns\n", true)

	c.checkCaminhoNSS()
	c.checkCaminhoNSS()

	if n := abertosDoTipo(t, c, alerts.TypeCaminhoDNSForaDoLocal); n != 0 {
		t.Errorf("abriu alerta (%d) por não conseguir ler o arquivo inteiro", n)
	}
	if n := abertosDoTipo(t, c, alerts.TypeResolucaoSemModuloDNS); n != 0 {
		t.Errorf("abriu o alerta grave (%d) sobre a parte da linha que não foi lida", n)
	}
	if _, known := c.healthState("dns:caminho"); known {
		t.Error("um tique sem veredito registrou estado de saúde")
	}
}

// TestCaminhoNSSNaoOpinaSemONsswitch: não saber não é estar quebrado. Sem o
// arquivo em mãos não se abre nem se fecha alerta — mesma regra de todo
// early-return deste pacote.
func TestCaminhoNSSNaoOpinaSemONsswitch(t *testing.T) {
	c := coletorDeCaminho(t, "", true) // o arquivo nem existe

	c.checkCaminhoNSS()
	c.checkCaminhoNSS()

	if _, known := c.healthState("dns:caminho"); known {
		t.Error("deu veredito sem conseguir ler o nsswitch.conf")
	}
}

// TestCaminhoNSSNaoOpinaComResolvConfExterno: se o resolv.conf não aponta para o
// resolver local, quem responde é o dns_resolver_drift. Abrir aqui também seria
// dois vermelhos para uma causa só — e com uma mensagem que afirma que o
// resolv.conf aponta para o unbound, o que seria falso.
func TestCaminhoNSSNaoOpinaComResolvConfExterno(t *testing.T) {
	c := coletorDeCaminho(t, hostsVM, true)
	c.resolvConfPath = writeTempFile(t, "nameserver 189.40.0.1\n")

	c.checkCaminhoNSS()
	c.checkCaminhoNSS()

	if _, known := c.healthState("dns:caminho"); known {
		t.Error("opinou sobre o caminho até um resolver local que o resolv.conf nem aponta")
	}
}

// TestCollectRodaOCheckCaminhoNSS guarda a ligação contra deriva. Sem a chamada
// no collect() a checagem inteira vira código morto, e o defeito que ela mede é
// invisível: nada falha, o painel mostra o resolver local no ar. Nada quebra
// visivelmente se esta linha sumir — que é o motivo de o guarda existir, sobre a
// árvore sintática do collector.
//
// Este guarda mora aqui, e não em cmd/, de propósito: os testes de cmd/ não
// compilam sem web/dist construído (embed), e um guarda que só roda às vezes é
// decoração.
func TestCollectRodaOCheckCaminhoNSS(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("não foi possível localizar o arquivo de teste")
	}
	src := filepath.Join(filepath.Dir(thisFile), "collector.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, src, nil, 0)
	if err != nil {
		t.Fatalf("parsear collector.go: %v", err)
	}

	chamado := false
	ast.Inspect(file, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel {
			return true
		}
		if sel.Sel.Name == "checkCaminhoNSS" {
			chamado = true
		}
		return true
	})
	if !chamado {
		t.Fatal("o collect() não chama mais checkCaminhoNSS: o resolver local fora do caminho de resolução (issue #195) volta a ser invisível")
	}
}
