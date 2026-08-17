package main

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// Este arquivo é a REDE DE EXECUÇÃO embaixo dos guardas de AST de
// boot_order_test.go, e não a substituição deles.
//
// O que os guardas de lá conseguem dizer é que main.go CONTÉM as chamadas de
// ligação, em que ordem elas aparecem no texto e dentro de qual bloco moram.
// O que nenhum deles consegue dizer é o que este arquivo mede: que a ligação,
// EXECUTADA, produz o comportamento por causa do qual ela existe — o
// /etc/nftables.conf que não recebe a regra não confirmada, e a chain input
// que sai com as duas metades. O próprio boot_order_test.go registra duas
// ocasiões (I-5 e m-6) em que um guarda de texto reescrito passou verde sobre
// código errado; um teste que roda a sequência não tem essa forma de errar.
//
// A costura entre as duas redes é TestTheRuntimeWiringIsTheOneMainUses, no fim
// deste arquivo: ele confere, também na AST, que os ARGUMENTOS que main.go
// passa aos dois setters são exatamente os que os testes de runtime daqui
// ligam. Sem essa checagem os testes de runtime mediriam uma composição que
// ninguém garante ser a de produção — e os guardas atuais só olham o NOME da
// chamada, não o que entra nela.
//
// Nada aqui refatora main.go (issue #24 do dono): run() continua sendo uma
// função só, e a montagem que estes testes exercitam é a MESMA composição de
// tipos reais que ela faz — nftables.Service + firewallrules.Service sobre um
// banco de verdade —, com o executor falso no lugar do nft.

// TestMain aponta o ConfPath padrão de internal/nftables para um arquivo
// descartável antes de qualquer teste deste pacote rodar. É a mesma rede que
// internal/nftables/main_test.go e internal/firewallrules/main_test.go já
// armam, agora que os testes daqui também chegam ao nftables.Persist — a
// ÚNICA escrita em disco daquele pacote que o executor falso não intercepta.
//
// Sem isto, `go test ./cmd/linkguard-fw/` rodado como root na própria
// appliance (mesmo binário, mesma máquina; diagnosticar em produção é coisa
// que se faz como root) sobrescreveria o /etc/nftables.conf DE VERDADE com o
// dump do executor falso, e a máquina voltaria do próximo boot com o firewall
// vazio. Cada teste daqui ainda aponta o Service para o próprio t.TempDir()
// (SetConfPath, o caminho de verdade); isto é o que sobra embaixo.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "linkguard-boot-conf")
	if err != nil {
		fmt.Fprintf(os.Stderr, "não foi possível criar o diretório temporário do ConfPath: %v\n", err)
		os.Exit(1)
	}
	nftables.ConfPath = filepath.Join(dir, "nftables.conf")
	code := m.Run()
	os.RemoveAll(dir) //nolint:errcheck // limpeza de melhor esforço
	os.Exit(code)
}

// bootExec é o `nft` de mentira: responde às leituras de que a reconciliação
// depende e guarda tudo que seria executado, para os testes perguntarem o que
// chegaria ao kernel.
//
// tableOut é o dump que o Persist copia para o arquivo de boot — trocá-lo no
// meio do teste é como o ruleset vivo mudar entre uma passada e outra.
type bootExec struct {
	mu       sync.Mutex
	tableOut string
	executed []string
}

func (e *bootExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.executed = append(e.executed, cmd+" "+strings.Join(args, " "))
	return "", nil
}

func (e *bootExec) ExecuteRead(_ context.Context, _ string, args ...string) (string, error) {
	joined := strings.Join(args, " ")
	switch {
	case strings.Contains(joined, "-c") && strings.Contains(joined, "-f"):
		// pré-voo `nft -c -f`: aprova tudo.
		return "", nil
	case strings.Contains(joined, "-a list chain") && strings.Contains(joined, "user_rules"):
		return "table inet linkguard {\n\tchain user_rules {\n\t}\n}\n", nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.tableOut, nil
}

func (_ *bootExec) IsDryRun() bool { return false }

// WriteFile nunca toca em disco: nenhum teste deste arquivo pode escrever
// fora do t.TempDir().
func (_ *bootExec) WriteFile(string, []byte, os.FileMode) error { return nil }

func (e *bootExec) setTable(dump string) {
	e.mu.Lock()
	e.tableOut = dump
	e.mu.Unlock()
}

func (e *bootExec) calls() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, len(e.executed))
	copy(out, e.executed)
	return out
}

func (e *bootExec) forget() {
	e.mu.Lock()
	e.executed = nil
	e.mu.Unlock()
}

// bootPair é a dupla de serviços que o boot monta, com o banco de verdade
// atrás dela.
type bootPair struct {
	db       *storage.DB
	exec     *bootExec
	nft      *nftables.Service
	fr       *firewallrules.Service
	confPath string
}

// newBootPair monta nftables.Service + firewallrules.Service como run() monta,
// sobre um banco real em t.TempDir() e com o `nft` falso no lugar do de
// verdade. wire=false deixa as duas ligações DE FORA de propósito: é o
// binário sem SetPersistGuard/SetInputChainSources, usado pelos testes de
// controle que provam que as afirmações daqui medem a ligação e não uma
// propriedade que valeria de qualquer jeito.
//
// A fonte de NTP é montada com a MESMA expressão de main.go
// (ntpInputStateFrom sobre db.GetSetting, a função de produção deste pacote),
// e não com um fake: é ela que fecha a metade do círculo que o teste mede.
func newBootPair(t *testing.T, wire bool) *bootPair {
	t.Helper()

	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("abrir o banco: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	exec := &bootExec{tableOut: rulesetBefore}
	nftSvc := nftables.NewService(exec)
	// O arquivo de boot deste teste. Ver TestMain para o que acontece sem isto.
	confPath := filepath.Join(t.TempDir(), "nftables.conf")
	nftSvc.SetConfPath(confPath)

	frSvc := firewallrules.NewService(db, nftSvc)
	if wire {
		ntpInputState := func() ([]string, bool, error) { return ntpInputStateFrom(db.GetSetting) }
		nftSvc.SetInputChainSources(frSvc.StoredGroups, ntpInputState)
		nftSvc.SetPersistGuard(frSvc.UnconfirmedChangePending)
	}

	// Como toda máquina fica no começo do boot, antes de qualquer coisa que
	// reconcilie: sem os grupos do sistema na lista, Reconcile se recusa a
	// reconstruir a forward (e com razão).
	if err := frSvc.EnsureSystemGroups(context.Background()); err != nil {
		t.Fatalf("criar os grupos do sistema: %v", err)
	}
	return &bootPair{db: db, exec: exec, nft: nftSvc, fr: frSvc, confPath: confPath}
}

// Os dois estados do ruleset vivo que os testes usam: o de antes da mudança
// arriscada e o de depois. dangerousInputRule é a linha que tranca o operador
// para fora — o que não pode ser congelado no arquivo de boot enquanto a
// janela de confirmação estiver aberta.
const (
	dangerousInputRule = "tcp dport 22 counter drop"
	rulesetBefore      = "table inet linkguard {\n\tchain input {\n\t\tct state related counter accept\n\t}\n}\n"
	rulesetAfter       = "table inet linkguard {\n\tchain input {\n\t\tct state related counter accept\n\t\t" +
		dangerousInputRule + "\n\t}\n}\n"
)

// openConfirmationWindow deixa o banco no estado "mudança aplicada, ainda não
// confirmada" — o mesmo que uma mutação de escopo input deixa ao abrir os 90
// segundos.
func openConfirmationWindow(t *testing.T, db *storage.DB) {
	t.Helper()
	err := db.SavePendingChange(storage.PendingChange{
		ID:        "00000000-0000-4000-8000-00000000dead",
		Snapshot:  `{"groups":[],"rules":[]}`,
		ExpiresAt: time.Now().Add(90 * time.Second),
		AppliedBy: "admin",
		Summary:   "regra de escopo input que dropa tcp/22",
	})
	if err != nil {
		t.Fatalf("abrir a janela de confirmação: %v", err)
	}
}

func readBootFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ler o arquivo de boot: %v", err)
	}
	return string(body)
}

// TestWiredPersistGuardFreezesTheBootFileWhileAChangeIsUnconfirmed é o teste
// de EXECUÇÃO da ligação que TestMainWiresThePersistGuard só consegue ver como
// texto: monta os dois serviços reais como o boot monta, abre a janela de
// confirmação no banco e reconcilia — e mede o ARQUIVO.
//
// O que está sendo defendido, por inteiro: o operador cria um grupo de escopo
// input que dropa tcp/22; a reconciliação aplica no kernel; aos 30 segundos
// cai a energia. O nftables.service carrega o /etc/nftables.conf ANTES de o
// LinkGuard subir — se a regra não confirmada tiver ido para lá, a máquina
// volta sem SSH e sem painel, e quem a devolveria (RevertPendingOnBoot) só
// roda depois que o LinkGuard sobe, coisa que este projeto já viu demorar 50
// minutos (2026-07-24).
//
// As três afirmações são as três metades do contrato: o arquivo não muda
// enquanto a janela está aberta, ele continua com o conteúdo ANTERIOR (não
// apagado, não truncado), e ele volta a ser gravado assim que a janela se
// fecha — a guarda protege, não congela para sempre.
func TestWiredPersistGuardFreezesTheBootFileWhileAChangeIsUnconfirmed(t *testing.T) {
	ctx := context.Background()
	p := newBootPair(t, true)

	// 1. Máquina saudável, sem janela aberta: o arquivo de boot descreve o
	//    firewall vivo.
	if err := p.fr.Reconcile(ctx); err != nil {
		t.Fatalf("reconciliação inicial: %v", err)
	}
	before := readBootFile(t, p.confPath)
	if !strings.Contains(before, "table inet linkguard") {
		t.Fatalf("pré-condição: o arquivo de boot tinha que ter o ruleset da máquina, veio:\n%s", before)
	}
	stBefore, err := os.Stat(p.confPath)
	if err != nil {
		t.Fatalf("stat do arquivo de boot: %v", err)
	}

	// 2. A mudança arriscada entra no kernel e abre a janela de 90 segundos.
	p.exec.setTable(rulesetAfter)
	openConfirmationWindow(t, p.db)

	if err := p.fr.Reconcile(ctx); err != nil {
		t.Fatalf("a reconciliação com a janela aberta não pode falhar (as regras entram no kernel normalmente): %v", err)
	}

	after := readBootFile(t, p.confPath)
	if strings.Contains(after, dangerousInputRule) {
		t.Errorf("o arquivo de boot recebeu a regra NÃO CONFIRMADA %q: uma queda de energia dentro dos 90 segundos faz a máquina voltar com ela valendo, sem SSH e sem painel, antes de o LinkGuard subir para reverter\n%s",
			dangerousInputRule, after)
	}
	if after != before {
		t.Errorf("o arquivo de boot foi REESCRITO com a janela de confirmação aberta.\nantes:\n%s\ndepois:\n%s", before, after)
	}
	if stAfter, err := os.Stat(p.confPath); err != nil {
		t.Errorf("stat do arquivo de boot depois da passada bloqueada: %v", err)
	} else if !stAfter.ModTime().Equal(stBefore.ModTime()) {
		t.Errorf("o arquivo de boot foi regravado (mtime %v → %v) mesmo com o conteúdo igual: a guarda tem que parar ANTES da escrita",
			stBefore.ModTime(), stAfter.ModTime())
	}

	// 3. E não é um congelamento permanente: fechada a janela, a próxima
	//    passada volta a gravar. Sem isto, a proteção viraria um firewall de
	//    boot eternamente desatualizado.
	if err := p.db.ClearPendingChange(); err != nil {
		t.Fatalf("fechar a janela de confirmação: %v", err)
	}
	if err := p.fr.Reconcile(ctx); err != nil {
		t.Fatalf("reconciliação com a janela fechada: %v", err)
	}
	final := readBootFile(t, p.confPath)
	if !strings.Contains(final, dangerousInputRule) {
		t.Errorf("fechada a janela, o arquivo de boot tem que voltar a descrever o firewall vivo (inclusive a regra já confirmada), veio:\n%s", final)
	}
}

// TestGuardErrorAlsoFreezesTheBootFile: quem não consegue PROVAR que não há
// janela aberta também não grava. É a mesma decisão do doc-comment de
// SetPersistGuard, medida do lado do arquivo — e o caminho é real (o banco
// pode estar travado justamente durante uma reversão).
//
// Este é o único ponto em que o teste substitui a expressão de produção por
// uma função de mentira: não há como fazer o SELECT de
// UnconfirmedChangePending falhar sem derrubar o banco inteiro, e derrubá-lo
// mudaria o caminho medido (o Reconcile abortaria antes de chegar ao Persist).
func TestGuardErrorAlsoFreezesTheBootFile(t *testing.T) {
	ctx := context.Background()
	p := newBootPair(t, true)

	if err := p.fr.Reconcile(ctx); err != nil {
		t.Fatalf("reconciliação inicial: %v", err)
	}
	before := readBootFile(t, p.confPath)

	p.exec.setTable(rulesetAfter)
	p.nft.SetPersistGuard(func() (bool, error) { return false, fmt.Errorf("banco travado") })

	if err := p.fr.Reconcile(ctx); err != nil {
		t.Fatalf("a reconciliação não pode falhar por causa da guarda: %v", err)
	}
	if after := readBootFile(t, p.confPath); after != before {
		t.Errorf("com a guarda em ERRO o arquivo de boot não pode ser gravado por otimismo: não saber se há janela aberta é motivo para não congelar nada no arquivo.\nantes:\n%s\ndepois:\n%s", before, after)
	}
}

// TestUnwiredPersistGuardLetsTheUnconfirmedRuleReachTheBootFile é o CONTROLE
// dos dois testes acima — o vermelho, escrito como teste que passa.
//
// Ele monta exatamente a mesma dupla SEM a linha de SetPersistGuard, isto é, o
// binário que sairia de um refactor que perdesse a ligação, e mede o mesmo
// arquivo. Se um dia esta afirmação começar a falhar, é porque a proteção
// passou a vir de outro lugar que não a ligação do main — e aí os testes de
// cima estariam medindo outra coisa, verdes por acidente. É esta a forma de
// falha que os guardas de posição de byte não conseguem ter.
func TestUnwiredPersistGuardLetsTheUnconfirmedRuleReachTheBootFile(t *testing.T) {
	ctx := context.Background()
	p := newBootPair(t, false)
	// A metade do NTP continua ligada: sem ela o Reconcile aborta a chain
	// input e nem chega ao Persist, e o controle mediria o motivo errado.
	p.nft.SetInputChainSources(p.fr.StoredGroups, func() ([]string, bool, error) {
		return ntpInputStateFrom(p.db.GetSetting)
	})

	if err := p.fr.Reconcile(ctx); err != nil {
		t.Fatalf("reconciliação inicial: %v", err)
	}
	p.exec.setTable(rulesetAfter)
	openConfirmationWindow(t, p.db)

	if err := p.fr.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !strings.Contains(readBootFile(t, p.confPath), dangerousInputRule) {
		t.Fatal("controle quebrado: sem SetPersistGuard o arquivo de boot TINHA que receber a regra não confirmada. Se isto parou de acontecer, os testes da guarda deste arquivo podem estar passando por outro motivo — reveja os três juntos")
	}
}

// TestWiredInputChainSourcesFeedBothHalvesAtRuntime executa o círculo que
// TestMainWiresTheInputChainSources só vê como uma chamada no texto.
//
// A chain input tem um renderizador só desde a Fase C2: quem reconcilia o NTP
// sabe o estado do NTP e precisa dos grupos; quem reconcilia os grupos sabe os
// grupos e precisa do estado do NTP. As duas passadas abaixo entram por pontas
// OPOSTAS e cada uma tem que sair com as DUAS metades na chain — é assim que
// se mede que a fonte injetada foi mesmo consultada, e não que a chamada
// existe no arquivo.
//
// O que a falha significa na máquina: salvar um grupo apaga a proteção do
// serviço de hora da chain input viva, ou ligar o NTP apaga os jumps dos
// grupos do admin — nos dois casos sem nada mudar na tela.
func TestWiredInputChainSourcesFeedBothHalvesAtRuntime(t *testing.T) {
	ctx := context.Background()
	p := newBootPair(t, true)

	chain := seedInputScopeGroup(t, p.db)
	seedNTPServing(t, p.db)

	// Ponta 1: quem entra pelo NTP tem que sair com os grupos do banco —
	// groupsSource ligado a frSvc.StoredGroups, consultado em runtime.
	p.exec.forget()
	if err := p.nft.ReconcileNTPInput(ctx, []string{"192.168.3.0/24"}, true); err != nil {
		t.Fatalf("ReconcileNTPInput: %v", err)
	}
	ntpPass := inputChainCommands(p.exec.calls())
	if !containsSubstr(ntpPass, "jump "+chain) {
		t.Errorf("a passada do NTP reconstruiu a chain input SEM o jump do grupo de escopo input (%s): ligar/desligar o NTP passaria a apagar os grupos do admin do firewall vivo.\ncomandos: %v", chain, ntpPass)
	}
	if !containsSubstr(ntpPass, "udp dport 123") {
		t.Fatalf("pré-condição: a passada do NTP tinha que emitir as próprias linhas de udp/123.\ncomandos: %v", ntpPass)
	}

	// Ponta 2: quem entra pelos grupos tem que sair com a proteção do NTP —
	// ntpInputSource ligado a ntpInputStateFrom(db.GetSetting), lido do banco
	// em runtime.
	p.exec.forget()
	if err := p.fr.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	groupPass := inputChainCommands(p.exec.calls())
	if !containsSubstr(groupPass, "udp dport 123") {
		t.Errorf("a passada dos grupos reconstruiu a chain input SEM as linhas de proteção do NTP: salvar um grupo passaria a apagar a proteção do serviço de hora do firewall vivo, com o toggle continuando ligado na tela.\ncomandos: %v", groupPass)
	}
	if !containsSubstr(groupPass, "jump "+chain) {
		t.Fatalf("pré-condição: a passada dos grupos tinha que emitir o jump do próprio grupo.\ncomandos: %v", groupPass)
	}
}

// TestUnwiredInputChainSourcesLoseEachOtherAtRuntime é o CONTROLE do teste
// acima, pelas mesmas razões do controle da guarda: sem a ligação, cada ponta
// escreve a chain input só com a metade que ela conhece.
//
// As duas metades falham de formas diferentes de propósito, e as duas estão
// aqui: sem fonte de grupos, a chain sai só com o NTP (m3 da revisão deixou
// esse lado como aviso, porque a fonte pode legitimamente não existir num
// binário sem banco); sem fonte de NTP, a reconciliação dos grupos ABORTA a
// chain input em vez de reescrevê-la sem as linhas de udp/123 — fail-closed,
// que é o certo, e o teste prende essa diferença para que ninguém a "uniformize"
// sem perceber o que perde.
func TestUnwiredInputChainSourcesLoseEachOtherAtRuntime(t *testing.T) {
	ctx := context.Background()
	p := newBootPair(t, false)
	chain := seedInputScopeGroup(t, p.db)
	seedNTPServing(t, p.db)

	if err := p.nft.ReconcileNTPInput(ctx, []string{"192.168.3.0/24"}, true); err != nil {
		t.Fatalf("ReconcileNTPInput sem fonte ligada: %v", err)
	}
	if pass := inputChainCommands(p.exec.calls()); containsSubstr(pass, "jump "+chain) {
		t.Fatal("controle quebrado: sem SetInputChainSources a passada do NTP não teria como conhecer os grupos do banco. Se ela passou a conhecê-los, reveja o teste da ligação — ele pode estar verde por outro motivo")
	}

	p.exec.forget()
	if err := p.fr.Reconcile(ctx); err == nil {
		t.Error("sem fonte de NTP ligada, a reconciliação dos grupos tem que ABORTAR a chain input (fail-closed) em vez de reescrevê-la sem a proteção do serviço de hora")
	}
	if pass := inputChainCommands(p.exec.calls()); len(pass) > 0 {
		t.Errorf("a chain input não podia ter sido tocada nessa passada: %v", pass)
	}
}

// seedInputScopeGroup cria no banco um grupo de escopo input ativado, como o
// CRUD real cria, e devolve o nome da chain dele.
func seedInputScopeGroup(t *testing.T, db *storage.DB) string {
	t.Helper()
	id := "11111111-0000-4000-8000-000000000001"
	existing, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatalf("ListFirewallGroups: %v", err)
	}
	g := storage.FirewallGroup{
		ID:          id,
		Name:        "Acesso ao firewall",
		ChainName:   nftables.GroupChainName(id),
		Position:    len(existing),
		Enabled:     true,
		Fallthrough: nftables.FallthroughContinue,
		Scope:       nftables.ScopeInput,
	}
	if err := db.CreateFirewallGroup(&g); err != nil {
		t.Fatalf("CreateFirewallGroup: %v", err)
	}
	return g.ChainName
}

// seedNTPServing liga "servir NTP para a LAN" no banco, na mesma chave e no
// mesmo formato que ntpInputStateFrom lê em produção.
func seedNTPServing(t *testing.T, db *storage.DB) {
	t.Helper()
	if err := db.SetSetting("ntp_config", `{"serve_lan":true,"allowed_networks":["192.168.3.0/24"]}`); err != nil {
		t.Fatalf("gravar ntp_config: %v", err)
	}
}

// inputChainCommands filtra, do que foi executado, só o que escreve regra na
// chain input.
func inputChainCommands(calls []string) []string {
	prefix := fmt.Sprintf("nft add rule %s %s %s ", nftables.Family, nftables.Table, nftables.InputChain)
	var out []string
	for _, c := range calls {
		if strings.HasPrefix(c, prefix) {
			out = append(out, strings.TrimPrefix(c, prefix))
		}
	}
	return out
}

func containsSubstr(lines []string, want string) bool {
	for _, l := range lines {
		if strings.Contains(l, want) {
			return true
		}
	}
	return false
}

// TestTheRuntimeWiringIsTheOneMainUses é a costura entre as duas redes deste
// pacote, e a única parte deste arquivo que volta a olhar a AST.
//
// Os testes de runtime acima ligam `frSvc.StoredGroups`,
// `ntpInputStateFrom(db.GetSetting)` e `frSvc.UnconfirmedChangePending` aos
// setters do nftSvc. Isso só significa alguma coisa sobre a produção enquanto
// main.go passar os MESMOS argumentos — e os guardas de boot_order_test.go
// olham só o nome da chamada: `nftSvc.SetPersistGuard(func() (bool, error) {
// return false, nil })` passaria verde em todos eles, com o arquivo de boot
// recebendo a regra não confirmada de novo.
//
// Daí a checagem ser sobre os ARGUMENTOS, e não sobre a posição de mais nada:
// posição já é assunto dos guardas de lá.
func TestTheRuntimeWiringIsTheOneMainUses(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("não foi possível localizar o arquivo de teste")
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(filepath.Dir(thisFile), "main.go"), nil, 0)
	if err != nil {
		t.Fatalf("parsear main.go: %v", err)
	}

	var guardArg, groupsArg ast.Expr
	var ntpArgName string
	ast.Inspect(file, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel {
			return true
		}
		if recv, isIdent := sel.X.(*ast.Ident); !isIdent || recv.Name != "nftSvc" {
			return true
		}
		switch sel.Sel.Name {
		case "SetPersistGuard":
			if len(call.Args) == 1 && guardArg == nil {
				guardArg = call.Args[0]
			}
		case "SetInputChainSources":
			if len(call.Args) == 2 && groupsArg == nil {
				groupsArg = call.Args[0]
				if id, isIdent := call.Args[1].(*ast.Ident); isIdent {
					ntpArgName = id.Name
				}
			}
		}
		return true
	})

	if guardArg == nil {
		t.Fatal("não achei `nftSvc.SetPersistGuard(<algo>)` em main.go -- se a forma mudou, este teste e os testes de runtime deste arquivo precisam mudar junto")
	}
	if !isSelectorOn(guardArg, "frSvc", "UnconfirmedChangePending") {
		t.Errorf("a guarda do Persist tem que ser frSvc.UnconfirmedChangePending — a fonte que consulta a janela de confirmação no banco. Qualquer outra coisa faz o /etc/nftables.conf voltar a receber a regra de escopo input não confirmada, e os testes de runtime deste arquivo passariam a medir uma composição que a produção não usa")
	}
	if groupsArg == nil {
		t.Fatal("não achei `nftSvc.SetInputChainSources(<grupos>, <ntp>)` em main.go -- se a forma mudou, este teste e os testes de runtime deste arquivo precisam mudar junto")
	}
	if !isSelectorOn(groupsArg, "frSvc", "StoredGroups") {
		t.Errorf("a fonte de grupos da chain input tem que ser frSvc.StoredGroups: é ela que traz os grupos de escopo input do banco, e é ela que os testes de runtime deste arquivo ligam")
	}
	if ntpArgName == "" {
		t.Fatal("o segundo argumento de SetInputChainSources tem que ser a fonte do estado do NTP nomeada em main.go -- se a forma mudou, este teste precisa mudar junto")
	}
	if !identIsAssignedAFuncCalling(file, ntpArgName, "ntpInputStateFrom") {
		t.Errorf("a fonte do estado do NTP (%q) tem que sair de ntpInputStateFrom: é ela que NÃO transforma erro de leitura em \"servir NTP está desligado\" (I-1), e é ela que os testes de runtime deste arquivo ligam", ntpArgName)
	}
}

// isSelectorOn diz se a expressão é exatamente `<recv>.<sel>` (o valor de
// método, sem chamada).
func isSelectorOn(e ast.Expr, recv, sel string) bool {
	s, isSel := e.(*ast.SelectorExpr)
	if !isSel || s.Sel.Name != sel {
		return false
	}
	id, isIdent := s.X.(*ast.Ident)
	return isIdent && id.Name == recv
}

// identIsAssignedAFuncCalling diz se `name := func(...) { … fn(…) … }` aparece
// em algum lugar do arquivo.
func identIsAssignedAFuncCalling(file *ast.File, name, fn string) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		assign, isAssign := n.(*ast.AssignStmt)
		if !isAssign || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		id, isIdent := assign.Lhs[0].(*ast.Ident)
		if !isIdent || id.Name != name {
			return true
		}
		lit, isLit := assign.Rhs[0].(*ast.FuncLit)
		if !isLit {
			return true
		}
		ast.Inspect(lit, func(m ast.Node) bool {
			call, isCall := m.(*ast.CallExpr)
			if !isCall {
				return true
			}
			if callee, isIdent := call.Fun.(*ast.Ident); isIdent && callee.Name == fn {
				found = true
			}
			return true
		})
		return true
	})
	return found
}
