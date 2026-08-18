package firewallrules

// A rede da issue #20: a ordem dos oito passos, exercitada SEM montar uma
// requisição HTTP.
//
// Esse "sem HTTP" é o ponto, não um detalhe de conveniência. Enquanto a ordem
// vivia nos handlers, cada passo recebia um http.ResponseWriter, e afirmar
// qualquer coisa sobre ela exigia httptest — o que amarrava a rede de segurança
// do firewall à camada de transporte e deixava sem cobertura todo caminho de
// mutação que não fosse uma requisição.
//
// Aqui a Mutation é um espião: ela grava a sequência em que foi chamada. Os
// testes afirmam sobre ESSA sequência, que é a rede propriamente dita.
//
// Todos partem de newBootedService, e não de um banco pelado, porque o domínio
// se RECUSA a reconciliar ou a armar janela sem os dois grupos do sistema —
// snapshot sem grupo nenhum, se restaurado, apagaria o firewall inteiro. Um
// banco vazio faria estes testes medirem essa recusa em vez da ordem.

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// mutacaoEspia registra a ordem das chamadas e falha onde o teste mandar.
type mutacaoEspia struct {
	passos []string

	erroValidate  error
	erroPreflight error
	erroWrite     error

	precisaJanela bool
	resumo        string
}

func (m *mutacaoEspia) marca(p string) { m.passos = append(m.passos, p) }

func (m *mutacaoEspia) Validate() error {
	m.marca("validate")
	return m.erroValidate
}

func (m *mutacaoEspia) Preflight(context.Context) error {
	m.marca("preflight")
	return m.erroPreflight
}

func (m *mutacaoEspia) Window() (bool, string) {
	m.marca("window")
	return m.precisaJanela, m.resumo
}

func (m *mutacaoEspia) Write() error {
	m.marca("write")
	return m.erroWrite
}

func (m *mutacaoEspia) Audit() (string, string, string) {
	return "nft.teste", "recurso:1", "detalhe"
}

func (m *mutacaoEspia) ordem() string { return strings.Join(m.passos, " → ") }

// hooksEspiao registra a auditoria e o snapshot, que são os dois efeitos que
// ApplyGuarded delega a quem chama.
type hooksEspiao struct {
	auditorias [][3]string
	snapshots  int
}

func (h *hooksEspiao) hooks() Hooks {
	return Hooks{
		Audit:       func(a, r, d string) { h.auditorias = append(h.auditorias, [3]string{a, r, d}) },
		SnapshotNft: func() { h.snapshots++ },
	}
}

// TestApplyGuardedSegueAOrdemObrigatoria é a afirmação central da #20.
func TestApplyGuardedSegueAOrdemObrigatoria(t *testing.T) {
	s, _ := newBootedService(t, newTestDB(t))
	m := &mutacaoEspia{}
	h := &hooksEspiao{}

	if _, err := s.ApplyGuarded(context.Background(), "admin", m, h.hooks()); err != nil {
		t.Fatalf("ApplyGuarded: %v", err)
	}

	// A ordem é a rede inteira. Validar vem antes de tocar no banco (C-5); o
	// pré-voo vem antes de escrever; a decisão da janela vem depois do pré-voo
	// e antes da escrita, porque é nesse intervalo que o banco ainda é o
	// estado anterior — que é o que o snapshot precisa ser.
	const querida = "validate → preflight → window → write"
	if m.ordem() != querida {
		t.Errorf("ordem = %q, esperada %q", m.ordem(), querida)
	}

	if len(h.auditorias) != 1 || h.auditorias[0][0] != "nft.teste" {
		t.Errorf("esperava uma auditoria da mutação, veio %v", h.auditorias)
	}
	if h.snapshots != 1 {
		t.Errorf("esperava 1 snapshot do nft depois da reconciliação, veio %d", h.snapshots)
	}
}

// TestApplyGuardedNaoLeOBancoQuandoOsCamposSaoInvalidos é o C-5, que o
// repositório registra ter acontecido de verdade.
//
// Com o banco fora do ar, um corpo inválido virava 500 e o admin não ficava
// sabendo que o problema era o que ele mandou.
func TestApplyGuardedNaoLeOBancoQuandoOsCamposSaoInvalidos(t *testing.T) {
	s, _ := newBootedService(t, newTestDB(t))
	m := &mutacaoEspia{erroValidate: errors.New("porta 99999 não existe")}

	_, err := s.ApplyGuarded(context.Background(), "admin", m, Hooks{})
	if err == nil {
		t.Fatal("esperava erro de validação")
	}
	if st, ok := StageOf(err); !ok || st != StageValidate {
		t.Errorf("etapa = %v, esperada StageValidate", st)
	}
	if m.ordem() != "validate" {
		t.Errorf("depois de a validação falhar nada mais pode rodar; ordem = %q", m.ordem())
	}
}

// TestApplyGuardedNaoEscreveQuandoOPreVooRecusa: uma regra que o `nft -c`
// recusa é recusada ANTES de existir no banco.
func TestApplyGuardedNaoEscreveQuandoOPreVooRecusa(t *testing.T) {
	s, _ := newBootedService(t, newTestDB(t))
	m := &mutacaoEspia{erroPreflight: errors.New("nft: sintaxe inválida")}

	_, err := s.ApplyGuarded(context.Background(), "admin", m, Hooks{})
	if err == nil {
		t.Fatal("esperava erro de pré-voo")
	}
	if st, _ := StageOf(err); st != StagePreflight {
		t.Errorf("etapa = %v, esperada StagePreflight", st)
	}
	if strings.Contains(m.ordem(), "write") {
		t.Errorf("o pré-voo recusou e a escrita aconteceu assim mesmo; ordem = %q", m.ordem())
	}
}

// TestApplyGuardedDescartaAJanelaQuandoAEscritaFalha — e o ponto é que ela
// DESCARTA, não reverte (N-3).
//
// A escrita é atômica, então não sobrou meia mudança para desfazer. Rodar a
// reversão inteira aqui mandaria dez comandos ao nft — flush das chains e
// reconstrução — por causa de um erro que não alterou uma linha do banco.
// Reescrever as chains vivas de um firewall de produção é a última coisa que se
// quer fazer em cima de um erro sem efeito.
func TestApplyGuardedDescartaAJanelaQuandoAEscritaFalha(t *testing.T) {
	s, _ := newBootedService(t, newTestDB(t))
	m := &mutacaoEspia{
		precisaJanela: true,
		resumo:        "criação do grupo \"teste\" (escopo input)",
		erroWrite:     errors.New("banco travado"),
	}
	h := &hooksEspiao{}

	_, err := s.ApplyGuarded(context.Background(), "admin", m, h.hooks())
	if err == nil {
		t.Fatal("esperava erro de escrita")
	}
	if st, _ := StageOf(err); st != StageWrite {
		t.Errorf("etapa = %v, esperada StageWrite", st)
	}

	// A janela não pode ficar para trás: armada, ela tranca a edição do
	// firewall por 90 segundos por causa de uma mudança que nem chegou a valer.
	p, err := s.PendingChangeOrError()
	if err != nil {
		t.Fatalf("PendingChangeOrError: %v", err)
	}
	if p != nil {
		t.Errorf("a janela ficou aberta depois de a escrita falhar: %+v", p)
	}

	// E nada foi auditado: não houve alteração para registrar.
	if len(h.auditorias) != 0 {
		t.Errorf("a escrita falhou e mesmo assim algo foi auditado: %v", h.auditorias)
	}
}

// TestApplyGuardedNaoAbreJanelaParaMutacaoQueNaoAlcancaAInput: a janela é para
// o que pode trancar o operador do lado de fora. Abrir uma para toda mutação
// travaria a edição do firewall por 90 segundos a cada regra de forward salva.
func TestApplyGuardedNaoAbreJanelaParaMutacaoQueNaoAlcancaAInput(t *testing.T) {
	s, _ := newBootedService(t, newTestDB(t))
	m := &mutacaoEspia{precisaJanela: false}

	out, err := s.ApplyGuarded(context.Background(), "admin", m, Hooks{})
	if err != nil {
		t.Fatalf("ApplyGuarded: %v", err)
	}
	if out.WindowID != "" {
		t.Errorf("abriu janela para uma mutação que não alcança a input: %q", out.WindowID)
	}
	p, err := s.PendingChangeOrError()
	if err != nil {
		t.Fatalf("PendingChangeOrError: %v", err)
	}
	if p != nil {
		t.Errorf("sobrou um pendente: %+v", p)
	}
}

// TestApplyGuardedAbreJanelaParaMutacaoDeInput, o contraponto do teste acima —
// sem ele, uma implementação que nunca abre janela passaria.
func TestApplyGuardedAbreJanelaParaMutacaoDeInput(t *testing.T) {
	s, _ := newBootedService(t, newTestDB(t))
	m := &mutacaoEspia{precisaJanela: true, resumo: "criação do grupo \"painel\" (escopo input)"}

	out, err := s.ApplyGuarded(context.Background(), "admin", m, Hooks{})
	if err != nil {
		t.Fatalf("ApplyGuarded: %v", err)
	}
	if out.WindowID == "" {
		t.Fatal("a mutação alcança a input e nenhuma janela foi armada")
	}
	if out.Pending == nil {
		t.Fatal("a faixa do operador ficou sem o pendente")
	}
	if out.Pending.Summary != m.resumo {
		t.Errorf("resumo da faixa = %q, esperado %q", out.Pending.Summary, m.resumo)
	}
}

// TestApplyGuardedRecusaComJanelaAberta é a trava (spec §5.3): com duas
// mudanças pendentes, "reverter ao estado anterior" não teria resposta.
func TestApplyGuardedRecusaComJanelaAberta(t *testing.T) {
	s, _ := newBootedService(t, newTestDB(t))

	primeira := &mutacaoEspia{precisaJanela: true, resumo: "a primeira (escopo input)"}
	if _, err := s.ApplyGuarded(context.Background(), "admin", primeira, Hooks{}); err != nil {
		t.Fatalf("primeira mutação: %v", err)
	}

	segunda := &mutacaoEspia{}
	_, err := s.ApplyGuarded(context.Background(), "outro-admin", segunda, Hooks{})
	if err == nil {
		t.Fatal("a segunda mutação passou com uma janela aberta")
	}
	if st, _ := StageOf(err); st != StageLocked {
		t.Errorf("etapa = %v, esperada StageLocked", st)
	}
	// A trava é lida ANTES de tudo, menos da validação: a segunda mutação não
	// pode ter chegado nem ao pré-voo.
	if segunda.ordem() != "validate" {
		t.Errorf("a mutação travada foi além da validação; ordem = %q", segunda.ordem())
	}
	// E a mensagem nomeia a mudança e quem a aplicou — é o que o operador
	// precisa para decidir entre confirmar e reverter.
	var g *GuardError
	if errors.As(err, &g) && !strings.Contains(g.Message, "admin") {
		t.Errorf("a recusa não diz quem armou a janela: %q", g.Message)
	}
}
