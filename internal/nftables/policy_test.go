package nftables

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// A política padrão configurável (issues #81 e #78).
//
// O teste que mais importa aqui é o primeiro, e ele afirma uma NÃO-MUDANÇA: sem
// fonte ligada, o comando emitido é byte a byte o que o produto emitia antes.
// Toda máquina instalada passa por este caminho a cada reconciliação.

type execGravador struct {
	comandos [][]string
	erro     error
}

func (e *execGravador) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	e.comandos = append(e.comandos, append([]string{cmd}, args...))
	return "", e.erro
}
func (e *execGravador) ExecuteRead(context.Context, string, ...string) (string, error) {
	return "", nil
}
func (e *execGravador) IsDryRun() bool                              { return false }
func (e *execGravador) WriteFile(string, []byte, os.FileMode) error { return nil }

func (e *execGravador) declaracaoDaChain(t *testing.T) string {
	t.Helper()
	for _, c := range e.comandos {
		linha := strings.Join(c, " ")
		if strings.Contains(linha, "add chain") && strings.Contains(linha, InputChain) {
			return linha
		}
	}
	t.Fatalf("nenhum `add chain %s` foi emitido; comandos: %v", InputChain, e.comandos)
	return ""
}

func servicoComExec(e *execGravador) *Service {
	s := NewService(e)
	s.SetInputChainSources(
		func() ([]StoredGroup, error) { return nil, nil },
		func() ([]string, bool, error) { return nil, false, nil },
	)
	return s
}

// TestPoliticaPadraoEhAceitarSemFonte é a asserção de não-regressão.
//
// Toda instalação existente roda sem fonte de política ligada. Se este teste
// quebrar, alguma máquina em produção mudou de comportamento num upgrade — que
// é a única coisa que este projeto proíbe sem exceção.
func TestPoliticaPadraoEhAceitarSemFonte(t *testing.T) {
	e := &execGravador{}
	s := servicoComExec(e)

	if err := s.reconcileInputChain(context.Background(), nil, nil, false); err != nil {
		t.Fatalf("reconcileInputChain: %v", err)
	}

	const querida = "nft add chain inet linkguard input { type filter hook input priority filter ; policy accept ; }"
	if got := e.declaracaoDaChain(t); got != querida {
		t.Errorf("a declaração mudou para quem não usa o recurso:\n  veio     %q\n  esperada %q", got, querida)
	}
}

func TestPoliticaAceitarExplicitaEhIdenticaAoPadrao(t *testing.T) {
	e := &execGravador{}
	s := servicoComExec(e)
	s.SetInputPolicySource(func() (Policy, error) { return PolicyAccept, nil })

	if err := s.reconcileInputChain(context.Background(), nil, nil, false); err != nil {
		t.Fatalf("reconcileInputChain: %v", err)
	}
	if got := e.declaracaoDaChain(t); !strings.Contains(got, "policy accept ;") {
		t.Errorf("accept explícito não produziu a mesma declaração: %q", got)
	}
}

func TestPoliticaRestritivaChegaNaDeclaracao(t *testing.T) {
	e := &execGravador{}
	s := servicoComExec(e)
	s.SetInputPolicySource(func() (Policy, error) { return PolicyDrop, nil })
	s.SetAdminAccessSource(func() (AdminAccess, error) {
		return AdminAccess{PanelPort: 9997, LANNetworks: []string{"192.168.3.0/24"}}, nil
	})

	if err := s.reconcileInputChain(context.Background(), nil, nil, false); err != nil {
		t.Fatalf("reconcileInputChain: %v", err)
	}
	if got := e.declaracaoDaChain(t); !strings.Contains(got, "policy drop ;") {
		t.Errorf("a política restritiva não chegou à declaração: %q", got)
	}

	// E as regras de sobrevivência entram junto: é a política sem elas que
	// tranca o admin fora.
	tudo := ""
	for _, c := range e.comandos {
		tudo += strings.Join(c, " ") + "\n"
	}
	for _, esperada := range []string{"iif lo counter accept", "tcp dport", "icmpv6"} {
		if !strings.Contains(tudo, esperada) {
			t.Errorf("com política restritiva, faltou a linha de sobrevivência %q", esperada)
		}
	}
}

// TestPoliticaRestritivaSemAcessoAdministrativoAborta é a proteção que a
// política trouxe junto.
//
// Renderizar `drop` sem saber quais portas manter abertas é exatamente como o
// admin se tranca fora. A fonte ausente aqui é ERRO — ao contrário da fonte de
// política ausente, que resolve para accept —, e a assimetria tem motivo:
// política ausente significa "o recurso não está em uso"; chegar aqui significa
// que a política JÁ é restritiva.
func TestPoliticaRestritivaSemAcessoAdministrativoAborta(t *testing.T) {
	e := &execGravador{}
	s := servicoComExec(e)
	s.SetInputPolicySource(func() (Policy, error) { return PolicyDrop, nil })
	// sem SetAdminAccessSource

	if err := s.reconcileInputChain(context.Background(), nil, nil, false); err == nil {
		t.Fatal("renderizou política restritiva sem saber o que manter aberto")
	}
	if len(e.comandos) != 0 {
		t.Errorf("tocou na chain antes de abortar: %v", e.comandos)
	}
}

// TestPoliticaPermissivaNaoEmiteSobrevivencia é o contraponto, e o mais
// importante para a base instalada.
//
// Com `accept`, as regras de sobrevivência entrariam ACIMA dos jumps dos grupos
// — e um admin com um grupo de escopo input bloqueando DNS de uma VLAN teria
// esse bloqueio anulado em silêncio por um accept nosso. Seria o produto
// afrouxando o firewall de quem já o usa.
func TestPoliticaPermissivaNaoEmiteSobrevivencia(t *testing.T) {
	e := &execGravador{}
	s := servicoComExec(e)
	s.SetInputPolicySource(func() (Policy, error) { return PolicyAccept, nil })
	s.SetAdminAccessSource(func() (AdminAccess, error) {
		return AdminAccess{PanelPort: 9997, LANNetworks: []string{"192.168.3.0/24"}}, nil
	})

	if err := s.reconcileInputChain(context.Background(), nil, nil, false); err != nil {
		t.Fatalf("reconcileInputChain: %v", err)
	}
	tudo := ""
	for _, c := range e.comandos {
		tudo += strings.Join(c, " ") + "\n"
	}
	for _, proibida := range []string{"iif lo counter accept", "icmpv6", "dport 68"} {
		if strings.Contains(tudo, proibida) {
			t.Errorf("com política permissiva, a linha %q foi emitida e anularia regras do admin", proibida)
		}
	}
}

// TestPoliticaErroDeLeituraAbortaSemTocarNaChain.
//
// Aqui a lógica é a mesma dos grupos e do NTP, e é o oposto do caso da fonte
// ausente: um SELECT que falhou NÃO é "o admin não escolheu política". Se ele
// escolheu bloquear e a leitura falha, resolver para `accept` desligaria a
// postura do firewall em silêncio, com o painel continuando a mostrar
// "bloquear" e o apply reportado ok.
func TestPoliticaErroDeLeituraAbortaSemTocarNaChain(t *testing.T) {
	e := &execGravador{}
	s := servicoComExec(e)
	s.SetInputPolicySource(func() (Policy, error) { return "", errors.New("banco travado") })

	err := s.reconcileInputChain(context.Background(), nil, nil, false)
	if err == nil {
		t.Fatal("erro de leitura da política não abortou")
	}
	if len(e.comandos) != 0 {
		t.Errorf("a chain foi tocada mesmo sem saber a política: %v", e.comandos)
	}
}

// TestPoliticaInvalidaAborta: normalizar para accept seria escolher a resposta
// permissiva para uma pergunta que não foi entendida. E o valor vem do banco,
// onde alguém pode ter gravado qualquer coisa.
func TestPoliticaInvalidaAborta(t *testing.T) {
	for _, v := range []Policy{"", "ACCEPT", "reject", "dropp", "policy drop"} {
		e := &execGravador{}
		s := servicoComExec(e)
		s.SetInputPolicySource(func() (Policy, error) { return v, nil })

		if err := s.reconcileInputChain(context.Background(), nil, nil, false); err == nil {
			t.Errorf("política %q foi aceita", v)
		} else if len(e.comandos) != 0 {
			t.Errorf("política %q tocou na chain antes de abortar", v)
		}
	}
}

func TestPolicyValid(t *testing.T) {
	if !PolicyAccept.Valid() || !PolicyDrop.Valid() {
		t.Error("as duas políticas do produto precisam ser válidas")
	}
	for _, v := range []Policy{"", "x", "Accept", "DROP"} {
		if v.Valid() {
			t.Errorf("%q passou como válida", v)
		}
	}
}
