package nftables

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// A postura da chain FORWARD — o tráfego que ATRAVESSA o firewall (issue #92).
//
// A #78 entregou a postura da chain `input`: o que chega ao próprio aparelho.
// Ela não responde a pergunta que motivou o recurso ("bloquear tudo e liberar
// só algumas coisas"), porque o tráfego da LAN para a internet não passa pela
// input — passa pela forward, que continuava `policy accept` sempre.
//
// Os dois primeiros testes são de NÃO-MUDANÇA e valem mais que o resto: toda
// máquina instalada roda sem fonte ligada, e este caminho é percorrido a cada
// reconciliação.

// grupoDeTeste é o par mínimo que faz a forward ter conteúdo: um grupo de admin
// com condição, para que exista um jump a preservar.
func grupoDeTeste() []StoredGroup {
	return []StoredGroup{
		{ID: "a", Name: "Visitantes", ChainName: "grp_aaa", Kind: GroupKindAdmin, Enabled: true,
			Position: 2, CondSaddr: "192.168.50.0/24", Fallthrough: FallthroughDrop},
	}
}

// servicoForward monta o Service dos testes daqui.
//
// O SetConfPath para um temporário não é detalhe: ReconcileGroups persiste o
// ruleset no fim, e Persist é a única escrita em disco deste pacote que NÃO
// passa pelo Executor — um exec falso não a intercepta. Sem esta linha, os
// testes daqui gravam no ConfPath do pacote e o próximo teste a olhar para ele
// (TestPersistWritesTheServiceConfPath) falha por causa do lixo que deixamos.
// Foi o que aconteceu ao criar este arquivo: o nome dele ordena antes de
// persist_test.go, e a poluição que já existia nos testes de reconciliação
// passou a acontecer ANTES de quem a observa.
func servicoForward(t *testing.T, e *fakeReconcileExec) *Service {
	t.Helper()
	s := &Service{exec: e}
	s.SetConfPath(filepath.Join(t.TempDir(), "nftables.conf"))
	wireNoInputExtras(s)
	return s
}

// linhasDaForward extrai, do script aplicado por `nft -f`, só as regras.
func linhasDaForward(script string) []string {
	var out []string
	for _, l := range strings.Split(script, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "add rule inet linkguard forward ") {
			out = append(out, strings.TrimPrefix(l, "add rule inet linkguard forward "))
		}
	}
	return out
}

// TestForwardSemFonteEhOCaminhoDeSempre é a asserção de não-regressão.
//
// Sem fonte de política ligada, a sequência tem de ser exatamente a de antes da
// #92: `add chain ... policy accept`, `flush chain`, N × `add rule` — e NENHUM
// `nft -f`. Se este teste quebrar, alguma máquina em produção mudou de
// comportamento num upgrade sem ninguém ter pedido.
func TestForwardSemFonteEhOCaminhoDeSempre(t *testing.T) {
	e := &fakeReconcileExec{}
	s := servicoForward(t, e)

	if err := s.ReconcileGroups(context.Background(), grupoDeTeste()); err != nil {
		t.Fatalf("ReconcileGroups: %v", err)
	}

	if len(e.applyScripts) != 0 {
		t.Errorf("o caminho atômico foi usado sem política restritiva: %v", e.applyScripts)
	}
	if !ranCommand(e.executed, "nft flush chain inet linkguard forward") {
		t.Error("o flush separado da forward sumiu: o caminho permissivo tem de continuar sendo o de sempre")
	}
	const decl = "nft add chain inet linkguard forward { type filter hook forward priority filter ; policy accept ; }"
	if !ranCommand(e.executed, decl) {
		t.Errorf("a declaração da forward mudou.\n  esperada %q\n  comandos: %v", decl, e.executed)
	}
	// E nenhuma linha de sobrevivência entrou. Elas ficam ACIMA dos jumps dos
	// grupos: emiti-las com política permissiva anularia, em silêncio, um
	// bloqueio que o admin criou — o produto afrouxando o firewall de quem já
	// o usa para preparar um recurso que ele não ligou.
	for _, c := range e.executed {
		if strings.Contains(c, "linkguard forward ct state established") {
			t.Errorf("regra de sobrevivência emitida com política permissiva: %q", c)
		}
	}
}

func TestForwardAcceptExplicitoEhIdenticoAoPadrao(t *testing.T) {
	semFonte := &fakeReconcileExec{}
	if err := servicoForward(t, semFonte).ReconcileGroups(context.Background(), grupoDeTeste()); err != nil {
		t.Fatalf("sem fonte: %v", err)
	}

	comFonte := &fakeReconcileExec{}
	s := servicoForward(t, comFonte)
	s.SetForwardPolicySource(func() (Policy, error) { return PolicyAccept, nil })
	if err := s.ReconcileGroups(context.Background(), grupoDeTeste()); err != nil {
		t.Fatalf("com fonte: %v", err)
	}

	if strings.Join(semFonte.executed, "\n") != strings.Join(comFonte.executed, "\n") {
		t.Errorf("escolher `accept` explicitamente não pode diferir do padrão:\n  sem fonte: %v\n  com fonte: %v",
			semFonte.executed, comFonte.executed)
	}
}

// TestForwardDropUsaOCaminhoAtomico cobre a propriedade que justifica o
// caminho separado: com `flush` + N × `add`, a chain fica vazia COM POLÍTICA
// DROP por alguns milissegundos, e todo o tráfego da rede é cortado a cada
// reconciliação. Numa casa isso é um vídeo travando; num escritório é o
// telefone caindo.
func TestForwardDropUsaOCaminhoAtomico(t *testing.T) {
	e := &fakeReconcileExec{}
	s := servicoForward(t, e)
	s.SetForwardPolicySource(func() (Policy, error) { return PolicyDrop, nil })

	if err := s.ReconcileGroups(context.Background(), grupoDeTeste()); err != nil {
		t.Fatalf("ReconcileGroups: %v", err)
	}

	if len(e.applyScripts) != 1 {
		t.Fatalf("esperava um único `nft -f` para a forward, vieram %d: %v", len(e.applyScripts), e.executed)
	}
	script := e.applyScripts[0]
	if !strings.Contains(script, "policy drop") {
		t.Errorf("o script não troca a política:\n%s", script)
	}
	if !strings.Contains(script, "flush chain inet linkguard forward") {
		t.Errorf("o script não esvazia a chain, então as regras antigas ficariam empilhadas:\n%s", script)
	}
	// O flush NÃO pode ter saído também como comando solto: seria a janela de
	// corte que este caminho existe para eliminar.
	if ranCommand(e.executed, "nft flush chain inet linkguard forward") {
		t.Errorf("o flush saiu fora da transação, reabrindo a janela de corte: %v", e.executed)
	}
	for _, c := range e.executed {
		if strings.HasPrefix(c, "nft add rule inet linkguard forward ") {
			t.Errorf("regra da forward aplicada fora da transação: %q", c)
		}
	}
}

// TestForwardDropComecaPelaSobrevivencia: sem `established,related` na frente,
// "bloquear tudo" não bloqueia o que não foi liberado — bloqueia TUDO, porque
// nenhuma resposta de servidor casa com uma regra de saída.
func TestForwardDropComecaPelaSobrevivencia(t *testing.T) {
	e := &fakeReconcileExec{}
	s := servicoForward(t, e)
	s.SetForwardPolicySource(func() (Policy, error) { return PolicyDrop, nil })
	if err := s.ReconcileGroups(context.Background(), grupoDeTeste()); err != nil {
		t.Fatalf("ReconcileGroups: %v", err)
	}

	regras := linhasDaForward(e.applyScripts[0])
	if len(regras) < 3 {
		t.Fatalf("script curto demais: %v", regras)
	}
	if !strings.Contains(regras[0], "ct state established,related") {
		t.Errorf("a primeira regra não é a de conexões já estabelecidas: %q\n"+
			"Sem ela, aplicar a política derruba toda conexão em curso da rede.", regras[0])
	}
	if !strings.Contains(regras[1], "ct status dnat") {
		t.Errorf("a segunda regra não é a dos encaminhamentos de porta: %q\n"+
			"Sem ela, todo redirecionamento de porta é traduzido e morre na política.", regras[1])
	}
	// E os jumps dos grupos continuam lá, DEPOIS delas.
	if !strings.Contains(strings.Join(regras, "\n"), "jump grp_aaa") {
		t.Errorf("o jump do grupo sumiu com a política restritiva: %v", regras)
	}
}

// TestForwardDropVoltaParaAccept: uma máquina já bloqueada precisa poder ser
// liberada. Como o caminho permissivo é o de sempre, ele só funciona porque
// reafirma a declaração da chain — `flush` não mexe em política.
func TestForwardDropVoltaParaAccept(t *testing.T) {
	e := &fakeReconcileExec{}
	s := servicoForward(t, e)
	s.SetForwardPolicySource(func() (Policy, error) { return PolicyAccept, nil })
	if err := s.ReconcileGroups(context.Background(), grupoDeTeste()); err != nil {
		t.Fatalf("ReconcileGroups: %v", err)
	}
	if !ranCommand(e.executed, "nft add chain inet linkguard forward { type filter hook forward priority filter ; policy accept ; }") {
		t.Errorf("a chain não é redeclarada com `policy accept`: uma máquina em drop nunca mais seria liberada.\n%v", e.executed)
	}
}

// TestForwardErroDeLeituraAbortaSemTocarNaChain.
//
// Não saber qual é a política não pode virar "então é accept": a máquina pode
// estar bloqueando de propósito, e um SELECT lento abriria a rede inteira. O
// mesmo contrato da chain input (#78) e do NTP.
func TestForwardErroDeLeituraAbortaSemTocarNaChain(t *testing.T) {
	e := &fakeReconcileExec{}
	s := servicoForward(t, e)
	s.SetForwardPolicySource(func() (Policy, error) { return "", errors.New("banco fora do ar") })

	err := s.ReconcileGroups(context.Background(), grupoDeTeste())
	if err == nil {
		t.Fatal("erro de leitura da política não abortou a reconciliação")
	}
	if !strings.Contains(err.Error(), "banco fora do ar") {
		t.Errorf("a causa se perdeu no caminho: %v", err)
	}
	if ranCommand(e.executed, "nft flush chain inet linkguard forward") {
		t.Errorf("a forward foi esvaziada mesmo sem saber qual política aplicar: %v", e.executed)
	}
}

// TestForwardPoliticaInvalidaAborta: valor estranho no banco não vira accept em
// silêncio. Alguém gravou algo que este código não entende, e escolher a
// resposta permissiva para uma pergunta não entendida é como um firewall se
// abre sozinho.
func TestForwardPoliticaInvalidaAborta(t *testing.T) {
	e := &fakeReconcileExec{}
	s := servicoForward(t, e)
	s.SetForwardPolicySource(func() (Policy, error) { return Policy("reject"), nil })

	if err := s.ReconcileGroups(context.Background(), grupoDeTeste()); err == nil {
		t.Fatal("política inválida foi aceita")
	}
	if ranCommand(e.executed, "nft flush chain inet linkguard forward") {
		t.Errorf("a forward foi mexida com política inválida: %v", e.executed)
	}
}

// TestForwardDropNaoInterfereNaInput e vice-versa: as duas posturas são
// independentes, e "bloquear o que atravessa" é a escolha comum de quem quer
// continuar entrando no painel pela LAN.
func TestForwardDropNaoInterfereNaInput(t *testing.T) {
	e := &fakeReconcileExec{}
	s := servicoForward(t, e)
	s.SetForwardPolicySource(func() (Policy, error) { return PolicyDrop, nil })

	if err := s.ReconcileGroups(context.Background(), grupoDeTeste()); err != nil {
		t.Fatalf("ReconcileGroups: %v", err)
	}
	for _, c := range e.executed {
		if strings.Contains(c, "hook input") && !strings.Contains(c, "policy accept") {
			t.Errorf("a postura da forward mudou a chain input: %q", c)
		}
	}
}

// TestForwardDropFalhandoNaoDerrubaAReconciliacao: `nft -f` recusa o script
// inteiro numa regra ruim, então a chain fica EXATAMENTE como estava — que é a
// propriedade que justifica o caminho atômico. O erro é reportado, e os grupos
// já aplicados não são desfeitos.
func TestForwardDropFalhandoNaoDerrubaAReconciliacao(t *testing.T) {
	e := &fakeReconcileExec{failOn: func(cmd string) error {
		if strings.HasPrefix(cmd, "nft -f ") {
			return errors.New("regra recusada")
		}
		return nil
	}}
	s := servicoForward(t, e)
	s.SetForwardPolicySource(func() (Policy, error) { return PolicyDrop, nil })

	err := s.ReconcileGroups(context.Background(), grupoDeTeste())
	if err == nil {
		t.Fatal("a falha do script atômico foi engolida")
	}
	if !strings.Contains(err.Error(), "regra recusada") {
		t.Errorf("a saída do nft não chegou ao operador: %v", err)
	}
}
