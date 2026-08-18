package nftables

// A política padrão da chain input, configurável (issues #81 e #78).
//
// ESTE ARQUIVO NÃO MUDA COMPORTAMENTO NENHUM. Sem fonte ligada — que é o estado
// de toda máquina instalada — a política resolve para `accept`, que é
// exatamente o que reconcileInputChain escrevia literalmente antes. O que ele
// entrega é o SEAM: o ponto de leitura existindo, no lugar certo, sob o lock
// certo, antes de alguém precisar dele no meio da mudança arriscada.
//
// POR QUE O LUGAR IMPORTA (issue #81). A chain input tem dois escritores:
// reconcileGroups (passo 3b) e ReconcileNTPInput. Os dois já rodam sob
// reconcileMu, e é isso que impede um toggle de NTP de escrever por cima de uma
// reversão em curso (o I-3 da revisão final). Se a política fosse lida FORA
// desse lock, ela reabriria o mesmo buraco por outro lado: o toggle leria a
// política antiga e a reescreveria depois de a reversão ter gravado a nova.
//
// Por isso a leitura acontece dentro de reconcileInputChain, que já está no
// caminho travado dos dois — e não em quem chama.

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// Policy é a política padrão de uma chain.
type Policy string

const (
	// PolicyAccept: o que não casou com regra nenhuma passa. É o padrão de
	// fábrica e o estado de toda instalação existente.
	PolicyAccept Policy = "accept"
	// PolicyDrop: o que não casou com regra nenhuma é descartado.
	//
	// NENHUM caminho do produto grava isto hoje. A capacidade de escolher a
	// política é a issue #78, e ela depende de pré-requisitos que ainda não
	// estão prontos — em especial as regras de sobrevivência (survival.go)
	// estarem LIGADAS, sem o que `drop` na input corta SSH e painel no instante
	// em que é aplicada.
	PolicyDrop Policy = "drop"
)

// Valid diz se p é uma política que este código sabe escrever.
//
// Existe porque o valor vem do banco, e um valor estranho ali não pode virar
// argumento de `nft`: ele seria recusado no meio de um script que também
// contém as regras, derrubando a chain inteira em vez de só a linha.
func (p Policy) Valid() bool {
	return p == PolicyAccept || p == PolicyDrop
}

// SetInputPolicySource liga a fonte da política da chain input.
//
// Separada de SetInputChainSources de propósito: aquelas duas fontes são
// pré-requisito para a chain ser reconstruída CORRETAMENTE, e a ausência delas
// aborta. Esta é opcional por natureza — um binário que nunca a ligue continua
// se comportando como o produto se comportou até aqui.
func (s *Service) SetInputPolicySource(src func() (Policy, error)) {
	s.inputPolicySource = src
}

// inputPolicy resolve a política a escrever na declaração da chain input.
//
// AS DUAS FORMAS DE NÃO CONSEGUIR RESPONDER TÊM TRATAMENTOS OPOSTOS AQUI, e a
// diferença é o contrário do que ntpInputState faz — o que exige explicação,
// porque a assimetria parece um descuido:
//
//   - FONTE NÃO LIGADA devolve `accept`, sem erro. Não é fail-open: é o estado
//     de todo binário anterior a esta mudança, e de toda máquina que nunca vai
//     usar o recurso. Abortar aqui faria a chain input parar de ser reconciliada
//     em qualquer instalação sem a ligação — trocaria "o recurso não está em
//     uso" por "o firewall parou de se atualizar";
//
//   - ERRO DE LEITURA propaga, e o chamador aborta sem tocar na chain. Aqui a
//     lógica do NTP vale inteira: um SELECT que falhou NÃO é "o admin não
//     escolheu política". Se ele escolheu `drop` e a leitura falha, resolver
//     para `accept` desligaria a postura do firewall em silêncio — com o painel
//     continuando a mostrar "bloquear" e o apply reportado ok. É o fail-open
//     que o I-1 existe para fechar, e é por isso que este caminho aborta.
//
// Valor inválido também aborta, pelo mesmo motivo: normalizá-lo para `accept`
// seria escolher a resposta permissiva para uma pergunta que não foi entendida.
func (s *Service) inputPolicy() (Policy, error) {
	if s.inputPolicySource == nil {
		return PolicyAccept, nil
	}
	p, err := s.inputPolicySource()
	if err != nil {
		return "", fmt.Errorf("ler a política padrão da chain %s: %w", InputChain, err)
	}
	if !p.Valid() {
		return "", fmt.Errorf("política padrão inválida para a chain %s: %q", InputChain, p)
	}
	if p == PolicyDrop {
		// Registrado em toda reconciliação de propósito: é a informação que
		// explica um "parou de responder" no diagnóstico seguinte.
		slog.Info("chain input reconciliada com política restritiva", "chain", InputChain, "policy", p)
	}
	return p, nil
}

// SetAdminAccessSource liga a fonte do acesso administrativo — as portas, as
// redes da LAN e se alguma WAN é por DHCP.
//
// Só é consultada quando a política é restritiva: com `accept` as regras de
// sobrevivência não são emitidas, e uma leitura a mais seria só mais uma forma
// de a chain input deixar de ser reconciliada.
func (s *Service) SetAdminAccessSource(src func() (AdminAccess, error)) {
	s.adminAccessSource = src
}

// adminAccess resolve o acesso administrativo para as regras de sobrevivência.
//
// Fonte ausente é ERRO aqui, ao contrário da política. A assimetria tem motivo:
// política ausente significa "o recurso não está em uso", e responder `accept`
// é o comportamento de sempre. Já chegar neste ponto significa que a política
// JÁ é restritiva — e renderizar `drop` sem saber quais portas manter abertas é
// exatamente como o admin se tranca fora. Abortar deixa a chain como estava,
// que é o único lado seguro.
func (s *Service) adminAccess() (AdminAccess, error) {
	if s.adminAccessSource == nil {
		return AdminAccess{}, fmt.Errorf(
			"política restritiva pedida sem fonte de acesso administrativo ligada: " +
				"renderizar a chain assim cortaria SSH e painel (ver SetAdminAccessSource)")
	}
	return s.adminAccessSource()
}

// SetForwardPolicySource liga a fonte da política da chain forward (#92).
//
// Separada da input de propósito: as duas posturas são independentes. Bloquear
// o que atravessa e liberar o que chega ao próprio firewall é uma combinação
// legítima e comum — e amarrá-las num valor só tiraria do admin exatamente a
// escolha que ele veio fazer.
func (s *Service) SetForwardPolicySource(src func() (Policy, error)) {
	s.forwardPolicySource = src
}

// forwardPolicy resolve a política da chain forward. Mesmo contrato da input:
// fonte ausente é accept (o estado de sempre), erro de leitura aborta.
func (s *Service) forwardPolicy() (Policy, error) {
	if s.forwardPolicySource == nil {
		return PolicyAccept, nil
	}
	p, err := s.forwardPolicySource()
	if err != nil {
		return "", fmt.Errorf("ler a política padrão da chain %s: %w", ForwardChain, err)
	}
	if !p.Valid() {
		return "", fmt.Errorf("política padrão inválida para a chain %s: %q", ForwardChain, p)
	}
	if p == PolicyDrop {
		slog.Info("chain forward reconciliada com política restritiva", "chain", ForwardChain, "policy", p)
	}
	return p, nil
}

// rebuildChainAtomic reconstrói uma chain INTEIRA — declaração, flush e regras —
// num único script aplicado com `nft -f`, que o nft trata como transação.
//
// POR QUE ELE EXISTE, E POR QUE NÃO É O PADRÃO.
//
// rebuildChain é `flush chain` seguido de N × `add rule`, cada um um comando
// separado. Com política PERMISSIVA isso é inofensivo: entre o flush e a
// primeira regra a chain está vazia, e chain vazia com `policy accept` deixa
// tudo passar — que é o que ela ia fazer mesmo.
//
// Com política RESTRITIVA a mesma janela inverte de sinal: a chain fica vazia
// com `policy drop`, e por alguns milissegundos TODO o tráfego da rede é
// cortado — inclusive o que as regras de sobrevivência existem para preservar.
// Num firewall de produção isso é uma queda, curta e real, a cada reconciliação.
//
// E ele NÃO substitui o rebuildChain de sempre, de propósito: com `nft -f`, uma
// regra ruim aborta o script INTEIRO, enquanto o caminho de hoje aplica as
// demais e reporta a rejeitada (C-1). Trocar isso para toda a base instalada
// seria uma mudança de comportamento que ninguém pediu, num caminho onde o
// comportamento atual está documentado e testado.
//
// Então: atômico só onde a atomicidade é necessária.
func (s *Service) rebuildChainAtomic(ctx context.Context, chain, decl string, rules [][]string) error {
	var b strings.Builder
	// A declaração vem primeiro: ela cria a chain se não existir e ALTERA a
	// política se existir, sem tocar nas regras. Dentro do mesmo script, o
	// flush logo abaixo é quem esvazia.
	b.WriteString(decl + "\n")
	fmt.Fprintf(&b, "flush chain %s %s %s\n", Family, Table, chain)
	for _, tokens := range rules {
		fmt.Fprintf(&b, "add rule %s %s %s %s\n", Family, Table, chain, strings.Join(tokens, " "))
	}

	f, err := os.CreateTemp("", "linkguard-chain-*.nft")
	if err != nil {
		return fmt.Errorf("criar o script da chain %s: %w", chain, err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(b.String()); err != nil {
		f.Close() //nolint:errcheck // já estamos devolvendo erro
		return fmt.Errorf("escrever o script da chain %s: %w", chain, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("fechar o script da chain %s: %w", chain, err)
	}

	if out, err := s.exec.Execute(ctx, "nft", "-f", f.Name()); err != nil {
		// O script inteiro foi recusado, então a chain continua EXATAMENTE como
		// estava — que é a propriedade que justifica este caminho.
		return fmt.Errorf("aplicar a chain %s: %w (saída: %s)", chain, err, out)
	}
	return nil
}

// SurvivalPreview devolve, em texto, as linhas que uma política restritiva
// emitiria em cada chain — a lista que o painel mostra ao operador ANTES de ele
// bloquear (issue #94).
//
// Ela existe porque a alternativa era o painel adivinhar. A porta do painel não
// é fixa (8080 no binário, 9997 no .deb, outra atrás de um proxy), as redes da
// LAN vêm da configuração, e a linha do cliente DHCP só sai em quem tem WAN por
// DHCP. Uma tela que mostrasse `tcp dport { 22, 9997 }` para quem usa outra
// porta estaria mentindo justamente na frase que o operador vai ler para decidir
// se continua entrando na máquina depois de apertar o botão.
//
// A lista sai das MESMAS funções que a reconciliação usa. Se elas mudarem, a
// tela muda junto — não há uma segunda cópia para ficar velha.
//
// O erro do acesso administrativo NÃO é fatal aqui: esta é uma pré-visualização,
// e mostrar a lista da forward (que não depende dele) é melhor que não mostrar
// nada. A input volta vazia, e o painel diz que não conseguiu montá-la.
func (s *Service) SurvivalPreview() (input, forward []string, err error) {
	for _, tokens := range ForwardSurvivalRules() {
		forward = append(forward, strings.Join(tokens, " "))
	}
	access, aerr := s.adminAccess()
	if aerr != nil {
		return nil, forward, aerr
	}
	for _, tokens := range SurvivalRules(access) {
		input = append(input, strings.Join(tokens, " "))
	}
	return input, forward, nil
}
