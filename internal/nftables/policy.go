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
	"fmt"
	"log/slog"
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
