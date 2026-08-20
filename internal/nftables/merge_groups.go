package nftables

import (
	"sort"
	"strings"
)

// GroupView é um grupo do banco somado ao que o firewall vivo diz sobre
// ele: se o jump está mesmo lá (Applied), quanto tráfego entrou (o contador
// da linha do jump) e as regras de dentro já pareadas com suas contrapartes
// vivas.
type GroupView struct {
	StoredGroup
	Applied    bool      `json:"applied"`
	Handle     int       `json:"handle"`
	Packets    uint64    `json:"packets"`
	Bytes      uint64    `json:"bytes"`
	HasCounter bool      `json:"has_counter"`
	Rules      ChainInfo `json:"rules"`
}

// liveRule é o que uma linha viva do nft tem a dizer sobre o grupo que ela
// alcança: o handle e o contador, quando medido.
type liveRule struct {
	handle         int
	packets, bytes uint64
	hasCounter     bool
}

// indexGroupJumps indexa, por chain de destino, toda linha de `jump` para uma
// chain de grupo (GroupChainPrefix) dentro de UMA chain viva. Recebe as regras
// de uma chain só de propósito: um jump para grp_x achado na forward não prova
// nada sobre um grupo que deveria morar na input, e vice-versa.
//
// O alvo é lido pela mesma convenção de ApplyGroupNames — o último "jump " da
// linha, e o que vier depois —, e as duas não podem discordar sobre qual chain
// uma linha alcança.
func indexGroupJumps(rules []ChainRule) map[string]liveRule {
	out := make(map[string]liveRule, len(rules))
	for _, r := range rules {
		idx := strings.LastIndex(r.Expression, "jump ")
		if idx < 0 {
			continue
		}
		target := strings.TrimSpace(r.Expression[idx+len("jump "):])
		if !strings.HasPrefix(target, GroupChainPrefix) {
			continue
		}
		out[target] = liveRule{handle: r.Handle, packets: r.Packets, bytes: r.Bytes, hasCounter: r.HasCounter}
	}
	return out
}

// systemGroupExpressions rende as linhas que systemGroupForwardRules emite
// para este kind na forma normalizada de ChainRule.Expression — a mesma
// fonte que forwardChainRules usa para EMITIR essas linhas, aqui usada para
// PROCURÁ-las na forward viva, para que as duas nunca possam divergir sobre
// o que um grupo de sistema é.
//
// `counter` é removido: parseChainRuleLine já consome a cláusula counter do
// nft (packets/bytes viram HasCounter/Packets/Bytes) e não deixa o token
// sobrar no Expression — comparar com ele presente nunca casaria com uma
// linha real.
func systemGroupExpressions(kind string) []string {
	renderer, ok := systemGroupForwardRules[kind]
	if !ok {
		return nil
	}
	var exprs []string
	// false: a visão do painel compara com a forma SEM log. A regra de log é
	// uma linha à parte, com verdict nenhum — ela não é o bloqueio, e contá-la
	// aqui faria o painel dizer que o grupo do sistema tem o dobro de regras.
	for _, tokens := range renderer(false) {
		var parts []string
		for _, t := range tokens {
			if t == "counter" {
				continue
			}
			parts = append(parts, t)
		}
		exprs = append(exprs, strings.Join(parts, " "))
	}
	return exprs
}

// MergeGroups produz a visão honesta dos grupos: todos os grupos do banco,
// em ordem, cada um dizendo se está de fato valendo no firewall.
//
// Para um grupo do admin, Applied só é verdadeiro quando existe, NA CHAIN
// HOSPEDEIRA DELE, uma linha de jump para a chain deste grupo — nunca
// inferido de Enabled. A chain hospedeira sai de GroupHostChain: forward para
// um grupo de tráfego atravessando, input para um de escopo input (Fase C2).
// Procurar sempre na forward faria todo grupo de escopo input aparecer
// eternamente como "configurado, não aplicado", com o jump vivo o tempo todo
// na input. Para um grupo do sistema (bloqueado por host, bloqueado por
// destino) não existe chain própria nem jump: o conteúdo dele é o named set,
// e as linhas de drop moram direto na forward — Applied vem de todas essas
// linhas estarem vivas ali (systemGroupExpressions/IsSystemGroup). Nos dois
// casos, Enabled é o que o admin pediu; Applied é o que o kernel está
// fazendo. Confundir os dois é exatamente a confiança falsa que este painel
// existe para eliminar, e foi um achado crítico da revisão da Fase B.
//
// A forward continua vindo por parâmetro (o chamador a trata em separado: uma
// forward ausente é "nenhum grupo em vigor", nunca um erro — ver
// handlers.indexChains) e a input é lida de `chains`, o índice por nome que
// esta função já recebe. Uma input ausente do índice vira ChainInfo vazia,
// que diz exatamente a verdade: sem chain input, nenhum grupo de escopo input
// está em vigor.
//
// Sem contrapartida viva, o contador fica com HasCounter=false — "não
// medido" —, jamais com um zero, que significaria "medido, e deu zero".
//
// O QUE "APLICADA" SIGNIFICA AQUI, EXATAMENTE (I-1):
//
// Para um grupo do admin, Applied é PRESENÇA DO JUMP para a chain dele —
// nunca EQUIVALÊNCIA da linha viva com a que o banco descreve. indexGroupJumps
// lê só o alvo do último `jump ` e joga fora todo o resto da expressão, de modo
// que uma linha viva irrestrita (`... counter jump grp_x`) e uma restrita
// (`... ct state new counter jump grp_x`) são indistinguíveis daqui. O mesmo
// vale, e desde antes desta coluna existir, para a condição de entrada
// (cond_saddr, cond_daddr, cond_iif).
//
// O CENÁRIO PREVISTO NÃO SE CONFIRMOU — MEDIDO EM VM (§11 da validação final).
// A previsão registrada aqui era: grupo de escopo FORWARD (que não abre janela
// de confirmação) mudado para "só conexões novas", reconciliação falhando
// depois do UPDATE no banco, e o painel dizendo "Aplicada" com a linha antiga
// viva. Exercitado com um shim de `nft` que recusava SÓ a linha restrita do
// grupo alvo, o que a máquina faz é outra coisa:
//
//   - a tela NÃO diz "Aplicada". Diz `applied: false`, `apply_status.ok:
//     false`, e o erro NOMEIA a linha que o nft recusou. O operador tem sinal.
//   - a chain forward fica SEM LINHA NENHUMA para aquele grupo — nem a
//     restrita nem a irrestrita. rebuildChain é `flush chain` + N × `add rule`
//     e não é atômico: quem cai no meio não deixa a linha velha para trás,
//     deixa o vazio. É o comportamento que rebuildChain documenta ("um
//     firewall parcial com as outras regras intactas é estritamente mais
//     seguro que um vazio"), mas num grupo de BLOQUEIO ele é fail-open: o
//     grupo deixa de bloquear até o próximo restart, que reconcilia tudo.
//
// Ou seja: o risco real desta função não é o falso "Aplicada" (que não se
// reproduziu), é a JANELA EM QUE O GRUPO NÃO BLOQUEIA NADA, com a tela
// mostrando a falha. Dois detalhes medidos na mesma passada, que pertencem ao
// caminho de apply e não a esta função: o corpo do 500 é genérico ("erro
// interno do servidor") e o motivo só aparece no apply_status da listagem, de
// modo que quem clica "Salvar" e lê só a mensagem de erro não descobre qual
// linha caiu; e um shim mais largo (recusando qualquer linha com `ct`) esvaziou
// a chain input inteira, perdendo até o `ct state related counter accept` — não
// é cenário realista de produção, foi construído para medir o alcance, e o
// restart recuperou.
//
// POR QUE NÃO APERTAR O CRITÉRIO AQUI, AINDA. Exigir equivalência da linha
// significa reproduzir a forma EXATA que o nft imprime — aspas em iifname, /32
// comido, a cláusula counter consumida por parseChainRuleLine, a ordem dos
// tokens — e qualquer diferença de grafia vira "configurado, não aplicado" num
// grupo que está perfeitamente em vigor. Esse falso negativo é a mesma
// confiança falsa com o sinal trocado, e já custou uma correção neste painel:
// o M-1 da revisão da Fase C2, em que procurar o jump na chain errada deixava
// todo grupo de escopo input eternamente como não aplicado com o jump vivo o
// tempo todo (TestMergeGroupsAppliedFromTheInputChainForAnInputScopeGroup).
// Um aperto aqui só se sustenta passando pelo normalizeExpression dos dois
// lados e com fixture de saída REAL do nft — não é mudança de uma linha. E,
// com o cenário que o justificava medido e desmentido, ele deixou de ter um
// caso concreto que o motive: fica como opção, não como pendência.
func MergeGroups(groups []StoredGroup, chains map[string]ChainInfo, forward ChainInfo) []GroupView {
	sorted := make([]StoredGroup, len(groups))
	copy(sorted, groups)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Position < sorted[j].Position })

	// Indexa os jumps vivos por chain hospedeira e nome de chain de destino
	// (grupos do admin) e, separadamente, toda linha da forward por sua
	// expressão normalizada (grupos do sistema, cujas linhas não são jumps).
	jumpsByHost := map[string]map[string]liveRule{
		ForwardChain: indexGroupJumps(forward.Rules),
		InputChain:   indexGroupJumps(chains[InputChain].Rules),
	}
	byExpr := map[string]liveRule{}
	for _, r := range forward.Rules {
		byExpr[r.Expression] = liveRule{handle: r.Handle, packets: r.Packets, bytes: r.Bytes, hasCounter: r.HasCounter}
	}

	out := make([]GroupView, 0, len(sorted))
	for _, g := range sorted {
		v := GroupView{StoredGroup: g}

		if IsSystemGroup(g.Kind) {
			// Grupo do sistema: sem chain própria, sem jump — Applied exige
			// que TODAS as linhas que este kind emite estejam vivas na
			// forward; o contador do grupo é a soma delas (não há um único
			// jump para medir a entrada), e HasCounter só é verdadeiro se
			// todas as linhas encontradas também mediram.
			exprs := systemGroupExpressions(g.Kind)
			allFound, allCounted := len(exprs) > 0, true
			var packets, bytes uint64
			for _, expr := range exprs {
				l, ok := byExpr[expr]
				if !ok {
					allFound = false
					continue
				}
				packets += l.packets
				bytes += l.bytes
				allCounted = allCounted && l.hasCounter
			}
			v.Applied = allFound
			if v.Applied {
				v.Packets, v.Bytes, v.HasCounter = packets, bytes, allCounted
			}
			// Grupo do sistema não tem regras de chain — o conteúdo dele é o
			// named set, que a tela exibe pelos membros, não por aqui. Fatia
			// vazia, não nil: "rules": null tem cara de erro de leitura.
			v.Rules = ChainInfo{Rules: []ChainRule{}}
			out = append(out, v)
			continue
		}

		if l, ok := jumpsByHost[GroupHostChain(g)][g.ChainName]; ok {
			v.Applied = true
			v.Handle = l.handle
			v.Packets, v.Bytes, v.HasCounter = l.packets, l.bytes, l.hasCounter
		}
		// As regras de dentro reusam integralmente o pareamento por
		// identidade da Fase B — inclusive a normalização da forma que o nft
		// imprime (aspas em iifname, /32 comido).
		//
		// A chain vem do BANCO quando o nft ainda não a tem (grupo recém-criado,
		// reconciliação que não rodou): MergeUserRules carimba o nome da chain
		// em cada regra sintética (C-1), e o zero-value do mapa traria "" —
		// dizer que a regra não mora em chain nenhuma quando o banco sabe
		// exatamente qual é.
		live := chains[g.ChainName]
		if live.Name == "" {
			live.Name = g.ChainName
		}
		v.Rules = MergeUserRules(g.Rules, live)

		// Mas o pareamento sozinho mente aqui, e MergeUserRules não tem como
		// saber: ele foi escrito para user_rules, uma chain ligada direto na
		// forward, onde "existe no nft" implica "é alcançada". A chain de um
		// grupo não: ReconcileGroups deixa a chain de um grupo desligado viva
		// e preenchida de propósito (as regras ficam guardadas para quando
		// ele voltar), e só remove o jump. Sem esta correção, todo grupo
		// desligado com regras — o caso normal, não uma borda — exibiria as
		// regras de dentro como aplicadas, com contador real, ao lado de um
		// grupo marcado como não aplicado.
		//
		// Alcançabilidade é transitiva: se nada pula para a chain, nada
		// dentro dela está em vigor, por mais que o nft a liste. Os
		// contadores são preservados porque são medição verdadeira — do
		// tempo em que o grupo estava ligado —, e apagá-los seria inventar
		// um "não medido" onde houve medição; quem exibe é que decide como
		// apresentar histórico de uma regra que hoje não é alcançada.
		if !v.Applied {
			for i := range v.Rules.Rules {
				v.Rules.Rules[i].Applied = false
			}
		}
		out = append(out, v)
	}
	return out
}
