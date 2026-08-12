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
	for _, tokens := range renderer() {
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
// Para um grupo do admin, Applied só é verdadeiro quando existe, na chain
// forward viva, uma linha de jump para a chain deste grupo — nunca inferido
// de Enabled. Para um grupo do sistema (bloqueado por host, bloqueado por
// destino) não existe chain própria nem jump: o conteúdo dele é o named set,
// e as linhas de drop moram direto na forward — Applied vem de todas essas
// linhas estarem vivas ali (systemGroupExpressions/IsSystemGroup). Nos dois
// casos, Enabled é o que o admin pediu; Applied é o que o kernel está
// fazendo. Confundir os dois é exatamente a confiança falsa que este painel
// existe para eliminar, e foi um achado crítico da revisão da Fase B.
//
// Sem contrapartida viva, o contador fica com HasCounter=false — "não
// medido" —, jamais com um zero, que significaria "medido, e deu zero".
func MergeGroups(groups []StoredGroup, chains map[string]ChainInfo, forward ChainInfo) []GroupView {
	sorted := make([]StoredGroup, len(groups))
	copy(sorted, groups)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Position < sorted[j].Position })

	// Indexa os jumps vivos por nome de chain de destino (grupos do admin) e,
	// separadamente, toda linha da forward por sua expressão normalizada
	// (grupos do sistema, cujas linhas não são jumps).
	type live struct {
		handle         int
		packets, bytes uint64
		hasCounter     bool
	}
	jumps := map[string]live{}
	byExpr := map[string]live{}
	for _, r := range forward.Rules {
		l := live{handle: r.Handle, packets: r.Packets, bytes: r.Bytes, hasCounter: r.HasCounter}
		byExpr[r.Expression] = l

		idx := strings.LastIndex(r.Expression, "jump ")
		if idx < 0 {
			continue
		}
		target := strings.TrimSpace(r.Expression[idx+len("jump "):])
		if !strings.HasPrefix(target, GroupChainPrefix) {
			continue
		}
		jumps[target] = l
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

		if l, ok := jumps[g.ChainName]; ok {
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
