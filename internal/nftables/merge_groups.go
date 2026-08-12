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

// MergeGroups produz a visão honesta dos grupos: todos os grupos do banco,
// em ordem, cada um dizendo se está de fato valendo no firewall.
//
// Applied só é verdadeiro quando existe, na chain forward viva, uma linha de
// jump para a chain deste grupo — nunca inferido de Enabled. Enabled é o que
// o admin pediu; Applied é o que o kernel está fazendo. Confundir os dois é
// exatamente a confiança falsa que este painel existe para eliminar, e foi
// um achado crítico da revisão da Fase B.
//
// Sem contrapartida viva, o contador fica com HasCounter=false — "não
// medido" —, jamais com um zero, que significaria "medido, e deu zero".
func MergeGroups(groups []StoredGroup, chains map[string]ChainInfo, forward ChainInfo) []GroupView {
	sorted := make([]StoredGroup, len(groups))
	copy(sorted, groups)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Position < sorted[j].Position })

	// Indexa os jumps vivos por nome de chain de destino.
	type live struct {
		handle         int
		packets, bytes uint64
		hasCounter     bool
	}
	jumps := map[string]live{}
	for _, r := range forward.Rules {
		idx := strings.LastIndex(r.Expression, "jump ")
		if idx < 0 {
			continue
		}
		target := strings.TrimSpace(r.Expression[idx+len("jump "):])
		if !strings.HasPrefix(target, GroupChainPrefix) {
			continue
		}
		jumps[target] = live{handle: r.Handle, packets: r.Packets,
			bytes: r.Bytes, hasCounter: r.HasCounter}
	}

	out := make([]GroupView, 0, len(sorted))
	for _, g := range sorted {
		v := GroupView{StoredGroup: g}
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
