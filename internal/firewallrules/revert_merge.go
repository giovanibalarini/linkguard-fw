package firewallrules

// O 3-way da reversão (issue #20a) — como desfazer a MINHA janela sem apagar a
// mudança de outra pessoa.
//
// O DEFEITO QUE ISTO FECHA. A trava das mutações (handlers.confirmWindowBlocks)
// é lida no começo da requisição e a escrita no banco acontece muito depois: no
// meio ficam dois SELECTs e um `nft -c`, que é um subprocesso de dezenas de
// milissegundos. Uma mutação que NÃO abre janela (escopo forward) podia então
// passar pela trava quando não havia janela nenhuma, e aterrissar no banco
// depois de outro admin ter armado a dele. O snapshot da janela alheia foi
// tirado ANTES dessa escrita e não a contém — e `ReplaceFirewallGroupsAndRules`
// restaura o snapshot INTEIRO, isto é, um "volte tudo", não um "desfaça o que
// eu fiz". O grupo do primeiro admin sumia do banco E da chain viva, depois de
// ele ter recebido HTTP 200 e visto a linha na tela, sem erro, sem alerta e sem
// uma linha de auditoria dizendo que tinha sido desfeito.
//
// A SAÍDA ESCOLHIDA. A outra possível era alargar a trava — ler o estado e
// escrever dentro de uma seção crítica só. Foi descartada de propósito: essa
// seção teria de englobar o pré-voo `nft -c`, e uma trava segurada por dezenas
// de milissegundos em cima de um subprocesso é como se prende o operador dentro
// da própria janela (os defeitos C-5 e C-6, já vividos e registrados nos
// comentários deste mecanismo). O que se faz aqui é o contrário: a trava
// continua barata, e quem passou a conferir o estado é a REVERSÃO, no único
// instante em que a pergunta tem resposta — o de aplicar o snapshot.
//
// A PERGUNTA QUE A REVERSÃO PASSA A FAZER. Ela tem três estados nas mãos:
//
//	base    (p.Snapshot)     — o firewall ANTES da mutação desta janela
//	applied (p.AppliedState) — o firewall como a mutação desta janela o deixou
//	current                  — o firewall AGORA
//
// Onde `current` ainda é igual a `applied`, ninguém mexeu depois: aquela linha
// é obra desta janela e volta a ser o que `base` diz. Onde `current` DIVERGE de
// `applied`, alguém gravou no meio do caminho — e essa linha fica como está.
//
// O LIMITE, QUE É DE SEGURANÇA E NÃO DE PREGUIÇA. Nada que alcance a chain
// input é preservado, mesmo divergindo. A janela de 90 segundos é uma promessa
// sobre o ACESSO à máquina: "se você não confirmar, o que decide sobre o seu
// SSH e o seu painel volta ao que era". Preservar uma linha de input porque ela
// "parece de outra pessoa" trocaria essa promessa por um palpite — e é
// exatamente o palpite errado no caso que importa, o do processo que morreu
// entre a escrita da mutação e o registro do applied_state (aí a mudança da
// PRÓPRIA janela parece concorrente). Na prática o limite não custa nada: toda
// mutação que alcança a input abre a sua própria janela, e a tabela de uma
// linha só as serializa — não existe uma segunda mutação de input concorrente
// para preservar.

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// revertMerge é o que a reversão vai aplicar, mais o que ela precisa contar.
//
// `preserved` e `dropped` não são diagnóstico opcional: eles são a linha de
// auditoria que faltava. Uma mudança de outro admin que sobrevive à reversão é
// tão digna de registro quanto uma que é desfeita — sem isso o histórico não
// distingue "a reversão devolveu o estado anterior" de "a reversão devolveu o
// estado anterior MENOS o que o Fulano gravou às 03:12".
type revertMerge struct {
	target    stateSnapshot
	preserved []string
	dropped   []string
}

// merged diz se a reversão vai aplicar algo diferente do snapshot cru.
func (m revertMerge) merged() bool { return len(m.preserved) > 0 || len(m.dropped) > 0 }

// mergeRevertTarget calcula o estado que a reversão desta janela deve deixar no
// banco.
//
// Sem divergência entre `applied` e `current` — o caso comum, e o único que
// existia antes desta correção — o resultado é `base` LITERAL, byte a byte,
// posições incluídas. Isso é deliberado: a reversão normal não pode passar a
// mexer em nada por causa de um caminho que ela não percorreu.
func mergeRevertTarget(base, applied, current stateSnapshot) revertMerge {
	baseGroups, appliedGroups, currentGroups := indexGroups(base), indexGroups(applied), indexGroups(current)
	baseRules, appliedRules, currentRules := indexRules(base), indexRules(applied), indexRules(current)

	out := revertMerge{target: base}
	var groups []storage.FirewallGroup
	var rules []storage.FirewallRule

	for _, id := range unionIDs(baseGroups, appliedGroups, currentGroups) {
		b, inB := baseGroups[id]
		a, inA := appliedGroups[id]
		c, inC := currentGroups[id]
		keepConcurrent := !sameGroup(a, inA, c, inC) &&
			!groupTouchesInput(b, inB) && !groupTouchesInput(a, inA) && !groupTouchesInput(c, inC)
		switch {
		case !keepConcurrent:
			if inB {
				groups = append(groups, b)
			}
		case inC:
			groups = append(groups, c)
			out.preserved = append(out.preserved, describeGroupChange(inB, c))
		default:
			// Divergência por AUSÊNCIA: outro admin apagou o grupo depois. A
			// preservação aqui é não trazê-lo de volta.
			out.preserved = append(out.preserved, fmt.Sprintf("a remoção do grupo %q continua valendo", b.Name))
		}
	}

	kept := make(map[string]bool, len(groups))
	for _, g := range groups {
		kept[g.ID] = true
	}

	for _, id := range unionIDs(baseRules, appliedRules, currentRules) {
		b, inB := baseRules[id]
		a, inA := appliedRules[id]
		c, inC := currentRules[id]
		keepConcurrent := !sameRule(a, inA, c, inC) &&
			!ruleTouchesInput(b, inB, baseGroups) &&
			!ruleTouchesInput(a, inA, appliedGroups) &&
			!ruleTouchesInput(c, inC, currentGroups)
		switch {
		case !keepConcurrent:
			if inB {
				rules = append(rules, b)
			}
		case inC && kept[c.GroupID]:
			rules = append(rules, c)
			out.preserved = append(out.preserved, describeRuleChange(inB, c, currentGroups))
		case inC:
			// O grupo dela some com a reversão (foi esta janela que o criou) e
			// uma regra órfã não é renderizada em chain nenhuma: ela ficaria no
			// banco, visível na tela e ausente do firewall — a mesma confiança
			// falsa que este painel existe para eliminar. Sai, e sai DITA.
			out.dropped = append(out.dropped, describeRuleChange(inB, c, currentGroups))
		default:
			out.preserved = append(out.preserved, fmt.Sprintf("a remoção da regra %s continua valendo", shortRule(b)))
		}
	}

	if !out.merged() {
		return out
	}

	// Posições renumeradas só neste caminho. Misturar linhas de `base` (posições
	// de antes) com linhas de `current` (posições de depois) produz repetição e
	// buraco na mesma lista, e a ORDEM É a semântica do firewall — dois grupos
	// na mesma posição deixariam a avaliação decidida pelo desempate de
	// created_at, isto é, por acaso.
	out.target = stateSnapshot{Groups: renumberGroups(groups), Rules: renumberRules(rules)}
	return out
}

// ─── Índices e igualdade ──────────────────────────────────────────────────

func indexGroups(st stateSnapshot) map[string]storage.FirewallGroup {
	out := make(map[string]storage.FirewallGroup, len(st.Groups))
	for _, g := range st.Groups {
		out[g.ID] = g
	}
	return out
}

func indexRules(st stateSnapshot) map[string]storage.FirewallRule {
	out := make(map[string]storage.FirewallRule, len(st.Rules))
	for _, r := range st.Rules {
		out[r.ID] = r
	}
	return out
}

// unionIDs devolve as chaves dos três mapas, sem repetição e em ordem estável —
// a decisão de cada linha não pode depender da ordem de iteração de um map.
func unionIDs[T any](a, b, c map[string]T) []string {
	seen := make(map[string]bool, len(a)+len(b)+len(c))
	for _, m := range []map[string]T{a, b, c} {
		for id := range m {
			seen[id] = true
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// sameGroup compara as duas versões de um grupo tratando a AUSÊNCIA como um
// valor: ausente dos dois lados é "ninguém mexeu", e presente de um lado só é
// divergência. Os carimbos de tempo vão para UTC antes da comparação pela mesma
// razão de canonicalState — o snapshot faz uma ida e volta pelo banco e o mesmo
// instante serializa diferente em fusos diferentes.
func sameGroup(a storage.FirewallGroup, inA bool, b storage.FirewallGroup, inB bool) bool {
	if inA != inB {
		return false
	}
	if !inA {
		return true
	}
	a.CreatedAt, a.UpdatedAt = a.CreatedAt.UTC(), a.UpdatedAt.UTC()
	b.CreatedAt, b.UpdatedAt = b.CreatedAt.UTC(), b.UpdatedAt.UTC()
	return jsonEqual(a, b)
}

func sameRule(a storage.FirewallRule, inA bool, b storage.FirewallRule, inB bool) bool {
	if inA != inB {
		return false
	}
	if !inA {
		return true
	}
	a.CreatedAt, a.UpdatedAt = a.CreatedAt.UTC(), a.UpdatedAt.UTC()
	b.CreatedAt, b.UpdatedAt = b.CreatedAt.UTC(), b.UpdatedAt.UTC()
	return jsonEqual(a, b)
}

// jsonEqual compara duas linhas pelo JSON delas. Erro de serialização responde
// FALSE — "não sei se são iguais" tem que cair no lado que NÃO preserva, que é
// o lado do estado anterior voltar inteiro.
func jsonEqual(a, b any) bool {
	x, err := json.Marshal(a)
	if err != nil {
		return false
	}
	y, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return string(x) == string(y)
}

// ─── Quem alcança a chain input ───────────────────────────────────────────

// groupTouchesInput usa GroupHostChain, e não a coluna `scope` crua, porque é
// ela que decide de verdade onde o jump do grupo é escrito (grupo do sistema é
// sempre forward, escopo vazio conta como forward). É a mesma pergunta de
// handlers.groupReachesInput, feita aqui do lado de quem reverte.
func groupTouchesInput(g storage.FirewallGroup, present bool) bool {
	if !present {
		return false
	}
	return nftables.GroupHostChain(ToStoredGroup(g)) == nftables.InputChain
}

// ruleTouchesInput pergunta pelo GRUPO da regra: uma regra só existe dentro da
// chain de um grupo, e é o grupo que diz em qual chain ela é alcançada.
func ruleTouchesInput(r storage.FirewallRule, present bool, groups map[string]storage.FirewallGroup) bool {
	if !present {
		return false
	}
	g, ok := groups[r.GroupID]
	return groupTouchesInput(g, ok)
}

// ─── Renumeração ──────────────────────────────────────────────────────────

// renumberGroups ordena pelo mesmo critério do banco (ORDER BY position ASC,
// created_at ASC) e reatribui posições sequenciais, para que o resultado da
// mistura seja lido de volta exatamente na ordem em que foi decidido aqui.
func renumberGroups(groups []storage.FirewallGroup) []storage.FirewallGroup {
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].Position != groups[j].Position {
			return groups[i].Position < groups[j].Position
		}
		if !groups[i].CreatedAt.Equal(groups[j].CreatedAt) {
			return groups[i].CreatedAt.Before(groups[j].CreatedAt)
		}
		return groups[i].ID < groups[j].ID
	})
	for i := range groups {
		groups[i].Position = i
	}
	return groups
}

// renumberRules faz o mesmo com o critério de ListFirewallRules (ORDER BY
// position, created_at). A ordem RELATIVA é o que importa — é ela que o
// renderizador usa dentro de cada chain de grupo.
func renumberRules(rules []storage.FirewallRule) []storage.FirewallRule {
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Position != rules[j].Position {
			return rules[i].Position < rules[j].Position
		}
		if !rules[i].CreatedAt.Equal(rules[j].CreatedAt) {
			return rules[i].CreatedAt.Before(rules[j].CreatedAt)
		}
		return rules[i].ID < rules[j].ID
	})
	for i := range rules {
		rules[i].Position = i
	}
	return rules
}

// ─── O texto que vai para a auditoria ─────────────────────────────────────

func describeGroupChange(existed bool, now storage.FirewallGroup) string {
	if !existed {
		return fmt.Sprintf("o grupo %q, criado depois desta janela ter sido aberta", now.Name)
	}
	return fmt.Sprintf("a alteração do grupo %q, feita depois desta janela ter sido aberta", now.Name)
}

func describeRuleChange(existed bool, now storage.FirewallRule, groups map[string]storage.FirewallGroup) string {
	where := now.GroupID
	if g, ok := groups[now.GroupID]; ok {
		where = fmt.Sprintf("%q", g.Name)
	}
	if !existed {
		return fmt.Sprintf("a regra %s do grupo %s, criada depois desta janela ter sido aberta", shortRule(now), where)
	}
	return fmt.Sprintf("a alteração da regra %s do grupo %s, feita depois desta janela ter sido aberta", shortRule(now), where)
}

// shortRule identifica a regra para quem lê a auditoria. A descrição do
// operador vem primeiro quando ela existe: é o nome que ELE deu à linha.
func shortRule(r storage.FirewallRule) string {
	if r.Description != "" {
		return fmt.Sprintf("%q", r.Description)
	}
	if r.Dport != "" {
		return fmt.Sprintf("%s %s dport %s", r.Action, r.Proto, r.Dport)
	}
	return fmt.Sprintf("%s (%s)", r.Action, r.ID)
}
