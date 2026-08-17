package firewallrules

// A decisão do 3-way da reversão (issue #20a), medida sem banco e sem nft.
//
// mergeRevertTarget é uma função pura de três estados, e é onde mora a escolha
// que separa "desfiz a minha mudança" de "apaguei a de outra pessoa". Testá-la
// direto é o que permite exercitar os casos que uma sonda de ponta a ponta não
// consegue montar de propósito — o processo que morreu antes de registrar o
// estado pós-mutação, a regra órfã, a remoção concorrente.

import (
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

var mergeEpoch = time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

func mergeGroup(id, name string, pos int, scope string) storage.FirewallGroup {
	return storage.FirewallGroup{
		ID: id, Name: name, ChainName: "grp_" + id, Position: pos, Enabled: true,
		Fallthrough: "continue", Scope: scope,
		CreatedAt: mergeEpoch, UpdatedAt: mergeEpoch,
	}
}

func mergeSystemGroups() []storage.FirewallGroup {
	a := mergeGroup("sys-hosts", BlockedHostsGroupName, 0, nftables.ScopeForward)
	a.Kind = nftables.GroupKindBlockedHosts
	b := mergeGroup("sys-block", BlocklistGroupName, 1, nftables.ScopeForward)
	b.Kind = nftables.GroupKindBlocklist
	return []storage.FirewallGroup{a, b}
}

func mergeRule(id, groupID string, pos int) storage.FirewallRule {
	return storage.FirewallRule{
		ID: id, GroupID: groupID, Position: pos, Enabled: true, Action: "drop",
		Proto: "tcp", Dport: "22", CreatedAt: mergeEpoch, UpdatedAt: mergeEpoch,
	}
}

func groupIDs(gs []storage.FirewallGroup) []string {
	out := make([]string, 0, len(gs))
	for _, g := range gs {
		out = append(out, g.ID)
	}
	return out
}

func hasGroup(gs []storage.FirewallGroup, id string) bool {
	for _, g := range gs {
		if g.ID == id {
			return true
		}
	}
	return false
}

func hasRule(rs []storage.FirewallRule, id string) bool {
	for _, r := range rs {
		if r.ID == id {
			return true
		}
	}
	return false
}

// Sem ninguém tendo gravado no meio, a reversão não pode passar a fazer nada
// diferente do que fazia: o alvo é o snapshot LITERAL — mesmas linhas, mesmas
// posições, mesmos carimbos — e a auditoria não ganha linha nenhuma.
//
// É a asserção que impede esta correção de vazar para o caminho comum, que é o
// de toda reversão de produção.
func TestWithNoConcurrentWriteTheTargetIsTheSnapshotItself(t *testing.T) {
	base := stateSnapshot{
		Groups: append(mergeSystemGroups(), mergeGroup("lan", "LAN", 2, nftables.ScopeForward)),
		Rules:  []storage.FirewallRule{mergeRule("r1", "lan", 0)},
	}
	// A janela criou um grupo de input; o banco de agora é exatamente isso.
	applied := stateSnapshot{
		Groups: append(append([]storage.FirewallGroup{}, base.Groups...),
			mergeGroup("ssh", "Acesso remoto", 3, nftables.ScopeInput)),
		Rules: base.Rules,
	}

	m := mergeRevertTarget(base, applied, applied)
	if m.merged() {
		t.Fatalf("sem escrita concorrente a reversão tinha que aplicar o snapshot cru; preservou %v e descartou %v", m.preserved, m.dropped)
	}
	if got, want := len(m.target.Groups), len(base.Groups); got != want {
		t.Fatalf("o alvo tinha que ser o snapshot (%d grupos), veio com %d: %v", want, got, groupIDs(m.target.Groups))
	}
	if hasGroup(m.target.Groups, "ssh") {
		t.Errorf("o grupo de input criado pela janela sobreviveu à reversão: %v", groupIDs(m.target.Groups))
	}
}

// O caso da issue: outro admin gravou um grupo de escopo forward dentro dos 90
// segundos. Ele fica — e a reversão diz que ficou.
func TestAConcurrentForwardGroupSurvivesTheRevert(t *testing.T) {
	base := stateSnapshot{Groups: mergeSystemGroups()}
	applied := stateSnapshot{
		Groups: append(append([]storage.FirewallGroup{}, base.Groups...),
			mergeGroup("ssh", "Acesso remoto", 2, nftables.ScopeInput)),
	}
	current := stateSnapshot{
		Groups: append(append([]storage.FirewallGroup{}, applied.Groups...),
			mergeGroup("torrent", "Bloqueio do torrent", 3, nftables.ScopeForward)),
	}

	m := mergeRevertTarget(base, applied, current)
	if !hasGroup(m.target.Groups, "torrent") {
		t.Fatalf("a reversão apagou o grupo que outro admin gravou no meio da janela: %v", groupIDs(m.target.Groups))
	}
	if hasGroup(m.target.Groups, "ssh") {
		t.Errorf("a reversão deixou de pé o grupo de input que ela existia para desfazer: %v", groupIDs(m.target.Groups))
	}
	if len(m.preserved) != 1 {
		t.Fatalf("a reversão tinha que registrar exatamente o que preservou; registrou %v", m.preserved)
	}
	// Posições sequenciais: misturar linhas de dois instantes não pode deixar
	// dois grupos disputando o mesmo lugar na ordem de avaliação.
	for i, g := range m.target.Groups {
		if g.Position != i {
			t.Errorf("posição %d no grupo %q, esperada %d: %v", g.Position, g.Name, i, groupIDs(m.target.Groups))
		}
	}
}

// O limite que torna a preservação segura: alteração que alcança a chain input
// NUNCA é preservada, mesmo divergindo do estado pós-mutação.
//
// É o que salva o caso do processo que morreu entre a escrita da mutação e o
// registro do applied_state: ali a mudança da PRÓPRIA janela parece obra de
// terceiros, e preservá-la deixaria valendo para sempre a regra que pode ter
// trancado o operador para fora da máquina — o oposto exato do que os 90
// segundos prometem.
func TestAChangeReachingTheInputChainIsNeverPreserved(t *testing.T) {
	base := stateSnapshot{Groups: mergeSystemGroups()}
	// applied == base: é o que se sabe quando o registro do pós-mutação não
	// aconteceu (processo morto, ou linha de uma versão anterior à coluna).
	current := stateSnapshot{
		Groups: append(append([]storage.FirewallGroup{}, base.Groups...),
			mergeGroup("ssh", "Acesso remoto", 2, nftables.ScopeInput),
			mergeGroup("torrent", "Bloqueio do torrent", 3, nftables.ScopeForward)),
	}

	m := mergeRevertTarget(base, base, current)
	if hasGroup(m.target.Groups, "ssh") {
		t.Errorf("um grupo de escopo input sobreviveu à reversão porque ela não sabia de quem ele era: a janela promete devolver o ACESSO, não adivinhar autoria")
	}
	if !hasGroup(m.target.Groups, "torrent") {
		t.Errorf("o grupo de forward de outro admin foi apagado junto: %v", groupIDs(m.target.Groups))
	}
}

// Regra que outro admin criou dentro de um grupo que a reversão vai remover.
//
// Preservar a regra sozinha faria dela uma órfã: sem grupo, ela não é
// renderizada em chain nenhuma — ficaria no banco, visível na tela e ausente do
// firewall, que é a confiança falsa que este painel existe para eliminar.
// Trazer o grupo de volta só para hospedá-la é pior ainda: seria a reversão
// deixando de pé justamente o que ela existe para desfazer. Sobra descartar a
// regra — e o que este teste exige é que o descarte seja DITO, nunca silencioso.
//
// O grupo aqui é de escopo forward de propósito: com um de input a regra nem
// chegaria a este ramo (nada que alcance a chain input é preservado, ver o teste
// acima), e o que se quer medir é o ramo da órfã.
func TestARuleLeftWithoutItsGroupIsDroppedOutLoud(t *testing.T) {
	base := stateSnapshot{Groups: mergeSystemGroups()}
	applied := stateSnapshot{
		Groups: append(append([]storage.FirewallGroup{}, base.Groups...),
			mergeGroup("vis", "Visitantes", 2, nftables.ScopeForward)),
	}
	current := stateSnapshot{
		Groups: applied.Groups,
		Rules:  []storage.FirewallRule{mergeRule("r-outro", "vis", 0)},
	}

	m := mergeRevertTarget(base, applied, current)
	if hasGroup(m.target.Groups, "vis") {
		t.Fatalf("o grupo criado pela janela sobreviveu: %v", groupIDs(m.target.Groups))
	}
	if hasRule(m.target.Rules, "r-outro") {
		t.Fatalf("a regra ficou no banco sem o grupo dela: seria invisível para o nft e visível na tela")
	}
	if len(m.dropped) != 1 {
		t.Fatalf("o descarte da regra tinha que ser registrado; veio %v", m.dropped)
	}
}

// A remoção que outro admin fez no meio da janela também é uma escrita dele: a
// reversão não pode ressuscitar o grupo que ele apagou.
func TestAConcurrentDeletionIsNotUndoneByTheRevert(t *testing.T) {
	lan := mergeGroup("lan", "LAN", 2, nftables.ScopeForward)
	base := stateSnapshot{Groups: append(mergeSystemGroups(), lan)}
	applied := base
	current := stateSnapshot{Groups: mergeSystemGroups()}

	m := mergeRevertTarget(base, applied, current)
	if hasGroup(m.target.Groups, "lan") {
		t.Fatalf("a reversão trouxe de volta o grupo que outro admin apagou depois: %v", groupIDs(m.target.Groups))
	}
	if len(m.preserved) != 1 {
		t.Fatalf("a remoção preservada tinha que ir para a auditoria; veio %v", m.preserved)
	}
}
