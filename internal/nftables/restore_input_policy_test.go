package nftables

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// ─── O Restore não reintroduz `policy drop` na chain input ───────────────────
//
// A invariante mais dura deste projeto: a chain `input` nasce e permanece com
// `policy accept`, e bloqueio se faz por REGRA explícita, nunca por política. A
// razão é operacional e não estética — uma política restritiva trancaria o
// operador para fora de um firewall em produção, possivelmente de madrugada e
// sem acesso físico.
//
// O produto nunca EMITE `policy drop` (TestInputChainIsNeverPolicyDrop, e
// outros), então isto não é alcançável por um snapshot gerado por nós. Mas o
// Restore é o ÚNICO caminho que aplica texto de firewall que o produto não
// gerou: a linha de `iptables_backups` pode ter sido editada à mão, vir de outra
// máquina, ou ter sido capturada enquanto alguém mexia no ruleset por fora. É a
// única porta pela qual um `policy drop` editado à mão entra no kernel.
//
// ─── Sobre as fixtures ───────────────────────────────────────────────────────
//
// TODAS as três abaixo são saída REAL do nft 1.1.3 (`unshare -rn` + `nft -f` +
// `nft list ruleset`), nunca texto escrito à mão. Neste projeto uma fixture
// inventada já deixou um bug crítico passar por cinco testes verdes, e aqui há
// três detalhes que só a saída de verdade fixa:
//
//   - o nft SEMPRE imprime `policy <x>;` numa chain base, mesmo quando o arquivo
//     de entrada não trazia política nenhuma (o `accept` default é
//     materializado). Logo, "não tem linha `type … hook …`" significa "não é
//     chain base", não "política escondida";
//   - `priority` sai por NOME (`filter`, `srcnat`) e não pelo número que entrou;
//   - o comentário de uma regra é impresso LITERALMENTE, e cabe nele a
//     declaração inteira de uma chain base — a armadilha de falso positivo que
//     dropCommentTrap exercita.

// dropDump é o snapshot PROIBIDO. Byte a byte igual ao que o nft imprimiu para
// uma tabela `inet linkguard` completa, com uma diferença: `policy drop` na
// chain input. É exatamente o que um snapshot editado à mão pareceria.
const dropDump = `table inet linkguard {
	map host_wan {
		type ipv4_addr : mark
		elements = { 192.168.1.50 : 0x00000064,
			     192.168.1.51 : 0x000000c8 }
	}

	set blocklist {
		type ipv4_addr
		flags interval
		elements = { 10.10.0.0/24, 10.10.1.0/24,
			     10.10.2.0/24, 10.10.3.0/24,
			     10.10.4.0/24, 10.10.5.0/24,
			     10.10.6.0/24, 10.10.7.0/24,
			     10.10.8.0/24 }
	}

	set blocked_hosts {
		type ipv4_addr
		elements = { 192.168.1.77 }
	}

	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		tcp dport 22 accept comment "SSH do admin (nao remover) }"
	}

	chain forward {
		type filter hook forward priority filter; policy accept;
		ip saddr @blocked_hosts counter packets 0 bytes 0 drop
		counter packets 0 bytes 0 jump user_rules
	}

	chain user_rules {
		ip saddr 192.168.1.90 drop
	}

	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "enp4s0" masquerade
	}
}
table ip docker {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr 172.17.0.0/16 oifname != "docker0" masquerade
	}
}
`

// dropCommentTrap é O teste do falso positivo, e é saída real do nft: a chain
// input está com `policy accept` (legítima), mas o COMENTÁRIO de uma regra
// contém a declaração inteira de uma chain base com `policy drop;` dentro. Uma
// verificação por substring (`strings.Contains(block, "policy drop")`) recusaria
// este snapshot — e recusar um snapshot legítimo é PIOR que o defeito, porque
// tira do operador a única ferramenta de recuperação que ele tem numa máquina
// que só alcança pela rede.
//
// A `chain forward` com `policy drop` está aqui de propósito pelo mesmo motivo:
// a recusa é sobre a chain `input`, que é a que tranca o acesso do operador.
const dropCommentTrap = `table inet linkguard {
	chain input {
		type filter hook input priority filter; policy accept;
		ct state established,related accept
		tcp dport 22 accept comment "type filter hook input priority filter; policy drop;"
		tcp dport 9997 accept comment "painel — policy drop nunca"
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
	}

	chain sem_hook {
		tcp dport 1 drop
	}
}
`

// regularInputDump é uma chain `input` que NÃO é chain base (sem
// `type … hook …`). Também saída real do nft. Não há hook, logo não há política
// de input a valer, logo não há tranca: aceitar é a decisão certa. É o outro
// lado do falso positivo.
const regularInputDump = `table inet linkguard {
	chain input {
		tcp dport 22 accept
	}

	chain forward {
		type filter hook forward priority filter; policy accept;
	}
}
`

func TestRestoreRefusesASnapshotWithARestrictiveInputPolicy(t *testing.T) {
	exec := &restoreExec{}
	s := NewService(exec)

	_, err := s.Restore(context.Background(), dropDump)
	if !errors.Is(err, ErrInputPolicyNotAccept) {
		t.Fatalf("um snapshot com `policy drop` na chain input tinha que ser recusado com ErrInputPolicyNotAccept, veio: %v", err)
	}
	// A mensagem tem que NOMEAR o motivo: quem lê isto às 3 da manhã precisa
	// entender que a recusa é a proteção, não um defeito.
	for _, want := range []string{"policy drop", "input", "trancaria"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("a mensagem da recusa tem que conter %q; veio: %q", want, err.Error())
		}
	}
	// E, sobretudo: ANTES de aplicar qualquer coisa. Nem o pré-voo `nft -c -f`
	// pode ter rodado — um snapshot que não pode ser aplicado não merece nem
	// arquivo temporário.
	if exec.nApplies != 0 {
		t.Errorf("a recusa não podia ter tocado no firewall: %v", exec.calls)
	}
	if len(exec.calls) != 0 {
		t.Errorf("a recusa tem que vir antes de qualquer chamada ao nft, inclusive o pré-voo: %v", exec.calls)
	}
}

// TestRestoreStillAcceptsALegitimateSnapshot é a contraprova obrigatória:
// recusar o que é válido seria pior que o defeito. Os três casos legítimos —
// o dump de produção, o comentário-armadilha e a chain input que não é base —
// têm que passar inteiros até o `nft -f`.
func TestRestoreStillAcceptsALegitimateSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name string
		dump string
		want string // um trecho que prova que o conteúdo chegou íntegro
	}{
		{"dump de produção (o mesmo do teste de escopo)", prodDump, `oifname "enp4s0" masquerade`},
		{"comentário de regra contendo `policy drop`", dropCommentTrap, `comment "type filter hook input priority filter; policy drop;"`},
		{"chain input que não é chain base", regularInputDump, "chain input {"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exec := &restoreExec{}
			if _, err := NewService(exec).Restore(context.Background(), tc.dump); err != nil {
				t.Fatalf("um snapshot LEGÍTIMO foi recusado — isto é pior que o defeito que a recusa conserta: %v", err)
			}
			if exec.nApplies != 1 {
				t.Fatalf("o snapshot legítimo tinha que ter sido aplicado uma vez, foram %d: %v", exec.nApplies, exec.calls)
			}
			if !strings.Contains(exec.applied, tc.want) {
				t.Errorf("o conteúdo chegou truncado ao nft: falta %q\n%s", tc.want, exec.applied)
			}
		})
	}
}

// TestRefuseRestrictiveInputPolicyReadsThePolicyItself vai direto na unidade,
// para que a mensagem de falha aponte para a linha e não para o Restore inteiro.
func TestRefuseRestrictiveInputPolicyReadsThePolicyItself(t *testing.T) {
	block, err := LinkguardTableBlock(dropDump)
	if err != nil {
		t.Fatalf("LinkguardTableBlock: %v", err)
	}
	if err := refuseRestrictiveInputPolicy(block); err == nil {
		t.Fatal("`policy drop` na chain input tinha que ser recusado")
	}

	// `policy queue`, `policy continue`… qualquer coisa que não seja accept: a
	// recusa é por lista de permissão, não por lista de proibição. Uma versão
	// futura do nft que aceite outra política restritiva não abre buraco aqui.
	queued := strings.Replace(block, "policy drop;", "policy queue;", 1)
	err = refuseRestrictiveInputPolicy(queued)
	if !errors.Is(err, ErrInputPolicyNotAccept) {
		t.Errorf("qualquer política que não seja `accept` tem que ser recusada, veio: %v", err)
	}
	if err != nil && !strings.Contains(err.Error(), "policy queue") {
		t.Errorf("a mensagem tem que nomear a política que veio; veio: %q", err.Error())
	}

	// E o LinkguardTableBlock continua sendo um extrator PURO: ele LÊ o bloco
	// proibido sem reclamar. Um leitor futuro (mostrar o diff de um snapshot,
	// comparar dois backups) precisa conseguir olhar justamente o snapshot ruim
	// para explicar por que ele é ruim.
	if !strings.Contains(block, "policy drop;") {
		t.Error("LinkguardTableBlock deixou de devolver o bloco literal: a recusa tem que morar no Restore, não no recorte")
	}
}
