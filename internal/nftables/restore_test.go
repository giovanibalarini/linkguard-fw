package nftables

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// ─── O restore é ESCOPADO à tabela inet linkguard ────────────────────────────
//
// A regra de ouro do produto: o LinkGuard só mexe na tabela dele. O Restore era
// o único lugar que a violava — `flush ruleset` seguido do dump inteiro que o
// Save guardou —, e ele roda em dois caminhos que alcançam produção: o botão
// "Restaurar" da tela de Firewall e o boot que acabou de criar a tabela do zero
// (cmd/linkguard-fw/main.go, depois de EnsureTable devolver true).
//
// prodDump é a saída REAL do nft 1.1.3 (`nft list ruleset` dentro de um
// `unshare -rn`, ver .superpowers/sdd/rollback-trava-e-flush.md), não um texto
// escrito à mão: os dois detalhes que decidem se o recorte da tabela está certo
// só existem no que o nft emite de verdade —
//
//   - o comentário de uma regra pode conter `}` (aqui, a regra do SSH), e
//   - uma lista de elementos longa é quebrada pelo nft em várias linhas.
//
// Um recorte por contagem de chaves erra no primeiro e um recorte "até a linha
// em branco" erra no segundo; os dois devolveriam um bloco TRUNCADO, que ainda
// seria um ruleset válido e entraria no kernel como se fosse o snapshot inteiro.
const prodDump = `table inet linkguard {
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
		type filter hook input priority filter; policy accept;
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
table inet tailscale {
	chain forward {
		type filter hook forward priority filter; policy accept;
		iifname "tailscale0" accept
	}
}
`

// restoreExec captura o TEXTO do arquivo entregue ao nft, tanto no pré-voo
// (`nft -c -f`) quanto no apply (`nft -f`) — é o único jeito de um teste
// afirmar o que de fato seria carregado no kernel.
type restoreExec struct {
	checkErr error
	applyErr error

	calls    []string
	checked  string
	applied  string
	nApplies int
}

func (e *restoreExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	e.calls = append(e.calls, cmd+" "+strings.Join(args, " "))
	if cmd == "nft" && len(args) >= 2 && args[0] == "-f" {
		b, _ := os.ReadFile(args[1])
		e.applied = string(b)
		e.nApplies++
		return "", e.applyErr
	}
	return "", nil
}

func (e *restoreExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	e.calls = append(e.calls, "read:"+cmd+" "+strings.Join(args, " "))
	if cmd == "nft" && len(args) >= 3 && args[0] == "-c" && args[1] == "-f" {
		b, _ := os.ReadFile(args[2])
		e.checked = string(b)
		return "", e.checkErr
	}
	return "", nil
}

func (e *restoreExec) IsDryRun() bool { return false }

func TestRestoreNeverFlushesTheWholeRulesetNorForeignTables(t *testing.T) {
	exec := &restoreExec{}
	s := NewService(exec)

	if _, err := s.Restore(context.Background(), prodDump); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if exec.applied == "" {
		t.Fatal("o Restore não chegou a entregar arquivo nenhum ao `nft -f`")
	}
	t.Logf("ARQUIVO ENTREGUE AO NFT:\n%s", exec.applied)

	if strings.Contains(exec.applied, "flush ruleset") {
		t.Errorf("o restore ainda apaga o ruleset inteiro da máquina:\n%s", exec.applied)
	}
	// A tabela do Docker e a do Tailscale estavam no snapshot; reimpor a versão
	// ANTIGA delas é dano, não restauração — e apagá-las é pior ainda, porque
	// nem o Docker nem o Tailscale recriam a tabela deles sem reiniciar.
	for _, foreign := range []string{"table ip docker", "table inet tailscale", "docker0", "tailscale0"} {
		if strings.Contains(exec.applied, foreign) {
			t.Errorf("o restore mexe em tabela de terceiro (%q):\n%s", foreign, exec.applied)
		}
	}
	// O preâmbulo idempotente já provado em produção pelo Persist: cria (para
	// que o delete nunca falhe), apaga a NOSSA tabela e recarrega a definição
	// inteira. Sem o delete, `nft -f` ACRESCENTA à tabela existente — foi assim
	// que a produção acabou com dois `masquerade` na postrouting.
	if !strings.HasPrefix(exec.applied, "table inet linkguard\ndelete table inet linkguard\n") {
		t.Errorf("faltou o preâmbulo `table` + `delete table` da nossa tabela:\n%s", exec.applied)
	}
	// E o que entra tem que ser o snapshot INTEIRO da nossa tabela, incluindo o
	// que um recorte errado cortaria: o comentário com `}` e a última linha da
	// lista de elementos quebrada em várias linhas.
	for _, want := range []string{
		"map host_wan {",
		"10.10.8.0/24 }",
		`tcp dport 22 accept comment "SSH do admin (nao remover) }"`,
		"chain user_rules {",
		"ip saddr 192.168.1.90 drop",
		`oifname "enp4s0" masquerade`,
	} {
		if !strings.Contains(exec.applied, want) {
			t.Errorf("o snapshot da nossa tabela entrou truncado: falta %q\n%s", want, exec.applied)
		}
	}
}

func TestRestoreRefusesASnapshotWithoutTheLinkguardTable(t *testing.T) {
	// Um snapshot gravado antes de a tabela existir, ou vindo de outra máquina.
	// Antes, ele resultava em `flush ruleset` + tabelas de terceiro: a máquina
	// terminava SEM firewall nenhum do LinkGuard e com as tabelas dos outros
	// programas reescritas.
	foreignOnly := prodDump[strings.Index(prodDump, "table ip docker"):]
	exec := &restoreExec{}
	s := NewService(exec)

	if _, err := s.Restore(context.Background(), foreignOnly); !errors.Is(err, ErrNoLinkguardTable) {
		t.Fatalf("esperava ErrNoLinkguardTable, obtive %v", err)
	}
	if exec.nApplies != 0 {
		t.Errorf("a recusa não podia ter tocado no firewall: %v", exec.calls)
	}
}

func TestRestoreChecksBeforeApplying(t *testing.T) {
	exec := &restoreExec{}
	s := NewService(exec)
	if _, err := s.Restore(context.Background(), prodDump); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if exec.checked != exec.applied {
		t.Errorf("o pré-voo validou um texto e o apply escreveu outro:\nvalidado:\n%s\naplicado:\n%s", exec.checked, exec.applied)
	}
	// E a ordem: validar DEPOIS de aplicar não valida nada.
	iCheck, iApply := -1, -1
	for i, c := range exec.calls {
		if strings.HasPrefix(c, "read:nft -c -f") && iCheck < 0 {
			iCheck = i
		}
		if strings.HasPrefix(c, "nft -f") && iApply < 0 {
			iApply = i
		}
	}
	if iCheck < 0 || iApply < 0 || iCheck > iApply {
		t.Errorf("o pré-voo `nft -c -f` tem que vir antes do apply: %v", exec.calls)
	}

	// Snapshot que não compila: nada é aplicado.
	bad := &restoreExec{checkErr: errors.New("Error: syntax error, unexpected end of file")}
	if _, err := NewService(bad).Restore(context.Background(), prodDump); err == nil {
		t.Fatal("um snapshot recusado pelo `nft -c -f` tinha que devolver erro")
	}
	if bad.nApplies != 0 {
		t.Errorf("o snapshot recusado no pré-voo não podia ter sido aplicado: %v", bad.calls)
	}
}

func TestLinkguardTableBlockStopsAtTheTableClosingBrace(t *testing.T) {
	block, err := LinkguardTableBlock(prodDump)
	if err != nil {
		t.Fatalf("LinkguardTableBlock: %v", err)
	}
	if !strings.HasPrefix(block, "table inet linkguard {\n") {
		t.Errorf("o bloco não começa na abertura da nossa tabela:\n%s", block)
	}
	if !strings.HasSuffix(block, "\n}") {
		t.Errorf("o bloco não termina no fechamento da nossa tabela:\n%s", block)
	}
	if strings.Contains(block, "docker") || strings.Contains(block, "tailscale") {
		t.Errorf("o bloco levou junto tabela de terceiro:\n%s", block)
	}
	// O corte tem que ser DEPOIS da última chain da nossa tabela: o `}` do
	// comentário do SSH e o `}` que fecha cada chain estão indentados, e só o da
	// tabela fica na coluna 0 — é essa a âncora.
	if !strings.Contains(block, `oifname "enp4s0" masquerade`) {
		t.Errorf("o bloco foi cortado antes do fim da nossa tabela:\n%s", block)
	}
	// E o bloco tem que ser, byte a byte, o trecho do dump: o restore promete
	// "o resultado é exatamente o snapshot".
	if !strings.Contains(prodDump, block) {
		t.Error("o bloco não é um trecho literal do dump")
	}
}

func TestLinkguardTableBlockRefusesAnUnclosedTable(t *testing.T) {
	// Dump cortado no meio (arquivo truncado, coluna do banco cortada): sem o
	// fechamento na coluna 0 não há prova de que a tabela veio inteira, e
	// aplicar meia tabela é o desfecho que este produto não pode ter.
	cut := prodDump[:strings.Index(prodDump, "chain forward {")]
	if _, err := LinkguardTableBlock(cut); err == nil {
		t.Fatal("um bloco sem fechamento tinha que ser recusado")
	}
	if _, err := LinkguardTableBlock(cut); errors.Is(err, ErrNoLinkguardTable) {
		t.Error("a mensagem tem que distinguir 'truncado' de 'não tem a nossa tabela'")
	}
}
