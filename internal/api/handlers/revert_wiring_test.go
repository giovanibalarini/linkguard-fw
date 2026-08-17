package handlers_test

// A FIAÇÃO da reversão que confere o estado (issue #20a), medida de ponta a
// ponta.
//
// Os testes puros de `mergeRevertTarget` provam a FUNÇÃO: dados três estados,
// qual é o alvo. Eles passam `applied` explícito na mão, e por isso continuam
// verdes mesmo que a coluna `applied_state`, a migração 11 e a chamada de
// `MarkWindowApplied` sejam arrancadas do caminho de execução. O mesmo vale
// para `SetPendingSnapshot` e para a segunda leitura da trava no Rollback:
// linhas que o produto inteiro depende e que nenhuma asserção alcançava.
//
// Os três testes deste arquivo medem o FIO, não a função. Cada um nasceu
// vermelho contra a versão mutilada correspondente, e a saída real está no
// comentário de cada um.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// ─── (M2) O applied_state está mesmo ligado ao caminho da mutação ─────────

// groupOrder é a ORDEM DE AVALIAÇÃO dos grupos como o banco a devolve —
// `nome@posição`, na sequência do ORDER BY position. É esta lista, e não o
// conjunto de grupos, que decide qual regra vê o pacote primeiro.
func groupOrder(t *testing.T, db *storage.DB) []string {
	t.Helper()
	groups, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatalf("ListFirewallGroups: %v", err)
	}
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		out = append(out, fmt.Sprintf("%s@%d", g.Name, g.Position))
	}
	return out
}

// preservedAuditLines devolve o que a auditoria registrou como PRESERVADO por
// uma reversão.
func preservedAuditLines(t *testing.T, db *storage.DB) []string {
	t.Helper()
	logs, err := db.GetAuditLogs(100)
	if err != nil {
		t.Fatalf("GetAuditLogs: %v", err)
	}
	var out []string
	for _, l := range logs {
		if l.Action == "nft.pending.revert.preserved" {
			out = append(out, l.Details)
		}
	}
	return out
}

// A reordenação é o cenário em que a AUSÊNCIA do applied_state faz estrago
// visível, e é por isso que o guarda da fiação é escrito com ela.
//
// Reordenar grupos abre janela quando o índice de um grupo de escopo input
// muda (groups.go, ReorderGroups) — mas `ReorderFirewallGroups` reescreve a
// posição de TODOS os grupos, os de forward inclusive. Então o "delta desta
// janela" é a tabela inteira.
//
// Com o applied_state gravado (MarkWindowApplied no topo de reconcileArmed),
// a reversão compara o banco de agora com o pós-mutação, não encontra
// divergência nenhuma — ninguém mais escreveu — e aplica o snapshot LITERAL:
// a ordem de avaliação volta byte a byte ao que era.
//
// Sem ele, `AppliedStateOrSnapshot` responde o snapshot, isto é, o estado de
// ANTES. Aí toda linha do banco "diverge do pós-mutação", e a mistura preserva
// tudo o que não alcança a chain input — que é justamente a reordenação que se
// pediu para desfazer. A reversão devolve uma ordem que nunca existiu, e ainda
// registra na auditoria que outro administrador mexeu em três grupos que
// ninguém tocou.
//
// VERIFICADO VERMELHO (não é guarda morta) com a chamada de MarkWindowApplied
// arrancada de reconcileArmed — as três asserções caem de uma vez:
//
//	--- FAIL: TestTheRevertUndoesAReorderInsteadOfPreservingIt (0.02s)
//	    a reversão não devolveu a ordem de avaliação anterior
//	     antes:  [Hosts bloqueados@0 Destinos bloqueados@1 LAN@2 Acesso ao firewall@3]
//	     depois: [LAN@0 Destinos bloqueados@1 Hosts bloqueados@2 Acesso ao firewall@3]
//	    a reversão não devolveu a ordem de avaliação da chain forward VIVA
//	     antes:  [ip saddr @blocked_hosts counter drop | ip daddr @blocked_hosts counter drop |
//	              ip daddr @blocklist counter drop | ip saddr @blocklist counter drop |
//	              ip saddr 192.168.3.0/24 counter jump grp_0587ea1a5cee]
//	     depois: [ip saddr 192.168.3.0/24 counter jump grp_0587ea1a5cee |
//	              ip daddr @blocklist counter drop | ip saddr @blocklist counter drop |
//	              ip saddr @blocked_hosts counter drop | ip daddr @blocked_hosts counter drop]
//	    a reversão registrou que PRESERVOU alteração de outro administrador, e não houve
//	     outro administrador nenhum: [A reversão de "reordenação dos grupos (há grupo de
//	     escopo input entre eles)" (aplicada por unknown) desfez apenas o que esta janela
//	     mudou. Outro administrador gravou dentro dos 90 segundos e isto foi PRESERVADO:
//	     a alteração do grupo "LAN", feita depois desta janela ter sido aberta e a
//	     alteração do grupo "Hosts bloqueados", feita depois desta janela ter sido aberta
//	     e a alteração do grupo "Destinos bloqueados", feita depois desta janela ter sido
//	     aberta.]
//
// Os dois bloqueios administrativos passam a ser avaliados DEPOIS do grupo do
// admin, e a auditoria acusa três administradores que não existem.
func TestTheRevertUndoesAReorderInsteadOfPreservingIt(t *testing.T) {
	w := newOrderWorld(t)

	antes := groupOrder(t, w.db)
	forwardAntes := w.exec.liveChain(nftables.ForwardChain)

	rec := doJSON(t, w.h.ReorderGroups, "POST", "/api/nftables/groups/reorder",
		`{"ids":`+reversedGroupIDsJSON(t, w.db)+`}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("a reordenação: %d (%s)", rec.Code, rec.Body.String())
	}
	p := getPending(t, w.h)
	if p == nil {
		t.Fatalf("a reordenação que move um grupo de input tinha que abrir a janela")
	}
	if reordenada := groupOrder(t, w.db); sameOrder(antes, reordenada) {
		t.Fatalf("a reordenação não mudou nada; a sonda não é a que se quer medir: %v", reordenada)
	}

	// Ninguém mais escreveu nada nesta máquina entre o arme e a reversão: o
	// único delta é o da própria janela, e desfazê-lo é devolver a ordem de
	// antes, inteira.
	rv := doJSON(t, w.h.RevertPendingChange, "POST", "/api/nftables/pending/revert",
		`{"id":"`+p.ID+`"}`)
	if rv.Code != http.StatusOK {
		t.Fatalf("a reversão: %d (%s)", rv.Code, rv.Body.String())
	}

	depois := groupOrder(t, w.db)
	if !sameOrder(antes, depois) {
		t.Errorf("a reversão não devolveu a ordem de avaliação anterior\n antes:  %v\n depois: %v",
			antes, depois)
	}
	// A ordem no banco é metade; a chain VIVA é a que decide sobre o pacote.
	// Um banco certo com a forward reconstruída em outra ordem é a mesma
	// mentira, só que com a tela concordando com o banco.
	if forwardDepois := w.exec.liveChain(nftables.ForwardChain); !sameOrder(forwardAntes, forwardDepois) {
		t.Errorf("a reversão não devolveu a ordem de avaliação da chain forward VIVA\n antes:  %v\n depois: %v",
			forwardAntes, forwardDepois)
	}
	if preservadas := preservedAuditLines(t, w.db); len(preservadas) > 0 {
		t.Errorf("a reversão registrou que PRESERVOU alteração de outro administrador, e não houve outro administrador nenhum: %v",
			preservadas)
	}
}

func sameOrder(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ─── (M6) O alvo misturado é gravado NO LUGAR do snapshot ─────────────────

// A reversão que precisou preservar a alteração de outro admin aplica um
// estado que NÃO é mais o snapshot original. `SetPendingSnapshot` grava esse
// alvo por cima do snapshot antes de aplicá-lo, e essa linha é a única coisa
// entre o operador e o beco C-6.
//
// O caminho do estrago, quando ela sai: a mistura é aplicada, o banco vira o
// alvo misturado, a reconciliação seguinte falha (é o caso comum de uma
// máquina em apuros — é por isso que a reversão está acontecendo), o pendente
// FICA marcado como "revertendo", e a partir daí `RevertSettled` compara o
// banco com o p.Snapshot VELHO. Eles nunca mais vão casar: a reversão já
// aconteceu e nunca vai produzir aquele estado de novo. `confirmWindowBlocks`
// responde 409 para SEMPRE — sem apagar a regra que quebra o reconcile, sem
// desligar o grupo, sem confirmar, sem reverter. É a máquina que já custou
// uma visita ao sqlite3, e é o motivo de a liberação por RevertSettled
// existir.
//
// A sonda é a corrida da #20a com um detalhe a mais: depois de a mutação de A
// já ter passado, a máquina passa a recusar no APPLY a chain de um dos grupos
// — que é como a reconciliação falha de verdade (o `nft -c` aprova, o comando
// de verdade recusa). É o estado em que uma reversão costuma acontecer, e é o
// único em que o pendente sobrevive à reversão para poder ser inspecionado.
//
// VERIFICADO VERMELHO (não é guarda morta) com a chamada de
// s.db.SetPendingSnapshot arrancada de revertTarget, junto com o
// `p.Snapshot = string(blob)` que a acompanha:
//
//	--- FAIL: TestAMergedRevertRewritesTheSnapshotSoTheLockCanRelease (0.02s)
//	    o snapshot da janela continua sendo o ANTIGO: ele não contém o grupo "Bloqueio do
//	     torrent" (221fecd1-...), que a reversão preservou e deixou no banco — o estado
//	     que ele descreve nunca mais vai existir
//	    RevertSettled não reconhece a reversão que ACABOU de restaurar o banco: a trava
//	     fica fechada para sempre (beco C-6)
//	    o operador ficou trancado do lado de fora do próprio painel: a mutação que
//	     conserta a máquina levou 409 — a trava respondeu "a reversão da mudança está em
//	     andamento e o estado anterior ainda não voltou por completo ao banco; espere ela
//	     concluir antes de alterar grupos ou regras"
//
// A terceira linha é o beco inteiro numa frase: 409 para sempre, numa máquina
// que só o sqlite3 destranca.
func TestAMergedRevertRewritesTheSnapshotSoTheLockCanRelease(t *testing.T) {
	w := newOrderWorld(t)
	h, db, exec, fr := w.h, w.db, w.exec, w.fr

	// A corrida da #20a: B arma a janela dele no meio do pré-voo de A.
	var idDeB string
	armado := false
	exec.hookCheck(func(string) {
		if armado {
			return
		}
		armado = true
		id, err := fr.OpenConfirmWindow(context.Background(), "admin-b",
			`edição do grupo "Acesso remoto" (escopo input)`)
		if err != nil {
			t.Errorf("armar a janela de B: %v", err)
		}
		idDeB = id
	})
	rec := doJSON(t, h.CreateGroup, "POST", "/api/nftables/groups",
		`{"name":"Bloqueio do torrent","cond_saddr":"192.168.3.77","fallthrough":"continue"}`)
	exec.hookCheck(nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("a mutação de escopo forward de A: %d (%s)", rec.Code, rec.Body.String())
	}
	var grupoDeA storage.FirewallGroup
	if err := json.Unmarshal(rec.Body.Bytes(), &grupoDeA); err != nil {
		t.Fatalf("decode do grupo criado por A: %v (%s)", err, rec.Body.String())
	}

	// A máquina "em apuros", que é o estado em que uma reversão costuma
	// acontecer: a chain de um grupo qualquer passa a ser recusada no APPLY —
	// o `nft -c` aprova e o comando de verdade falha. A reversão de B restaura
	// o banco e a reconciliação que vem DEPOIS dela não passa, então o
	// pendente fica onde está, marcado como "revertendo".
	exec.refuseApplyIn(w.fwd.ChainName)

	rv := doJSON(t, h.RevertPendingChange, "POST", "/api/nftables/pending/revert",
		`{"id":"`+idDeB+`"}`)
	if rv.Code == http.StatusOK {
		t.Fatalf("a sonda precisa de uma reconciliação que NÃO passa depois da reversão; ela passou: %s", rv.Body.String())
	}

	p, err := db.GetPendingChange()
	if err != nil {
		t.Fatalf("GetPendingChange: %v", err)
	}
	if p == nil {
		t.Fatalf("o pendente tinha que continuar no banco: a reconciliação da reversão falhou, e é ele que mantém o watchdog tentando")
	}
	if !p.Reverting() {
		t.Fatalf("o pendente tinha que estar marcado como revertendo (o banco já foi restaurado): %+v", p)
	}
	// A sonda só mede o que se quer medir se a reversão TIVER misturado: sem
	// preservação não há alvo diferente do snapshot, e o teste passaria por
	// não ter exercitado nada.
	if len(preservedAuditLines(t, db)) == 0 {
		t.Fatalf("a reversão não preservou nada; esta sonda precisa do caminho da MISTURA")
	}

	// 1. O snapshot gravado é o ALVO que a reversão aplicou, e não o de antes:
	//    ele contém o grupo de A, que a mistura deixou de pé.
	var gravado struct {
		Groups []storage.FirewallGroup `json:"groups"`
	}
	if err := json.Unmarshal([]byte(p.Snapshot), &gravado); err != nil {
		t.Fatalf("snapshot gravado ilegível: %v", err)
	}
	temGrupoDeA := false
	for _, g := range gravado.Groups {
		if g.ID == grupoDeA.ID {
			temGrupoDeA = true
		}
	}
	if !temGrupoDeA {
		t.Errorf("o snapshot da janela continua sendo o ANTIGO: ele não contém o grupo %q (%s), que a reversão preservou e deixou no banco — o estado que ele descreve nunca mais vai existir",
			grupoDeA.Name, grupoDeA.ID)
	}

	// 2. E por isso RevertSettled consegue dizer "terminou": é essa resposta
	//    que solta a trava.
	settled, err := fr.RevertSettled(p)
	if err != nil {
		t.Fatalf("RevertSettled: %v", err)
	}
	if !settled {
		t.Errorf("RevertSettled não reconhece a reversão que ACABOU de restaurar o banco: a trava fica fechada para sempre (beco C-6)")
	}

	// 3. O que isso significa para quem está do outro lado da tela, com a
	//    máquina ainda recusando o apply: a mutação seguinte — a que conserta
	//    a máquina — não pode ser recusada pela trava.
	fix := doJSON(t, h.DeleteGroup, "DELETE", "/api/nftables/groups", `{"id":"`+grupoDeA.ID+`"}`)
	if fix.Code == http.StatusConflict {
		t.Errorf("o operador ficou trancado do lado de fora do próprio painel: a mutação que conserta a máquina levou 409 — %s", fix.Body.String())
	}
}

// ─── (M5) A trava relida imediatamente antes do `nft -f` ──────────────────

// O Rollback lê a trava duas vezes: no topo, depois de decodificar o corpo, e
// DE NOVO logo antes de `Service.Restore`. A segunda leitura é a que importa
// aqui, e ela não tem como ser medida por uma janela armada antes da
// requisição — essa a primeira leitura já pega.
//
// A instrumentação usa a única conexão do pool do SQLite (storage.Open faz
// SetMaxOpenConns(1)) como relógio: com ela na mão, o handler não consegue
// executar consulta nenhuma e para no lugar exato onde precisaria dela. Entre
// a primeira leitura da trava e a segunda, o Rollback faz UMA consulta — a
// lista de snapshots —, e é aí que a janela do outro admin é armada, por uma
// segunda conexão ao mesmo arquivo.
//
// Qual das duas mãos pega a conexão livre primeiro é decidido pelo
// database/sql e não dá para escolher, então a sonda repete: em metade das
// tentativas a janela cai ANTES da primeira leitura (e é a primeira que
// recusa), na outra metade ela cai DEPOIS (e só a segunda pode recusar). As
// duas metades exigem a mesma coisa — 409 e nenhum comando no nft —, e é isso
// que o teste afirma em toda tentativa.
//
// VERIFICADO VERMELHO (não é guarda morta) com a segunda leitura da trava
// arrancada de Rollback — 8 execuções em 8 vermelhas, sempre nas três
// primeiras tentativas:
//
//	--- FAIL: TestRollbackRefusesAWindowArmedAfterTheFirstLockRead (0.02s)
//	    tentativa 2: o rollback reescreveu o ruleset por cima da janela de outro admin
//	     em vez de recusar: 200 ({"message":"rollback completed","output":""})
//
// Com a releitura no lugar, 20 execuções com -race, todas verdes.
func TestRollbackRefusesAWindowArmedAfterTheFirstLockRead(t *testing.T) {
	h, db, exec, fr := newGroupTestHandlerFR(t)

	backup := &storage.IptablesBackup{
		Label: "antes-do-incidente",
		Rules: "table inet linkguard {\n\tchain user_rules {\n\t}\n}\n",
	}
	if err := db.CreateIptablesBackup(backup); err != nil {
		t.Fatalf("CreateIptablesBackup: %v", err)
	}
	// O snapshot da janela de B é tirado ANTES do relógio começar: dentro da
	// sonda a única conexão do pool está reservada e nada mais pode consultar.
	snapshot, err := fr.SnapshotState()
	if err != nil {
		t.Fatalf("SnapshotState: %v", err)
	}
	outroAdmin := sameFileDB(t, db)
	pool := db.Conn()

	for tentativa := 1; tentativa <= 24; tentativa++ {
		exec.forgetCommands()
		base := pool.Stats().WaitCount

		gate, err := pool.Conn(context.Background())
		if err != nil {
			t.Fatalf("reservar a única conexão do pool: %v", err)
		}

		resposta := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			resposta <- doJSON(t, h.Rollback, "POST", "/api/nftables/rollback",
				`{"backup_id":"`+backup.ID+`"}`)
		}()
		// O Rollback parou na PRIMEIRA consulta que faz, que é a leitura da
		// trava lá do topo.
		waitForDBWaiters(t, pool, base+1)

		// Uma segunda mão na fila. Ela é o que impede o Rollback de correr até
		// o fim assim que a conexão for solta.
		segunda := make(chan *sql.Conn, 1)
		go func() {
			c, err := pool.Conn(context.Background())
			if err != nil {
				t.Errorf("segunda mão na conexão: %v", err)
			}
			segunda <- c
		}()
		waitForDBWaiters(t, pool, base+2)

		// Soltando: ou a segunda mão pega primeiro (e o Rollback continua
		// parado na primeira leitura da trava), ou o Rollback pega, faz a
		// leitura, devolve a conexão — que vai direto para a segunda mão, que
		// já estava na fila — e para na consulta seguinte, a dos snapshots.
		// Nos dois casos quem termina com a conexão na mão é a segunda.
		gate.Close()
		mao := <-segunda

		// A janela de outro admin é armada AQUI, por fora do pool travado. No
		// segundo caso ela nasce depois da primeira leitura da trava: só a
		// releitura pode vê-la.
		if err := outroAdmin.SavePendingChange(storage.PendingChange{
			ID:        fmt.Sprintf("janela-de-outro-admin-%d", tentativa),
			Snapshot:  snapshot,
			ExpiresAt: time.Now().Add(90 * time.Second),
			AppliedBy: "admin-b",
			Summary:   `edição do grupo "Acesso remoto" (escopo input)`,
		}); err != nil {
			t.Fatalf("tentativa %d: armar a janela do outro admin: %v", tentativa, err)
		}
		if err := mao.Close(); err != nil {
			t.Fatalf("devolver a conexão ao pool: %v", err)
		}

		rec := <-resposta
		if rec.Code != http.StatusConflict {
			t.Fatalf("tentativa %d: o rollback reescreveu o ruleset por cima da janela de outro admin em vez de recusar: %d (%s)",
				tentativa, rec.Code, rec.Body.String())
		}
		if exec.ranWith("nft -f") {
			t.Fatalf("tentativa %d: o rollback foi recusado, mas DEPOIS de o `nft -f` já ter reescrito a tabela inteira: %v",
				tentativa, nftCommands(exec))
		}

		if err := outroAdmin.ClearPendingChange(); err != nil {
			t.Fatalf("limpar a janela entre as tentativas: %v", err)
		}
	}
}

// sameFileDB abre um SEGUNDO handle para o mesmo arquivo do banco — o outro
// admin, que escreve por uma conexão que não é a que a sonda mantém
// reservada. O caminho sai do próprio SQLite para não depender de a fixture
// devolvê-lo.
func sameFileDB(t *testing.T, db *storage.DB) *storage.DB {
	t.Helper()
	var seq int
	var name, file string
	if err := db.Conn().QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &file); err != nil {
		t.Fatalf("PRAGMA database_list: %v", err)
	}
	other, err := storage.Open(file)
	if err != nil {
		t.Fatalf("abrir o segundo handle de %s: %v", file, err)
	}
	t.Cleanup(func() { other.Close() })
	return other
}

// waitForDBWaiters espera até que o pool tenha acumulado `want` pedidos de
// conexão que precisaram esperar. É a prova de que a goroutine que se quer
// medir já chegou na consulta seguinte e parou lá.
func waitForDBWaiters(t *testing.T, pool *sql.DB, want int64) {
	t.Helper()
	limite := time.Now().Add(10 * time.Second)
	for pool.Stats().WaitCount < want {
		if time.Now().After(limite) {
			t.Fatalf("o pool não chegou a %d esperas por conexão (parou em %d): a sonda não está medindo o que acha que mede",
				want, pool.Stats().WaitCount)
		}
		time.Sleep(200 * time.Microsecond)
	}
}

// forgetCommands esquece os comandos que o nft de mentira já executou.
func (f *fakeNft) forgetCommands() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.executed = nil
}
