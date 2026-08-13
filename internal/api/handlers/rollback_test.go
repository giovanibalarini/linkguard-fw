package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// ─── Rollback (I-1) ─────────────────────────────────────────────────────────
//
// Restore writes a stored ruleset snapshot straight into nft via `nft -f`,
// bypassing the DB-authoritative model entirely (design spec §4.1): right
// after a rollback, the live user_rules chain would hold whatever the
// snapshot happened to contain, disagreeing with the DB's own rule rows
// until the next unrelated mutation silently re-renders over it. Rollback
// must reconcile user_rules from the DB immediately afterwards, the same as
// every other mutation, so the panel and the firewall never disagree.

func TestRollbackReconcilesGroupsFromDBAfterRestoring(t *testing.T) {
	h, db, exec := newFirewallRulesTestHandler(t)

	g := newRuleGroup(t, db)
	row := &storage.FirewallRule{GroupID: g.ID, Action: "accept", Saddr: "10.0.0.55"}
	if err := db.CreateFirewallRule(row); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}

	backup := &storage.IptablesBackup{Label: "antes-do-incidente", Rules: "table inet linkguard {\n\tchain user_rules {\n\t}\n}\n"}
	if err := db.CreateIptablesBackup(backup); err != nil {
		t.Fatalf("CreateIptablesBackup: %v", err)
	}
	exec.executed = nil

	req := httptest.NewRequest("POST", "/api/nftables/rollback", strings.NewReader(mustJSON(t, map[string]any{"backup_id": backup.ID})))
	w := httptest.NewRecorder()
	h.Rollback(w, req)
	if w.Code != 200 {
		t.Fatalf("Rollback: status %d, body %s", w.Code, w.Body.String())
	}

	found := false
	for _, c := range exec.executed {
		if strings.Contains(c, "10.0.0.55") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the rollback to reconcile the admin's groups from the DB afterwards (the DB rule's content must be re-rendered), ran: %v", exec.executed)
	}
}

func mustJSON(t *testing.T, m map[string]any) string {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// M-3 da revisão final — o rollback é a operação que mais briga com uma reversão
// em andamento: ele reescreve o RULESET INTEIRO (`flush ruleset` dentro de
// Service.Restore) e, até aqui, era a única mutação que não consultava a trava
// da janela de confirmação. Disparado no meio dos 90 segundos, ele escreve por
// cima do que o watchdog acabou de impor, e a reconciliação que viria depois
// falha em silêncio — slog.Warn e HTTP 200 na tela.
func TestRollbackIsRefusedWhileAConfirmWindowIsOpen(t *testing.T) {
	h, db, exec, fr := newGroupTestHandlerFR(t)

	backup := &storage.IptablesBackup{Label: "antes-do-incidente", Rules: "table inet linkguard {\n}\n"}
	if err := db.CreateIptablesBackup(backup); err != nil {
		t.Fatalf("CreateIptablesBackup: %v", err)
	}
	if _, err := fr.OpenConfirmWindow(context.Background(), "admin", "grupo de escopo input aplicado"); err != nil {
		t.Fatalf("abrir a janela: %v", err)
	}

	w := doJSON(t, h.Rollback, "POST", "/api/nftables/rollback", `{"backup_id":"`+backup.ID+`"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("o rollback tinha que ser recusado com a janela aberta: status %d, body %s", w.Code, w.Body.String())
	}
	// E a recusa não pode ter tocado no firewall vivo: `nft -f` é o comando com
	// que Restore aplica o snapshot inteiro.
	if exec.ranWith("nft -f") {
		t.Error("o rollback recusado chegou a reescrever o ruleset")
	}
}

// A OUTRA METADE da trava, e a que impede que ela vire um beco sem saída (N-2):
// no estado "revertendo" com o estado anterior JÁ de volta ao banco, a trava
// LIBERA — o banco é a verdade do produto e o trabalho da reversão terminou nele;
// o que falta é o nft aceitar, e toda mutação seguinte também reconcilia.
//
// Se o rollback travasse aqui, ele recriaria exatamente o beco que custou caro
// consertar nas mutações de grupo e regra: numa máquina cujo reconcile não passa,
// restaurar um snapshot bom é uma das poucas saídas que sobram ao operador, e ela
// não pode estar trancada justamente pela reversão que não consegue terminar.
func TestRollbackIsAllowedOnceTheRevertHasSettledInTheDB(t *testing.T) {
	h, db, exec, fr := newGroupTestHandlerFR(t)

	backup := &storage.IptablesBackup{Label: "antes-do-incidente", Rules: "table inet linkguard {\n\tchain user_rules {\n\t}\n}\n"}
	if err := db.CreateIptablesBackup(backup); err != nil {
		t.Fatalf("CreateIptablesBackup: %v", err)
	}
	// Janela aberta e marcada como revertendo, com o banco intocado desde o
	// snapshot: é a definição de "a reversão já terminou na camada que manda"
	// (firewallrules.RevertSettled), o estado em que a máquina fica quando o
	// nft recusa e o watchdog não consegue concluir.
	id := openWindow(t, fr)
	if err := db.MarkPendingReverting(id, time.Now()); err != nil {
		t.Fatalf("MarkPendingReverting: %v", err)
	}

	w := doJSON(t, h.Rollback, "POST", "/api/nftables/rollback", `{"backup_id":"`+backup.ID+`"}`)
	if w.Code == http.StatusConflict {
		t.Fatalf("o rollback foi travado por uma reversão que já terminou no banco — é o beco sem saída de volta: %s", w.Body.String())
	}
	if w.Code != http.StatusOK {
		t.Fatalf("Rollback: status %d, body %s", w.Code, w.Body.String())
	}
	if !exec.ranWith("nft -f") {
		t.Errorf("o rollback passou pela trava mas não chegou a restaurar nada: %v", exec.executed)
	}
}

// A reconciliação que falha DEPOIS do restore não pode responder 200.
//
// O que era: `slog.Warn` no journal e "Ruleset restaurado." na tela, com o
// firewall vivo sendo o conteúdo do snapshot e as regras do banco — as que o
// painel mostra — fora dele. Um rollback que responde "pronto" e deixa o
// firewall diferente do que a tela afirma é a mesma classe de mentira que este
// projeto vem eliminando (o Persist mudo, §10 da validação em VM).
func TestRollbackReportsAReconcileThatFailedAfterRestoring(t *testing.T) {
	h, db, exec, _ := newGroupTestHandlerFR(t)

	// A máquina com defeito: um grupo com regra que passa no `nft -c` e é
	// recusada no apply — a categoria de falha que faz o Reconcile devolver erro.
	g := createGroupViaAPI(t, h, db, `{"name":"LAN","cond_saddr":"192.168.3.0/24","fallthrough":"continue"}`)
	createRuleViaAPI(t, h, db, `{"group_id":"`+g.ID+`","action":"drop","saddr":"10.0.0.5"}`)
	exec.refuseApplyIn(g.ChainName)

	backup := &storage.IptablesBackup{Label: "antes-do-incidente", Rules: "table inet linkguard {\n\tchain user_rules {\n\t}\n}\n"}
	if err := db.CreateIptablesBackup(backup); err != nil {
		t.Fatalf("CreateIptablesBackup: %v", err)
	}

	w := doJSON(t, h.Rollback, "POST", "/api/nftables/rollback", `{"backup_id":"`+backup.ID+`"}`)
	if w.Code == http.StatusOK {
		t.Fatalf("o rollback respondeu sucesso com as regras do banco fora do firewall: %s", w.Body.String())
	}
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("esperava 500, obtive %d (%s)", w.Code, w.Body.String())
	}
	// E a mensagem tem que dizer o que ficou valendo — o snapshot —, não o
	// genérico "erro interno do servidor", que mandaria o operador procurar
	// defeito no LinkGuard sem saber em que estado o firewall dele ficou.
	body := w.Body.String()
	if !strings.Contains(body, backup.Label) || !strings.Contains(body, "reaplicadas") {
		t.Errorf("a resposta não diz o que aconteceu com o firewall: %s", body)
	}
}

// Um snapshot que não contém a tabela `inet linkguard` (gravado antes de ela
// existir, ou vindo de outra máquina) tem que ser RECUSADO, com o motivo na
// tela. Antes do escopo, ele era o pior caso do `flush ruleset`: apagava o
// ruleset inteiro da máquina — a nossa tabela e as de terceiros — e carregava
// no lugar um snapshot que não tem firewall nenhum do LinkGuard dentro.
func TestRollbackRefusesASnapshotWithoutOurTable(t *testing.T) {
	h, db, exec, _ := newGroupTestHandlerFR(t)

	// Saída REAL do nft 1.1.3 para uma máquina que só tem a tabela do Docker.
	semNossaTabela := "table ip docker {\n" +
		"\tchain postrouting {\n" +
		"\t\ttype nat hook postrouting priority srcnat; policy accept;\n" +
		"\t\tip saddr 172.17.0.0/16 oifname != \"docker0\" masquerade\n" +
		"\t}\n}\n"
	backup := &storage.IptablesBackup{Label: "de-outra-maquina", Rules: semNossaTabela}
	if err := db.CreateIptablesBackup(backup); err != nil {
		t.Fatalf("CreateIptablesBackup: %v", err)
	}
	exec.executed = nil

	w := doJSON(t, h.Rollback, "POST", "/api/nftables/rollback", `{"backup_id":"`+backup.ID+`"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("esperava 400 para um snapshot sem a nossa tabela, obtive %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "inet linkguard") {
		t.Errorf("a resposta não diz por que o snapshot não serve: %s", w.Body.String())
	}
	if exec.ranWith("nft -f") {
		t.Errorf("a recusa chegou a tocar no firewall: %v", exec.executed)
	}
}

// Um snapshot cuja chain `input` traz política restritiva tem que ser RECUSADO
// com 400, e o firewall não pode ser tocado.
//
// A invariante: a chain `input` nasce e permanece com `policy accept`; bloqueio
// se faz por regra explícita, nunca por política. A razão é operacional — uma
// política restritiva trancaria o operador para fora de um firewall em produção,
// possivelmente de madrugada e sem acesso físico. O produto nunca emite
// `policy drop`, então isto não chega por snapshot gerado por nós; o Restore é o
// único caminho que aplica firewall que o produto não gerou (linha editada à
// mão, backup de outra máquina), e portanto a única porta de entrada.
//
// 400 e não 500 pelo mesmo motivo do teste acima: o LinkGuard está são, é o
// snapshot que não serve. Um 500 genérico mandaria o operador procurar defeito
// no produto em vez de escolher outro snapshot.
func TestRollbackRefusesASnapshotWithARestrictiveInputPolicy(t *testing.T) {
	h, db, exec, _ := newGroupTestHandlerFR(t)

	// Saída REAL do nft 1.1.3 (`unshare -rn` + `nft list ruleset`), com a única
	// diferença que importa: `policy drop` na chain input.
	trancado := "table inet linkguard {\n" +
		"\tchain input {\n" +
		"\t\ttype filter hook input priority filter; policy drop;\n" +
		"\t\tct state established,related accept\n" +
		"\t\ttcp dport 22 accept comment \"SSH do admin (nao remover) }\"\n" +
		"\t}\n\n" +
		"\tchain forward {\n" +
		"\t\ttype filter hook forward priority filter; policy accept;\n" +
		"\t}\n}\n"
	backup := &storage.IptablesBackup{Label: "editado-a-mao", Rules: trancado}
	if err := db.CreateIptablesBackup(backup); err != nil {
		t.Fatalf("CreateIptablesBackup: %v", err)
	}
	exec.executed = nil

	w := doJSON(t, h.Rollback, "POST", "/api/nftables/rollback", `{"backup_id":"`+backup.ID+`"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("esperava 400 para um snapshot com `policy drop` na input, obtive %d (%s)", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, backup.Label) || !strings.Contains(body, "policy drop") {
		t.Errorf("a resposta não nomeia o snapshot nem o motivo: %s", body)
	}
	if exec.ranWith("nft -f") {
		t.Errorf("a recusa chegou a tocar no firewall: %v", exec.executed)
	}
}

// E a contraprova: um snapshot LEGÍTIMO continua sendo aplicado. Recusar o que é
// válido tiraria do operador a única ferramenta de recuperação que ele tem numa
// máquina que só alcança pela rede — seria pior que o defeito.
func TestRollbackStillAcceptsASnapshotWithPolicyAccept(t *testing.T) {
	h, db, exec, _ := newGroupTestHandlerFR(t)

	legitimo := "table inet linkguard {\n" +
		"\tchain input {\n" +
		"\t\ttype filter hook input priority filter; policy accept;\n" +
		"\t\tct state established,related accept\n" +
		"\t\ttcp dport 22 accept comment \"type filter hook input priority filter; policy drop;\"\n" +
		"\t}\n\n" +
		"\tchain forward {\n" +
		"\t\ttype filter hook forward priority filter; policy accept;\n" +
		"\t}\n}\n"
	backup := &storage.IptablesBackup{Label: "bom", Rules: legitimo}
	if err := db.CreateIptablesBackup(backup); err != nil {
		t.Fatalf("CreateIptablesBackup: %v", err)
	}
	exec.executed = nil

	w := doJSON(t, h.Rollback, "POST", "/api/nftables/rollback", `{"backup_id":"`+backup.ID+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("um snapshot legítimo foi recusado (%d): %s", w.Code, w.Body.String())
	}
	if !exec.ranWith("nft -f") {
		t.Errorf("o snapshot legítimo tinha que ter sido aplicado: %v", exec.executed)
	}
}
