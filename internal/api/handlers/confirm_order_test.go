package handlers_test

// A ORDEM do confirmar-ou-reverte (Fase C2, spec §5), medida por si.
//
// As dez mutações de grupo e regra repetem, à mão, sempre a mesma sequência:
//
//	validar campos → confirmWindowBlocks (a trava) → resolver o id →
//	pré-voo `nft -c` → anyGroupReachesInput → openConfirmWindow (o arme) →
//	escrever no banco → auditAction → reconcileArmed (o apply)
//
// Toda garantia que a suíte tinha até aqui é INDIRETA: um status HTTP, uma
// linha no banco, um comando no nft de mentira. Nenhum teste afirmava que um
// passo aconteceu ANTES do outro, e é justamente aí que os defeitos deste
// mecanismo moram — trocar duas linhas de lugar num handler não muda status
// nenhum no caminho feliz, e o preço aparece só com um operador trancado para
// fora de uma máquina remota.
//
// Um teste de ordem tem que falhar POR SI: mover a escrita para antes do
// pré-voo, ou o arme para depois do reconcile, tem que ficar vermelho AQUI,
// sem depender de o banco recusar nada nem de o nft ter defeito. É o que os
// ganchos onCheck/onApply do fakeNft compram — eles param o tempo no instante
// exato de cada passo e deixam o teste olhar o mundo:
//
//	onCheck → o instante do pré-voo `nft -c`   (nada pode ter sido escrito)
//	onApply → o instante do primeiro comando de nft de verdade
//	          (a escrita já aconteceu E a janela já tem que estar armada)
//
// E há o caso (b), no fim do arquivo: a mutação SEM janela que atravessa o
// arme de OUTRA. Esse é um bug real, já reproduzido, que continua no código de
// hoje — o teste que o descreve está marcado _KnownBug_ e explicado lá.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// ─── Instrumentação: parar o tempo no meio de uma mutação ─────────────────

// hookCheck e hookApply instalam (ou tiram, com nil) os ganchos de ordem.
// Tomam f.mu porque o falso é compartilhado com a goroutine da requisição;
// o gancho em si já roda com a trava na mão, e por isso ele só pode LER O
// BANCO — chamar qualquer método deste falso de dentro dele trava tudo.
func (f *fakeNft) hookCheck(fn func(script string)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onCheck = fn
}

func (f *fakeNft) hookApply(fn func(cmd string)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onApply = fn
}

// nftCommands é uma cópia de tudo o que o falso executou até agora.
func nftCommands(exec *fakeNft) []string {
	exec.mu.Lock()
	defer exec.mu.Unlock()
	return append([]string{}, exec.executed...)
}

// worldState é o estado que a janela de confirmação guarda e que a reversão
// restaura — grupos e regras, na ordem em que o banco os devolve. Serializado
// para poder ser comparado byte a byte com o de outro instante.
//
// É de propósito o MESMO recorte de firewallrules.stateSnapshot: um teste que
// comparasse menos campos deixaria passar exatamente a escrita que a ordem
// existe para adiar.
func worldState(t *testing.T, db *storage.DB) string {
	t.Helper()
	groups, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatalf("ListFirewallGroups: %v", err)
	}
	rules, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	b, err := json.Marshal(struct {
		Groups []storage.FirewallGroup `json:"groups"`
		Rules  []storage.FirewallRule  `json:"rules"`
	}{groups, rules})
	if err != nil {
		t.Fatalf("serializar o estado: %v", err)
	}
	return string(b)
}

// armedWindowID é o id da janela em aberto neste instante, ou "" quando não há
// nenhuma. Lê o banco direto — é o que o gancho pode fazer sem reentrar em
// nada.
func armedWindowID(t *testing.T, db *storage.DB) string {
	t.Helper()
	p, err := db.GetPendingChange()
	if err != nil {
		t.Fatalf("GetPendingChange: %v", err)
	}
	if p == nil {
		return ""
	}
	return p.ID
}

// snap é o mundo congelado num instante do meio da mutação.
type snap struct {
	fired  bool
	state  string // grupos e regras como estavam
	window string // id da janela armada, "" se não havia
	cmd    string // o comando/script que disparou o gancho
}

// firstOnly devolve um gancho que só registra a PRIMEIRA vez que dispara —
// o pré-voo pode rodar mais de uma vez numa requisição, e o reconcile emite
// muitos comandos; o que interessa é a primeira vez, que é a fronteira.
func firstOnly(t *testing.T, db *storage.DB, into *snap) func(string) {
	t.Helper()
	return func(cmd string) {
		if into.fired {
			return
		}
		into.fired = true
		into.cmd = cmd
		into.state = worldState(t, db)
		into.window = armedWindowID(t, db)
	}
}

// ─── A máquina de teste e as dez mutações ─────────────────────────────────

// orderWorld é um firewall com a cara de um de verdade: um grupo de forward
// com uma regra dentro e um grupo de escopo input com a dele. É o mínimo para
// que reordenar signifique alguma coisa e para que cada uma das dez mutações
// tenha em que mexer.
type orderWorld struct {
	h       *handlers.NftablesHandler
	db      *storage.DB
	exec    *fakeNft
	fr      *firewallrules.Service
	fwd     storage.FirewallGroup
	fwdRule storage.FirewallRule
	in      storage.FirewallGroup
	inRule  storage.FirewallRule
}

func newOrderWorld(t *testing.T) *orderWorld {
	t.Helper()
	h, db, exec, fr := newGroupTestHandlerFR(t)
	w := &orderWorld{h: h, db: db, exec: exec, fr: fr}
	w.fwd = createGroupViaAPI(t, h, db, `{"name":"LAN","cond_saddr":"192.168.3.0/24","fallthrough":"continue"}`)
	w.fwdRule = createRuleViaAPI(t, h, db, `{"group_id":"`+w.fwd.ID+`","action":"drop","saddr":"10.0.0.5"}`)
	w.in = createGroupViaAPI(t, h, db, inputGroupBody)
	confirmWindow(t, h) // a criação do grupo de input abriu a janela dela
	w.inRule = createRuleViaAPI(t, h, db, `{"group_id":"`+w.in.ID+`","action":"accept","proto":"tcp","dport":"22"}`)
	confirmWindow(t, h)
	if p := getPending(t, h); p != nil {
		t.Fatalf("a máquina de teste tinha que começar sem janela aberta: %+v", p)
	}
	return w
}

// mutationCase é uma das dez mutações de grupo e regra, mais o que a ORDEM
// obriga cada uma a fazer:
//
//   - preflight: ela pergunta ao `nft -c` antes de escrever (apagar não
//     pergunta — o nft não recusa a remoção de uma linha — e reordenar
//     tampouco);
//   - opensWindow: ela alcança a chain input nesta máquina e por isso tem que
//     armar a janela ANTES de escrever.
type mutationCase struct {
	name        string
	preflight   bool
	opensWindow bool
	call        func(t *testing.T, w *orderWorld) *httptest.ResponseRecorder
}

func mutationCases() []mutationCase {
	return []mutationCase{
		{
			name: "criar grupo de forward", preflight: true, opensWindow: false,
			call: func(t *testing.T, w *orderWorld) *httptest.ResponseRecorder {
				return doJSON(t, w.h.CreateGroup, "POST", "/api/nftables/groups",
					`{"name":"Visitantes","cond_saddr":"192.168.9.0/24","fallthrough":"continue"}`)
			},
		},
		{
			name: "criar grupo de input", preflight: true, opensWindow: true,
			call: func(t *testing.T, w *orderWorld) *httptest.ResponseRecorder {
				return doJSON(t, w.h.CreateGroup, "POST", "/api/nftables/groups",
					`{"name":"Outro acesso","scope":"input","cond_saddr":"10.0.0.0/24","fallthrough":"continue"}`)
			},
		},
		{
			// A mutação que não arma janela NEM faz pré-voo: aqui a trava é a
			// ÚNICA coisa entre a requisição e a escrita. Nas que armam, o arme
			// serializa por baixo (a tabela de uma linha só) e mascararia uma
			// trava lida tarde demais; nesta, não há máscara nenhuma.
			name: "apagar grupo de forward", preflight: false, opensWindow: false,
			call: func(t *testing.T, w *orderWorld) *httptest.ResponseRecorder {
				return doJSON(t, w.h.DeleteGroup, "DELETE", "/api/nftables/groups", `{"id":"`+w.fwd.ID+`"}`)
			},
		},
		{
			name: "editar grupo de input", preflight: true, opensWindow: true,
			call: func(t *testing.T, w *orderWorld) *httptest.ResponseRecorder {
				return doJSON(t, w.h.UpdateGroup, "PUT", "/api/nftables/groups",
					`{"id":"`+w.in.ID+`","name":"Acesso renomeado","scope":"input","cond_saddr":"192.168.3.0/24","fallthrough":"continue"}`)
			},
		},
		{
			name: "apagar grupo de input", preflight: false, opensWindow: true,
			call: func(t *testing.T, w *orderWorld) *httptest.ResponseRecorder {
				return doJSON(t, w.h.DeleteGroup, "DELETE", "/api/nftables/groups", `{"id":"`+w.in.ID+`"}`)
			},
		},
		{
			name: "desligar grupo de input", preflight: false, opensWindow: true,
			call: func(t *testing.T, w *orderWorld) *httptest.ResponseRecorder {
				return doJSON(t, w.h.ToggleGroup, "POST", "/api/nftables/groups/toggle",
					`{"id":"`+w.in.ID+`","enabled":false}`)
			},
		},
		{
			name: "reordenar grupos com um de input", preflight: false, opensWindow: true,
			call: func(t *testing.T, w *orderWorld) *httptest.ResponseRecorder {
				return doJSON(t, w.h.ReorderGroups, "POST", "/api/nftables/groups/reorder",
					`{"ids":`+reversedGroupIDsJSON(t, w.db)+`}`)
			},
		},
		{
			name: "criar regra em grupo de input", preflight: true, opensWindow: true,
			call: func(t *testing.T, w *orderWorld) *httptest.ResponseRecorder {
				return doJSON(t, w.h.CreateRule, "POST", "/api/nftables/rules",
					`{"group_id":"`+w.in.ID+`","action":"accept","proto":"tcp","dport":"9997"}`)
			},
		},
		{
			name: "editar regra de grupo de input", preflight: true, opensWindow: true,
			call: func(t *testing.T, w *orderWorld) *httptest.ResponseRecorder {
				return doJSON(t, w.h.UpdateRule, "PUT", "/api/nftables/rules",
					`{"id":"`+w.inRule.ID+`","group_id":"`+w.in.ID+`","action":"accept","proto":"tcp","dport":"2222"}`)
			},
		},
		{
			name: "apagar regra de grupo de input", preflight: false, opensWindow: true,
			call: func(t *testing.T, w *orderWorld) *httptest.ResponseRecorder {
				return doJSON(t, w.h.DeleteRule, "DELETE", "/api/nftables/rules", `{"id":"`+w.inRule.ID+`"}`)
			},
		},
		{
			name: "desligar regra de grupo de input", preflight: false, opensWindow: true,
			call: func(t *testing.T, w *orderWorld) *httptest.ResponseRecorder {
				return doJSON(t, w.h.ToggleRule, "POST", "/api/nftables/rules/toggle",
					`{"id":"`+w.inRule.ID+`","enabled":false}`)
			},
		},
		{
			name: "reordenar regras com uma de input", preflight: false, opensWindow: true,
			call: func(t *testing.T, w *orderWorld) *httptest.ResponseRecorder {
				rules, err := w.db.ListFirewallRules()
				if err != nil {
					t.Fatalf("ListFirewallRules: %v", err)
				}
				ids := make([]string, 0, len(rules))
				for i := len(rules) - 1; i >= 0; i-- {
					ids = append(ids, rules[i].ID)
				}
				out, err := json.Marshal(ids)
				if err != nil {
					t.Fatalf("marshal dos ids: %v", err)
				}
				return doJSON(t, w.h.ReorderRules, "POST", "/api/nftables/rules/reorder", `{"ids":`+string(out)+`}`)
			},
		},
	}
}

// ─── (a1) A trava é lida ANTES de qualquer escrita ────────────────────────

// A trava (confirmWindowBlocks) é o primeiro passo depois da validação dos
// campos, e o "antes" dela é o que ela vale: uma mutação recusada não pode ter
// tocado em NADA — nem no banco, nem no firewall vivo.
//
// Por que este teste falha por si, e o 409 sozinho não: com a leitura da trava
// movida para depois da escrita (ou para depois do reconcile), a resposta
// continua sendo 409 — a mutação seria recusada do mesmo jeito, só que depois
// de já ter gravado a linha e reescrito as chains. O status não distingue os
// dois mundos; o estado do banco e a lista de comandos do nft, sim.
//
// A janela aqui é armada direto pelo serviço, e não por uma mutação, de
// propósito: é a única forma de medir a TRAVA isoladamente. Se abrir a janela
// dependesse de uma mutação, um defeito na trava e um defeito no arme ficariam
// indistinguíveis.
//
// VERIFICADO VERMELHO (não é guarda morta): com o confirmWindowBlocks de
// DeleteGroup movido para depois de DeleteFirewallGroup, o subteste "apagar
// grupo de forward" falha em "a mutação foi recusada DEPOIS de escrever no
// banco". O caso de forward é o que prova a trava: nas mutações que ARMAM
// janela, o arme serializa por baixo e mascara a trava lida tarde demais.
func TestTheLockIsReadBeforeAnythingIsWritten(t *testing.T) {
	for _, c := range mutationCases() {
		t.Run(c.name, func(t *testing.T) {
			w := newOrderWorld(t)

			if _, err := w.fr.OpenConfirmWindow(context.Background(), "admin-b",
				`edição do grupo "Acesso remoto" (escopo input)`); err != nil {
				t.Fatalf("armar a janela do outro admin: %v", err)
			}
			antes := worldState(t, w.db)
			comandosAntes := len(nftCommands(w.exec))

			rec := c.call(t, w)
			if rec.Code != http.StatusConflict {
				t.Fatalf("com uma janela aberta, esta mutação tinha que ser recusada com 409; obtive %d (%s)",
					rec.Code, rec.Body.String())
			}
			if depois := worldState(t, w.db); depois != antes {
				t.Errorf("a mutação foi recusada DEPOIS de escrever no banco: a trava tem que ser lida antes de qualquer escrita\nantes:  %s\ndepois: %s",
					antes, depois)
			}
			if cmds := nftCommands(w.exec)[comandosAntes:]; len(cmds) != 0 {
				t.Errorf("a mutação recusada mandou %d comandos ao firewall vivo: %v", len(cmds), cmds)
			}
			// E a janela do outro admin continua inteira: uma mutação recusada
			// não pode ter consumido, apagado nem substituído a rede de proteção
			// de quem está com os 90 segundos correndo.
			if p := getPending(t, w.h); p == nil || p.AppliedBy != "admin-b" {
				t.Errorf("a janela do outro admin foi perdida pela mutação recusada: %+v", p)
			}
		})
	}
}

// ─── (a2) O pré-voo acontece ANTES da escrita ─────────────────────────────

// "Nada chega ao banco antes de o nft aceitar" é a invariante herdada da Fase
// B, e até aqui ela só era afirmada pelo caminho INFELIZ: um corpo que o nft
// recusa não aparece no banco. Esse teste passa igual com a escrita movida
// para antes do pré-voo desde que o handler apague o que gravou — e passa
// igual, sem apagar nada, para toda mutação que o nft ACEITA, que é o caso
// comum.
//
// Aqui a pergunta é feita no caminho FELIZ e no instante certo: no momento em
// que o `nft -c` roda, o banco ainda tem que ser o de antes, byte a byte. Uma
// escrita adiantada fica vermelha mesmo quando a requisição termina em 200.
//
// VERIFICADO VERMELHO: com o CreateFirewallGroup de CreateGroup movido para
// antes do CheckPendingGroups, os subtestes de criar grupo (forward e input)
// falham em "no instante do pré-voo o banco JÁ tinha mudado" — com a
// requisição respondendo 200 normalmente, que é o mundo em que nenhum outro
// teste da suíte enxerga nada.
func TestThePreflightRunsBeforeTheWrite(t *testing.T) {
	for _, c := range mutationCases() {
		if !c.preflight {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			w := newOrderWorld(t)
			antes := worldState(t, w.db)

			var noPrevoo snap
			w.exec.hookCheck(firstOnly(t, w.db, &noPrevoo))
			rec := c.call(t, w)
			w.exec.hookCheck(nil)

			if rec.Code != http.StatusOK {
				t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
			}
			if !noPrevoo.fired {
				t.Fatalf("esta mutação não fez pré-voo `nft -c` nenhum: o firewall que ela produziria nunca foi submetido ao nft")
			}
			if noPrevoo.state != antes {
				t.Errorf("no instante do pré-voo o banco JÁ tinha mudado: a escrita passou na frente do `nft -c`\nantes do pedido: %s\nno pré-voo:      %s",
					antes, noPrevoo.state)
			}
			// E o pré-voo tem que ter validado a mudança PRETENDIDA, não o
			// firewall de hoje: sem isto, mover a escrita para depois de um
			// pré-voo que valida o estado antigo continuaria verde.
			if depois := worldState(t, w.db); depois == antes {
				t.Fatalf("a mutação respondeu 200 sem mudar nada; o teste estaria medindo outra coisa")
			}
		})
	}
}

// O outro lado do mesmo passo: quando o nft RECUSA (a recusa por conteúdo, que
// nenhuma validação de campo alcança), a mutação para ali — 400, banco
// intocado e nenhum comando no firewall vivo.
func TestAPreflightRefusalStopsTheMutationBeforeTheWrite(t *testing.T) {
	w := newOrderWorld(t)
	antes := worldState(t, w.db)
	comandosAntes := len(nftCommands(w.exec))

	for _, c := range []struct {
		name string
		rec  func() *httptest.ResponseRecorder
	}{
		{"grupo de input com condição que o nft recusa", func() *httptest.ResponseRecorder {
			return doJSON(t, w.h.CreateGroup, "POST", "/api/nftables/groups",
				`{"name":"Acesso","scope":"input","cond_iif":"`+nftRefusesToken+`","fallthrough":"continue"}`)
		}},
		{"regra em grupo de input que o nft recusa", func() *httptest.ResponseRecorder {
			return doJSON(t, w.h.CreateRule, "POST", "/api/nftables/rules",
				`{"group_id":"`+w.in.ID+`","action":"accept","iif":"`+nftRefusesToken+`","proto":"tcp","dport":"22"}`)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			rec := c.rec()
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("esperava 400 do pré-voo, obtive %d (%s)", rec.Code, rec.Body.String())
			}
			if depois := worldState(t, w.db); depois != antes {
				t.Errorf("o nft recusou e a linha chegou ao banco assim mesmo\nantes:  %s\ndepois: %s", antes, depois)
			}
			if cmds := nftCommands(w.exec)[comandosAntes:]; len(cmds) != 0 {
				t.Errorf("o nft recusou no pré-voo e o firewall vivo foi tocado assim mesmo: %v", cmds)
			}
			if p := getPending(t, w.h); p != nil {
				t.Errorf("uma mudança que nunca foi aplicada não pode ter janela: %+v", p)
			}
		})
	}
}

// ─── (a3) A janela é armada ANTES da escrita e ANTES do firewall ──────────

// O defeito original da Fase C2 era exatamente este, e ele NÃO aparece no
// caminho feliz por status nenhum: com o arme depois do reconcile, uma mutação
// de escopo input responde 200 com a janela na resposta e o GET a enxerga — só
// que, entre a escrita e o arme, existiu um intervalo em que a regra já valia
// no kernel sem rede de proteção nenhuma. Quem morre nesse intervalo (o
// reconcile que falha, a segunda requisição simultânea) leva a máquina junto.
//
// Este teste olha o instante em que o firewall vivo é tocado pela primeira vez
// e exige que, ali, a janela JÁ exista. É a asserção que fica vermelha se
// alguém mover openConfirmWindow para depois de reconcileArmed — sem precisar
// de nft com defeito, sem concorrência e sem esperar 90 segundos.
//
// VERIFICADO VERMELHO: com o openConfirmWindow de CreateGroup movido para
// depois do reconcileArmed (que é literalmente o defeito original da Fase C2),
// o subteste "criar grupo de input" falha em "o firewall vivo foi tocado
// (\"add chain inet linkguard grp_…\") com a mudança de escopo input SEM
// janela armada" — enquanto a requisição responde 200 com a faixa na resposta
// e todo o resto da suíte segue verde.
func TestTheWindowIsArmedBeforeTheWriteAndBeforeTheFirewallIsTouched(t *testing.T) {
	for _, c := range mutationCases() {
		if !c.opensWindow {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			w := newOrderWorld(t)
			antes := worldState(t, w.db)

			var noPrevoo, noApply snap
			w.exec.hookCheck(firstOnly(t, w.db, &noPrevoo))
			w.exec.hookApply(firstOnly(t, w.db, &noApply))
			rec := c.call(t, w)
			w.exec.hookCheck(nil)
			w.exec.hookApply(nil)

			if rec.Code != http.StatusOK {
				t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
			}
			if pendingOf(t, rec) == nil {
				t.Fatalf("mutação que alcança a chain input respondeu sem janela: %s", rec.Body.String())
			}

			// O arme vem DEPOIS do pré-voo: armar antes de saber que o nft
			// aceita deixaria uma janela para trás em toda mutação inválida,
			// travando a edição por 90 segundos à toa.
			if noPrevoo.fired && noPrevoo.window != "" {
				t.Errorf("a janela já estava armada no pré-voo (%s): o arme tem que vir depois do `nft -c`", noPrevoo.window)
			}
			if noPrevoo.fired && noPrevoo.state != antes {
				t.Errorf("no instante do pré-voo o banco já tinha mudado: %s", noPrevoo.state)
			}

			// E o que este teste existe para exigir: quando o primeiro comando
			// chega ao firewall vivo, a rede de proteção já está armada e a
			// mudança já está no banco.
			if !noApply.fired {
				t.Fatalf("esta mutação não emitiu comando nenhum ao firewall vivo; o teste não mediu nada")
			}
			if noApply.window == "" {
				t.Errorf("o firewall vivo foi tocado (%q) com a mudança de escopo input SEM janela armada: se o reconcile morrer aqui, a regra fica valendo sem reversão automática, sem watchdog e sem trava",
					noApply.cmd)
			}
			if noApply.state == antes {
				t.Errorf("o firewall vivo foi reconstruído antes de a mudança chegar ao banco (o nft passaria a afirmar o que o banco não diz): %q", noApply.cmd)
			}
			// A janela que ficou aberta é a mesma que já estava armada no
			// instante do apply — e não uma segunda, aberta depois.
			p := getPending(t, w.h)
			if p == nil {
				t.Fatalf("a janela sumiu ao fim da mutação")
			}
			if noApply.window != "" && p.ID != noApply.window {
				t.Errorf("a janela do fim (%s) não é a que protegia o apply (%s)", p.ID, noApply.window)
			}
		})
	}
}

// ─── (b) A mutação sem janela intercalada com o arme de OUTRA ─────────────
//
// O CASO, passo a passo (dois admins, um painel só):
//
//	A: POST /api/nftables/groups {"scope":"forward"}      → não abre janela
//	A: passa pela trava (não há janela nenhuma ainda)
//	A: pré-voo `nft -c` ................................. AQUI entra B
//	B: arma a janela dele — e o snapshot que ela guarda é
//	   o estado SEM o grupo de A, porque A ainda não escreveu
//	A: grava o grupo, reconcilia, responde 200 (com a linha criada)
//	B: reverte (ou os 90 segundos vencem, dá no mesmo)
//	→ ReplaceFirewallGroupsAndRules restaura o snapshot de B
//	→ o grupo de A DESAPARECE, sem erro, sem alerta e sem uma linha de
//	  auditoria dizendo que ele foi desfeito
//
// A trava não cobre isto e não tem como cobrir: ela é lida no COMEÇO de A,
// quando ainda não havia janela nenhuma. A serialização de verdade (a tabela de
// uma linha só, sob mutex) protege duas mutações que ABREM janela uma da outra;
// a que não abre atravessa o arme alheio sem tocar em nada que o detecte.
//
// Vale para as duas pontas: qualquer mutação de forward, de port forward, de
// bloqueio por host ou de NTP feita dentro dos 90 segundos de outra pessoa é
// desfeita pela reversão dela — o snapshot cobre `groups` e `rules` inteiros, e
// restaurá-lo é um "volte tudo", não um "desfaça a minha mudança".
//
// ESTA TAREFA NÃO CORRIGE O BUG. Os dois testes abaixo o registram: um diz o
// que TEM que acontecer (e fica vermelho hoje), o outro guarda o
// comportamento de hoje para que a correção não passe despercebida.

// knownBugsEnv liga os testes que descrevem bug conhecido e ainda não
// corrigido. Sem ele o teste é pulado com a explicação inteira — o CI segue
// verde e ninguém precisa decidir se "aquele vermelho" é o de sempre.
const knownBugsEnv = "LINKGUARD_KNOWN_BUGS"

// swallowedByAnotherAdminsRevert roda a sonda inteira e devolve se o grupo de
// A sobreviveu à reversão de B. Compartilhada pelos dois testes para que os
// dois falem, literalmente, do mesmo caminho.
func swallowedByAnotherAdminsRevert(t *testing.T) (grupoDeA storage.FirewallGroup, sobreviveu bool) {
	t.Helper()
	h, db, exec, fr := newGroupTestHandlerFR(t)

	// B arma a janela dele no meio do pré-voo de A. O arme é chamado direto no
	// serviço porque é exatamente o que o handler de B faz neste passo
	// (openConfirmWindow → OpenConfirmWindow, com o snapshot tirado lá dentro);
	// uma segunda requisição HTTP de verdade reentraria no nft de mentira, que
	// está com a trava na mão durante o gancho.
	var idDeB string
	var erroDeB error
	armado := false
	exec.hookCheck(func(string) {
		if armado {
			return
		}
		armado = true
		idDeB, erroDeB = fr.OpenConfirmWindow(context.Background(), "admin-b",
			`edição do grupo "Acesso remoto" (escopo input)`)
	})

	rec := doJSON(t, h.CreateGroup, "POST", "/api/nftables/groups",
		`{"name":"Bloqueio do torrent","cond_saddr":"192.168.3.77","fallthrough":"continue"}`)
	exec.hookCheck(nil)

	if erroDeB != nil {
		t.Fatalf("a janela do admin B não pôde ser armada: %v", erroDeB)
	}
	if !armado {
		t.Fatalf("o gancho do pré-voo não disparou; a sonda não reproduziu nada")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("a mutação de escopo forward de A tinha que ser aceita: %d (%s)", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &grupoDeA); err != nil {
		t.Fatalf("decode do grupo criado por A: %v (%s)", err, rec.Body.String())
	}
	// O 200 de A é verdade neste instante: o grupo está no banco e o jump está
	// na forward viva. É isso que faz o desaparecimento seguinte ser silencioso.
	if !existeNoBanco(t, db, grupoDeA.ID) {
		t.Fatalf("o grupo de A nem chegou ao banco; a sonda não é a que se quer medir")
	}
	if !exec.forwardHasJumpTo(grupoDeA.ChainName) {
		t.Fatalf("o grupo de A não chegou à forward viva; a sonda não é a que se quer medir")
	}

	// B reverte. Podia ser o watchdog aos 90 segundos — o caminho é o mesmo
	// (firewallrules.revert → ReplaceFirewallGroupsAndRules).
	rv := doJSON(t, h.RevertPendingChange, "POST", "/api/nftables/pending/revert", `{"id":"`+idDeB+`"}`)
	if rv.Code != http.StatusOK {
		t.Fatalf("a reversão de B: %d (%s)", rv.Code, rv.Body.String())
	}
	return grupoDeA, existeNoBanco(t, db, grupoDeA.ID)
}

func existeNoBanco(t *testing.T, db *storage.DB, id string) bool {
	t.Helper()
	groups, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatalf("ListFirewallGroups: %v", err)
	}
	for _, g := range groups {
		if g.ID == id {
			return true
		}
	}
	return false
}

// O TESTE QUE DESCREVE O CERTO — e que fica VERMELHO contra o código de hoje.
//
// Como reproduzir:
//
//	LINKGUARD_KNOWN_BUGS=1 go test -race -count=1 \
//	  -run TestAnotherAdminsRevertMustNotSwallowAConcurrentMutation \
//	  ./internal/api/handlers/
//
// O que se vê hoje: "o 200 que o admin A recebeu foi desfeito pela reversão de
// outro admin". A correção é de quem for consertar o mecanismo (as saídas
// possíveis, para o registro: o snapshot deixar de ser um "volte tudo" e virar
// um desfazer cirúrgico; ou a trava passar a valer para TODA mutação e ser
// verificada de novo imediatamente antes da escrita; ou o arme rejeitar a
// abertura enquanto houver mutação em voo). Nenhuma delas cabe aqui: esta
// tarefa é a rede de teste, não o conserto.
func TestAnotherAdminsRevertMustNotSwallowAConcurrentMutation_KnownBug_(t *testing.T) {
	if os.Getenv(knownBugsEnv) == "" {
		t.Skipf(`BUG CONHECIDO E NÃO CORRIGIDO — este teste FALHA de propósito.

Uma mutação que não abre janela (escopo forward, e o mesmo vale para port
forward, bloqueio por host e NTP) pode ser gravada DEPOIS de outro admin ter
armado a janela dele e ANTES de a reversão dessa janela acontecer. O snapshot
da janela alheia não contém essa mudança, e restaurá-lo a apaga: o operador
recebeu 200, viu a regra na tela, e ela some sem erro, sem alerta e sem linha
de auditoria dizendo que foi desfeita.

Para ver o vermelho: %s=1 go test -race -count=1 -run %s ./internal/api/handlers/

Enquanto o bug existir, quem guarda o comportamento de hoje no CI é
TestKnownBug_AConcurrentMutationIsStillSwallowed, logo abaixo: ele fica
vermelho no dia em que a correção entrar, e é o lembrete de apagar este skip.`,
			knownBugsEnv, t.Name())
	}

	g, sobreviveu := swallowedByAnotherAdminsRevert(t)
	if !sobreviveu {
		t.Fatalf("o 200 que o admin A recebeu foi desfeito pela reversão de OUTRO admin: o grupo %q (%s) sumiu do banco porque não estava no snapshot da janela alheia",
			g.Name, g.ID)
	}
}

// O guarda que roda SEMPRE, e que existe por causa da regra "um guarda que
// nunca ficou vermelho é indistinguível de guarda quebrado": ele afirma o
// comportamento de HOJE. Enquanto o bug existir ele fica verde; no dia em que
// alguém corrigir o mecanismo, ele fica vermelho apontando para o teste de
// cima — que é o que passa a valer.
//
// Ele NÃO abençoa o comportamento. É o oposto: é o alarme de que o
// comportamento mudou, num caminho que nenhum teste de status HTTP enxerga.
func TestKnownBug_AConcurrentMutationIsStillSwallowed(t *testing.T) {
	g, sobreviveu := swallowedByAnotherAdminsRevert(t)
	if sobreviveu {
		t.Fatalf(`BOA NOTÍCIA: o grupo %q (%s) sobreviveu à reversão do outro admin — o bug parece corrigido.

Agora: apague este teste e tire o t.Skip de
TestAnotherAdminsRevertMustNotSwallowAConcurrentMutation_KnownBug_ (que passa a
ser o guarda de verdade, rodando sempre).`, g.Name, g.ID)
	}
}

// ─── O que o operador NÃO recebe quando isso acontece ─────────────────────

// A mesma sonda, olhada pelo outro lado: o desaparecimento é SILENCIOSO. Não
// há erro para o admin A (ele já recebeu 200 e foi embora), não há alerta e a
// auditoria fica com a linha `nft.group.add` da criação dele e nada dizendo que
// ela foi desfeita — o histórico afirma uma alteração que já não existe.
//
// Este teste também roda sempre e também descreve o hoje: ele documenta o
// TAMANHO do estrago, que é o que decide a prioridade da correção. Se um dia a
// auditoria passar a registrar o desfazer, ele fica vermelho e é atualizado
// junto com a correção.
func TestKnownBug_TheSwallowedMutationLeavesNoTraceOfBeingUndone(t *testing.T) {
	h, db, exec, fr := newGroupTestHandlerFR(t)

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
		t.Fatalf("a mutação de A: %d (%s)", rec.Code, rec.Body.String())
	}
	if rv := doJSON(t, h.RevertPendingChange, "POST", "/api/nftables/pending/revert",
		`{"id":"`+idDeB+`"}`); rv.Code != http.StatusOK {
		t.Fatalf("a reversão de B: %d (%s)", rv.Code, rv.Body.String())
	}

	logs, err := db.GetAuditLogs(50)
	if err != nil {
		t.Fatalf("GetAuditLogs: %v", err)
	}
	var criacao, desfazer bool
	for _, l := range logs {
		if l.Action == "nft.group.add" && strings.Contains(l.Details, "Bloqueio do torrent") {
			criacao = true
		}
		// A reversão de B registra o desfazer DELA (pending:<id>), não o do
		// grupo de A: nada no histórico liga a criação de A ao sumiço dela.
		if l.Action == "nft.group.del" {
			desfazer = true
		}
	}
	if !criacao {
		t.Fatalf("a criação de A tinha que estar na auditoria: %+v", logs)
	}
	if desfazer {
		t.Fatalf(`BOA NOTÍCIA: a auditoria passou a registrar o desfazer do grupo engolido.

Confira o teste TestKnownBug_AConcurrentMutationIsStillSwallowed e atualize
estes dois junto com a correção.`)
	}
}
