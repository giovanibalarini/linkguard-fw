package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"testing/fstest"

	"github.com/go-chi/chi/v5"
)

// TestMaxBodySizeSkipsBackupRestorePath proves the global maxBodySize
// middleware does not wrap the body for /api/backup/restore, so a body
// between the global default (2MB) and BackupHandler.Restore's own limit
// (32MB) still reaches the handler intact. http.MaxBytesReader nests rather
// than replaces: calling it a second time on an already-wrapped r.Body
// enforces the *smaller* of the two limits, regardless of which was applied
// most recently. If the global middleware wrapped this route too, a body
// like this (well under 32MB, over 2MB) would be rejected — which is
// exactly what this test guards against.
func TestMaxBodySizeSkipsBackupRestorePath(t *testing.T) {
	const globalLimit = 2 << 20   // 2MB, same as the production default
	const handlerLimit = 32 << 20 // 32MB, same as BackupHandler.Restore

	payload := bytes.Repeat([]byte("x"), 5<<20) // 5MB: over global, under handler

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, handlerLimit)
		got, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(got) != len(payload) {
			http.Error(w, "short read", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := maxBodySize(globalLimit)(inner)

	req := httptest.NewRequest(http.MethodPost, backupRestorePath, bytes.NewReader(payload))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for a %d-byte restore body (over the 2MB global cap, under the 32MB handler cap), got %d: %s", len(payload), w.Code, w.Body.String())
	}
}

// TestMaxBodySizeRejectsOverGlobalLimitForOtherPaths confirms the global
// middleware still enforces its cap for every route that doesn't manage its
// own, larger limit.
func TestMaxBodySizeRejectsOverGlobalLimitForOtherPaths(t *testing.T) {
	const globalLimit = 2 << 20
	payload := bytes.Repeat([]byte("x"), 3<<20) // 3MB, over the 2MB global cap

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := maxBodySize(globalLimit)(inner)

	req := httptest.NewRequest(http.MethodPost, "/api/whatever", bytes.NewReader(payload))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a body over the global 2MB cap, got %d", w.Code)
	}
}

// ─── As rotas legadas de iptables não voltam ─────────────────────────────────
//
// POST /api/firewall/backup e POST /api/firewall/rollback foram removidas em
// 2026-08-13, antes do deploy em produção. O rollback legado não tinha trava de
// janela de confirmação, não reconciliava o banco depois, e lia AS MESMAS LINHAS
// da tabela `iptables_backups` que o botão do painel lê. Era inofensivo por
// acidente — o conteúdo gravado hoje é dump do `nft` e o `iptables-restore`
// falha na linha 1 —, mas o backup legado gravava `iptables-save` na MESMA
// tabela, e uma linha nesse formato seria recusada com 400 pelo botão novo e
// APLICADA pela rota legada. `iptables-restore` sem `-n` dá flush em
// `ip filter/nat/mangle`: as chains do Docker.
//
// Este teste lê o código-fonte de propósito. Montar um *Server de verdade aqui
// exigiria as vinte e poucas dependências que o main injeta, e o que precisa ser
// guardado é textual e exato: que ninguém registre estas duas rotas de novo. A
// verificação é por REGISTRO (`Post("…"`), não pela substring do caminho, para
// que o comentário que explica a remoção — e que cita os dois caminhos — não
// faça o teste passar por engano nem falhar por engano.
func TestLegacyIptablesBackupAndRollbackRoutesStayRemoved(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("ReadFile server.go: %v", err)
	}
	for _, path := range []string{"/api/firewall/backup", "/api/firewall/rollback"} {
		if bytes.Contains(src, []byte(`Post("`+path+`"`)) {
			t.Errorf("a rota legada POST %s voltou a ser registrada. Ela dá flush nas chains do Docker (`ip filter/nat/mangle`) sem trava de janela e sem reconciliar; o que faz backup e rollback do firewall é o par /api/nftables/*.", path)
		}
	}
	// E o par que substitui as duas continua de pé — remover a rota errada seria
	// tirar do operador o botão de recuperação.
	for _, path := range []string{"/api/nftables/backup", "/api/nftables/rollback"} {
		if !bytes.Contains(src, []byte(`Post("`+path+`"`)) {
			t.Errorf("POST %s sumiu: é ele que faz backup/rollback do firewall desde a migração para nftables", path)
		}
	}
}

// Mesmo raciocínio, mesma técnica: o DELETE /api/firewall/rules chamava
// iptables.Service.DeleteRule, que — ao contrário do CreateRule e do
// ReplaceRule — não passava por validateTableChain. Aceitava qualquer
// table/chain e apagava regra viva de terceiros: filter/DOCKER-USER derruba o
// isolamento de containers, nat/POSTROUTING derruba o MASQUERADE do Docker.
// Nenhuma tela chamava o verbo; o frontend só faz POST, no assistente de
// balanceamento WAN. O PUT foi junto pelo mesmo motivo de superfície morta.
func TestLegacyIptablesRuleMutationRoutesStayRemoved(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("ReadFile server.go: %v", err)
	}
	for _, verb := range []string{"Put", "Delete"} {
		if bytes.Contains(src, []byte(verb+`("/api/firewall/rules"`)) {
			t.Errorf("a rota legada %s /api/firewall/rules voltou a ser registrada. O DeleteRule do pacote iptables não valida table/chain, então ela apaga regra de outro programa (as chains do Docker); regra de firewall se gerencia por /api/nftables/*.", verb)
		}
	}
	// O POST fica: é ele que o assistente de balanceamento WAN usa, e ele passa
	// por validateTableChain (restrito a mangle/PREROUTING).
	if !bytes.Contains(src, []byte(`Post("/api/firewall/rules"`)) {
		t.Error("POST /api/firewall/rules sumiu: é o que o assistente de balanceamento WAN usa para marcar tráfego em mangle/PREROUTING")
	}
}

// TestWebUICacheHeaders prova a correção do bug que fez a aba Postura não
// aparecer em produção depois do upgrade.
//
// O index.html não tem hash no nome (é sempre "/"), então ele PRECISA ser
// revalidado a cada carga — senão o navegador guarda o antigo e continua
// carregando o bundle antigo depois de um upgrade. Os arquivos sob /assets têm
// o hash do conteúdo no nome e podem ser cacheados para sempre.
func TestWebUICacheHeaders(t *testing.T) {
	// Um FS embutido de mentira com a mesma forma do web/dist: o index e um
	// asset com nome hasheado.
	dist := fstest.MapFS{
		"web/dist/index.html":             {Data: []byte("<!doctype html><div id=root></div>")},
		"web/dist/assets/index-ABC123.js": {Data: []byte("console.log(1)")},
	}
	s := &Server{webFS: dist}
	r := chi.NewRouter()
	s.mountWebUI(r)
	srv := httptest.NewServer(r)
	defer srv.Close()

	casos := []struct {
		path      string
		querCache string
		porque    string
	}{
		{"/", "no-cache", "o index tem de revalidar, senão o upgrade não aparece"},
		{"/firewall", "no-cache", "uma rota da SPA também cai no index e tem de revalidar"},
		{"/assets/index-ABC123.js", "public, max-age=31536000, immutable", "o asset hasheado pode ser cacheado para sempre"},
	}
	for _, c := range casos {
		resp, err := http.Get(srv.URL + c.path)
		if err != nil {
			t.Fatalf("GET %s: %v", c.path, err)
		}
		resp.Body.Close()
		if got := resp.Header.Get("Cache-Control"); got != c.querCache {
			t.Errorf("Cache-Control de %s = %q, queria %q — %s", c.path, got, c.querCache, c.porque)
		}
	}
}
