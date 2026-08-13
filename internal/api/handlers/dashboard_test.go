package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/auth"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func newDashboardTestHandler(t *testing.T) (*handlers.DashboardHandler, *storage.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return handlers.NewDashboardHandler(db), db
}

// userWithPermissions cria um papel com exatamente as permissões pedidas e um
// usuário nele — o jeito de montar "o admin de rede" e "o admin de suporte" da
// spec §4.1 sem depender de nenhum papel de fábrica.
func userWithPermissions(t *testing.T, db *storage.DB, username string, perms ...auth.Permission) *storage.User {
	t.Helper()
	keys := make([]string, len(perms))
	for i, p := range perms {
		keys[i] = string(p)
	}
	role := &storage.Role{Name: "Papel de " + username, Permissions: keys}
	if err := db.CreateRole(role); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	u := &storage.User{Username: username}
	if err := db.CreateUser(u, "$2a$10$fakehashfakehashfakehashfakehashfakehashfakehashfa", []string{role.ID}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

func getLayout(t *testing.T, h *handlers.DashboardHandler, u *storage.User) (int, handlers.LayoutResponse) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/layout", nil)
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: u.ID, Username: u.Username}))
	w := httptest.NewRecorder()
	h.GetLayout(w, req)
	var resp handlers.LayoutResponse
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decodificar resposta: %v (corpo: %s)", err, w.Body.String())
		}
	}
	return w.Code, resp
}

// Widget fora da permissão do usuário não volta no layout nem aparece no
// catálogo. O admin de suporte perdeu o hosts.read; o painel que ele já tinha
// salvo continua abrindo, só que sem os widgets de host — sem erro, e sem
// buraco (spec §4.1). Um 403 aqui, ou um item de host vindo assim mesmo, seria
// o painel punindo o operador por uma permissão que outro admin mexeu.
func TestWidgetOutsidePermissionIsNotReturned(t *testing.T) {
	h, db := newDashboardTestHandler(t)
	// Admin de rede: monitoramento e links, SEM hosts.read.
	u := userWithPermissions(t, db, "rede", auth.PermMonitoringRead, auth.PermLinksRead)

	if err := db.SaveDashboardLayout(u.ID, []storage.LayoutItem{
		{Widget: "system_health", X: 0, Y: 0, W: 6, H: 2},
		{Widget: "lan_hosts", X: 6, Y: 0, W: 6, H: 2},
		{Widget: "wan_links", X: 0, Y: 2, W: 6, H: 2},
		{Widget: "top_talkers", X: 6, Y: 2, W: 6, H: 2},
	}); err != nil {
		t.Fatalf("salvar: %v", err)
	}

	code, resp := getLayout(t, h, u)
	if code != http.StatusOK {
		t.Fatalf("esperava 200 (o painel abre), obtive %d", code)
	}
	if len(resp.Items) != 2 {
		t.Fatalf("esperava 2 itens (os que ele pode ver), obtive %d: %+v", len(resp.Items), resp.Items)
	}
	for _, it := range resp.Items {
		if it.Widget == "lan_hosts" || it.Widget == "top_talkers" {
			t.Errorf("widget %q exige hosts.read, que este usuário não tem, e voltou mesmo assim", it.Widget)
		}
	}

	// E nem para adicionar: o catálogo que o painel oferece a ele não pode
	// listar um widget que ele não tem permissão de ver.
	available := map[string]bool{}
	for _, name := range resp.Available {
		available[name] = true
	}
	if available["lan_hosts"] || available["top_talkers"] {
		t.Errorf("os widgets de host não podiam aparecer no catálogo dele: %v", resp.Available)
	}
	if !available["system_health"] || !available["wan_links"] {
		t.Errorf("os widgets que ele pode ver sumiram do catálogo: %v", resp.Available)
	}
}

// O layout que o PUT grava é o do usuário autenticado, e o GET devolve o dele —
// o corpo da requisição não escolhe usuário. Sem isto, "cada admin monta o seu"
// dependeria do cliente pedir o usuário certo.
func TestSaveLayoutIsScopedToTheAuthenticatedUser(t *testing.T) {
	h, db := newDashboardTestHandler(t)
	rede := userWithPermissions(t, db, "rede", auth.PermMonitoringRead, auth.PermLinksRead)
	suporte := userWithPermissions(t, db, "suporte", auth.PermMonitoringRead, auth.PermHostsRead)

	body, _ := json.Marshal(handlers.LayoutRequest{Items: []storage.LayoutItem{
		{Widget: "wan_links", X: 0, Y: 0, W: 12, H: 3},
	}})
	req := httptest.NewRequest(http.MethodPut, "/api/dashboard/layout", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: rede.ID, Username: rede.Username}))
	w := httptest.NewRecorder()
	h.SaveLayout(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("salvar: esperava 200, obtive %d: %s", w.Code, w.Body.String())
	}

	code, resp := getLayout(t, h, rede)
	if code != http.StatusOK || len(resp.Items) != 1 || resp.Items[0].Widget != "wan_links" {
		t.Fatalf("o usuário que salvou tinha que reler o que salvou, obtive %d %+v", code, resp.Items)
	}

	// O outro admin não foi tocado: continua no padrão de fábrica.
	code, outro := getLayout(t, h, suporte)
	if code != http.StatusOK {
		t.Fatalf("ler o outro: %d", code)
	}
	if len(outro.Items) == 1 && outro.Items[0].Widget == "wan_links" {
		t.Error("salvar o painel de um admin sobrescreveu o do outro")
	}
}

// Item que aponta para widget inexistente é descartado item a item também na
// GRAVAÇÃO, e o resto é salvo. Um 400 aqui travaria o operador: uma aba antiga
// aberta com um widget que a versão nova removeu deixaria de conseguir salvar
// qualquer arrasto.
func TestSaveDropsUnknownWidgetsInsteadOfRejectingTheWholeLayout(t *testing.T) {
	h, db := newDashboardTestHandler(t)
	u := userWithPermissions(t, db, "rede", auth.PermMonitoringRead, auth.PermLinksRead)

	body, _ := json.Marshal(handlers.LayoutRequest{Items: []storage.LayoutItem{
		{Widget: "system_health", X: 0, Y: 0, W: 6, H: 2},
		{Widget: "widget_de_uma_versao_futura", X: 6, Y: 0, W: 6, H: 2},
		{Widget: "wan_links", X: 0, Y: 2, W: 12, H: 2},
	}})
	req := httptest.NewRequest(http.MethodPut, "/api/dashboard/layout", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: u.ID, Username: u.Username}))
	w := httptest.NewRecorder()
	h.SaveLayout(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("esperava 200 com o item ruim descartado, obtive %d: %s", w.Code, w.Body.String())
	}

	_, resp := getLayout(t, h, u)
	if len(resp.Items) != 2 {
		t.Fatalf("esperava os 2 itens válidos gravados, obtive %+v", resp.Items)
	}
}

// Erro de banco é 500 e não vaza SQL nem detalhe do driver — dívida conhecida
// do projeto que esta entrega não amplia. E nunca 400: o cliente não fez nada
// errado.
func TestDatabaseErrorIs500WithoutRawSQL(t *testing.T) {
	h, db := newDashboardTestHandler(t)
	u := userWithPermissions(t, db, "rede", auth.PermMonitoringRead)
	db.Close() // toda consulta a partir daqui falha

	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/layout", nil)
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: u.ID, Username: u.Username}))
	w := httptest.NewRecorder()
	h.GetLayout(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("esperava 500, obtive %d: %s", w.Code, w.Body.String())
	}
	corpo := strings.ToLower(w.Body.String())
	for _, vazamento := range []string{"select", "insert", "dashboard_layout", "sqlite"} {
		if strings.Contains(corpo, vazamento) {
			t.Errorf("a resposta de erro vazou %q: %s", vazamento, w.Body.String())
		}
	}
}

// Sem sessão não há layout: o handler depende do usuário autenticado, e sem
// claims a resposta é 401 — nunca o painel de outra pessoa.
func TestLayoutWithoutClaimsIsUnauthorized(t *testing.T) {
	h, _ := newDashboardTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/layout", nil)
	w := httptest.NewRecorder()
	h.GetLayout(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("esperava 401, obtive %d", w.Code)
	}
}
