package handlers_test

import (
	"bytes"
	"encoding/json"
	"github.com/giovanibalarini/linkguard-fw/internal/dashboard"
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

// grantPermissions concede permissões NOVAS a um usuário que já existe, sem
// tirar as que ele tinha — é o "outro admin te deu hosts.read depois" da spec
// §4.1, o momento em que os widgets escondidos têm que reaparecer.
func grantPermissions(t *testing.T, db *storage.DB, u *storage.User, perms ...auth.Permission) {
	t.Helper()
	keys := make([]string, len(perms))
	for i, p := range perms {
		keys[i] = string(p)
	}
	role := &storage.Role{Name: "Papel extra de " + u.Username, Permissions: keys}
	if err := db.CreateRole(role); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	ids, err := db.GetUserRoleIDs(u.ID)
	if err != nil {
		t.Fatalf("GetUserRoleIDs: %v", err)
	}
	if err := db.SetUserRoles(u.ID, append(ids, role.ID)); err != nil {
		t.Fatalf("SetUserRoles: %v", err)
	}
}

func putLayout(t *testing.T, h *handlers.DashboardHandler, u *storage.User, items []dashboard.LayoutItem) (int, handlers.LayoutResponse) {
	t.Helper()
	body, err := json.Marshal(handlers.LayoutRequest{Items: items})
	if err != nil {
		t.Fatalf("serializar corpo: %v", err)
	}
	req := httptest.NewRequest(http.MethodPut, "/api/dashboard/layout", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: u.ID, Username: u.Username}))
	w := httptest.NewRecorder()
	h.SaveLayout(w, req)
	var resp handlers.LayoutResponse
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decodificar resposta: %v (corpo: %s)", err, w.Body.String())
		}
	}
	return w.Code, resp
}

// itemDoWidget acha um item pelo nome do widget na lista, para as asserções de
// posição ficarem legíveis.
func itemDoWidget(items []dashboard.LayoutItem, widget string) (dashboard.LayoutItem, bool) {
	for _, it := range items {
		if it.Widget == widget {
			return it, true
		}
	}
	return dashboard.LayoutItem{}, false
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

	if err := db.SaveDashboardLayout(u.ID, []dashboard.LayoutItem{
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

	body, _ := json.Marshal(handlers.LayoutRequest{Items: []dashboard.LayoutItem{
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

	body, _ := json.Marshal(handlers.LayoutRequest{Items: []dashboard.LayoutItem{
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

// O ARRASTO DE QUEM NÃO VÊ TUDO NÃO APAGA O QUE ELE NÃO VÊ.
//
// Este é o defeito que a entrega corrige. O GET devolve o layout já filtrado por
// permissão, e a tela manda de volta exatamente o que leu: sem a fusão na
// escrita, o primeiro arrasto do admin sem hosts.read gravava a lista reduzida
// por cima da linha, e os widgets de host sumiam PARA SEMPRE — quando a
// permissão fosse concedida depois, o catálogo os oferecia de novo, mas a
// posição que ele tinha montado já não existia.
func TestSaveKeepsStoredWidgetsTheCallerCannotSee(t *testing.T) {
	h, db := newDashboardTestHandler(t)
	// Admin de rede: monitoramento e links, SEM hosts.read.
	u := userWithPermissions(t, db, "rede", auth.PermMonitoringRead, auth.PermLinksRead)

	// O painel que ele tinha, montado quando ele ainda via tudo (ou montado por
	// outro admin antes de a permissão ser tirada).
	if err := db.SaveDashboardLayout(u.ID, []dashboard.LayoutItem{
		{Widget: "system_health", X: 0, Y: 0, W: 6, H: 2},
		{Widget: "lan_hosts", X: 6, Y: 0, W: 6, H: 2},
		{Widget: "wan_links", X: 0, Y: 2, W: 6, H: 2},
		{Widget: "top_talkers", X: 6, Y: 2, W: 6, H: 3},
	}); err != nil {
		t.Fatalf("salvar: %v", err)
	}

	// Ele arrasta: a tela manda de volta só o que ela leu, que é só o que ele vê.
	code, resp := putLayout(t, h, u, []dashboard.LayoutItem{
		{Widget: "wan_links", X: 0, Y: 0, W: 12, H: 2},
		{Widget: "system_health", X: 0, Y: 2, W: 12, H: 2},
	})
	if code != http.StatusOK {
		t.Fatalf("salvar: esperava 200, obtive %d", code)
	}
	// A resposta continua sendo só o que ele enxerga: o item preservado não pode
	// vazar de volta para a tela dele.
	if len(resp.Items) != 2 {
		t.Fatalf("a resposta tinha que ter os 2 itens visíveis, obtive %+v", resp.Items)
	}
	for _, it := range resp.Items {
		if it.Widget == "lan_hosts" || it.Widget == "top_talkers" {
			t.Errorf("widget fora da permissão vazou na resposta do PUT: %q", it.Widget)
		}
	}

	// O que ficou GRAVADO (sem filtro de permissão): os widgets de host
	// sobreviveram ao arrasto dele.
	gravado, err := db.GetDashboardLayout(u.ID)
	if err != nil {
		t.Fatalf("reler o gravado: %v", err)
	}
	if _, ok := itemDoWidget(gravado, "lan_hosts"); !ok {
		t.Fatalf("lan_hosts foi apagado por um admin que nem podia vê-lo: %+v", gravado)
	}
	if _, ok := itemDoWidget(gravado, "top_talkers"); !ok {
		t.Fatalf("top_talkers foi apagado por um admin que nem podia vê-lo: %+v", gravado)
	}

	// E agora outro admin concede hosts.read: os widgets voltam, NA POSIÇÃO QUE
	// TINHAM. Voltar recolocado no rodapé seria a mesma perda, só mais discreta.
	grantPermissions(t, db, u, auth.PermHostsRead)
	code, resp = getLayout(t, h, u)
	if code != http.StatusOK {
		t.Fatalf("ler depois da permissão: %d", code)
	}
	hosts, ok := itemDoWidget(resp.Items, "lan_hosts")
	if !ok {
		t.Fatalf("lan_hosts não voltou depois do hosts.read: %+v", resp.Items)
	}
	if hosts.X != 6 || hosts.Y != 0 || hosts.W != 6 || hosts.H != 2 {
		t.Errorf("lan_hosts voltou fora do lugar: %+v (esperava x=6 y=0 w=6 h=2)", hosts)
	}
	talkers, ok := itemDoWidget(resp.Items, "top_talkers")
	if !ok {
		t.Fatalf("top_talkers não voltou depois do hosts.read: %+v", resp.Items)
	}
	if talkers.X != 6 || talkers.Y != 2 || talkers.W != 6 || talkers.H != 3 {
		t.Errorf("top_talkers voltou fora do lugar: %+v (esperava x=6 y=2 w=6 h=3)", talkers)
	}
}

// A fusão preserva o que já estava gravado; ela NÃO é porta de entrada. Um PUT
// que tente gravar um widget fora da permissão de quem chama não o grava — nem
// como item novo, nem "restaurando" um que nunca esteve lá.
func TestSaveCannotWriteWidgetOutsideTheCallersPermission(t *testing.T) {
	h, db := newDashboardTestHandler(t)
	u := userWithPermissions(t, db, "rede", auth.PermMonitoringRead, auth.PermLinksRead)

	// O painel gravado dele NÃO tem widget de host nenhum — assim o que
	// aparecer depois só pode ter vindo do corpo da requisição. (Sem isto o
	// teste ficaria ambíguo: quem nunca salvou parte do layout de fábrica, que
	// já traz top_talkers, e a fusão preserva esse item de propósito.)
	if err := db.SaveDashboardLayout(u.ID, []dashboard.LayoutItem{
		{Widget: "system_health", X: 0, Y: 0, W: 6, H: 2},
		{Widget: "wan_links", X: 6, Y: 0, W: 6, H: 2},
	}); err != nil {
		t.Fatalf("salvar: %v", err)
	}

	code, resp := putLayout(t, h, u, []dashboard.LayoutItem{
		{Widget: "wan_links", X: 0, Y: 0, W: 6, H: 2},
		{Widget: "lan_hosts", X: 6, Y: 0, W: 6, H: 2},
		{Widget: "top_talkers", X: 0, Y: 2, W: 12, H: 3},
	})
	if code != http.StatusOK {
		t.Fatalf("salvar: esperava 200 com os itens fora da permissão descartados, obtive %d", code)
	}
	if len(resp.Items) != 1 || resp.Items[0].Widget != "wan_links" {
		t.Fatalf("a resposta tinha que trazer só o widget que ele pode ver, obtive %+v", resp.Items)
	}

	gravado, err := db.GetDashboardLayout(u.ID)
	if err != nil {
		t.Fatalf("reler o gravado: %v", err)
	}
	for _, proibido := range []string{"lan_hosts", "top_talkers"} {
		if _, ok := itemDoWidget(gravado, proibido); ok {
			t.Errorf("o PUT gravou %q, que o chamador não tem permissão de ver: %+v", proibido, gravado)
		}
	}
}

// O CAMINHO NORMAL NÃO PODE QUEBRAR: quem enxerga tudo continua substituindo o
// layout inteiro, INCLUSIVE removendo o widget que tirou do painel. Uma fusão
// feita errado ressuscita o que o admin removeu de propósito — e aí o widget
// volta sozinho a cada abertura, sem ele conseguir se livrar dele.
func TestSaveStillRemovesWidgetsTheCallerCanSee(t *testing.T) {
	h, db := newDashboardTestHandler(t)
	u := userWithPermissions(t, db, "geral", auth.PermMonitoringRead, auth.PermLinksRead, auth.PermHostsRead)

	if err := db.SaveDashboardLayout(u.ID, []dashboard.LayoutItem{
		{Widget: "system_health", X: 0, Y: 0, W: 6, H: 2},
		{Widget: "lan_hosts", X: 6, Y: 0, W: 6, H: 2},
		{Widget: "wan_links", X: 0, Y: 2, W: 6, H: 2},
	}); err != nil {
		t.Fatalf("salvar: %v", err)
	}

	// Ele tira "Hosts na rede" do painel e rearranja o resto.
	code, resp := putLayout(t, h, u, []dashboard.LayoutItem{
		{Widget: "system_health", X: 0, Y: 0, W: 12, H: 2},
		{Widget: "wan_links", X: 0, Y: 2, W: 12, H: 2},
	})
	if code != http.StatusOK {
		t.Fatalf("salvar: esperava 200, obtive %d", code)
	}
	if _, ok := itemDoWidget(resp.Items, "lan_hosts"); ok {
		t.Fatalf("o widget que ele removeu voltou na resposta: %+v", resp.Items)
	}

	gravado, err := db.GetDashboardLayout(u.ID)
	if err != nil {
		t.Fatalf("reler o gravado: %v", err)
	}
	if _, ok := itemDoWidget(gravado, "lan_hosts"); ok {
		t.Fatalf("o widget que ele removeu continuou gravado: %+v", gravado)
	}
	if len(gravado) != 2 {
		t.Fatalf("esperava exatamente os 2 itens que ele deixou, obtive %+v", gravado)
	}
	saude, _ := itemDoWidget(gravado, "system_health")
	if saude.W != 12 {
		t.Errorf("o rearranjo dele não foi gravado: %+v", saude)
	}
}

// "Restaurar padrão" continua sendo a saída de quem se perdeu arrastando: apaga
// a linha e devolve JÁ o layout de fábrica, filtrado pelo que o usuário pode
// ver, sem uma segunda ida ao servidor (spec §6).
func TestResetLayoutRestoresTheFactoryDefault(t *testing.T) {
	h, db := newDashboardTestHandler(t)
	u := userWithPermissions(t, db, "rede", auth.PermMonitoringRead, auth.PermLinksRead)

	if err := db.SaveDashboardLayout(u.ID, []dashboard.LayoutItem{
		{Widget: "quick_actions", X: 0, Y: 0, W: 12, H: 3},
	}); err != nil {
		t.Fatalf("salvar: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/dashboard/layout", nil)
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: u.ID, Username: u.Username}))
	w := httptest.NewRecorder()
	h.ResetLayout(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("restaurar: esperava 200, obtive %d: %s", w.Code, w.Body.String())
	}
	var resp handlers.LayoutResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decodificar resposta: %v", err)
	}
	if _, ok := itemDoWidget(resp.Items, "quick_actions"); ok {
		t.Errorf("o layout customizado continuou depois do restaurar: %+v", resp.Items)
	}
	if _, ok := itemDoWidget(resp.Items, "system_health"); !ok {
		t.Errorf("o padrão de fábrica não voltou na resposta do DELETE: %+v", resp.Items)
	}
	// E o padrão volta filtrado: ele não tem hosts.read.
	if _, ok := itemDoWidget(resp.Items, "top_talkers"); ok {
		t.Errorf("o DELETE devolveu um widget fora da permissão dele: %+v", resp.Items)
	}

	// A leitura seguinte também é o padrão: a linha foi apagada mesmo.
	code, depois := getLayout(t, h, u)
	if code != http.StatusOK {
		t.Fatalf("ler depois do restaurar: %d", code)
	}
	if _, ok := itemDoWidget(depois.Items, "quick_actions"); ok {
		t.Errorf("a linha não foi apagada: %+v", depois.Items)
	}
	if _, ok := itemDoWidget(depois.Items, "system_health"); !ok {
		t.Errorf("a leitura depois do restaurar não trouxe o padrão: %+v", depois.Items)
	}
}
