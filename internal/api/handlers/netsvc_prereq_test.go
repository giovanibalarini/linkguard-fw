package handlers

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// prereqMsg is the sentence the provider produces when the DHCP package is
// absent and could not be installed — package, reason, consequence and the
// manual command, exactly what internal/bootstrapdeps renders.
const prereqMsg = "o pacote kea-dhcp4-server não está instalado e o LinkGuard não conseguiu instalá-lo " +
	"(apt: E: Unable to locate package). kea-dhcp4-server — sem ele não existe servidor DHCP: " +
	"os hosts da LAN não recebem IP. Verifique a conexão com a internet e o repositório APT, " +
	"ou instale à mão: apt-get install -y kea-dhcp4-server"

// prereqNetsvcProvider is a box where the DHCP package is missing and apt
// cannot bring it in.
type prereqNetsvcProvider struct{ fakeNetsvcProvider }

func (prereqNetsvcProvider) ReloadConfigs(context.Context, netsvc.Config, []netsvc.Reservation, []string, string) (netsvc.ApplyResult, error) {
	return netsvc.ApplyResult{}, &netsvc.PrereqError{Msg: prereqMsg}
}

// installingNetsvcProvider is the happy on-demand path: the apply worked
// because LinkGuard installed the package first.
type installingNetsvcProvider struct{ fakeNetsvcProvider }

func (installingNetsvcProvider) ReloadConfigs(context.Context, netsvc.Config, []netsvc.Reservation, []string, string) (netsvc.ApplyResult, error) {
	return netsvc.ApplyResult{Installed: []string{"kea-dhcp4-server"}}, nil
}

func newPrereqTestDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// The reported defect: POST /api/netsvc/apply answered 500 {"error":"erro
// interno do servidor"} on a machine without kea-dhcp4-server. The admin has
// no way to act on that. A missing prerequisite is not an internal error —
// it is the one thing the panel must say out loud (FEATURES.md, "Regra de
// entrega": "se depende de um pré-requisito ausente, diz isso claramente em
// vez de fingir sucesso").
func TestApplyExplainsAMissingPrerequisiteInsteadOfAGenericInternalError(t *testing.T) {
	db := newPrereqTestDB(t)
	h := NewNetsvcHandler(db, prereqNetsvcProvider{}, nil)

	w := httptest.NewRecorder()
	h.Apply(w, httptest.NewRequest("POST", "/api/netsvc/apply", nil))

	if w.Code == 200 {
		t.Fatalf("aplicar sem o pacote não pode responder sucesso: %s", w.Body.String())
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("resposta não é JSON: %v (%s)", err, w.Body.String())
	}
	if strings.Contains(body.Error, "erro interno do servidor") {
		t.Errorf("a resposta continua genérica: %q", body.Error)
	}
	for _, want := range []string{"kea-dhcp4-server", "DHCP", "apt-get install -y"} {
		if !strings.Contains(body.Error, want) {
			t.Errorf("a resposta tem que citar %q, obtive %q", want, body.Error)
		}
	}
}

// The same honesty applies to the debounced auto-apply, which nobody is
// watching: the reason has to survive in the persisted status the DHCP/DNS
// pages render, not only in the journal.
func TestAutoApplyRecordsThePrerequisiteReasonInTheApplyStatus(t *testing.T) {
	db := newPrereqTestDB(t)
	h := NewNetsvcHandler(db, prereqNetsvcProvider{}, nil)

	if err := h.doReload(context.Background()); err == nil {
		t.Fatal("esperava falha de apply sem o pacote")
	}
	st := h.lastApplyStatus()
	if st == nil {
		t.Fatal("esperava um last_apply registrado")
	}
	if st.OK {
		t.Errorf("o apply falhou, o status não pode dizer ok: %+v", st)
	}
	if !strings.Contains(st.Error, "kea-dhcp4-server") {
		t.Errorf("o motivo tem que chegar ao painel, obtive %q", st.Error)
	}
}

// A missing DHCP/DNS package is an ongoing condition, not a firewall rule
// error: it deserves its own alert (like base_deps_missing) so the title
// says what is actually wrong and so it can be closed when it is fixed.
func TestPrerequisiteFailureRaisesItsOwnAlert(t *testing.T) {
	db := newPrereqTestDB(t)
	h := NewNetsvcHandler(db, prereqNetsvcProvider{}, alerts.NewService(db))

	if err := h.doReload(context.Background()); err == nil {
		t.Fatal("esperava falha de apply sem o pacote")
	}

	open, err := db.GetAlerts(true, 50)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	var found *storage.Alert
	for i, a := range open {
		if a.Type == alerts.TypeNetsvcDepsMissing {
			found = &open[i]
		}
		if a.Type == alerts.TypeRuleError {
			t.Errorf("um pacote ausente não é 'Firewall Rule Error': %+v", a)
		}
	}
	if found == nil {
		t.Fatalf("esperava um alerta %s aberto, obtive %+v", alerts.TypeNetsvcDepsMissing, open)
	}
	if !strings.Contains(found.Message, "kea-dhcp4-server") {
		t.Errorf("o alerta tem que dizer o que falta, obtive %q", found.Message)
	}
}

// And it must close itself once LinkGuard manages to install what was
// missing — an alert nothing ever resolves trains the admin to ignore the
// panel (the same reasoning behind BaseDepsOK).
func TestASuccessfulOnDemandInstallClearsTheAlert(t *testing.T) {
	db := newPrereqTestDB(t)
	alertSvc := alerts.NewService(db)

	failing := NewNetsvcHandler(db, prereqNetsvcProvider{}, alertSvc)
	if err := failing.doReload(context.Background()); err == nil {
		t.Fatal("esperava falha de apply sem o pacote")
	}

	fixed := NewNetsvcHandler(db, installingNetsvcProvider{}, alertSvc)
	if err := fixed.doReload(context.Background()); err != nil {
		t.Fatalf("doReload depois de instalar: %v", err)
	}

	open, err := db.GetAlerts(true, 50)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	for _, a := range open {
		if a.Type == alerts.TypeNetsvcDepsMissing {
			t.Errorf("o alerta devia ter sido resolvido depois da instalação: %+v", a)
		}
	}
}

// A plain successful apply (nothing installed, the common case) must not
// spam a recovery alert on every save.
func TestARoutineApplyDoesNotCreateRecoveryNoise(t *testing.T) {
	db := newPrereqTestDB(t)
	h := NewNetsvcHandler(db, fakeNetsvcProvider{}, alerts.NewService(db))

	if err := h.doReload(context.Background()); err != nil {
		t.Fatalf("doReload: %v", err)
	}

	all, err := db.GetAlerts(false, 50)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	if len(all) != 0 {
		t.Errorf("um apply rotineiro não gera alerta nenhum, obtive %+v", all)
	}
}
