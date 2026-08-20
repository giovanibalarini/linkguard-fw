package handlers

import (
	"net/http"

	"github.com/giovanibalarini/linkguard-fw/internal/ddns"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// DDNSHandler expõe o DNS dinâmico por link (#129).
type DDNSHandler struct {
	db  *storage.DB
	svc *ddns.Service
	sec secrets.Secrets
}

// NewDDNSHandler cria o handler.
func NewDDNSHandler(db *storage.DB, svc *ddns.Service, sec secrets.Secrets) *DDNSHandler {
	return &DDNSHandler{db: db, svc: svc, sec: sec}
}

// ddnsView é o que a tela mostra: a configuração de um link e o resultado da
// última tentativa, lado a lado.
//
// Os dois juntos porque separados eles enganam: configuração sem resultado diz
// o que o admin PEDIU, e é exatamente o que ele já sabe. O que ele não sabe é
// se funcionou.
type ddnsView struct {
	ddns.Config
	State ddns.State `json:"state"`
	// LinkName e Interface vêm junto para a tela não precisar cruzar listas.
	LinkName  string `json:"link_name"`
	Interface string `json:"interface"`
	// SecretSet diz se há segredo guardado, sem devolvê-lo.
	SecretSet bool `json:"secret_set"`
}

// List devolve uma linha por link WAN, configurado ou não.
func (h *DDNSHandler) List(w http.ResponseWriter, r *http.Request) {
	links, err := h.db.GetLinks()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	cfgs, err := h.svc.Configs()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	estados, _ := h.svc.States()

	out := make([]ddnsView, 0, len(links))
	for _, l := range links {
		c := cfgs[l.ID]
		c.LinkID = l.ID
		set := false
		if h.sec != nil {
			set, _ = h.sec.Status(ddns.SecretName(l.ID))
		}
		out = append(out, ddnsView{
			Config: c, State: estados[l.ID],
			LinkName: l.Name, Interface: l.Interface, SecretSet: set,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// Save grava a configuração de um link e, se veio, o segredo.
func (h *DDNSHandler) Save(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ddns.Config
		// Secret vem só quando o admin digita um novo. Vazio significa
		// "mantenha o que está guardado" — sem isso, abrir a tela e salvar
		// qualquer outro campo apagaria o token, e a atualização passaria a
		// falhar com "badauth" sem ninguém ter mexido nele.
		Secret string `json:"secret"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	if err := h.svc.SaveConfig(b.Config); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if b.Secret != "" && h.sec != nil {
		if err := h.sec.Set(ddns.SecretName(b.LinkID), b.Secret); err != nil {
			writeInternalError(w, err)
			return
		}
		// Token novo republica: o anterior pode ter sido revogado, e o estado
		// guardado diria "atualizado" para sempre sem nada ter sido publicado.
		h.svc.ClearState(b.LinkID)
	}
	auditAction(h.db, r, "ddns.config", "ddns", b.LinkID)
	writeJSON(w, http.StatusOK, map[string]bool{"saved": true})
}

// CheckNow força uma verificação, para o admin não esperar o ciclo de cinco
// minutos só para saber se o que ele acabou de configurar funciona.
func (h *DDNSHandler) CheckNow(w http.ResponseWriter, r *http.Request) {
	h.svc.CheckOnce(r.Context())
	estados, _ := h.svc.States()
	auditAction(h.db, r, "ddns.check", "ddns", "")
	writeJSON(w, http.StatusOK, estados)
}
