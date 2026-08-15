package handlers

import (
	"fmt"
	"net/http"

	"github.com/giovanibalarini/linkguard-fw/internal/notify"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

const secretMask = "********"

// NotifyHandler manages external notification channels (webhook/Telegram/email).
type NotifyHandler struct {
	db  *storage.DB
	svc *notify.Service
}

// NewNotifyHandler creates a NotifyHandler.
func NewNotifyHandler(db *storage.DB, svc *notify.Service) *NotifyHandler {
	return &NotifyHandler{db: db, svc: svc}
}

// redactOut masks stored secrets so they are never sent to the browser, while
// signalling that a value is set (so the UI can show "•••• configurado").
func redactOut(c notify.Config) notify.Config {
	if c.Telegram.Token != "" {
		c.Telegram.Token = secretMask
	}
	if c.WhatsApp.Token != "" {
		c.WhatsApp.Token = secretMask
	}
	if c.Email.Password != "" {
		c.Email.Password = secretMask
	}
	return c
}

// mergeSecrets keeps the existing secret when the client submits the mask (i.e.
// the user did not change it).
//
// A máscara só é remontada quando o DESTINO submetido é o mesmo que estava
// gravado. Sem essa amarra, o segredo redigido na leitura voltava a ser real do
// lado do servidor mesmo quando o host tinha sido trocado na mesma requisição —
// e o Test então conectava no host novo carregando a credencial antiga. Um
// system.write que nunca conseguiu LER a senha do SMTP conseguia fazê-la sair
// pela rede, via AUTH PLAIN, para um servidor dele.
//
// É a mesma defesa que o WhatsApp já tinha por outro caminho: lá o host não é
// editável (ver o comentário em notify.WhatsAppCfg). Aqui o host é editável por
// necessidade, então a amarra é explícita. Trocar de servidor SMTP continua
// possível: basta mandar a senha nova junto, em vez da máscara.
//
// A máscara que não pode ser remontada nunca é gravada como se fosse a senha:
// mergeSecrets devolve erro, e o handler responde 400 pedindo o segredo. Aceitar
// "********" em silêncio trocaria uma falha de segurança por um canal de
// notificação quebrado sem aviso.
func mergeSecrets(incoming, existing notify.Config) (notify.Config, error) {
	// O host do Telegram é fixo (api.telegram.org), então o chat_id é o que
	// determina para onde a mensagem vai — e o token viaja na URL.
	if incoming.Telegram.Token == secretMask {
		if incoming.Telegram.ChatID != existing.Telegram.ChatID {
			return incoming, errSecretNeedsRetyping("o chat do Telegram mudou", "o token")
		}
		incoming.Telegram.Token = existing.Telegram.Token
	}
	// O host do WhatsApp não é configurável; o telefone é o destino.
	if incoming.WhatsApp.Token == secretMask {
		if incoming.WhatsApp.Phone != existing.WhatsApp.Phone {
			return incoming, errSecretNeedsRetyping("o telefone do WhatsApp mudou", "o token")
		}
		incoming.WhatsApp.Token = existing.WhatsApp.Token
	}
	if incoming.Email.Password == secretMask {
		if incoming.Email.Host != existing.Email.Host ||
			incoming.Email.Port != existing.Email.Port ||
			incoming.Email.Username != existing.Email.Username {
			return incoming, errSecretNeedsRetyping("o servidor SMTP mudou", "a senha")
		}
		incoming.Email.Password = existing.Email.Password
	}
	return incoming, nil
}

func errSecretNeedsRetyping(whatChanged, secret string) error {
	return fmt.Errorf("%s, então %s guardada não é reaproveitada — digite %s do destino novo", whatChanged, secret, secret)
}

// Get returns the notification config with secrets redacted.
func (h *NotifyHandler) Get(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, redactOut(h.svc.LoadConfig()))
}

// Update persists the notification config (preserving unchanged secrets).
func (h *NotifyHandler) Update(w http.ResponseWriter, r *http.Request) {
	var in notify.Config
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	merged, err := mergeSecrets(in, h.svc.LoadConfig())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.svc.SaveConfig(merged); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "update", "notifications", "")
	writeJSON(w, http.StatusOK, redactOut(merged))
}

// Test sends a sample message to one channel using the submitted config (with
// any masked secret resolved from storage).
func (h *NotifyHandler) Test(w http.ResponseWriter, r *http.Request) {
	channel := r.URL.Query().Get("channel")
	var in notify.Config
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	cfg, err := mergeSecrets(in, h.svc.LoadConfig())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.svc.Test(r.Context(), channel, cfg); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	auditAction(h.db, r, "test", "notifications", channel)
	writeJSON(w, http.StatusOK, map[string]bool{"sent": true})
}
