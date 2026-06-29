package handlers

import (
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
	if c.Email.Password != "" {
		c.Email.Password = secretMask
	}
	return c
}

// mergeSecrets keeps the existing secret when the client submits the mask (i.e.
// the user did not change it).
func mergeSecrets(incoming, existing notify.Config) notify.Config {
	if incoming.Telegram.Token == secretMask {
		incoming.Telegram.Token = existing.Telegram.Token
	}
	if incoming.Email.Password == secretMask {
		incoming.Email.Password = existing.Email.Password
	}
	return incoming
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
	merged := mergeSecrets(in, h.svc.LoadConfig())
	if err := h.svc.SaveConfig(merged); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
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
	cfg := mergeSecrets(in, h.svc.LoadConfig())
	if err := h.svc.Test(r.Context(), channel, cfg); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	auditAction(h.db, r, "test", "notifications", channel)
	writeJSON(w, http.StatusOK, map[string]bool{"sent": true})
}
