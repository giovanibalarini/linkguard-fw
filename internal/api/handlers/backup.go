package handlers

import (
	"errors"
	"io"
	"net/http"

	"github.com/giovanibalarini/linkguard-fw/internal/backup"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// minPassphraseLen is higher than the 8-char minimum for a user login
// password: a backup file has no 2FA and no login rate-limit behind it — the
// passphrase is the only barrier protecting network topology + host
// inventory if the file leaks.
const minPassphraseLen = 12

// BackupHandler exports and restores the configuration.
type BackupHandler struct {
	db      *storage.DB
	sec     secrets.Secrets
	version string
	sched   *backup.Scheduler
}

// NewBackupHandler creates a BackupHandler. sched is used by SendNow to
// trigger an immediate encrypted backup e-mail — the same code path the
// scheduler's ticker uses.
func NewBackupHandler(db *storage.DB, sec secrets.Secrets, version string, sched *backup.Scheduler) *BackupHandler {
	return &BackupHandler{db: db, sec: sec, version: version, sched: sched}
}

// Export downloads the full configuration, encrypted, as a .lgbak attachment.
func (h *BackupHandler) Export(w http.ResponseWriter, r *http.Request) {
	encrypted, err := backup.EncryptSnapshot(h.db, h.sec, h.version)
	if errors.Is(err, backup.ErrPassphraseNotConfigured) {
		writeError(w, http.StatusBadRequest, "configure uma senha de backup em Configurações → Backup antes de exportar")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	auditAction(h.db, r, "export", "backup", "")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="linkguard-backup.lgbak"`)
	_, _ = w.Write(encrypted)
}

// restoreResult reports what the restore applied.
type restoreResult struct {
	Settings             int      `json:"settings"`
	Reservations         int      `json:"reservations"`
	Blocklist            int      `json:"blocklist"`
	SecretsToReconfigure []string `json:"secrets_to_reconfigure"`
}

// Restore applies settings, DHCP reservations and the DNS blocklist from an
// uploaded, encrypted backup. It does not restart services (the operator
// re-applies DHCP/DNS/firewall afterwards) and does not touch users/roles or
// WAN links, so it can never lock the operator out or disturb live routing.
//
// The passphrase always comes from the request, never from the locally
// configured secret — the main restore scenario is a *different* machine
// than the one that created the backup, so assuming "the local passphrase
// must be the same one" would be wrong more often than right.
func (h *BackupHandler) Restore(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "requisição inválida")
		return
	}
	passphrase := r.FormValue("passphrase")
	if passphrase == "" {
		writeError(w, http.StatusBadRequest, "informe a senha do backup")
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "arquivo de backup ausente")
		return
	}
	defer file.Close()
	ciphertext, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusBadRequest, "não foi possível ler o arquivo")
		return
	}

	data, err := backup.DecryptRestore(ciphertext, passphrase)
	if err != nil {
		writeError(w, http.StatusBadRequest, "senha incorreta ou arquivo inválido")
		return
	}

	var res restoreResult
	for k, v := range data.Settings {
		if err := h.db.SetSetting(k, v); err == nil {
			res.Settings++
		}
	}
	for _, rsv := range data.Reservations {
		if err := h.db.UpsertDHCPReservation(rsv.MAC, rsv.IP, rsv.Hostname); err == nil {
			res.Reservations++
		}
	}
	for _, d := range data.Blocklist {
		if err := h.db.AddDNSBlocklist(d); err == nil {
			res.Blocklist++
		}
	}

	// Secrets are never in the backup file (they live in a separate table
	// ExportSettings never touches), so a restored device must be told which
	// ones it still needs configured by hand. totp_* is deliberately excluded:
	// 2FA is per-user state, not a single "is it configured" toggle, so it
	// can't be represented as one entry in this list.
	knownSecrets := []string{"github_update_token", "notifications", "wireguard"}
	missing := []string{}
	for _, name := range knownSecrets {
		if configured, _ := h.sec.Status(name); !configured {
			missing = append(missing, name)
		}
	}
	res.SecretsToReconfigure = missing

	auditAction(h.db, r, "restore", "backup", "")
	writeJSON(w, http.StatusOK, res)
}

// PassphraseSet configures (or rotates) the backup encryption passphrase.
// Rotating does NOT re-encrypt any backup already sent/downloaded — those
// stay readable only with the passphrase active when they were created.
func (h *BackupHandler) PassphraseSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Passphrase string `json:"passphrase"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "requisição inválida")
		return
	}
	if len(body.Passphrase) < minPassphraseLen {
		writeError(w, http.StatusBadRequest, "a senha precisa ter pelo menos 12 caracteres")
		return
	}
	if err := h.sec.Set(backup.PassphraseSecretName, body.Passphrase); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	auditAction(h.db, r, "set", "backup_passphrase", "")
	writeJSON(w, http.StatusOK, map[string]bool{"configured": true})
}

// PassphraseStatus reports whether a backup passphrase is configured.
func (h *BackupHandler) PassphraseStatus(w http.ResponseWriter, r *http.Request) {
	configured, _ := h.sec.Status(backup.PassphraseSecretName)
	writeJSON(w, http.StatusOK, map[string]bool{"configured": configured})
}

// ScheduleGet returns the current automatic-backup schedule.
func (h *BackupHandler) ScheduleGet(w http.ResponseWriter, r *http.Request) {
	schedule, _ := h.db.GetSetting(backup.ScheduleSettingKey)
	if schedule == "" {
		schedule = backup.ScheduleOff
	}
	writeJSON(w, http.StatusOK, map[string]string{"schedule": schedule})
}

// ScheduleSet updates the automatic-backup schedule. Turning it on (anything
// other than "off") requires a passphrase to already be configured — there's
// nothing to encrypt with otherwise.
func (h *BackupHandler) ScheduleSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Schedule string `json:"schedule"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "requisição inválida")
		return
	}
	switch body.Schedule {
	case backup.ScheduleOff, backup.ScheduleDaily, backup.ScheduleWeekly, backup.ScheduleMonthly:
	default:
		writeError(w, http.StatusBadRequest, "agendamento inválido")
		return
	}
	if body.Schedule != backup.ScheduleOff {
		if configured, _ := h.sec.Status(backup.PassphraseSecretName); !configured {
			writeError(w, http.StatusBadRequest, "configure uma senha de backup antes de ligar o agendamento")
			return
		}
	}
	if err := h.db.SetSetting(backup.ScheduleSettingKey, body.Schedule); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	auditAction(h.db, r, "set", "backup_schedule", body.Schedule)
	writeJSON(w, http.StatusOK, map[string]string{"schedule": body.Schedule})
}

// SendNow triggers an immediate encrypted backup e-mail, using the same
// RunOnce path the scheduler's ticker uses.
func (h *BackupHandler) SendNow(w http.ResponseWriter, r *http.Request) {
	if err := h.sched.RunOnce(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "falha ao enviar backup: "+err.Error())
		return
	}
	auditAction(h.db, r, "send", "backup_email", "")
	writeJSON(w, http.StatusOK, map[string]bool{"sent": true})
}

// LastRun returns the result of the most recent scheduled or manual backup
// send.
func (h *BackupHandler) LastRun(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.sched.LastRunStatus())
}
