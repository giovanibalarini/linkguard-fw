package handlers

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/giovanibalarini/linkguard-fw/internal/auth"
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
	// limiter é a trava contra força bruta na senha do backup, por usuário
	// autenticado. O handler a segura porque a identidade ("quem tentou") é
	// dele; a mecânica da trava é de internal/backup.
	limiter *backup.RestoreLimiter
}

// NewBackupHandler creates a BackupHandler. sched is used by SendNow to
// trigger an immediate encrypted backup e-mail — the same code path the
// scheduler's ticker uses.
func NewBackupHandler(db *storage.DB, sec secrets.Secrets, version string, sched *backup.Scheduler) *BackupHandler {
	return &BackupHandler{
		db: db, sec: sec, version: version, sched: sched,
		limiter: backup.NewRestoreLimiter(),
	}
}

// Export downloads the full configuration, encrypted, as a .lgbak attachment.
func (h *BackupHandler) Export(w http.ResponseWriter, r *http.Request) {
	encrypted, err := backup.EncryptSnapshot(h.db, h.sec, h.version)
	if errors.Is(err, backup.ErrPassphraseNotConfigured) {
		writeError(w, http.StatusBadRequest, "configure uma senha de backup em Configurações → Backup antes de exportar")
		return
	}
	if err != nil {
		writeInternalError(w, err)
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

// Restore applies an uploaded, encrypted backup.
//
// O que este handler faz é só o que é de HTTP: autenticação, ler o multipart
// dentro do limite de tamanho, e traduzir o erro do domínio em status. As
// regras da restauração em si — validar cada blob, pular o estado local da
// máquina, gravar as três coleções numa transação e a trava por tentativas —
// moram em internal/backup (ver backup.Restore), do mesmo lado da fronteira
// que o Snapshot que as gerou.
func (h *BackupHandler) Restore(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// A trava é consultada antes de ler o corpo para preservar a ordem das
	// respostas: quem está trancado recebe 429 mesmo mandando um multipart
	// inválido ou um arquivo acima do limite, e não um 400 que esconderia a
	// trava. Esta leitura é só o atalho; a checagem que decide roda dentro de
	// backup.Restore, com o mutex do usuário na mão (ver RestoreLimiter).
	if h.limiter.LockedOut(claims.UserID) {
		writeError(w, http.StatusTooManyRequests, "muitas tentativas com senha incorreta. Tente novamente em alguns minutos.")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 32<<20)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "requisição inválida ou arquivo maior que 32MB")
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

	applied, err := backup.Restore(h.db, h.limiter, claims.UserID, ciphertext, passphrase)
	switch {
	case errors.Is(err, backup.ErrLockedOut):
		writeError(w, http.StatusTooManyRequests, "muitas tentativas com senha incorreta. Tente novamente em alguns minutos.")
		return
	case errors.Is(err, backup.ErrBadPassphrase):
		writeError(w, http.StatusBadRequest, "senha incorreta ou arquivo inválido")
		return
	case err != nil:
		var invalidBackup *backup.ValidationError
		if errors.As(err, &invalidBackup) {
			// O domínio recusou o arquivo antes de gravar qualquer coisa; a
			// mensagem já diz qual campo e por quê.
			writeError(w, http.StatusBadRequest, invalidBackup.Error())
			return
		}
		slog.Error("restore de backup falhou; nada foi gravado", "err", err)
		writeError(w, http.StatusInternalServerError,
			"falha ao gravar a restauração — nada foi restaurado; o banco está como estava antes")
		return
	}

	res := restoreResult{
		Settings:     applied.Settings,
		Reservations: applied.Reservations,
		Blocklist:    applied.Blocklist,
	}

	// Secrets are never in the backup file (they live in a separate table
	// ExportSettings never touches), so a restored device must be told which
	// ones it still needs configured by hand. totp_* is deliberately excluded:
	// 2FA is per-user state, not a single "is it configured" toggle, so it
	// can't be represented as one entry in this list.
	knownSecrets := []string{"github_update_token", "notifications"}
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
		writeInternalError(w, err)
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
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "set", "backup_schedule", body.Schedule)
	writeJSON(w, http.StatusOK, map[string]string{"schedule": body.Schedule})
}

// SendNow triggers an immediate encrypted backup e-mail, using the same
// RunOnce path the scheduler's ticker uses.
func (h *BackupHandler) SendNow(w http.ResponseWriter, r *http.Request) {
	if err := h.sched.RunOnce(r.Context()); err != nil {
		writeInternalError(w, fmt.Errorf("falha ao enviar backup: %w", err))
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
