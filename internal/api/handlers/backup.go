package handlers

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

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

	mu             sync.Mutex
	failedRestores map[string]*restoreAttempts
	restoreLocks   map[string]*sync.Mutex
}

// restoreAttempts tracks consecutive wrong-passphrase restore attempts for a
// single authenticated user, so a lockout can kick in independently of IP
// (the restore endpoint already requires system.write, so "who" is always
// known — unlike login, which has no user identity to key on yet).
type restoreAttempts struct {
	count     int
	lockUntil time.Time
}

const (
	maxRestoreAttempts = 5
	restoreLockout     = 5 * time.Minute
)

// NewBackupHandler creates a BackupHandler. sched is used by SendNow to
// trigger an immediate encrypted backup e-mail — the same code path the
// scheduler's ticker uses.
func NewBackupHandler(db *storage.DB, sec secrets.Secrets, version string, sched *backup.Scheduler) *BackupHandler {
	return &BackupHandler{
		db: db, sec: sec, version: version, sched: sched,
		failedRestores: map[string]*restoreAttempts{},
		restoreLocks:   map[string]*sync.Mutex{},
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

// Restore applies settings, DHCP reservations and the DNS blocklist from an
// uploaded, encrypted backup. It does not restart services (the operator
// re-applies DHCP/DNS/firewall afterwards) and does not touch users/roles or
// WAN links, so it can never lock the operator out or disturb live routing.
//
// The passphrase always comes from the request, never from the locally
// configured secret — the main restore scenario is a *different* machine
// than the one that created the backup, so assuming "the local passphrase
// must be the same one" would be wrong more often than right.
func (h *BackupHandler) restoreLockedOut(userID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	a := h.failedRestores[userID]
	return a != nil && time.Now().Before(a.lockUntil)
}

func (h *BackupHandler) recordRestoreFailure(userID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	a := h.failedRestores[userID]
	if a == nil {
		a = &restoreAttempts{}
		h.failedRestores[userID] = a
	}
	a.count++
	if a.count >= maxRestoreAttempts {
		a.lockUntil = time.Now().Add(restoreLockout)
		a.count = 0
	}
}

func (h *BackupHandler) resetRestoreAttempts(userID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.failedRestores, userID)
}

// userRestoreLock returns the per-userID mutex that serializes restore
// attempts for that user, creating it on first use.
//
// Without this, "check lockout" -> "decrypt (slow, scrypt)" -> "record
// failure" is a check-then-act sequence split across separate critical
// sections: N concurrent requests from the *same* user can all read
// restoreLockedOut()==false before any of them calls recordRestoreFailure,
// because the decrypt in between is deliberately expensive. That lets an
// attacker fire attempts in parallel and bypass the 5-attempt cap entirely
// (confirmed 0/20 blocked in the Task 11 review).
//
// Holding this lock for the whole check-decrypt-record-apply sequence in
// Restore closes the race: only one in-flight restore per user is ever
// mid-decrypt, so the next one to acquire the lock always observes the
// previous attempt's recorded failure (or lockout) before running its own
// check. Different users get different locks and are not serialized against
// each other — this is not a global restore lock.
func (h *BackupHandler) userRestoreLock(userID string) *sync.Mutex {
	h.mu.Lock()
	defer h.mu.Unlock()
	l := h.restoreLocks[userID]
	if l == nil {
		l = &sync.Mutex{}
		h.restoreLocks[userID] = l
	}
	return l
}

func (h *BackupHandler) Restore(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Serialize per-user: see userRestoreLock for why this is required to
	// close the lockout race, and why it's scoped per-user rather than
	// global.
	lock := h.userRestoreLock(claims.UserID)
	lock.Lock()
	defer lock.Unlock()

	if h.restoreLockedOut(claims.UserID) {
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

	data, err := backup.DecryptRestore(ciphertext, passphrase)
	if err != nil {
		h.recordRestoreFailure(claims.UserID)
		writeError(w, http.StatusBadRequest, "senha incorreta ou arquivo inválido")
		return
	}
	h.resetRestoreAttempts(claims.UserID)

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
