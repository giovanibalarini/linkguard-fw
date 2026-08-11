package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/auth"
	"github.com/giovanibalarini/linkguard-fw/internal/backup"
	"github.com/giovanibalarini/linkguard-fw/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-fw/internal/monitoring"
	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/timesync"
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

// ─── Restore-time validation (input-validation-audit.md finding #1) ──────────
//
// ExportSettings dumps every row of the settings table with no filtering
// (that's deliberate — see its own doc comment — secrets simply never live
// there). Restore used to write every one of those rows straight back with
// db.SetSetting(k, v), with no validator in between: a crafted or corrupted
// .lgbak file could put anything at all into netsvc_config or the DNS
// blocklist, both of which reach a root daemon's config file
// (unbound.conf/kea-dhcp4.conf) by string concatenation elsewhere in this
// codebase (see internal/keaunbound.GenerateUnboundConfig, which now also
// defends itself independently — see that function's own fix — but restore
// is the entry point that made the gap reachable in practice, since it is
// the one place these values can land in the DB with no handler in front of
// them at all).
//
// knownSettingsValidators maps the settings keys this restore path
// recognizes as structured config with an existing, reusable validator to a
// function that parses+validates a raw settings value and returns a
// (nil-safe) error describing why it was rejected. Every key NOT in this
// map is restored exactly as before this fix — see the Restore doc comment
// for why that's a deliberate choice, not an oversight.
var knownSettingsValidators = map[string]func(raw string) error{
	netsvcCfgKey:          validateNetsvcConfigRestore,
	ntpCfgKey:             validateNTPConfigRestore,
	monitoringSettingsKey: validateMonitoringConfigRestore,
}

// machineLocalSettingKeys are the settings rows that describe the state of
// *this* machine rather than the operator's configuration, and therefore
// must never be written by a restore — a backup file is a configuration
// document, not a snapshot of another box's runtime.
//
// They are skipped silently (counted and logged, not rejected): a backup
// legitimately produced by Export always carries them — ExportSettings
// dumps the whole settings table — so refusing the file would make every
// real backup unrestorable. "This doesn't travel" is the right semantics,
// not "this is invalid".
//
//   - nft_live_snapshot: read at bootstrap (cmd/linkguard-fw/main.go) and
//     handed to `nft -f` as root with a "flush ruleset" prepended. Restoring
//     it would let a backup file redefine the destination firewall in full,
//     including on a fresh install — the documented restore scenario, where
//     EnsureTable reports a new table and the snapshot IS loaded (C-2).
//   - firewall_rules_imported: the one-time-import latch. BackupData has no
//     field for the firewall rules themselves, so restoring the latch writes
//     "already imported" onto a machine that received no rules: the next
//     boot skips ImportOnce and ReconcileUserRules empties the live
//     user_rules chain against an empty table (C-3).
//     TODO: firewall_rules ainda não é exportado no backup; incluí-las é
//     feature à parte (ver Crítico 3 da revisão final).
//   - firewall_rules_apply / netsvc_last_apply: results of an apply that
//     happened on the source machine. Restored, the panel would report a
//     success (or failure) that never took place here.
var machineLocalSettingKeys = map[string]bool{
	nftables.LiveSnapshotSettingKey:  true,
	firewallrules.ImportedSettingKey: true,
	firewallrules.ApplyStatusKey:     true,
	netsvcApplyStatusKey:             true,
}

// monitoringSettingsKey mirrors internal/monitoring's own unexported
// configKey ("monitoring"). Duplicated as a literal rather than imported:
// that constant is unexported, and this package already depends on
// internal/monitoring only for its exported Config type below — reaching
// for a private identifier just to spell one settings key isn't worth
// exporting it from a package that has no other reason to expose it.
const monitoringSettingsKey = "monitoring"

// validateNetsvcConfigRestore parses a netsvc_config settings blob and runs
// every field through the same checks NetsvcHandler.UpdateDHCPConfig and
// UpdateDNSConfig apply to an admin-submitted value (see netsvc.go) — same
// validIface/validDomain calls, same net.ParseIP/ParseCIDR checks, field
// for field. A value accepted here is exactly as injection-safe against
// unbound.conf/kea-dhcp4.conf as one that came in through the panel.
func validateNetsvcConfigRestore(raw string) error {
	var cfg netsvc.Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return fmt.Errorf("netsvc_config: JSON inválido: %w", err)
	}
	if cfg.Interface != "" && !validIface(cfg.Interface) {
		return fmt.Errorf("netsvc_config: interface inválida: %q", cfg.Interface)
	}
	if cfg.SubnetCIDR != "" {
		if _, _, err := net.ParseCIDR(cfg.SubnetCIDR); err != nil {
			return fmt.Errorf("netsvc_config: sub-rede (subnet_cidr) inválida: %q", cfg.SubnetCIDR)
		}
	}
	for _, v := range []string{cfg.RangeStart, cfg.RangeEnd, cfg.Gateway} {
		if v != "" && net.ParseIP(v) == nil {
			return fmt.Errorf("netsvc_config: endereço IP inválido: %q", v)
		}
	}
	if cfg.DomainSuffix != "" && !validDomain(cfg.DomainSuffix) {
		return fmt.Errorf("netsvc_config: domínio (domain_suffix) inválido: %q", cfg.DomainSuffix)
	}
	for _, d := range cfg.DNSToClients {
		if d != "" && net.ParseIP(d) == nil {
			return fmt.Errorf("netsvc_config: DNS (dns_to_clients) inválido: %q", d)
		}
	}
	for _, u := range cfg.Upstreams {
		if u != "" && net.ParseIP(u) == nil {
			return fmt.Errorf("netsvc_config: upstream inválido: %q", u)
		}
	}
	return nil
}

// validateNTPConfigRestore parses an ntp_config settings blob and runs it
// through the same checks NTPHandler.UpdateNTPConfig applies (see ntp.go):
// validNTPServer per server, timesync.ValidateAllowedNetworks for the
// list — including its own "no open wildcard" guard. Timezone is
// deliberately NOT validated here: UpdateNTPConfig itself accepts it as
// free text today (input-validation-audit.md finding #12, a lower-severity,
// separate gap this fix does not close) — mirroring "the same validation
// the API applies" means mirroring that gap too, not inventing a new,
// stricter rule restore alone would enforce.
func validateNTPConfigRestore(raw string) error {
	var cfg timesync.Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return fmt.Errorf("ntp_config: JSON inválido: %w", err)
	}
	for _, srv := range cfg.Servers {
		if srv != "" && !validNTPServer(srv) {
			return fmt.Errorf("ntp_config: servidor NTP inválido: %q", srv)
		}
	}
	if err := timesync.ValidateAllowedNetworks(cfg.AllowedNetworks); err != nil {
		return fmt.Errorf("ntp_config: %w", err)
	}
	return nil
}

// validateMonitoringConfigRestore parses a monitoring settings blob into its
// typed struct. MonitoringHandler.SetConfig applies no field-level
// validation today (input-validation-audit.md finding #10, a separate,
// lower-severity gap this fix does not close) — so "the same validation the
// API applies" is, honestly, just the structural JSON check below. This is
// still worth doing: it rejects a blob whose shape doesn't match
// monitoring.Config at all (e.g. "services" sent as an object instead of an
// array) instead of writing a value LoadConfig would then have to silently
// paper over.
func validateMonitoringConfigRestore(raw string) error {
	var cfg monitoring.Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return fmt.Errorf("monitoring: JSON inválido: %w", err)
	}
	return nil
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

	// Validate the entire payload before writing anything — see the
	// knownSettingsValidators doc comment above for what's checked and why,
	// and for the explicit decision on settings keys not in that map
	// (restored as-is, unchanged from before this fix). A backup that fails
	// here leaves the DB exactly as it was: nothing below this point runs
	// unless every check above it passed.
	for k, v := range data.Settings {
		if validate, ok := knownSettingsValidators[k]; ok {
			if err := validate(v); err != nil {
				writeError(w, http.StatusBadRequest, "backup contém "+k+" inválido — nada foi restaurado: "+err.Error())
				return
			}
		}
	}
	normalizedBlocklist := make([]string, 0, len(data.Blocklist))
	for _, d := range data.Blocklist {
		nd := strings.ToLower(strings.TrimSpace(d))
		if !validDomain(nd) {
			writeError(w, http.StatusBadRequest, "backup contém domínio de bloqueio inválido — nada foi restaurado: "+d)
			return
		}
		normalizedBlocklist = append(normalizedBlocklist, nd)
	}
	normalizedReservations := make([]storage.DHCPReservation, 0, len(data.Reservations))
	for _, rsv := range data.Reservations {
		mac := normalizeMAC(rsv.MAC)
		if mac == "" {
			writeError(w, http.StatusBadRequest, "backup contém reserva DHCP com MAC inválido — nada foi restaurado: "+rsv.MAC)
			return
		}
		ip := strings.TrimSpace(rsv.IP)
		if net.ParseIP(ip) == nil {
			writeError(w, http.StatusBadRequest, "backup contém reserva DHCP com IP inválido — nada foi restaurado: "+rsv.IP)
			return
		}
		normalizedReservations = append(normalizedReservations, storage.DHCPReservation{MAC: mac, IP: ip, Hostname: rsv.Hostname})
	}

	var res restoreResult
	skippedLocal := 0
	for k, v := range data.Settings {
		if machineLocalSettingKeys[k] {
			// Machine state, not configuration — see
			// machineLocalSettingKeys for what each one would do to this
			// box if it were restored.
			skippedLocal++
			continue
		}
		if err := h.db.SetSetting(k, v); err == nil {
			res.Settings++
		}
	}
	if skippedLocal > 0 {
		slog.Info("restore de backup: chaves de estado local da máquina ignoradas",
			"ignoradas", skippedLocal, "restauradas", res.Settings)
	}
	for _, rsv := range normalizedReservations {
		if err := h.db.UpsertDHCPReservation(rsv.MAC, rsv.IP, rsv.Hostname); err == nil {
			res.Reservations++
		}
	}
	for _, d := range normalizedBlocklist {
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
