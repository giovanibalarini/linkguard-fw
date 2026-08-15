package auth

import (
	"encoding/json"
	"errors"
	"log/slog"
)

// Two-factor (TOTP) state is stored per user in the secrets vault: key
// "totp_<userID>" → {secret, enabled}.
//
// An enrollment in progress lives under a SEPARATE key, "totp_pending_<userID>",
// and never under the active one. That separation is a security boundary, not
// tidiness: while the pending secret shared the active key, calling
// BeginTwoFASetup on an account that already had 2FA on overwrote the active
// state with enabled=false — a silent disable, reachable by anyone holding the
// user's token, and a way around DisableTwoFA's "prove possession first" rule.
// With two keys, setup cannot reach the active state at all.

type twoFAState struct {
	Secret  string `json:"secret"`
	Enabled bool   `json:"enabled"`
}

func twoFAKey(userID string) string        { return "totp_" + userID }
func twoFAPendingKey(userID string) string { return "totp_pending_" + userID }

func (s *Service) getTwoFA(userID string) twoFAState {
	return s.readTwoFA(twoFAKey(userID), userID)
}

func (s *Service) getPendingTwoFA(userID string) twoFAState {
	return s.readTwoFA(twoFAPendingKey(userID), userID)
}

func (s *Service) readTwoFA(key, userID string) twoFAState {
	var st twoFAState
	raw, err := s.sec.Get(key)
	if err != nil {
		// Treated as "not configured" below (same as before) — the boot-time
		// CheckNotOrphaned guard rules out the "wrong key, silently orphaned"
		// scenario, so a decrypt error here is most likely isolated ciphertext
		// corruption (e.g. a flipped disk bit). Not fatal, but an operator
		// needs a log trail instead of a fully silent "2FA looks disabled".
		slog.Warn("auth: failed to read 2FA state from secrets vault", "user_id", userID, "err", err)
	}
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &st)
	}
	return st
}

func (s *Service) saveTwoFA(userID string, st twoFAState) error {
	out, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.sec.Set(twoFAKey(userID), string(out))
}

// TwoFAEnabled reports whether the user has activated 2FA.
func (s *Service) TwoFAEnabled(userID string) bool {
	return s.getTwoFA(userID).Enabled
}

// ErrTwoFAAlreadyEnabled is returned when enrollment is attempted on an account
// that already has 2FA active. Trocar de aparelho passa por desativar primeiro,
// que exige um código válido — assim ninguém troca o segundo fator de outra
// pessoa só por estar de posse do token dela.
var ErrTwoFAAlreadyEnabled = errors.New("2FA já está ativo nesta conta; desative primeiro (exige um código atual) para cadastrar outro aparelho")

// BeginTwoFASetup creates (or replaces) a PENDING secret and returns it with the
// otpauth URL for the authenticator app. It never touches the active state: an
// account with 2FA on is refused outright, and the secret is written under the
// pending key. 2FA only turns on in ActivateTwoFA, after the code proves the
// user really has the authenticator.
func (s *Service) BeginTwoFASetup(userID, username string) (secret, otpauth string, err error) {
	if s.getTwoFA(userID).Enabled {
		return "", "", ErrTwoFAAlreadyEnabled
	}
	secret, err = GenerateTOTPSecret()
	if err != nil {
		return "", "", err
	}
	out, err := json.Marshal(twoFAState{Secret: secret, Enabled: false})
	if err != nil {
		return "", "", err
	}
	if err := s.sec.Set(twoFAPendingKey(userID), string(out)); err != nil {
		return "", "", err
	}
	return secret, OtpauthURL(secret, username, "LinkGuard FW"), nil
}

// ActivateTwoFA promotes the pending secret to active once the user proves
// possession with a valid code.
func (s *Service) ActivateTwoFA(userID, code string) error {
	pending := s.getPendingTwoFA(userID)
	if pending.Secret == "" {
		return errors.New("inicie a configuração de 2FA primeiro")
	}
	if !ValidateTOTP(pending.Secret, code) {
		return errors.New("código inválido")
	}
	if err := s.saveTwoFA(userID, twoFAState{Secret: pending.Secret, Enabled: true}); err != nil {
		return err
	}
	// A pendência cumpriu o papel; deixá-la para trás só amplia a superfície.
	if err := s.sec.Delete(twoFAPendingKey(userID)); err != nil {
		slog.Warn("auth: failed to clear pending 2FA secret", "user_id", userID, "err", err)
	}
	return nil
}

// DisableTwoFA turns off 2FA, requiring a valid current code to do so.
func (s *Service) DisableTwoFA(userID, code string) error {
	st := s.getTwoFA(userID)
	if !st.Enabled {
		return nil
	}
	if !ValidateTOTP(st.Secret, code) {
		return errors.New("código inválido")
	}
	if err := s.saveTwoFA(userID, twoFAState{}); err != nil {
		return err
	}
	if err := s.sec.Delete(twoFAPendingKey(userID)); err != nil {
		slog.Warn("auth: failed to clear pending 2FA secret", "user_id", userID, "err", err)
	}
	return nil
}
