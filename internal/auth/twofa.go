package auth

import (
	"encoding/json"
	"errors"
)

// Two-factor (TOTP) state is stored per user in the secrets vault: key
// "totp_<userID>" → {secret, enabled}. A pending setup is stored with
// enabled=false until the user proves possession with a valid code.

type twoFAState struct {
	Secret  string `json:"secret"`
	Enabled bool   `json:"enabled"`
}

func twoFAKey(userID string) string { return "totp_" + userID }

func (s *Service) getTwoFA(userID string) twoFAState {
	var st twoFAState
	if raw, _ := s.sec.Get(twoFAKey(userID)); raw != "" {
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

// BeginTwoFASetup creates (or replaces) a pending secret and returns the secret
// and otpauth URL for the authenticator app. It does not enable 2FA yet.
func (s *Service) BeginTwoFASetup(userID, username string) (secret, otpauth string, err error) {
	secret, err = GenerateTOTPSecret()
	if err != nil {
		return "", "", err
	}
	if err := s.saveTwoFA(userID, twoFAState{Secret: secret, Enabled: false}); err != nil {
		return "", "", err
	}
	return secret, OtpauthURL(secret, username, "LinkGuard FW"), nil
}

// ActivateTwoFA enables 2FA once the user proves possession with a valid code.
func (s *Service) ActivateTwoFA(userID, code string) error {
	st := s.getTwoFA(userID)
	if st.Secret == "" {
		return errors.New("inicie a configuração de 2FA primeiro")
	}
	if !ValidateTOTP(st.Secret, code) {
		return errors.New("código inválido")
	}
	st.Enabled = true
	return s.saveTwoFA(userID, st)
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
	return s.saveTwoFA(userID, twoFAState{})
}
