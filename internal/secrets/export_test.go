// Package secrets (test-only helpers). This file is named export_test.go and
// declared `package secrets` (not secrets_test) so it is compiled into the
// package under test only when running `go test` — never into the production
// binary — while still exporting methods that service_test.go (package
// secrets_test) can call. This is the standard Go "internal test helper
// bridge" pattern.
package secrets

// NonceForTest exposes the stored nonce for a name, for testing nonce
// uniqueness across Set calls. Test-only.
func (s *Service) NonceForTest(name string) []byte {
	var nonce []byte
	_ = s.db.Conn().QueryRow(`SELECT nonce FROM secrets WHERE name = ?`, name).Scan(&nonce)
	return nonce
}

// CorruptCiphertextForTest flips a byte of the stored ciphertext, simulating
// tampering or disk corruption, so tests can verify Get fails loudly instead
// of returning garbage. Test-only.
func (s *Service) CorruptCiphertextForTest(name string) {
	var ciphertext []byte
	_ = s.db.Conn().QueryRow(`SELECT ciphertext FROM secrets WHERE name = ?`, name).Scan(&ciphertext)
	if len(ciphertext) == 0 {
		return
	}
	ciphertext[0] ^= 0xFF
	_, _ = s.db.Conn().Exec(`UPDATE secrets SET ciphertext = ? WHERE name = ?`, ciphertext, name)
}
