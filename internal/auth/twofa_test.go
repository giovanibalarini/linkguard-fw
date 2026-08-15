package auth

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func newTwoFATestService(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return NewService(db, "test-secret-at-least-32-bytes-long-xxxx", secrets.NewService(db, key))
}

// enroll takes an account from "no 2FA" to "2FA active", the way the UI does.
func enroll(t *testing.T, svc *Service, userID string) string {
	t.Helper()
	secret, _, err := svc.BeginTwoFASetup(userID, "operador")
	if err != nil {
		t.Fatalf("BeginTwoFASetup: %v", err)
	}
	code, err := totpAt(secret, time.Now())
	if err != nil {
		t.Fatalf("totpAt: %v", err)
	}
	if err := svc.ActivateTwoFA(userID, code); err != nil {
		t.Fatalf("ActivateTwoFA: %v", err)
	}
	if !svc.TwoFAEnabled(userID) {
		t.Fatal("2FA should be active after a successful enrollment")
	}
	return secret
}

// O defeito: BeginTwoFASetup gravava {Secret: novo, Enabled: false} por cima do
// estado ATIVO, então uma única chamada desligava o 2FA de quem já o tinha —
// sem código, sem confirmação, contornando a regra do DisableTwoFA.
func TestBeginSetupDoesNotDisableActiveTwoFA(t *testing.T) {
	svc := newTwoFATestService(t)
	const userID = "u1"
	enroll(t, svc, userID)

	if _, _, err := svc.BeginTwoFASetup(userID, "operador"); err == nil {
		t.Fatal("BeginTwoFASetup deveria recusar quando o 2FA já está ativo")
	}
	if !svc.TwoFAEnabled(userID) {
		t.Fatal("o 2FA foi desligado por uma chamada de setup — a vulnerabilidade continua")
	}
}

// A barreira estrutural: o setup escreve SÓ na chave pendente. Enquanto a
// pendência morava na chave ativa, era essa escrita que desligava o 2FA de quem
// já o tinha. O teste chama o setup de verdade — num usuário sem 2FA, que é o
// único caso em que ele passa — e confere que a chave ativa continua intocada.
func TestBeginSetupWritesOnlyToThePendingKey(t *testing.T) {
	svc := newTwoFATestService(t)
	const userID = "u2"

	secret, _, err := svc.BeginTwoFASetup(userID, "operador")
	if err != nil {
		t.Fatalf("BeginTwoFASetup: %v", err)
	}

	if pending := svc.getPendingTwoFA(userID).Secret; pending != secret {
		t.Fatalf("o segredo não foi para a chave pendente: %q", pending)
	}
	if active := svc.getTwoFA(userID); active.Secret != "" || active.Enabled {
		t.Fatalf("o setup tocou a chave ATIVA (%+v) — é essa escrita que desligava o 2FA de quem já o tinha", active)
	}
	if svc.TwoFAEnabled(userID) {
		t.Fatal("o setup sozinho ativou o 2FA, sem prova de posse")
	}
}

func TestActivatePromotesThePendingSecretAndClearsIt(t *testing.T) {
	svc := newTwoFATestService(t)
	const userID = "u3"
	secret := enroll(t, svc, userID)

	if got := svc.getTwoFA(userID).Secret; got != secret {
		t.Fatalf("o segredo ativo não é o que foi cadastrado: %q != %q", got, secret)
	}
	if pending := svc.getPendingTwoFA(userID).Secret; pending != "" {
		t.Fatalf("a pendência sobreviveu à ativação: %q", pending)
	}
}

func TestActivateWithoutSetupIsRefused(t *testing.T) {
	svc := newTwoFATestService(t)
	if err := svc.ActivateTwoFA("u4", "000000"); err == nil {
		t.Fatal("ativar sem ter iniciado a configuração deveria falhar")
	}
	if svc.TwoFAEnabled("u4") {
		t.Fatal("2FA ficou ativo sem cadastro nenhum")
	}
}

func TestDisableRequiresAValidCodeAndThenAllowsReenrollment(t *testing.T) {
	svc := newTwoFATestService(t)
	const userID = "u5"
	secret := enroll(t, svc, userID)

	if err := svc.DisableTwoFA(userID, "000000"); err == nil {
		t.Fatal("desativar com código inválido deveria falhar")
	}
	if !svc.TwoFAEnabled(userID) {
		t.Fatal("o 2FA foi desligado apesar do código inválido")
	}

	code, err := totpAt(secret, time.Now())
	if err != nil {
		t.Fatalf("totpAt: %v", err)
	}
	if err := svc.DisableTwoFA(userID, code); err != nil {
		t.Fatalf("DisableTwoFA com código válido: %v", err)
	}
	if svc.TwoFAEnabled(userID) {
		t.Fatal("o 2FA continuou ativo depois de um disable válido")
	}

	// Trocar de aparelho é: desativar (com código) e cadastrar de novo.
	enroll(t, svc, userID)
}
