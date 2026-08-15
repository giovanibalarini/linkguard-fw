package auth

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

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

// ─── Troca da própria senha ──────────────────────────────────────────────────
//
// Este caminho não existia. A única forma de trocar senha era PUT /api/users/{id},
// gateado por users.manage — então quem não administra usuários não tinha como
// sair da senha que alguém definiu para ele, incluindo a da instalação.

func seedUser(t *testing.T, svc *Service, username, password string) *storage.User {
	t.Helper()
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	u := &storage.User{Username: username}
	if err := svc.db.CreateUser(u, hash, nil); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

func TestChangeOwnPasswordRequiresTheCurrentOne(t *testing.T) {
	svc := newTwoFATestService(t)
	u := seedUser(t, svc, "operador", "SenhaAtual123")

	err := svc.ChangeOwnPassword(u.ID, "chuteErrado999", "SenhaNova456")
	if !errors.Is(err, ErrWrongCurrentPassword) {
		t.Fatalf("esperava ErrWrongCurrentPassword, veio: %v", err)
	}

	// E a senha não pode ter mudado: senão quem pegasse uma sessão aberta
	// assumia a conta sem nunca ter sabido a senha.
	after, err := svc.db.GetUserByID(u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(after.Password), []byte("SenhaNova456")) == nil {
		t.Fatal("a senha foi trocada mesmo com a senha atual errada")
	}
}

func TestChangeOwnPasswordSucceedsAndInvalidatesOldTokens(t *testing.T) {
	svc := newTwoFATestService(t)
	u := seedUser(t, svc, "operador", "SenhaAtual123")

	before, err := svc.db.GetUserByID(u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}

	if err := svc.ChangeOwnPassword(u.ID, "SenhaAtual123", "SenhaNova456"); err != nil {
		t.Fatalf("ChangeOwnPassword: %v", err)
	}

	after, err := svc.db.GetUserByID(u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(after.Password), []byte("SenhaNova456")) != nil {
		t.Fatal("a senha nova não vale")
	}
	if bcrypt.CompareHashAndPassword([]byte(after.Password), []byte("SenhaAtual123")) == nil {
		t.Fatal("a senha antiga continua valendo")
	}
	if after.PasswordVersion <= before.PasswordVersion {
		t.Fatal("password_version não subiu — os tokens emitidos antes continuariam válidos")
	}
}

func TestChangeOwnPasswordRejectsShortAndUnchangedPasswords(t *testing.T) {
	svc := newTwoFATestService(t)
	u := seedUser(t, svc, "operador", "SenhaAtual123")

	if err := svc.ChangeOwnPassword(u.ID, "SenhaAtual123", "curta"); err == nil {
		t.Error("aceitou senha abaixo do mínimo")
	}
	if err := svc.ChangeOwnPassword(u.ID, "SenhaAtual123", "SenhaAtual123"); err == nil {
		t.Error("aceitou trocar a senha por ela mesma")
	}
}
