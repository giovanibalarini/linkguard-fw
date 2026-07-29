# Backup cifrado + envio periódico por e-mail Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cifrar o backup do LinkGuard FW (AES-256-GCM, chave derivada de uma senha do admin) nos dois
fluxos existentes (download manual, restore), e adicionar envio automático periódico por e-mail
reaproveitando o SMTP já configurado em Notificações.

**Architecture:** Pacote novo `internal/backupcrypt` isola a criptografia pura (sem HTTP, sem banco).
Pacote novo `internal/backup` isola o domínio (o tipo `BackupData`, montar o snapshot, cifrar/decifrar
usando `backupcrypt`, e o `Scheduler` que dispara o envio periódico) — colocando `BackupData` aqui em
vez de em `internal/api/handlers` evita um ciclo de import, já que tanto o handler HTTP quanto o
`Scheduler` precisam da mesma lógica. `internal/api/handlers/backup.go` vira só HTTP: decodifica a
requisição, chama `internal/backup`, escreve a resposta.

**Tech Stack:** Go 1.25 (`golang.org/x/crypto/scrypt`, já dependência do projeto — sem dependência nova
no `go.mod`), `mime/multipart`/`net/smtp` da stdlib pro e-mail com anexo. Frontend React/TypeScript
sem mudança de dependências.

## Global Constraints

- Formato do arquivo cifrado: magic `"LGB1"` (4 bytes) + salt scrypt (16 bytes) + nonce GCM (12 bytes)
  + ciphertext (GCM, tag incluído). scrypt N=32768, r=8, p=1. AES-256 (chave de 32 bytes).
- Senha de backup: mínimo 12 caracteres (validado só no handler HTTP, `internal/backupcrypt` aceita
  qualquer senha não-vazia — separação de responsabilidade entre política HTTP e algoritmo puro).
- Guardada em `internal/secrets` sob o nome `backup_passphrase` (reaproveita o serviço já existente,
  nada novo a construir para armazenamento).
- **Os dois fluxos de export (`GET /api/backup` manual, e-mail automático) sempre cifram** — sem opção
  de baixar em texto puro.
- **Restore sempre pede a senha na requisição**, nunca assume a senha configurada localmente (cenário
  principal é restaurar noutra máquina).
- **Alertas de falha/sucesso do backup automático disparam só na transição de estado** (nunca em
  estado repetido — sucesso após sucesso ou falha após falha não geram alerta novo), incluindo a
  primeira execução: primeira execução com sucesso dispara `BackupSucceeded`, primeira execução com
  falha dispara `BackupFailed` — só sucesso-após-sucesso e falha-após-falha ficam silenciosos.
- Sem dependência nova no `go.mod` — `golang.org/x/crypto` já é usado (`bcrypt` em `internal/auth`,
  `curve25519` em `internal/wireguard`); `scrypt` é do mesmo módulo.
- Backend: TDD real (escrever o teste que falha antes da implementação) é o padrão já estabelecido
  neste projeto para código Go — diferente do frontend. Rodar com:
  `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH"` antes de `go test ./...`.
- Frontend: sem framework de teste (decisão já estabelecida no projeto) — verificação por
  `npm run build`. Rodar com: `export PATH="$HOME/.nvm/versions/node/v22.21.1/bin:$PATH"` antes de
  `cd web && npm run build`.

---

### Task 1: `internal/backupcrypt` — criptografia pura

**Files:**
- Create: `internal/backupcrypt/backupcrypt.go`
- Test: `internal/backupcrypt/backupcrypt_test.go`

**Interfaces:**
- Produces: `Encrypt(plaintext []byte, passphrase string) ([]byte, error)`,
  `Decrypt(data []byte, passphrase string) ([]byte, error)`, `var ErrInvalidFormat error` — usados
  pelo Task 4.

- [ ] **Step 1: Escrever os testes que falham**

```go
// internal/backupcrypt/backupcrypt_test.go
package backupcrypt_test

import (
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/backupcrypt"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plaintext := []byte(`{"kind":"linkguard-fw-backup","settings":{}}`)
	ciphertext, err := backupcrypt.Encrypt(plaintext, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := backupcrypt.Decrypt(ciphertext, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("round trip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestEncryptProducesDifferentCiphertextEachTime(t *testing.T) {
	// Salt+nonce are random per call, so encrypting the same plaintext twice
	// must never produce identical bytes — a fixed salt/nonce would leak
	// whether two backups share content.
	a, err := backupcrypt.Encrypt([]byte("mesmo conteudo"), "senha-123456789012")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	b, err := backupcrypt.Encrypt([]byte("mesmo conteudo"), "senha-123456789012")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if string(a) == string(b) {
		t.Fatal("expected different ciphertext across calls (salt/nonce must be random per call)")
	}
}

func TestDecryptWrongPassphraseFails(t *testing.T) {
	ciphertext, err := backupcrypt.Encrypt([]byte("segredo"), "senha-certa-123456")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := backupcrypt.Decrypt(ciphertext, "senha-errada-123456"); err == nil {
		t.Fatal("expected error decrypting with wrong passphrase, got nil")
	}
}

func TestDecryptTamperedCiphertextFails(t *testing.T) {
	ciphertext, err := backupcrypt.Encrypt([]byte("dado importante"), "senha-123456789012")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 0xFF // flip a byte inside the GCM ciphertext/tag
	if _, err := backupcrypt.Decrypt(tampered, "senha-123456789012"); err == nil {
		t.Fatal("expected error decrypting tampered ciphertext, got nil")
	}
}

func TestDecryptUnknownMagicFails(t *testing.T) {
	garbage := []byte("not a linkguard backup file at all, just garbage bytes here")
	if _, err := backupcrypt.Decrypt(garbage, "qualquer-senha-1234"); err != backupcrypt.ErrInvalidFormat {
		t.Fatalf("expected ErrInvalidFormat, got %v", err)
	}
}

func TestDecryptTruncatedFileFails(t *testing.T) {
	if _, err := backupcrypt.Decrypt([]byte("LGB1x"), "qualquer-senha-1234"); err != backupcrypt.ErrInvalidFormat {
		t.Fatalf("expected ErrInvalidFormat for truncated file, got %v", err)
	}
}
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/backupcrypt/... -v`
Expected: FAIL — `package backupcrypt is not in std` / `undefined: backupcrypt.Encrypt` (o pacote ainda
não existe).

- [ ] **Step 3: Implementar**

```go
// internal/backupcrypt/backupcrypt.go

// Package backupcrypt encrypts and decrypts the LinkGuard FW backup file.
// AES-256-GCM with a key derived from a user passphrase via scrypt — pure
// algorithm, no knowledge of HTTP, storage, or what BackupData looks like.
package backupcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

// magic identifies a LinkGuard backup file and its format version. Bumping
// the version (a new magic value) lets a future format change coexist with
// files written by this version — Decrypt rejects unknown magic outright
// instead of trying to decrypt garbage.
var magic = []byte("LGB1")

const (
	saltSize = 16
	scryptN  = 32768
	scryptR  = 8
	scryptP  = 1
	keySize  = 32 // AES-256
)

// ErrInvalidFormat means data is not a recognizable LinkGuard backup file
// (wrong magic, or too short to contain one) — distinct from a wrong
// passphrase, which fails inside GCM's authentication check instead.
var ErrInvalidFormat = errors.New("backupcrypt: not a valid LinkGuard backup file")

// Encrypt derives a key from passphrase via scrypt (fresh random salt every
// call) and seals plaintext with AES-256-GCM (fresh random nonce every call).
// The returned bytes are self-contained: magic + salt + nonce + ciphertext.
func Encrypt(plaintext []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("gerar salt: %w", err)
	}
	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, keySize)
	if err != nil {
		return nil, fmt.Errorf("derivar chave: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("criar cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("criar GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("gerar nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	out := make([]byte, 0, len(magic)+len(salt)+len(nonce)+len(ciphertext))
	out = append(out, magic...)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// Decrypt reverses Encrypt. A wrong passphrase or a tampered file both fail
// (GCM is authenticated) — never decrypts silently into garbage.
func Decrypt(data []byte, passphrase string) ([]byte, error) {
	if len(data) < len(magic)+saltSize {
		return nil, ErrInvalidFormat
	}
	if !bytes.Equal(data[:len(magic)], magic) {
		return nil, ErrInvalidFormat
	}
	offset := len(magic)
	salt := data[offset : offset+saltSize]
	offset += saltSize

	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, keySize)
	if err != nil {
		return nil, fmt.Errorf("derivar chave: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("criar cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("criar GCM: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(data) < offset+nonceSize {
		return nil, ErrInvalidFormat
	}
	nonce := data[offset : offset+nonceSize]
	offset += nonceSize
	ciphertext := data[offset:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("senha incorreta ou arquivo inválido: %w", err)
	}
	return plaintext, nil
}
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/backupcrypt/... -v`
Expected: PASS — todos os 6 testes.

- [ ] **Step 5: Commit**

```bash
git add internal/backupcrypt/
git commit -m "feat(backupcrypt): AES-256-GCM + scrypt para o arquivo de backup"
```

---

### Task 2: `internal/notify` — e-mail com anexo

**Files:**
- Modify: `internal/notify/notify.go`
- Test: `internal/notify/notify_test.go`

**Interfaces:**
- Consumes: `Service.LoadConfig() Config` (já existe, `Config.Email EmailCfg` já existe com campos
  `Enabled/Host/Port/Username/Password/From/To`).
- Produces: `func (s *Service) SendEmailAttachment(subject, body string, attachment []byte, filename string) error`
  — usado pelo Task 5 (`Scheduler`, via a interface `emailSender` que o Task 5 define).

- [ ] **Step 1: Escrever os testes que falham**

Adicionar ao final de `internal/notify/notify_test.go` (reaproveita os helpers `openTestDB`/
`newTestSecrets` já existentes no topo do arquivo):

```go
func TestBuildMultipartMessageIncludesAttachment(t *testing.T) {
	msg, err := buildMultipartMessage("from@example.com", "to@example.com", "Backup LinkGuard", "Segue em anexo.",
		[]byte("conteudo cifrado de teste"), "linkguard-backup.lgbak")
	if err != nil {
		t.Fatalf("buildMultipartMessage: %v", err)
	}

	tp := textproto.NewReader(bufio.NewReader(bytes.NewReader(msg)))
	header, err := tp.ReadMIMEHeader()
	if err != nil {
		t.Fatalf("ReadMIMEHeader: %v", err)
	}
	mediaType, params, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("ParseMediaType: %v", err)
	}
	if mediaType != "multipart/mixed" {
		t.Fatalf("expected multipart/mixed, got %q", mediaType)
	}

	mr := multipart.NewReader(tp.R, params["boundary"])
	var sawText, sawAttachment bool
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("NextPart: %v", err)
		}
		partBody, _ := io.ReadAll(part)
		switch {
		case strings.HasPrefix(part.Header.Get("Content-Type"), "text/plain"):
			sawText = true
			if string(partBody) != "Segue em anexo." {
				t.Fatalf("text part mismatch: %q", partBody)
			}
		case part.Header.Get("Content-Disposition") != "":
			sawAttachment = true
			decoded, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(partBody)))
			if err != nil {
				t.Fatalf("base64 decode attachment: %v", err)
			}
			if string(decoded) != "conteudo cifrado de teste" {
				t.Fatalf("attachment mismatch: %q", decoded)
			}
			if !strings.Contains(part.Header.Get("Content-Disposition"), "linkguard-backup.lgbak") {
				t.Fatalf("filename missing from Content-Disposition: %q", part.Header.Get("Content-Disposition"))
			}
		}
	}
	if !sawText || !sawAttachment {
		t.Fatalf("expected both text and attachment parts, sawText=%v sawAttachment=%v", sawText, sawAttachment)
	}
}

func TestSendEmailAttachmentFailsWhenEmailDisabled(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db, newTestSecrets(t, db))

	if err := s.SendEmailAttachment("assunto", "corpo", []byte("dados"), "arquivo.lgbak"); err == nil {
		t.Fatal("expected error when email channel is not enabled, got nil")
	}
}
```

Adicionar os imports novos ao topo de `internal/notify/notify_test.go` (junto dos já existentes):

```go
import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/notify/... -run 'TestBuildMultipartMessage|TestSendEmailAttachment' -v`
Expected: FAIL — `undefined: buildMultipartMessage` / `s.SendEmailAttachment undefined`.

- [ ] **Step 3: Implementar**

Adicionar a `internal/notify/notify.go` (não muda `sendEmail` nem nenhuma outra função existente).
Primeiro, adicionar aos imports do topo do arquivo (junto dos já existentes: `bytes`, `context`,
`encoding/json`, `fmt`, `log/slog`, `net/http`, `net/smtp`, `net/url`, `strings`, `time`):

```go
	"encoding/base64"
	"mime/multipart"
	"net/textproto"
```

(`bytes` já está importado.) Depois, adicionar ao final do arquivo:

```go
// buildMultipartMessage assembles a MIME multipart/mixed e-mail (RFC822
// headers + a text part + one base64 attachment part), ready to hand to
// smtp.SendMail. Split out from SendEmailAttachment so the message format is
// testable without a real SMTP connection.
func buildMultipartMessage(from, to, subject, body string, attachment []byte, filename string) ([]byte, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	if _, err := fmt.Fprintf(&buf, "From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=%q\r\n\r\n",
		from, to, subject, w.Boundary()); err != nil {
		return nil, err
	}

	textPart, err := w.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/plain; charset=utf-8"}})
	if err != nil {
		return nil, fmt.Errorf("criar parte de texto: %w", err)
	}
	if _, err := textPart.Write([]byte(body)); err != nil {
		return nil, fmt.Errorf("escrever texto: %w", err)
	}

	attachPart, err := w.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {"application/octet-stream"},
		"Content-Transfer-Encoding": {"base64"},
		"Content-Disposition":       {fmt.Sprintf(`attachment; filename=%q`, filename)},
	})
	if err != nil {
		return nil, fmt.Errorf("criar parte do anexo: %w", err)
	}
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(attachment)))
	base64.StdEncoding.Encode(encoded, attachment)
	if _, err := attachPart.Write(encoded); err != nil {
		return nil, fmt.Errorf("escrever anexo: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("fechar multipart: %w", err)
	}
	return buf.Bytes(), nil
}

// SendEmailAttachment sends an e-mail with a single binary attachment via the
// same SMTP config sendEmail uses. Alerts stay text-only via sendEmail — this
// is the one case (the periodic encrypted backup) that needs a real
// attachment.
func (s *Service) SendEmailAttachment(subject, body string, attachment []byte, filename string) error {
	cfg := s.LoadConfig().Email
	if !cfg.Enabled {
		return fmt.Errorf("e-mail não está habilitado em Notificações")
	}
	port := cfg.Port
	if port == 0 {
		port = 587
	}
	addr := fmt.Sprintf("%s:%d", cfg.Host, port)
	from := cfg.From
	if from == "" {
		from = cfg.Username
	}
	msg, err := buildMultipartMessage(from, cfg.To, subject, body, attachment, filename)
	if err != nil {
		return fmt.Errorf("montar e-mail: %w", err)
	}
	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}
	if err := smtp.SendMail(addr, auth, from, strings.Split(cfg.To, ","), msg); err != nil {
		return fmt.Errorf("email: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/notify/... -v`
Expected: PASS — todos os testes do pacote, incluindo os pré-existentes (não devem quebrar).

- [ ] **Step 5: Commit**

```bash
git add internal/notify/
git commit -m "feat(notify): e-mail com anexo (SendEmailAttachment)"
```

---

### Task 3: `internal/alerts` — alerta de falha/sucesso do backup

**Files:**
- Modify: `internal/alerts/service.go`
- Test: `internal/alerts/service_test.go`

**Interfaces:**
- Produces: `TypeBackupFailed` (const), `func (s *Service) BackupFailed(detail string) error`,
  `func (s *Service) BackupSucceeded() error` — usados pelo Task 5 (`Scheduler`).

- [ ] **Step 1: Escrever os testes que falham**

Adicionar ao final de `internal/alerts/service_test.go` (reaproveita `openTestDB`/`fakeNotifier` já
existentes no topo do arquivo):

```go
func TestBackupFailedIsWarningNormal(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)
	fn := &fakeNotifier{}
	s.SetNotifier(fn)

	if err := s.BackupFailed("smtp indisponível"); err != nil {
		t.Fatal(err)
	}
	if len(fn.normal) != 1 || fn.normal[0] != "warning|Falha ao enviar backup" {
		t.Errorf("normal notifies = %v", fn.normal)
	}
	if len(fn.recovery) != 0 {
		t.Errorf("unexpected recovery notify: %v", fn.recovery)
	}
}

func TestBackupSucceededDeliversViaRecovery(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)
	fn := &fakeNotifier{}
	s.SetNotifier(fn)

	if err := s.BackupSucceeded(); err != nil {
		t.Fatal(err)
	}
	if len(fn.recovery) != 1 {
		t.Errorf("recovery notifies = %v, want 1", fn.recovery)
	}
}
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/alerts/... -run 'TestBackup' -v`
Expected: FAIL — `s.BackupFailed undefined` / `s.BackupSucceeded undefined`.

- [ ] **Step 3: Implementar**

Em `internal/alerts/service.go`, adicionar `TypeBackupFailed` ao bloco de constantes existente
(junto de `TypeDiskFull`, `TypeAppDown` etc.):

```go
	TypeBackupFailed   = "backup_failed"
```

Adicionar ao final do arquivo, mesmo padrão de `DiskFull`/`DiskCleared`:

```go
// BackupFailed raises a warning alert when the periodic (or manual "enviar
// agora") backup e-mail fails to send. Severity is warning, not critical —
// the server's own configuration didn't change, only the off-site copy is
// late; it's not a service outage.
func (s *Service) BackupFailed(detail string) error {
	return s.Create(TypeBackupFailed, SeverityWarning, "Falha ao enviar backup",
		"O backup automático não pôde ser enviado: "+detail, "")
}

// BackupSucceeded clears BackupFailed and notifies recovery.
func (s *Service) BackupSucceeded() error {
	s.AutoResolve(TypeBackupFailed, "")
	return s.createRecovery(TypeBackupFailed, "Backup enviado",
		"O backup automático voltou a ser enviado com sucesso.", "")
}
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/alerts/... -v`
Expected: PASS — todos os testes do pacote.

- [ ] **Step 5: Commit**

```bash
git add internal/alerts/
git commit -m "feat(alerts): alerta de falha/sucesso do backup automático"
```

---

### Task 4: `internal/backup` — dados e criptografia do snapshot

**Files:**
- Create: `internal/backup/data.go`
- Test: `internal/backup/data_test.go`

**Interfaces:**
- Consumes: `backupcrypt.Encrypt`/`backupcrypt.Decrypt` (Task 1); `storage.DB.ExportSettings()`,
  `storage.DB.GetLinks()`, `storage.DB.ListDHCPReservations()`, `storage.DB.ListDNSBlocklist()`
  (já existem, usados hoje em `internal/api/handlers/backup.go`'s `snapshot()`); `secrets.Secrets`
  interface (`Get`/`Set`/`Status`/`Delete`, já existe).
- Produces: `type BackupData struct{...}` (mesmos campos de hoje: `Version, Kind, Settings, Links,
  Reservations, Blocklist`), `const PassphraseSecretName = "backup_passphrase"`,
  `func Snapshot(db *storage.DB, version string) (BackupData, error)`,
  `func EncryptSnapshot(db *storage.DB, sec secrets.Secrets, version string) ([]byte, error)`,
  `func DecryptRestore(ciphertext []byte, passphrase string) (BackupData, error)`,
  `var ErrPassphraseNotConfigured error` — usados pelo Task 5 (`Scheduler`) e Task 6 (handler HTTP).

- [ ] **Step 1: Escrever os testes que falham**

```go
// internal/backup/data_test.go
package backup_test

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/backup"
	"github.com/giovanibalarini/linkguard-fw/internal/backupcrypt"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func openTestDB(t *testing.T) *storage.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func newTestSecrets(t *testing.T, db *storage.DB) *secrets.Service {
	t.Helper()
	dir := t.TempDir()
	key, err := secrets.LoadOrGenerateKey(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	return secrets.NewService(db, key)
}

func TestEncryptSnapshotFailsWithoutPassphrase(t *testing.T) {
	db := openTestDB(t)
	sec := newTestSecrets(t, db)

	if _, err := backup.EncryptSnapshot(db, sec, "v-test"); err != backup.ErrPassphraseNotConfigured {
		t.Fatalf("expected ErrPassphraseNotConfigured, got %v", err)
	}
}

func TestEncryptSnapshotThenDecryptRestoreRoundTrip(t *testing.T) {
	db := openTestDB(t)
	sec := newTestSecrets(t, db)
	if err := sec.Set(backup.PassphraseSecretName, "senha-de-teste-123456"); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}
	if err := db.SetSetting("some_key", "some_value"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}

	encrypted, err := backup.EncryptSnapshot(db, sec, "v-test")
	if err != nil {
		t.Fatalf("EncryptSnapshot: %v", err)
	}

	data, err := backup.DecryptRestore(encrypted, "senha-de-teste-123456")
	if err != nil {
		t.Fatalf("DecryptRestore: %v", err)
	}
	if data.Version != "v-test" {
		t.Fatalf("Version = %q, want v-test", data.Version)
	}
	if data.Kind != "linkguard-fw-backup" {
		t.Fatalf("Kind = %q, want linkguard-fw-backup", data.Kind)
	}
	if data.Settings["some_key"] != "some_value" {
		t.Fatalf("Settings[some_key] = %q, want some_value", data.Settings["some_key"])
	}
}

func TestDecryptRestoreRejectsNonBackupJSON(t *testing.T) {
	// A well-formed, correctly-encrypted file that just isn't a LinkGuard
	// backup (wrong "kind") must still be rejected, not silently accepted.
	plaintext, _ := json.Marshal(map[string]string{"kind": "something-else"})
	encrypted, err := backupcrypt.Encrypt(plaintext, "senha-1234567890ab")
	if err != nil {
		t.Fatalf("Encrypt fixture: %v", err)
	}
	if _, err := backup.DecryptRestore(encrypted, "senha-1234567890ab"); err == nil {
		t.Fatal("expected error for non-backup JSON, got nil")
	}
}

func TestDecryptRestoreWrongPassphraseFails(t *testing.T) {
	db := openTestDB(t)
	sec := newTestSecrets(t, db)
	if err := sec.Set(backup.PassphraseSecretName, "senha-certa-123456"); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}
	encrypted, err := backup.EncryptSnapshot(db, sec, "v-test")
	if err != nil {
		t.Fatalf("EncryptSnapshot: %v", err)
	}
	if _, err := backup.DecryptRestore(encrypted, "senha-errada-123456"); err == nil {
		t.Fatal("expected error decrypting with wrong passphrase, got nil")
	}
}
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/backup/... -v`
Expected: FAIL — o pacote `internal/backup` ainda não existe.

- [ ] **Step 3: Implementar**

```go
// internal/backup/data.go

// Package backup owns the LinkGuard FW configuration snapshot: what goes into
// a backup, and how it's encrypted/decrypted. Kept separate from
// internal/api/handlers so both the HTTP handler and the Scheduler (which
// runs with no HTTP request in sight) can share the exact same logic without
// an import cycle.
package backup

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/giovanibalarini/linkguard-fw/internal/backupcrypt"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// PassphraseSecretName is the internal/secrets entry holding the backup
// encryption passphrase.
const PassphraseSecretName = "backup_passphrase"

// BackupData is the portable snapshot of the panel's configuration. Settings
// carry the bulk of it (balancer, port forwards, VPN, notifications, DHCP/DNS,
// 2FA), plus the LAN-facing reservation/blocklist lists. Links are exported for
// reference but not auto-restored (they tie into live routing/table IDs).
type BackupData struct {
	Version      string                    `json:"version"`
	Kind         string                    `json:"kind"`
	Settings     map[string]string         `json:"settings"`
	Links        []storage.Link            `json:"links"`
	Reservations []storage.DHCPReservation `json:"dhcp_reservations"`
	Blocklist    []string                  `json:"dns_blocklist"`
}

// ErrPassphraseNotConfigured means EncryptSnapshot was called before a backup
// passphrase was ever set — there's nothing to encrypt with.
var ErrPassphraseNotConfigured = errors.New("nenhuma senha de backup configurada")

// Snapshot builds the current BackupData from the database.
func Snapshot(db *storage.DB, version string) (BackupData, error) {
	settings, err := db.ExportSettings()
	if err != nil {
		return BackupData{}, err
	}
	links, err := db.GetLinks()
	if err != nil {
		return BackupData{}, err
	}
	res, err := db.ListDHCPReservations()
	if err != nil {
		return BackupData{}, err
	}
	block, err := db.ListDNSBlocklist()
	if err != nil {
		return BackupData{}, err
	}
	if block == nil {
		block = []string{}
	}
	return BackupData{
		Version:      version,
		Kind:         "linkguard-fw-backup",
		Settings:     settings,
		Links:        links,
		Reservations: res,
		Blocklist:    block,
	}, nil
}

// EncryptSnapshot builds the current snapshot, serializes it to JSON, and
// encrypts it with the configured backup passphrase.
func EncryptSnapshot(db *storage.DB, sec secrets.Secrets, version string) ([]byte, error) {
	passphrase, err := sec.Get(PassphraseSecretName)
	if err != nil {
		return nil, fmt.Errorf("ler senha de backup: %w", err)
	}
	if passphrase == "" {
		return nil, ErrPassphraseNotConfigured
	}
	data, err := Snapshot(db, version)
	if err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("serializar backup: %w", err)
	}
	return backupcrypt.Encrypt(plaintext, passphrase)
}

// DecryptRestore decrypts ciphertext with passphrase and parses it back into
// BackupData, verifying it really is a LinkGuard backup (not just any file
// that happens to decrypt without error under this passphrase).
func DecryptRestore(ciphertext []byte, passphrase string) (BackupData, error) {
	plaintext, err := backupcrypt.Decrypt(ciphertext, passphrase)
	if err != nil {
		return BackupData{}, err
	}
	var data BackupData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return BackupData{}, fmt.Errorf("backup decifrado não é um JSON válido: %w", err)
	}
	if data.Kind != "linkguard-fw-backup" {
		return BackupData{}, errors.New("isto não parece um backup do LinkGuard FW")
	}
	return data, nil
}
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/backup/... -v`
Expected: PASS — todos os 5 testes.

- [ ] **Step 5: Commit**

```bash
git add internal/backup/
git commit -m "feat(backup): BackupData + Snapshot/EncryptSnapshot/DecryptRestore"
```

---

### Task 5: `internal/backup` — Scheduler (envio periódico)

**Files:**
- Create: `internal/backup/scheduler.go`
- Test: `internal/backup/scheduler_test.go`

**Interfaces:**
- Consumes: `EncryptSnapshot`/`ErrPassphraseNotConfigured` (Task 4);
  `alerts.Service.BackupFailed`/`.BackupSucceeded` (Task 3); `storage.DB.GetSetting`/`.SetSetting`
  (já existem).
- Produces: `type RunStatus struct{OK bool; Error string; At int64}` (exportado, com tags JSON
  `ok`/`error,omitempty`/`at`), `const ScheduleSettingKey = "backup_schedule"`,
  `const LastRunSettingKey = "backup_last_run"`,
  `const ScheduleOff = "off"`, `ScheduleDaily = "daily"`, `ScheduleWeekly = "weekly"`,
  `ScheduleMonthly = "monthly"`,
  `type Scheduler struct{...}`, `func NewScheduler(db *storage.DB, sec secrets.Secrets, sender emailSender, alertSvc *alerts.Service, version string) *Scheduler`,
  `func (s *Scheduler) Run(ctx context.Context)`, `func (s *Scheduler) RunOnce(ctx context.Context) error`,
  `func (s *Scheduler) LastRunStatus() RunStatus` — usados pelo Task 6 (handler HTTP, campo do
  `BackupHandler`) e Task 7 (wiring em `main.go`: `notify.Service` já satisfaz `emailSender`
  estruturalmente, sem mudança no call site).

- [ ] **Step 1: Escrever os testes que falham**

```go
// internal/backup/scheduler_test.go
package backup_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/backup"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

type fakeEmailSender struct {
	err   error
	calls int
}

func (f *fakeEmailSender) SendEmailAttachment(subject, body string, attachment []byte, filename string) error {
	f.calls++
	return f.err
}

type fakeSchedulerNotifier struct {
	normal   []string
	recovery []string
}

func (f *fakeSchedulerNotifier) Notify(severity, title, message string) {
	f.normal = append(f.normal, severity+"|"+title)
}
func (f *fakeSchedulerNotifier) NotifyRecovery(title, message string) {
	f.recovery = append(f.recovery, title)
}

func newSchedulerTestDeps(t *testing.T) (*storage.DB, *secrets.Service) {
	t.Helper()
	db := openTestDB(t)
	sec := newTestSecrets(t, db)
	if err := sec.Set(backup.PassphraseSecretName, "senha-de-teste-123456"); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}
	return db, sec
}

func TestRunOnceRecordsLastRunOnSuccess(t *testing.T) {
	db, sec := newSchedulerTestDeps(t)
	alertSvc := alerts.NewService(db)
	sender := &fakeEmailSender{}
	sched := backup.NewScheduler(db, sec, sender, alertSvc, "v-test")

	if err := sched.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if sender.calls != 1 {
		t.Fatalf("expected 1 send attempt, got %d", sender.calls)
	}
	status := sched.LastRunStatus()
	if !status.OK {
		t.Fatalf("expected OK last-run status, got %+v", status)
	}
	if status.At == 0 {
		t.Fatal("expected non-zero At timestamp")
	}
}

func TestRunOnceAlertsOnlyOnStateTransition(t *testing.T) {
	db, sec := newSchedulerTestDeps(t)
	alertSvc := alerts.NewService(db)
	fn := &fakeSchedulerNotifier{}
	alertSvc.SetNotifier(fn)
	sender := &fakeEmailSender{err: fmt.Errorf("smtp indisponível")}
	sched := backup.NewScheduler(db, sec, sender, alertSvc, "v-test")

	// First run ever, and it fails: must alert — this IS the transition into
	// a bad state, even with no prior "success" to transition away from.
	if err := sched.RunOnce(context.Background()); err == nil {
		t.Fatal("expected error from first RunOnce")
	}
	if len(fn.normal) != 1 {
		t.Fatalf("expected 1 alert after first failure, got %d: %v", len(fn.normal), fn.normal)
	}

	// Second run, still failing: same state as before, must NOT alert again.
	if err := sched.RunOnce(context.Background()); err == nil {
		t.Fatal("expected error from second RunOnce")
	}
	if len(fn.normal) != 1 {
		t.Fatalf("expected still 1 alert after repeated failure, got %d: %v", len(fn.normal), fn.normal)
	}

	// Third run succeeds: transition failure→success, must alert (recovery).
	sender.err = nil
	if err := sched.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(fn.recovery) != 1 {
		t.Fatalf("expected 1 recovery notification, got %d: %v", len(fn.recovery), fn.recovery)
	}

	// Fourth run also succeeds: same state as before, must NOT alert again.
	if err := sched.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(fn.recovery) != 1 {
		t.Fatalf("expected still 1 recovery notification after repeated success, got %d: %v", len(fn.recovery), fn.recovery)
	}
}

func TestRunOnceWithoutPassphraseReturnsError(t *testing.T) {
	db := openTestDB(t)
	sec := newTestSecrets(t, db)
	alertSvc := alerts.NewService(db)
	sender := &fakeEmailSender{}
	sched := backup.NewScheduler(db, sec, sender, alertSvc, "v-test")

	if err := sched.RunOnce(context.Background()); err == nil {
		t.Fatal("expected error when no passphrase is configured")
	}
	if sender.calls != 0 {
		t.Fatalf("expected no send attempt without a passphrase, got %d calls", sender.calls)
	}
}
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/backup/... -run TestRunOnce -v`
Expected: FAIL — `undefined: backup.NewScheduler`.

- [ ] **Step 3: Implementar**

```go
// internal/backup/scheduler.go
package backup

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// Schedule values accepted by ScheduleSettingKey.
const (
	ScheduleOff     = "off"
	ScheduleDaily   = "daily"
	ScheduleWeekly  = "weekly"
	ScheduleMonthly = "monthly"
)

// ScheduleSettingKey and LastRunSettingKey are internal/storage settings
// (same mechanism as traffic_retention_profile / netsvc_last_apply).
const (
	ScheduleSettingKey = "backup_schedule"
	LastRunSettingKey  = "backup_last_run"
)

var scheduleInterval = map[string]time.Duration{
	ScheduleDaily:   24 * time.Hour,
	ScheduleWeekly:  7 * 24 * time.Hour,
	ScheduleMonthly: 30 * 24 * time.Hour,
}

// tickInterval is how often the scheduler wakes up to check whether it's time
// to run — coarse enough that daily/weekly/monthly all resolve correctly
// without a real cron.
const tickInterval = 1 * time.Hour

// RunStatus is the persisted result of the most recent scheduled (or manual
// "enviar agora") backup send, surfaced in the UI — same shape as netsvc's
// applyStatus.
type RunStatus struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	At    int64  `json:"at"` // unix seconds, 0 if never run
}

// emailSender is the subset of notify.Service that Scheduler needs, narrowed
// to a local interface so tests can inject a fake without a real SMTP server.
// *notify.Service satisfies this today with no changes needed there.
type emailSender interface {
	SendEmailAttachment(subject, body string, attachment []byte, filename string) error
}

// Scheduler periodically encrypts and e-mails a backup, per the admin-
// configured schedule.
type Scheduler struct {
	db      *storage.DB
	sec     secrets.Secrets
	sender  emailSender
	alerts  *alerts.Service
	version string
}

// NewScheduler creates a Scheduler.
func NewScheduler(db *storage.DB, sec secrets.Secrets, sender emailSender, alertSvc *alerts.Service, version string) *Scheduler {
	return &Scheduler{db: db, sec: sec, sender: sender, alerts: alertSvc, version: version}
}

// Run starts the scheduler loop and blocks until ctx is done.
func (s *Scheduler) Run(ctx context.Context) {
	slog.Info("backup scheduler started", "tick_interval", tickInterval)
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.maybeRun(ctx)
		}
	}
}

// maybeRun checks the configured schedule and the last-run timestamp, and
// calls RunOnce only if enough time has passed since the last attempt.
func (s *Scheduler) maybeRun(ctx context.Context) {
	schedule, _ := s.db.GetSetting(ScheduleSettingKey)
	interval, ok := scheduleInterval[schedule]
	if !ok {
		return // off, or unset
	}
	last := s.lastRun()
	if last.At != 0 && time.Since(time.Unix(last.At, 0)) < interval {
		return
	}
	if err := s.RunOnce(ctx); err != nil {
		slog.Error("scheduled backup failed", "err", err)
	}
}

// RunOnce builds, encrypts, and e-mails a backup immediately — used by the
// ticker loop and by the "enviar agora" button alike. It always records the
// result in LastRunSettingKey, and raises/clears alerts.TypeBackupFailed only
// on a state transition (never on repeated success or repeated failure,
// including "first ever run" counting as a transition either way) — a
// routine daily send never spams a new alert or recovery notification.
func (s *Scheduler) RunOnce(ctx context.Context) error {
	prev := s.lastRun()
	neverRan := prev.At == 0

	encrypted, err := EncryptSnapshot(s.db, s.sec, s.version)
	if err == nil {
		err = s.sender.SendEmailAttachment(
			"Backup automático do LinkGuard FW",
			"Segue em anexo o backup cifrado da configuração. Guarde a senha configurada em Configurações → Backup — sem ela este arquivo não pode ser aberto.",
			encrypted, "linkguard-backup.lgbak")
	}

	st := RunStatus{OK: err == nil, At: time.Now().Unix()}
	if err != nil {
		st.Error = err.Error()
	}
	if b, mErr := json.Marshal(st); mErr == nil {
		_ = s.db.SetSetting(LastRunSettingKey, string(b))
	}

	switch {
	case err == nil && (neverRan || !prev.OK):
		_ = s.alerts.BackupSucceeded()
	case err != nil && (neverRan || prev.OK):
		_ = s.alerts.BackupFailed(err.Error())
	}

	_ = ctx // reserved for a future cancellable send path; encrypt+SMTP today have no cancellation point
	return err
}

// LastRunStatus returns the persisted result of the most recent send attempt.
func (s *Scheduler) LastRunStatus() RunStatus {
	return s.lastRun()
}

func (s *Scheduler) lastRun() RunStatus {
	var st RunStatus
	if raw, _ := s.db.GetSetting(LastRunSettingKey); raw != "" {
		_ = json.Unmarshal([]byte(raw), &st)
	}
	return st
}
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/backup/... -v`
Expected: PASS — todos os testes do pacote (Task 4 + Task 5 juntos).

- [ ] **Step 5: Commit**

```bash
git add internal/backup/
git commit -m "feat(backup): Scheduler com envio periódico e alerta por transição"
```

---

### Task 6: `internal/api/handlers/backup.go` — reescrever pro novo contrato

**Files:**
- Modify: `internal/api/handlers/backup.go`
- Modify: `internal/api/handlers/backup_test.go` (substitui o teste existente
  `TestRestoreReportsMissingSecretsToReconfigure`, que usa o contrato antigo de `Restore`)

**Interfaces:**
- Consumes: `backup.EncryptSnapshot`/`backup.DecryptRestore`/`backup.ErrPassphraseNotConfigured`/
  `backup.PassphraseSecretName`/`backup.ScheduleSettingKey`/`backup.ScheduleOff`/`.ScheduleDaily`/
  `.ScheduleWeekly`/`.ScheduleMonthly`/`backup.Scheduler`/`backup.Scheduler.RunOnce`/
  `backup.Scheduler.LastRunStatus` (Tasks 4/5); `secrets.Secrets.Set`/`.Status` (já existem).
- Produces: `NewBackupHandler(db, sec, version, sched)` com assinatura nova (ganha `sched
  *backup.Scheduler`), handlers `Export`, `Restore`, `PassphraseSet`, `PassphraseStatus`,
  `ScheduleGet`, `ScheduleSet`, `SendNow`, `LastRun` — usados pelo Task 7 (registro de rotas em
  `server.go`).

- [ ] **Step 1: Escrever os testes que falham (substituindo o arquivo de teste inteiro)**

```go
// internal/api/handlers/backup_test.go
package handlers_test

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/backup"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

type fakeEmailSender struct{ err error }

func (f *fakeEmailSender) SendEmailAttachment(subject, body string, attachment []byte, filename string) error {
	return f.err
}

func newBackupTestHandler(t *testing.T) (*handlers.BackupHandler, *secrets.Service) {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	key, err := secrets.LoadOrGenerateKey(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	sec := secrets.NewService(db, key)
	alertSvc := alerts.NewService(db)
	sched := backup.NewScheduler(db, sec, &fakeEmailSender{}, alertSvc, "test-version")
	h := handlers.NewBackupHandler(db, sec, "test-version", sched)
	return h, sec
}

func multipartRestoreBody(t *testing.T, encrypted []byte, passphrase string) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", "linkguard-backup.lgbak")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := fw.Write(encrypted); err != nil {
		t.Fatalf("write file part: %v", err)
	}
	if err := mw.WriteField("passphrase", passphrase); err != nil {
		t.Fatalf("WriteField: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("Close multipart writer: %v", err)
	}
	return &buf, mw.FormDataContentType()
}

func TestExportRequiresPassphrase(t *testing.T) {
	h, _ := newBackupTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/backup", nil)
	w := httptest.NewRecorder()
	h.Export(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without a configured passphrase, got %d: %s", w.Code, w.Body.String())
	}
}

func TestExportThenRestoreRoundTrip(t *testing.T) {
	h, sec := newBackupTestHandler(t)
	if err := sec.Set(backup.PassphraseSecretName, "senha-de-teste-123456"); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/backup", nil)
	w := httptest.NewRecorder()
	h.Export(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Export: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	encrypted := w.Body.Bytes()
	if len(encrypted) < 4 || string(encrypted[:4]) != "LGB1" {
		t.Fatalf("expected encrypted output starting with LGB1 magic, got %d bytes", len(encrypted))
	}

	body, contentType := multipartRestoreBody(t, encrypted, "senha-de-teste-123456")
	rreq := httptest.NewRequest(http.MethodPost, "/api/backup/restore", body)
	rreq.Header.Set("Content-Type", contentType)
	rw := httptest.NewRecorder()
	h.Restore(rw, rreq)
	if rw.Code != http.StatusOK {
		t.Fatalf("Restore: expected 200, got %d: %s", rw.Code, rw.Body.String())
	}
}

func TestRestoreWithWrongPassphraseFails(t *testing.T) {
	h, sec := newBackupTestHandler(t)
	if err := sec.Set(backup.PassphraseSecretName, "senha-certa-123456"); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/backup", nil)
	w := httptest.NewRecorder()
	h.Export(w, req)
	encrypted := w.Body.Bytes()

	body, contentType := multipartRestoreBody(t, encrypted, "senha-errada-123456")
	rreq := httptest.NewRequest(http.MethodPost, "/api/backup/restore", body)
	rreq.Header.Set("Content-Type", contentType)
	rw := httptest.NewRecorder()
	h.Restore(rw, rreq)
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong passphrase, got %d: %s", rw.Code, rw.Body.String())
	}
}

func TestRestoreReportsMissingSecretsToReconfigure(t *testing.T) {
	h, sec := newBackupTestHandler(t)
	if err := sec.Set(backup.PassphraseSecretName, "senha-de-teste-123456"); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}
	// Configure github_update_token before Restore so we can prove it is
	// correctly EXCLUDED from secrets_to_reconfigure — the counterpart to the
	// "notifications" case below, which proves an unconfigured secret IS
	// included.
	if err := sec.Set("github_update_token", "x"); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/backup", nil)
	w := httptest.NewRecorder()
	h.Export(w, req)
	encrypted := w.Body.Bytes()

	body, contentType := multipartRestoreBody(t, encrypted, "senha-de-teste-123456")
	rreq := httptest.NewRequest(http.MethodPost, "/api/backup/restore", body)
	rreq.Header.Set("Content-Type", contentType)
	rw := httptest.NewRecorder()
	h.Restore(rw, rreq)
	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rw.Code, rw.Body.String())
	}

	var resp struct {
		SecretsToReconfigure []string `json:"secrets_to_reconfigure"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	want := map[string]bool{"notifications": true}
	got := map[string]bool{}
	for _, k := range resp.SecretsToReconfigure {
		got[k] = true
	}
	for k := range want {
		if !got[k] {
			t.Fatalf("expected %q in secrets_to_reconfigure (never configured on this box), got %v", k, resp.SecretsToReconfigure)
		}
	}
	if got["github_update_token"] {
		t.Fatalf("expected 'github_update_token' NOT in secrets_to_reconfigure (it was configured before Restore), got %v", resp.SecretsToReconfigure)
	}
}

func TestPassphraseSetRejectsShortPassphrase(t *testing.T) {
	h, _ := newBackupTestHandler(t)
	body, _ := json.Marshal(map[string]string{"passphrase": "curta"})
	req := httptest.NewRequest(http.MethodPut, "/api/backup/passphrase", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.PassphraseSet(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short passphrase, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPassphraseSetThenStatusReportsConfigured(t *testing.T) {
	h, _ := newBackupTestHandler(t)
	body, _ := json.Marshal(map[string]string{"passphrase": "senha-valida-123456"})
	req := httptest.NewRequest(http.MethodPut, "/api/backup/passphrase", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.PassphraseSet(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("PassphraseSet: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	sreq := httptest.NewRequest(http.MethodGet, "/api/backup/passphrase/status", nil)
	sw := httptest.NewRecorder()
	h.PassphraseStatus(sw, sreq)
	var resp struct {
		Configured bool `json:"configured"`
	}
	if err := json.Unmarshal(sw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Configured {
		t.Fatal("expected configured=true after PassphraseSet")
	}
}

func TestScheduleSetRejectsEnablingWithoutPassphrase(t *testing.T) {
	h, _ := newBackupTestHandler(t)
	body, _ := json.Marshal(map[string]string{"schedule": "daily"})
	req := httptest.NewRequest(http.MethodPut, "/api/backup/schedule", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ScheduleSet(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 enabling schedule without passphrase, got %d: %s", w.Code, w.Body.String())
	}
}

func TestScheduleSetThenGetRoundTrip(t *testing.T) {
	h, sec := newBackupTestHandler(t)
	if err := sec.Set(backup.PassphraseSecretName, "senha-de-teste-123456"); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}
	body, _ := json.Marshal(map[string]string{"schedule": "weekly"})
	req := httptest.NewRequest(http.MethodPut, "/api/backup/schedule", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ScheduleSet(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("ScheduleSet: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	greq := httptest.NewRequest(http.MethodGet, "/api/backup/schedule", nil)
	gw := httptest.NewRecorder()
	h.ScheduleGet(gw, greq)
	var resp struct {
		Schedule string `json:"schedule"`
	}
	if err := json.Unmarshal(gw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Schedule != "weekly" {
		t.Fatalf("Schedule = %q, want weekly", resp.Schedule)
	}
}

func TestSendNowUsesScheduler(t *testing.T) {
	h, sec := newBackupTestHandler(t)
	if err := sec.Set(backup.PassphraseSecretName, "senha-de-teste-123456"); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/backup/send-now", nil)
	w := httptest.NewRecorder()
	h.SendNow(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/api/handlers/... -run 'TestExport|TestRestore|TestPassphrase|TestSchedule|TestSendNow' -v`
Expected: FAIL — assinatura de `NewBackupHandler` não bate (`too many arguments`), `h.PassphraseSet
undefined`, etc.

- [ ] **Step 3: Implementar (substitui o arquivo inteiro)**

```go
// internal/api/handlers/backup.go
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
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/api/handlers/... -v`
Expected: PASS — todos os testes do pacote `handlers` (não só os de backup).

- [ ] **Step 5: Commit**

```bash
git add internal/api/handlers/backup.go internal/api/handlers/backup_test.go
git commit -m "feat(api): backup.go usa o novo contrato cifrado (Export/Restore/passphrase/schedule/send-now)"
```

---

### Task 7: Wiring — `internal/api/server.go` + `cmd/linkguard-fw/main.go`

**Files:**
- Modify: `internal/api/server.go`
- Modify: `cmd/linkguard-fw/main.go`

**Interfaces:**
- Consumes: `backup.NewScheduler` (Task 5), `handlers.NewBackupHandler` com a nova assinatura
  (Task 6).
- Produces: endpoints HTTP registrados (`PUT/GET /api/backup/passphrase`,
  `GET /api/backup/passphrase/status`, `GET/PUT /api/backup/schedule`, `POST /api/backup/send-now`,
  `GET /api/backup/last-run`), `Scheduler` rodando em produção — nada consumido por tasks
  posteriores (Task 8 é o frontend, consome só o contrato HTTP, não símbolos Go).

- [ ] **Step 1: Adicionar o campo e o parâmetro em `internal/api/server.go`**

Adicionar o import (junto dos já existentes, em ordem alfabética com os outros
`github.com/giovanibalarini/linkguard-fw/internal/...`):

```go
	"github.com/giovanibalarini/linkguard-fw/internal/backup"
```

No struct `Server` (onde já estão `alertSvc`, `notifySvc` etc.), adicionar:

```go
	backupSched *backup.Scheduler
```

Na assinatura de `New(...)`, adicionar `backupSched *backup.Scheduler` como último parâmetro (depois
de `aiClient *ai.Client`):

```go
func New(cfg Config, db *storage.DB, exec firewall.Executor,
	linkSvc *links.Service, iptSvc *iptables.Service, routeSvc *routes.Service,
	failoverSvc *failover.Service, balancerSvc *balancer.Service, alertSvc *alerts.Service, authSvc *auth.Service,
	hostSvc *hosts.Service, netifSvc *netif.Service, nftSvc *nftables.Service, netSvc netsvc.Provider,
	vpnSvc *wireguard.Service, notifySvc *notify.Service, trafficSvc *hosttraffic.Service,
	sysCol *system.Collector, rrdSvc *tsdb.Service, promReg *prometheus.Registry,
	mon *monitoring.Collector, sec secrets.Secrets, aiClient *ai.Client, backupSched *backup.Scheduler) *Server {
```

E dentro da inicialização do struct `s := &Server{...}`, adicionar:

```go
		backupSched: backupSched,
```

- [ ] **Step 2: Trocar a construção do `BackupHandler` e adicionar as rotas novas**

Trocar (linhas atuais, dentro do bloco de registro de rotas):

```go
		backupH := handlers.NewBackupHandler(s.db, s.sec, cfg.Version)
		r.With(require(auth.PermSystemWrite)).Get("/api/backup", backupH.Export)
		r.With(require(auth.PermSystemWrite)).Post("/api/backup/restore", backupH.Restore)
```

por:

```go
		backupH := handlers.NewBackupHandler(s.db, s.sec, cfg.Version, s.backupSched)
		r.With(require(auth.PermSystemWrite)).Get("/api/backup", backupH.Export)
		r.With(require(auth.PermSystemWrite)).Post("/api/backup/restore", backupH.Restore)
		r.With(require(auth.PermSystemWrite)).Put("/api/backup/passphrase", backupH.PassphraseSet)
		r.With(require(auth.PermSystemWrite)).Get("/api/backup/passphrase/status", backupH.PassphraseStatus)
		r.With(require(auth.PermSystemWrite)).Get("/api/backup/schedule", backupH.ScheduleGet)
		r.With(require(auth.PermSystemWrite)).Put("/api/backup/schedule", backupH.ScheduleSet)
		r.With(require(auth.PermSystemWrite)).Post("/api/backup/send-now", backupH.SendNow)
		r.With(require(auth.PermSystemWrite)).Get("/api/backup/last-run", backupH.LastRun)
```

- [ ] **Step 3: Instanciar e iniciar o `Scheduler` em `cmd/linkguard-fw/main.go`**

Adicionar o import (junto dos outros `internal/...`):

```go
	"github.com/giovanibalarini/linkguard-fw/internal/backup"
```

Logo antes da chamada `server := api.New(...)` (perto de onde `metricsCollector` já é construído),
adicionar:

```go
	backupSched := backup.NewScheduler(db, secretsSvc, notifySvc, alertSvc, version)
```

Na chamada `server := api.New(...)`, adicionar `, backupSched` ao final da lista de argumentos (depois
de `aiClient`):

```go
	}, db, exec, linkSvc, iptSvc, routeSvc, failoverSvc, balancerSvc, alertSvc, authSvc, hostSvc, netifSvc, nftSvc, netSvc, vpnSvc, notifySvc, trafficSvc, sysCollector, rrdSvc, promReg, metricsCollector, secretsSvc, aiClient, backupSched)
```

Junto dos outros `go X.Run(ctx)` (depois de `go balancerSvc.Run(ctx)`), adicionar:

```go
	go backupSched.Run(ctx)
```

- [ ] **Step 4: Compilar e rodar a suíte inteira**

Run:
```bash
export PATH="/home/gov/sdk/go1.25.0/bin:$PATH"
go build ./...
go test ./...
```
Expected: build limpo, todos os testes passam (incluindo os das Tasks 1-6, agora integrados).

- [ ] **Step 5: Commit**

```bash
git add internal/api/server.go cmd/linkguard-fw/main.go
git commit -m "feat(api): registrar endpoints de backup cifrado e iniciar o Scheduler"
```

---

### Task 8: Frontend — `BackupRestore.tsx` + tipos

**Files:**
- Modify: `web/src/components/BackupRestore.tsx`
- Modify: `web/src/types/index.ts`

**Interfaces:**
- Consumes: `GET/PUT /api/backup/passphrase(/status)`, `GET/PUT /api/backup/schedule`,
  `POST /api/backup/send-now`, `GET /api/backup/last-run`, `GET /api/backup` (agora devolve bytes
  binários cifrados, não JSON), `POST /api/backup/restore` (agora `multipart/form-data` com campos
  `file`+`passphrase`, não JSON no corpo) — contrato definido no Task 6.

- [ ] **Step 1: Adicionar os tipos novos**

Em `web/src/types/index.ts`, na seção `// ─── Backup & Restore ...`, adicionar depois de
`RestoreResult` (mantendo o `RestoreResult` existente sem mudança):

```ts
export interface BackupPassphraseStatusResponse {
  configured: boolean;
}

export type BackupSchedule = 'off' | 'daily' | 'weekly' | 'monthly';

export interface BackupScheduleResponse {
  schedule: BackupSchedule;
}

export interface BackupLastRunResponse {
  ok: boolean;
  error?: string;
  at: number; // unix seconds, 0 se nunca rodou
}
```

- [ ] **Step 2: Rodar o build pra confirmar que os tipos novos compilam sozinhos**

Run:
```bash
export PATH="$HOME/.nvm/versions/node/v22.21.1/bin:$PATH"
cd web && npm run build
```
Expected: build passa (o componente ainda não usa os tipos novos, isso só confirma que a sintaxe TS
está correta).

- [ ] **Step 3: Reescrever `BackupRestore.tsx`**

```tsx
import { useEffect, useRef, useState } from 'react';
import { Download, Upload, Loader2, AlertTriangle, Check, Send, Lock } from 'lucide-react';
import client from '../api/client';
import HelpTip from './HelpTip';
import Panel from './ui/Panel';
import {
  RestoreResult, BackupSchedule, BackupPassphraseStatusResponse, BackupScheduleResponse, BackupLastRunResponse,
} from '../types';

const SCHEDULE_OPTIONS: { value: BackupSchedule; label: string }[] = [
  { value: 'off', label: 'Desligado' },
  { value: 'daily', label: 'Diário' },
  { value: 'weekly', label: 'Semanal' },
  { value: 'monthly', label: 'Mensal' },
];

/**
 * BackupRestore downloads/e-mails the full panel configuration, encrypted
 * with an admin-configured passphrase, and restores from an encrypted file.
 * Restore applies settings + DHCP reservations + DNS blocklist only (never
 * users/roles or live WAN links), so it can't lock the admin out.
 */
export default function BackupRestore() {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const [pendingFile, setPendingFile] = useState<File | null>(null);
  const [restorePassphrase, setRestorePassphrase] = useState('');
  const [restoreResult, setRestoreResult] = useState<RestoreResult | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const [passphraseConfigured, setPassphraseConfigured] = useState(false);
  const [newPassphrase, setNewPassphrase] = useState('');
  const [confirmPassphrase, setConfirmPassphrase] = useState('');
  const [savingPassphrase, setSavingPassphrase] = useState(false);

  const [schedule, setSchedule] = useState<BackupSchedule>('off');
  const [savingSchedule, setSavingSchedule] = useState(false);

  const [lastRun, setLastRun] = useState<BackupLastRunResponse | null>(null);
  const [sendingNow, setSendingNow] = useState(false);

  const flash = (m: string) => { setMsg(m); setTimeout(() => setMsg(''), 6000); };

  const loadStatus = async () => {
    try {
      const [{ data: pp }, { data: sch }, { data: lr }] = await Promise.all([
        client.get<BackupPassphraseStatusResponse>('/api/backup/passphrase/status'),
        client.get<BackupScheduleResponse>('/api/backup/schedule'),
        client.get<BackupLastRunResponse>('/api/backup/last-run'),
      ]);
      setPassphraseConfigured(pp.configured);
      setSchedule(sch.schedule);
      setLastRun(lr);
    } catch { /* ignore */ }
  };
  useEffect(() => { loadStatus(); }, []);

  const savePassphrase = async () => {
    if (newPassphrase.length < 12) { flash('Erro: a senha precisa ter pelo menos 12 caracteres.'); return; }
    if (newPassphrase !== confirmPassphrase) { flash('Erro: as senhas não coincidem.'); return; }
    setSavingPassphrase(true);
    try {
      await client.put('/api/backup/passphrase', { passphrase: newPassphrase });
      setNewPassphrase(''); setConfirmPassphrase('');
      setPassphraseConfigured(true);
      flash('Senha de backup configurada.');
    } catch (e) { flash('Erro: ' + errMsg(e)); }
    finally { setSavingPassphrase(false); }
  };

  const download = async () => {
    setBusy(true);
    try {
      const res = await client.get('/api/backup', { responseType: 'blob' });
      const url = URL.createObjectURL(res.data as Blob);
      const a = document.createElement('a');
      a.href = url; a.download = 'linkguard-backup.lgbak'; a.click();
      URL.revokeObjectURL(url);
      flash('Backup baixado.');
    } catch (e) { flash('Erro: ' + errMsg(e)); }
    finally { setBusy(false); }
  };

  const onFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f) return;
    setPendingFile(f);
    if (fileRef.current) fileRef.current.value = '';
  };

  const confirmRestore = async () => {
    if (!pendingFile) return;
    if (!restorePassphrase) { flash('Erro: informe a senha do backup.'); return; }
    setBusy(true);
    try {
      const form = new FormData();
      form.append('file', pendingFile);
      form.append('passphrase', restorePassphrase);
      const { data } = await client.post<RestoreResult>('/api/backup/restore', form);
      setPendingFile(null);
      setRestorePassphrase('');
      setRestoreResult(data);
      flash('Restaurado com sucesso.');
    } catch (e) { flash('Erro: ' + errMsg(e)); }
    finally { setBusy(false); }
  };

  const updateSchedule = async (next: BackupSchedule) => {
    if (next === schedule) return;
    setSavingSchedule(true);
    try {
      await client.put('/api/backup/schedule', { schedule: next });
      setSchedule(next);
      flash('Agendamento atualizado.');
    } catch (e) { flash('Erro: ' + errMsg(e)); }
    finally { setSavingSchedule(false); }
  };

  const sendNow = async () => {
    setSendingNow(true);
    try {
      await client.post('/api/backup/send-now');
      flash('Backup enviado por e-mail.');
      await loadStatus();
    } catch (e) { flash('Erro: ' + errMsg(e)); }
    finally { setSendingNow(false); }
  };

  return (
    <Panel title={<span className="flex items-center gap-2"><Download className="w-5 h-5 text-blue-400" /><span className="text-white font-semibold">Backup e restauração</span><HelpTip title="Backup">
          <>Salva num arquivo todas as suas configurações (links, firewall, DHCP/DNS, VPN, balanceamento,
          notificações...). Útil antes de mexer em algo ou para migrar de máquina. O arquivo é sempre
          cifrado com a senha configurada abaixo.</>
        </HelpTip></span>}>
      <div className="space-y-4">
      {msg && <div className={`px-3 py-2 rounded-lg text-sm ${msg.startsWith('Erro') ? 'bg-red-500/10 text-red-400' : 'bg-green-500/10 text-green-400'}`}>{msg}</div>}

      <div className="rounded-lg border border-gray-800 bg-gray-900/50 p-3 space-y-2">
        <div className="flex items-center gap-2 text-sm">
          <Lock className="w-4 h-4 text-gray-500" />
          <span className="text-gray-300">
            {passphraseConfigured ? 'Senha de backup configurada' : 'Nenhuma senha de backup configurada'}
          </span>
        </div>
        <p className="text-gray-600 text-xs">
          Protege o arquivo de backup (topologia de rede e inventário de hosts). Trocar a senha não
          recifra backups já gerados — eles continuam abrindo só com a senha usada na hora.
        </p>
        <div className="flex flex-wrap gap-2">
          <input type="password" value={newPassphrase} onChange={(e) => setNewPassphrase(e.target.value)}
            placeholder="Nova senha (mínimo 12 caracteres)" className="input flex-1 min-w-[200px]" />
          <input type="password" value={confirmPassphrase} onChange={(e) => setConfirmPassphrase(e.target.value)}
            placeholder="Confirmar senha" className="input flex-1 min-w-[200px]" />
          <button onClick={savePassphrase} disabled={savingPassphrase} className="btn-primary text-sm disabled:opacity-50">
            {savingPassphrase ? 'Salvando...' : 'Salvar senha'}
          </button>
        </div>
      </div>

      {restoreResult && (
        <div className="rounded-lg border border-green-500/40 bg-green-500/10 p-4 space-y-3">
          <div className="text-green-300 text-sm">
            <p className="font-medium">Restaurado: {restoreResult.settings} configs, {restoreResult.reservations} reservas, {restoreResult.blocklist} domínios.</p>
            <p className="text-green-400/70 text-xs mt-1">Reaplique DHCP/DNS e Firewall onde necessário.</p>
          </div>
          {restoreResult.secrets_to_reconfigure && restoreResult.secrets_to_reconfigure.length > 0 && (
            <div className="mt-3 p-3 rounded bg-yellow-500/10 border border-yellow-500/30 text-yellow-300 text-sm">
              <p className="font-medium mb-1">Reconfigure estas credenciais:</p>
              <ul className="list-disc list-inside space-y-0.5">
                {restoreResult.secrets_to_reconfigure.map(name => (
                  <li key={name}>
                    {name === 'github_update_token' ? 'Token do GitHub (Configurações → Atualizações)' :
                     name === 'notifications' ? 'Notificações (Configurações → Notificações)' :
                     name === 'wireguard' ? 'VPN WireGuard (chaves do servidor e dos clientes)' :
                     name}
                  </li>
                ))}
              </ul>
              <p className="text-yellow-400/70 text-xs mt-1">
                Segredos nunca fazem parte do arquivo de backup — precisam ser reinformados manualmente.
              </p>
            </div>
          )}
          <button onClick={() => setRestoreResult(null)} className="btn-secondary text-sm">Fechar</button>
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        <button onClick={download} disabled={busy || !passphraseConfigured} title={!passphraseConfigured ? 'Configure uma senha de backup primeiro' : undefined}
          className="btn-primary flex items-center gap-2 disabled:opacity-50">
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />} Baixar backup
        </button>
        <button onClick={sendNow} disabled={sendingNow || !passphraseConfigured} title={!passphraseConfigured ? 'Configure uma senha de backup primeiro' : undefined}
          className="btn-secondary flex items-center gap-2 disabled:opacity-50">
          {sendingNow ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />} Enviar por e-mail agora
        </button>
        <button onClick={() => fileRef.current?.click()} disabled={busy} className="btn-secondary flex items-center gap-2">
          <Upload className="w-4 h-4" /> Restaurar de arquivo
        </button>
        <input ref={fileRef} type="file" accept=".lgbak" onChange={onFile} className="hidden" />
      </div>

      <p className="text-gray-600 text-xs">
        A restauração aplica configurações, reservas de DHCP e blocklist de DNS. <b>Não</b> altera usuários/papéis nem os links WAN ativos — então não há risco de te trancar para fora. Depois de restaurar, reaplique DHCP/DNS e Firewall.
      </p>

      {pendingFile && (
        <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-4">
          <div className="flex items-center gap-2 text-amber-300 text-sm font-medium mb-2">
            <AlertTriangle className="w-4 h-4" /> Confirmar restauração?
          </div>
          <p className="text-amber-200/80 text-xs mb-3">Isto sobrescreve as configurações atuais pelas do arquivo. Recomendamos baixar um backup antes.</p>
          <input type="password" value={restorePassphrase} onChange={(e) => setRestorePassphrase(e.target.value)}
            placeholder="Senha do backup" className="input w-full mb-3" />
          <div className="flex gap-2">
            <button onClick={confirmRestore} disabled={busy || !restorePassphrase} className="btn-primary text-sm flex items-center gap-1.5 disabled:opacity-50">
              {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />} Restaurar agora
            </button>
            <button onClick={() => { setPendingFile(null); setRestorePassphrase(''); }} className="btn-secondary text-sm">Cancelar</button>
          </div>
        </div>
      )}

      <div className="rounded-lg border border-gray-800 bg-gray-900/50 p-3 space-y-2">
        <p className="text-gray-400 text-xs font-semibold uppercase tracking-wide">Backup automático por e-mail</p>
        <div className="flex flex-wrap items-center gap-2">
          {SCHEDULE_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              disabled={savingSchedule || (opt.value !== 'off' && !passphraseConfigured)}
              title={opt.value !== 'off' && !passphraseConfigured ? 'Configure uma senha de backup primeiro' : undefined}
              onClick={() => updateSchedule(opt.value)}
              className={`rounded-md px-3 py-1.5 text-sm transition-colors ${
                schedule === opt.value
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                  : 'bg-gray-900 text-gray-300 border border-gray-700 hover:border-gray-500'
              } disabled:opacity-50`}
            >
              {opt.label}
            </button>
          ))}
        </div>
        <p className="text-gray-600 text-xs">
          Envia o backup cifrado por e-mail no intervalo escolhido, usando o e-mail já configurado em
          Notificações.
        </p>
        {lastRun && lastRun.at > 0 && (
          <p className={`text-xs ${lastRun.ok ? 'text-gray-500' : 'text-red-400'}`}>
            Último envio automático: {lastRun.ok ? 'ok' : `falhou — ${lastRun.error}`}, {new Date(lastRun.at * 1000).toLocaleString()}
          </p>
        )}
      </div>
      </div>
    </Panel>
  );
}

function errMsg(e: unknown): string {
  const ax = e as { response?: { data?: { error?: string } } };
  return ax?.response?.data?.error || 'falha na operação';
}
```

- [ ] **Step 4: Rodar o build**

Run:
```bash
export PATH="$HOME/.nvm/versions/node/v22.21.1/bin:$PATH"
cd web && npm run build
```
Expected: build conclui sem erros de TypeScript.

- [ ] **Step 5: Commit**

```bash
git add web/src/components/BackupRestore.tsx web/src/types/index.ts
git commit -m "feat(web): tela de backup cifrado — senha, agendamento, enviar agora, status"
```

---

## Ordem de execução

Task 1 → Task 2 → Task 3 são independentes entre si (podem rodar em qualquer ordem, mas seguem em
sequência por simplicidade do ledger). Task 4 depende do Task 1 (`backupcrypt`). Task 5 depende dos
Tasks 2, 3 e 4. Task 6 depende dos Tasks 4 e 5. Task 7 depende dos Tasks 5 e 6. Task 8 depende do
contrato HTTP definido no Task 6 (não do código Go em si — pode ser implementado assim que o Task 6
estiver com o contrato fechado, mas segue por último por simplicidade do ledger).

Após as 8 tasks: revisão final de branch inteira (whole-branch review) no modelo mais capaz
disponível — com atenção extra à criptografia (Task 1), à lógica de transição de alerta (Task 5, onde
já foi pego um bug real durante a auto-revisão do spec) e ao novo contrato HTTP de `Restore` (Task 6,
mudança de JSON pra multipart é uma mudança de contrato real, não um reskin) — depois
`finishing-a-development-branch` (merge local em `main`), deploy manual (build → `.deb` → scp →
instalar em produção → verificar `/api/health`), tag `vX.Y.Z` + push.
